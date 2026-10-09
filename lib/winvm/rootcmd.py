"""`winvm-root`: everything that needs root, including the libvirt qemu hook.

    winvm-root hook DOMAIN OP SUBOP EXTRA     libvirt calls this (via /etc/libvirt/hooks/qemu.d/windows-vm);
                                              the domain XML arrives on stdin
    winvm-root preflight                      run the pre-flight, print every check, exit 1 on any refusal
    winvm-root layout show|verify|record      print the identity layout / dm table; verify the live GPT against
                                              the recorded one; print a TOML record of the live GPT
    winvm-root esp-manifest LABEL             sha256 manifest of the REAL ESP into the log dir; diff vs baseline
    winvm-root overlay new|discard|check      the read-only test domain's throwaway overlay
    winvm-root teardown DOMAIN                remove a leftover assembled disk (only when the domain is off)
    winvm-root define [--test-no-marker]      audit + (re)define the network and both domains, keeping their
                                              UUIDs; --test-no-marker defines windows-test WITHOUT the SMBIOS
                                              marker (only for the guard's restore test, P3)
    winvm-root inspect start|stop|cat P|ls P  read the throwaway overlay's C: from Garuda (both VMs off): the
                                              read-only disk is assembled, the overlay attached with qemu-nbd
                                              (no partition scan) and C:'s region exposed as a read-only loop
                                              device for ntfs-3g's offline readers. For logs a failed test boot
                                              left behind (SrtTrail.txt, event logs, the guard's log).
    winvm-root destroy-test                   destroy windows-test if it runs (windows-vm-test-guard.service,
                                              at Garuda's shutdown - never called from the hook)

The hook acts only on the two domains it owns and ignores every other domain. On `prepare` it audits the XML,
runs the pre-flight and assembles the disk; any failure exits 1, which makes libvirt abort the start. On
`release` it tears the disk down. Saved-state restores and incoming migrations are refused outright: resuming
RAM that was saved before the disk changed corrupts C:. Hooks must never call back into libvirt (deadlock), so
nothing here runs virsh.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from . import config, dm, esp, layout, ntfs, preflight, xmlgen
from .probe import RealProbe


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {msg}"
    print(msg, file=sys.stderr)
    try:
        config.LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(config.HOOK_LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def load_layout() -> layout.Layout:
    return layout.load(config.LAYOUT_FILE)


def read_bcd_flags() -> dict | None:
    """Recovery/diagnostic BCD flags for the test VM, from a root-only tmpfs file (see config). None if absent."""
    f = config.BCD_FLAGS_FILE
    if not f.exists():
        return None
    st = f.stat()
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise PermissionError(f"{f} must be root-owned and not group/world writable")
    flags = {}
    for line in f.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        k, _, v = line.partition("=")
        flags[k.strip()] = v.strip()
    return flags or None


def smb_password() -> str:
    st = os.stat(config.SMB_PASSWORD_FILE)
    if st.st_uid != 0 or st.st_mode & 0o077:
        raise PermissionError(f"{config.SMB_PASSWORD_FILE} must be root-owned and 0600")
    return config.SMB_PASSWORD_FILE.read_text().strip()


def fingerprint(lay: layout.Layout) -> str:
    """sha256 of C:'s $LogFile restart area: changes whenever Windows has written to C: (any boot, any OS)."""
    pr = RealProbe()
    cdev = pr.partuuid_path(lay.part(lay.windows_partition).unique_guid)
    pr.flush(cdev)  # T28: never fingerprint pages cached before a VM wrote C:
    head = ntfs.file_head(cdev, "$LogFile", 8192)
    if not head or len(head) != 8192:
        raise ntfs.NtfsError("could not read C:'s $LogFile restart area")
    return hashlib.sha256(head).hexdigest()


# ------------------------------------------------------------------------------------------- overlay ----

def overlay_new(lay: layout.Layout) -> None:
    """Fresh throwaway overlay over the read-only disk (the disk must be assembled: called from the hook)."""
    overlay_discard()
    config.QEMU_DIR.mkdir(mode=0o711, parents=True, exist_ok=True)
    dev = dm.dm_path(config.TEST_DOMAIN)
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "raw", "-b", dev, str(config.OVERLAY)],
                   check=True, capture_output=True)
    os.chmod(config.OVERLAY, 0o600)
    config.OVERLAY_META.write_text(json.dumps({"created": time.time(), "c_fingerprint": fingerprint(lay)}))
    log(f"new overlay {config.OVERLAY} (C: fingerprint recorded)")


def overlay_discard() -> None:
    for p in (config.OVERLAY, config.OVERLAY_META):
        p.unlink(missing_ok=True)


def overlay_problem(lay: layout.Layout) -> str | None:
    """Why the existing overlay must not be reused, or None. An overlay records C:'s fingerprint at creation;
    if C: changed since (a persistent VM run or a hardware boot), the overlay's blocks no longer fit the disk."""
    if not config.OVERLAY.exists():
        return None
    try:
        meta = json.loads(config.OVERLAY_META.read_text())
    except (OSError, ValueError):
        return "the overlay has no readable metadata"
    if meta.get("c_fingerprint") != fingerprint(lay):
        return "C: changed since the overlay was made (a persistent or hardware boot happened)"
    return None


# ---------------------------------------------------------------------------------------------- hook ----

def hook(argv: list[str], xml_text: str) -> int:
    if len(argv) < 2:
        return 0
    domain, op = argv[0], argv[1]
    sub = argv[2] if len(argv) > 2 else "-"
    if domain not in config.DOMAINS:
        return 0
    if op in ("restore", "migrate"):
        log(f"[{domain}] REFUSED {op}: resuming saved RAM or migrating this VM can corrupt C: (the disk may have "
            "changed since). Remove a managed save with `virsh managedsave-remove`.")
        return 1
    if op == "prepare" and sub == "begin":
        return _prepare(domain, xml_text)
    if op == "release" and sub == "end":
        try:
            dm.teardown(domain, log=lambda m: log(f"[{domain}] {m}"))
        except Exception as e:  # noqa: BLE001 - a failed teardown must be loud, but cannot fail the release
            log(f"[{domain}] TEARDOWN FAILED: {e} - run `sudo winvm-root teardown {domain}`")
        return 0
    return 0


EXPERIMENT_FILE = Path("/run/windows-vm/experiment")
UNWAIVABLE = ("disk", "source", "TPM", "Secure Boot", "backing", "firmware", "nvram", "NAT", "MAC", "display",
              "marker", "hostdev", "filesystem", "redirdev", "smartcard")


def waived(domain: str, problems: list[str]) -> tuple[list[str], list[str]]:
    """Diagnosis-only waiver for the THROWAWAY domain (its disk is read-only by construction): lines in the
    root-only, tmpfs file /run/windows-vm/experiment name audit rules to skip (substring match), e.g. `svm`.
    Never for the persistent domain, never for a disk/firmware/network/display rule, cleared by any reboot."""
    if domain != config.TEST_DOMAIN or not EXPERIMENT_FILE.exists():
        return problems, []
    st = EXPERIMENT_FILE.stat()
    if st.st_uid != 0 or st.st_mode & 0o022:
        return problems, []
    keys = [k.strip() for k in EXPERIMENT_FILE.read_text().splitlines() if k.strip()]
    keep, skip = [], []
    for pr in problems:
        if any(k in pr for k in keys) and not any(u in pr for u in UNWAIVABLE):
            skip.append(pr)
        else:
            keep.append(pr)
    return keep, skip


def _prepare(domain: str, xml_text: str) -> int:
    say = lambda m: log(f"[{domain}] {m}")  # noqa: E731
    problems, skipped = waived(domain, xmlgen.audit(xml_text, domain))
    for pr in skipped:
        say(f"EXPERIMENT: audit rule waived for the throwaway domain: {pr}")
    if problems:
        say("REFUSED: the domain XML breaks the safety rules: " + "; ".join(problems))
        return 1
    try:
        lay = load_layout()
        checks = preflight.run(RealProbe(), lay)
    except Exception as e:  # noqa: BLE001
        say(f"REFUSED: pre-flight could not run: {e}")
        return 1
    bad = preflight.refusals(checks)
    if bad:
        say("REFUSED by the pre-flight: " + "; ".join(f"{c.name}: {c.detail}" for c in bad))
        return 1
    say("pre-flight passed (" + ", ".join(c.name for c in checks) + ")")
    try:
        if domain == config.TEST_DOMAIN:
            why = overlay_problem(lay)
            if why:
                say(f"REFUSED: the throwaway overlay is stale - {why}. Run `winvm test new`.")
                return 1
        flags = read_bcd_flags() if domain == config.TEST_DOMAIN else None
        if flags:
            say(f"BCD flags for this throwaway boot: {flags}")
        dm.build(domain, lay, smb_password(), log=say, bcd_flags=flags)
        if domain == config.TEST_DOMAIN and not config.OVERLAY.exists():
            overlay_new(lay)
    except Exception as e:  # noqa: BLE001
        say(f"REFUSED: building the VM disk failed: {e}")
        try:
            dm.teardown(domain, log=say)
        except Exception as e2:  # noqa: BLE001
            say(f"teardown after failure also failed: {e2}")
        return 1
    return 0


# ------------------------------------------------------------------------------------------ commands ----

def esp_manifest(label: str) -> int:
    root = config.REAL_ESP_MOUNT
    lines = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            lines.append(f"{esp.sha256(p)}  ./{p.relative_to(root)}")
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    out = config.LOG_DIR / f"real-esp-{label}.txt"
    out.write_text("\n".join(lines) + "\n")
    base = config.LOG_DIR / "real-esp-baseline.txt"
    if not base.exists():
        base.write_text(out.read_text())
        print(f"{out}: {len(lines)} files (recorded as the baseline)")
        return 0
    a, b = set(base.read_text().splitlines()), set(lines)
    if a == b:
        print(f"{out}: {len(lines)} files, IDENTICAL to the baseline")
        return 0
    print(f"{out}: DIFFERS from the baseline")
    for line in sorted(a - b):
        print(f"  - {line}")
    for line in sorted(b - a):
        print(f"  + {line}")
    return 1


INSPECT_STATE = dm.RUN_DIR / "inspect.json"


OVERLAY_MNT = Path("/run/windows-vm/overlay-c")


def inspect(rest: list[str]) -> int:
    sub = rest[0] if rest else "status"
    rw = "--rw" in rest
    lay = load_layout()
    if sub == "start":
        if INSPECT_STATE.exists():
            print("already started: " + INSPECT_STATE.read_text())
            return 0
        for d in config.DOMAINS:
            st = _virsh("domstate", d).stdout.strip()
            if st not in ("shut off", ""):
                print(f"{d} is {st} - inspection needs both VMs off")
                return 1
        checks = preflight.run(RealProbe(), lay)
        bad = preflight.refusals(checks)
        if bad:
            print(preflight.report(bad))
            return 1
        # nbd with max_part=0: the kernel never scans the overlay's partition table, so udev never creates
        # /dev/disk/by-partuuid links carrying the REAL partitions' GUIDs for it.
        mpp = Path("/sys/module/nbd/parameters/max_part")
        if mpp.exists() and mpp.read_text().strip() != "0":
            print("the nbd module is loaded with max_part != 0 - refusing (partition scan would duplicate PARTUUIDs)")
            return 1
        subprocess.run(["modprobe", "nbd", "max_part=0", "nbds_max=4"], check=True)
        # The dm is ALWAYS read-only; the overlay qcow2 captures every write. The real C: (p5) is never
        # written or mounted here - only this throwaway overlay is, which is exactly the goal's rule.
        dm.build(config.TEST_DOMAIN, lay, smb_password(), log=lambda m: print(m))
        if not config.OVERLAY.exists():
            overlay_new(lay)
        nbd = next(f"/dev/nbd{i}" for i in range(4) if Path(f"/sys/block/nbd{i}/pid").exists() is False)
        qargv = ["qemu-nbd", "--fork", "-f", "qcow2", "-c", nbd, str(config.OVERLAY)]
        if not rw:
            qargv.insert(1, "--read-only")
        subprocess.run(qargv, check=True)
        subprocess.run(["udevadm", "settle"])
        c = lay.part(lay.windows_partition)
        bs = lay.logical_block_size
        want = lay.total_sectors * bs
        for _ in range(100):  # qemu-nbd --fork returns before the kernel knows the device's size
            if int(Path(f"/sys/block/{Path(nbd).name}/size").read_text()) * 512 == want:
                break
            time.sleep(0.1)
        else:
            print(f"{nbd} never reached the disk's size")
            return 1
        largv = ["losetup", "--find", "--show", "--offset", str(c.first_lba * bs),
                 "--sizelimit", str(c.sectors * bs), nbd]
        if not rw:
            largv.insert(1, "--read-only")
        loop = subprocess.run(largv, check=True, capture_output=True, text=True).stdout.strip()
        state = {"nbd": nbd, "loop": loop, "rw": rw}
        got = int(subprocess.run(["blockdev", "--getsize64", loop], capture_output=True, text=True).stdout)
        if got != c.sectors * bs:
            print(f"{loop} has {got} bytes, expected {c.sectors * bs}")
            INSPECT_STATE.write_text(json.dumps(state))
            return 1
        if rw:
            OVERLAY_MNT.mkdir(parents=True, exist_ok=True)
            r = subprocess.run(["mount", "-t", "ntfs-3g", "-o", "rw", loop, str(OVERLAY_MNT)], capture_output=True, text=True)
            if r.returncode != 0:
                print("mount failed: " + r.stderr.strip())
                INSPECT_STATE.write_text(json.dumps(state))
                return 1
            state["mnt"] = str(OVERLAY_MNT)
            INSPECT_STATE.write_text(json.dumps(state))
            print(f"overlay C: MOUNTED READ-WRITE at {OVERLAY_MNT} (writes go to the throwaway overlay, NOT real C:)")
            print(f"  SYSTEM hive: {OVERLAY_MNT}/Windows/System32/config/SYSTEM   (edit with hivexsh -w)")
            print("  `winvm-root inspect stop` to unmount and tear down")
        else:
            INSPECT_STATE.write_text(json.dumps(state))
            print(f"overlay C: is readable at {loop} (read-only); `winvm-root inspect stop` when done")
        return 0
    if sub == "stop":
        if INSPECT_STATE.exists():
            st = json.loads(INSPECT_STATE.read_text())
            if st.get("mnt"):
                subprocess.run(["umount", st["mnt"]], capture_output=True)
            subprocess.run(["losetup", "--detach", st["loop"]], capture_output=True)
            subprocess.run(["qemu-nbd", "-d", st["nbd"]], capture_output=True)
            INSPECT_STATE.unlink()
        dm.teardown(config.TEST_DOMAIN, log=lambda m: print(m))
        print("inspection stopped")
        return 0
    if sub in ("cat", "ls") and len(rest) > 1:
        if not INSPECT_STATE.exists():
            print("run `winvm-root inspect start` first")
            return 1
        loop = json.loads(INSPECT_STATE.read_text())["loop"]
        tool = ["ntfscat", loop, rest[1]] if sub == "cat" else ["ntfsls", "-l", "-p", rest[1], loop]
        return subprocess.run(tool).returncode
    print("usage: winvm-root inspect start [--rw]|stop|cat PATH|ls PATH")
    return 2


def _virsh(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["virsh", "-c", config.LIBVIRT_URI, *args], capture_output=True, text=True)


def define(test_marker: bool = True) -> int:
    """Audit and define the network and both domains (never while one of them runs)."""
    import tempfile
    for d in config.DOMAINS:
        st = _virsh("domstate", d)
        if st.returncode == 0 and st.stdout.strip() not in ("shut off",):
            print(f"{d} is {st.stdout.strip()} - stop it before redefining")
            return 1
    nu = _virsh("net-uuid", config.NETWORK)
    net = xmlgen.network_xml(nu.stdout.strip() if nu.returncode == 0 else None)
    problems = xmlgen.audit_network(net)
    if problems:
        print("network XML fails its audit: " + "; ".join(problems))
        return 1
    plan = [("net-define", net)]
    for d in config.DOMAINS:
        du = _virsh("domuuid", d)
        x = xmlgen.domain_xml(d, marker=test_marker or d != config.TEST_DOMAIN,
                              uuid=du.stdout.strip() if du.returncode == 0 else None)
        problems = xmlgen.audit(x, d)
        if problems:
            print(f"{d} XML fails its audit: " + "; ".join(problems))
            return 1
        plan.append(("define", x))
    for verb, x in plan:
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write(x)
        try:
            cp = _virsh(verb, f.name)
        finally:
            os.unlink(f.name)
        if cp.returncode != 0:
            print(cp.stderr.strip())
            return 1
        print(cp.stdout.strip())
    _virsh("net-autostart", config.NETWORK)
    print("defined: network default (autostart), domains " + ", ".join(config.DOMAINS)
          + ("" if test_marker else f" ({config.TEST_DOMAIN} WITHOUT the SMBIOS marker)"))
    return 0


def main(argv: list[str]) -> int:
    if os.geteuid() != 0:
        print("winvm-root must run as root", file=sys.stderr)
        return 2
    os.umask(0o077)
    if not argv:
        print(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "hook":
        return hook(rest, sys.stdin.read())
    if cmd == "preflight":
        checks = preflight.run(RealProbe(), load_layout())
        print(preflight.report(checks))
        return 1 if preflight.refusals(checks) else 0
    if cmd == "layout":
        lay = load_layout()
        sub = rest[0] if rest else "show"
        if sub == "show":
            for s in layout.segments(lay):
                print(f"{s.start:>12} +{s.length:<12} {s.kind}{f' p{s.part}' if s.part else ''}")
            return 0
        pr = RealProbe()
        disk = pr.resolve(lay.by_id)
        lo, ph = pr.block_sizes(disk)
        table = pr.read_gpt(lay.by_id, lay.logical_block_size, lay.total_sectors, lay.entry_sectors)
        if sub == "verify":
            d = layout.drift(lay, table, lo, ph)
            print("live GPT identical to the recorded layout" if not d else "\n".join(d))
            return 1 if d else 0
        if sub == "record":
            roles = {p.number: p.role for p in lay.parts}
            what = {p.number: p.what for p in lay.parts}
            print(layout.record(table, lay.by_id, lo, ph, roles, what, lay.windows_partition))
            return 0
    if cmd == "esp-manifest":
        return esp_manifest(rest[0] if rest else time.strftime("%Y%m%d-%H%M%S"))
    if cmd == "overlay":
        sub = rest[0] if rest else "check"
        if sub == "discard":
            overlay_discard()
            print("overlay discarded")
            return 0
        if sub == "check":
            why = overlay_problem(load_layout())
            print(why or ("no overlay" if not config.OVERLAY.exists() else "overlay is current"))
            return 1 if why else 0
        if sub == "new":
            overlay_discard()
            print("overlay discarded; the next `winvm test start` creates a fresh one")
            return 0
    if cmd == "teardown":
        dm.teardown(rest[0])
        return 0
    if cmd == "inspect":
        return inspect(rest)
    if cmd == "define":
        return define(test_marker="--test-no-marker" not in rest)
    if cmd == "destroy-test":
        cp = subprocess.run(["virsh", "-c", config.LIBVIRT_URI, "domstate", config.TEST_DOMAIN],
                            capture_output=True, text=True)
        if cp.returncode == 0 and cp.stdout.strip() not in ("shut off", ""):
            subprocess.run(["virsh", "-c", config.LIBVIRT_URI, "destroy", config.TEST_DOMAIN], capture_output=True)
            log(f"[{config.TEST_DOMAIN}] destroyed at host shutdown (throwaway overlay)")
        return 0
    print(__doc__)
    return 2

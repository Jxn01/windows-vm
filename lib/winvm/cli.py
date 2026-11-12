"""`winvm`: run the REAL Windows (C:) as a VM.

    winvm start                 pre-flight, start the VM, wait for SSH
    winvm stop [--timeout S]    clean shutdown: SSH `shutdown /s /f /t 0`, else ACPI power button; waits (default
                                300 s) and NEVER hard-kills - if it is still running after that, it says so
    winvm status                both domains, the assembled disk, the overlay, guest reachability
    winvm console               the GUI: the Windows desktop in a window (virt-viewer)
    winvm ssh [CMD...]          SSH into the VM (alias `windows-vm`, 192.168.122.10)
    winvm screenshot [FILE]     PNG of the VM's screen (default: ./windows-vm-<time>.png)
    winvm preflight             every pre-flight check (sudo)
    winvm layout [show|verify]  the identity layout / the live GPT against the recorded one (sudo)
    winvm esp-manifest [LABEL]  sha256 manifest of the REAL ESP, compared with the baseline (sudo)
    winvm restore-help          how to undo things by hand (guard state, rollback material)

    winvm test new              throw the read-only test VM's overlay away (next start makes a fresh one)
    winvm test start            start the READ-ONLY test VM (real C: read-only + throwaway overlay)
    winvm test stop             DESTROY it (an unguarded overlay must never shut down cleanly: the lights-off
                                tasks fire on the shutdown event); `--guarded` shuts down cleanly instead, only
                                after confirming over SSH that the guard has VM mode applied
    winvm test status|console|ssh|screenshot     as above, for the test VM

Only one of the two VMs can run at a time (they share the real C:); the pre-flight enforces it.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time

from . import config

ROOT = "/usr/local/lib/windows-vm/winvm-root"


def virsh(*args: str, check: bool = False, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["virsh", "-c", config.LIBVIRT_URI, *args], capture_output=capture, text=True, check=check)


def state(domain: str) -> str:
    cp = virsh("domstate", domain)
    return cp.stdout.strip() if cp.returncode == 0 else "undefined"


def root(*args: str) -> int:
    return subprocess.run(["sudo", ROOT, *args]).returncode


def ssh_up(timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((config.GUEST_IP, 22), timeout=timeout):
            return True
    except OSError:
        return False


def ssh(*cmd: str, capture: bool = False, timeout: int | None = None) -> subprocess.CompletedProcess:
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", config.SSH_ALIAS, *cmd]
    return subprocess.run(argv, capture_output=capture, text=True, timeout=timeout)


def wait_state(domain: str, want: str, timeout: int) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if state(domain) == want:
            return True
        time.sleep(2)
    return state(domain) == want


def start(domain: str) -> int:
    other = config.TEST_DOMAIN if domain == config.DOMAIN else config.DOMAIN
    if state(other) not in ("shut off", "undefined"):
        print(f"{other} is running - only one VM can use the real C: at a time. `winvm {'test ' if other == config.TEST_DOMAIN else ''}stop` first.")
        return 1
    if state(domain) == "running":
        print(f"{domain} is already running")
        return 0
    print("pre-flight:")
    if root("preflight") != 0:
        print("\nREFUSED - nothing was started. Fix the FAIL lines above.")
        return 1
    cp = virsh("start", domain)
    if cp.returncode != 0:
        print(cp.stderr.strip())
        print(f"\nThe libvirt hook refused or failed; its log: sudo tail {config.HOOK_LOG}")
        return 1
    print(f"{domain} started. Waiting for SSH on {config.GUEST_IP} ...")
    end = time.monotonic() + 240
    while time.monotonic() < end and not ssh_up():
        if state(domain) != "running":
            print(f"{domain} stopped while booting ({state(domain)})")
            return 1
        time.sleep(3)
    print("SSH is up." if ssh_up() else "SSH not up yet - look at `winvm console`.")
    print("GUI: winvm console      shell: winvm ssh      stop: winvm stop")
    return 0


def stop(domain: str, timeout: int) -> int:
    st = state(domain)
    if st in ("shut off", "undefined"):
        print(f"{domain} is not running")
        return 0
    if st == "paused":
        virsh("resume", domain)
    sent = False
    if ssh_up():
        cp = ssh("shutdown", "/s", "/f", "/t", "0", capture=True, timeout=30)
        sent = cp.returncode == 0
        print("asked Windows to shut down (SSH, forced: open apps are closed)" if sent else
              f"SSH shutdown failed: {cp.stderr.strip()[:200]}")
    if not sent:
        cp = virsh("shutdown", domain, "--mode", "acpi")
        print("pressed the virtual power button (ACPI: Windows' power button = Shut down)" if cp.returncode == 0
              else f"ACPI shutdown failed: {cp.stderr.strip()}")
    if wait_state(domain, "shut off", timeout):
        print(f"{domain} is off (clean shutdown).")
        return 0
    print(f"{domain} is STILL RUNNING after {timeout} s. It was not killed: a hard stop would leave C: dirty.\n"
          f"Look at it (`winvm {'test ' if domain == config.TEST_DOMAIN else ''}console`), then stop it again. "
          f"Only as a last resort: virsh -c {config.LIBVIRT_URI} destroy {domain}")
    return 1


def test_stop(guarded: bool) -> int:
    d = config.TEST_DOMAIN
    if state(d) in ("shut off", "undefined"):
        print(f"{d} is not running")
        return 0
    if guarded:
        cp = ssh("powershell", "-NoProfile", "-Command",
                 "& 'C:\\ProgramData\\jxn-vm\\guard.ps1' status -Quiet", capture=True, timeout=60)
        if cp.returncode != 0 or "vm-mode-applied" not in cp.stdout:
            print("the guard does not report VM mode applied - refusing a clean shutdown; destroying instead")
        else:
            return stop(d, config.STOP_TIMEOUT)
    virsh("destroy", d)
    ok = wait_state(d, "shut off", 30)
    print(f"{d} destroyed (throwaway overlay: nothing on the real disk changed)" if ok else f"{d} did not stop")
    return 0 if ok else 1


def status() -> int:
    for d in config.DOMAINS:
        print(f"{d:14} {state(d)}")
    dms = [n for n in os.listdir("/dev/mapper") if n.startswith(config.DM_PREFIX)]
    print(f"assembled disk  {', '.join('/dev/mapper/' + n for n in dms) or 'none'}")
    print(f"guest SSH       {config.GUEST_IP}:22 {'up' if ssh_up() else 'down'}")
    return 0


def console(domain: str) -> int:
    if not shutil.which("virt-viewer"):
        print("virt-viewer is not installed")
        return 1
    subprocess.Popen(["virt-viewer", "--connect", config.LIBVIRT_URI, "--attach", "--wait", "--reconnect", domain],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
    print(f"opened the {domain} window (virt-viewer). Sign in with the PASSWORD - never set up a PIN in the VM.")
    return 0


def screenshot(domain: str, path: str | None) -> int:
    path = path or f"{domain}-{time.strftime('%Y%m%d-%H%M%S')}.png"
    cp = virsh("screenshot", domain, path)
    if cp.returncode != 0:
        print(cp.stderr.strip())
        return 1
    print(path)
    return 0


RESTORE_HELP = f"""How to undo things by hand

The VM-mode guard (inside Windows, C:\\ProgramData\\jxn-vm\\):
  - It saves every item before it changes it (state.json there) and restores them on every boot that is
    NOT this VM. To force a restore from an elevated PowerShell on the hardware Windows:
        & C:\\ProgramData\\jxn-vm\\guard.ps1 restore
  - Its log: C:\\ProgramData\\jxn-vm\\guard.log

Rollback material (the backup taken before first use, kept mode 700):
  - nvme0n1-gpt.sgdisk / .sfdisk   the partition table (never written by this tooling)
  - an ESP tar + manifests          the real ESP (never written by this tooling)
  - hives/                         SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT, the user's NTUSER.DAT
  - tasks/                         C:\\Windows\\System32\\Tasks as it was

A leftover assembled disk (only when both VMs are off): sudo {ROOT} teardown windows|windows-test
"""


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd, rest = argv[0], argv[1:]
    domain = config.DOMAIN
    if cmd == "test":
        if not rest:
            print(__doc__)
            return 2
        domain = config.TEST_DOMAIN
        cmd, rest = rest[0], rest[1:]
        if cmd == "new":
            if state(domain) not in ("shut off", "undefined"):
                print("stop the test VM first")
                return 1
            return root("overlay", "discard")
        if cmd == "stop":
            return test_stop("--guarded" in rest)
    if cmd == "start":
        return start(domain)
    if cmd == "stop":
        t = int(rest[rest.index("--timeout") + 1]) if "--timeout" in rest else config.STOP_TIMEOUT
        return stop(domain, t)
    if cmd == "status":
        return status()
    if cmd == "console":
        return console(domain)
    if cmd == "ssh":
        os.execvp("ssh", ["ssh", config.SSH_ALIAS, *rest])
    if cmd == "screenshot":
        return screenshot(domain, rest[0] if rest else None)
    if cmd == "preflight":
        return root("preflight")
    if cmd == "layout":
        return root("layout", *(rest or ["show"]))
    if cmd == "esp-manifest":
        return root("esp-manifest", *rest)
    if cmd == "restore-help":
        print(RESTORE_HELP)
        return 0
    print(__doc__)
    return 2

"""Assemble and tear down the VM's disk (root only; called by the libvirt hook).

build():
    1. read the LIVE GPT (O_RDONLY), refuse on drift, write gpt-head.img / gpt-tail.img (absent entries blanked)
    2. rebuild the private ESP image from the real ESP (esp.py)
    3. attach the three images to loop devices (read-only ones for the read-only domain)
    4. resolve each mapped partition by PARTUUID to major:minor, re-checking it is that partition of that disk
    5. `dmsetup create` the identity table - read-only (`--readonly`) for windows-test
    6. PROVE it: the assembled disk's GPT parses and equals the VM table; the first MiB of every mapped segment
       equals the real partition's first MiB (identity offsets); for read-only, an O_WRONLY open of the
       device FAILS (kernel-enforced) and `blockdev --getro` is 1. Any failure tears everything down.

teardown(): remove the dm device, detach exactly the loop devices whose backing file is one of OUR images.
"""

from __future__ import annotations

import errno
import json
import os
import subprocess
import time
from pathlib import Path

from . import config, esp, gpt, layout
from .probe import RealProbe

RUN_DIR = Path("/run/windows-vm")
MIB = 1 << 20


class DmError(RuntimeError):
    pass


def _run(argv, input_text=None):
    cp = subprocess.run(argv, input=input_text.encode() if input_text else None, capture_output=True)
    if cp.returncode != 0:
        raise DmError(f"{' '.join(argv[:3])} failed ({cp.returncode}): {cp.stderr.decode(errors='replace').strip()[:400]}")
    return cp.stdout.decode().strip()


def dm_path(domain: str) -> str:
    return f"/dev/mapper/{config.DM_NAME[domain]}"


def _write_private(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".new")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _losetup(path: Path, readonly: bool) -> str:
    argv = ["losetup", "--find", "--show", "--direct-io=on"]
    if readonly:
        argv.append("--read-only")
    return _run(argv + [str(path)])


def _majmin(dev: str) -> str:
    st = os.stat(dev)
    return f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}"


def our_loops() -> list[str]:
    """Loop devices whose backing file is one of our images (and only those)."""
    ours = {str(p) for p in (config.HEAD_IMG, config.TAIL_IMG, config.ESP_IMG)}
    out = []
    for d in Path("/sys/block").glob("loop*"):
        bf = d / "loop" / "backing_file"
        if bf.exists() and bf.read_text().strip() in ours:
            out.append(f"/dev/{d.name}")
    return sorted(out)


def build(domain: str, lay: layout.Layout, password: str, log=print, bcd_flags: dict | None = None) -> str:
    readonly = domain == config.TEST_DOMAIN
    name = config.DM_NAME[domain]
    probe = RealProbe()
    if Path(dm_path(domain)).exists():
        raise DmError(f"{dm_path(domain)} already exists")
    disk = probe.resolve(lay.by_id)
    lo, ph = probe.block_sizes(disk)
    table = probe.read_gpt(lay.by_id, lay.logical_block_size, lay.total_sectors, lay.entry_sectors)
    d = layout.drift(lay, table, lo, ph)
    if d:
        raise DmError("GPT drift: " + "; ".join(d))
    head, tail, vm_table = layout.vm_images(lay, table)
    for p in (config.DISK_DIR,):
        p.mkdir(mode=0o700, parents=True, exist_ok=True)
    _write_private(config.HEAD_IMG, head)
    _write_private(config.TAIL_IMG, tail)
    espp = lay.by_role("esp")[0]
    built = esp.build(config.REAL_ESP_MOUNT, config.ESP_IMG, espp.sectors, password, lay.logical_block_size,
                      bcd_flags=bcd_flags, log=log)
    log(f"private ESP rebuilt from {config.REAL_ESP_MOUNT}: {len(built.manifest)} files verified")
    _log_manifest(built.manifest)

    loops: list[str] = []
    RUN_DIR.mkdir(mode=0o700, exist_ok=True)
    state = RUN_DIR / f"{domain}.json"
    try:
        devices = {}
        for key, img in (("head", config.HEAD_IMG), ("esp", config.ESP_IMG), ("tail", config.TAIL_IMG)):
            dev = _losetup(img, readonly)
            loops.append(dev)
            devices[key] = _majmin(dev)
        state.write_text(json.dumps({"loops": loops, "dm": name}))
        units = lay.logical_block_size // 512
        for p in lay.by_role("mapped"):
            bd = probe.resolve(probe.partuuid_path(p.unique_guid))
            if (bd is None or bd.parent != disk.name or bd.partition != p.number or bd.start != p.first_lba * units
                    or bd.size != p.sectors * units):
                raise DmError(f"partition {p.number} is not where the layout says (PARTUUID {p.unique_guid})")
            devices[f"part{p.number}"] = bd.majmin
        text = layout.dm_table(lay, devices)
        argv = ["dmsetup", "create", name, "--uuid", f"WINVM-{domain}"]
        if readonly:
            argv.append("--readonly")
        _run(argv, text)
        log(f"{dm_path(domain)} created ({'READ-ONLY' if readonly else 'read-write'})")
        prove(domain, lay, vm_table, readonly)
        log("assembled disk proven: GPT identical to the VM table, identity offsets match"
            + (", writes refused by the kernel" if readonly else ""))
        return dm_path(domain)
    except BaseException:
        teardown(domain, log=log)
        raise


def prove(domain: str, lay: layout.Layout, vm_table: gpt.Table, readonly: bool) -> None:
    dev = dm_path(domain)
    size = int(_run(["blockdev", "--getsz", dev]))
    if size != lay.total_sectors * (lay.logical_block_size // 512):
        raise DmError(f"assembled disk has {size} sectors, expected {lay.total_sectors}")
    fd = os.open(dev, os.O_RDONLY | os.O_CLOEXEC)
    try:
        n = lay.entry_sectors
        bs = lay.logical_block_size
        head = os.pread(fd, (2 + n) * bs, 0)
        tail = os.pread(fd, (n + 1) * bs, (lay.total_sectors - n - 1) * bs)
        got = gpt.read_table(head, tail, lay.total_sectors, bs)
        if got != vm_table:
            raise DmError("the assembled disk's GPT differs from the VM table")
        probe = RealProbe()
        for p in lay.by_role("mapped"):
            real = probe.partuuid_path(p.unique_guid)
            probe.flush(real)  # drop cached pages first
            rfd = os.open(real, os.O_RDONLY | os.O_CLOEXEC)
            try:
                want = os.pread(rfd, min(MIB, p.sectors * bs), 0)
            finally:
                os.close(rfd)
            if os.pread(fd, len(want), p.first_lba * bs) != want:
                raise DmError(f"partition {p.number}: assembled sectors differ from the real partition")
    finally:
        os.close(fd)
    if readonly:
        if _run(["blockdev", "--getro", dev]) != "1":
            raise DmError(f"{dev} is not read-only")
        prove_write_refused(dev, lay)


def zero_probe_sector(lay: layout.Layout) -> int:
    """A sector inside a dm `zero` segment (the host's root region): a write there is discarded by the target even if
    the read-only flag were broken, so the write test below can never change anything."""
    seg = next(s for s in layout.segments(lay) if s.kind == "zero")
    return seg.start + seg.length // 2


def prove_write_refused(dev: str, lay: layout.Layout) -> None:
    """Kernel-enforced read-only, proven by an actual write.

    Current kernels let root OPEN a read-only block device for writing and refuse the WRITE itself (EPERM in
    blkdev_write_iter) - on kernel 7.1.9 the open succeeded. So the proof is a write of one sector
    of zeros into a `zero` segment: harmless whatever happens, and it must fail with EPERM/EACCES/EROFS.
    """
    bs = lay.logical_block_size
    fd = os.open(dev, os.O_WRONLY | os.O_CLOEXEC)
    try:
        os.pwrite(fd, bytes(bs), zero_probe_sector(lay) * bs)
        os.fsync(fd)
    except OSError as e:
        if e.errno not in (errno.EPERM, errno.EACCES, errno.EROFS):
            raise DmError(f"write test on {dev} failed for an unexpected reason: {e}") from e
        return
    finally:
        os.close(fd)
    raise DmError(f"{dev} ACCEPTED a write - it is NOT read-only (the write went to a zero segment: nothing changed)")


def teardown(domain: str, log=print) -> None:
    name = config.DM_NAME[domain]
    if Path(dm_path(domain)).exists():
        for attempt in range(10):
            cp = subprocess.run(["dmsetup", "remove", name], capture_output=True)
            if cp.returncode == 0:
                log(f"{dm_path(domain)} removed")
                break
            time.sleep(0.5)
        else:
            raise DmError(f"could not remove {name}: {cp.stderr.decode(errors='replace').strip()}")
    state = RUN_DIR / f"{domain}.json"
    loops = set(our_loops())
    if state.exists():
        loops |= set(json.loads(state.read_text()).get("loops", []))
        state.unlink()
    for dev in sorted(loops):
        if Path(dev).exists() and dev in our_loops():
            subprocess.run(["losetup", "--detach", dev], capture_output=True)
    left = our_loops()
    if left:
        raise DmError(f"loop devices still attached to our images: {', '.join(left)}")
    _flush_windows_partitions()


def _flush_windows_partitions() -> None:
    """After the VM is gone, drop whatever the host cached of the partitions it wrote."""
    try:
        lay = layout.load(config.LAYOUT_FILE)
    except (OSError, ValueError):
        return
    probe = RealProbe()
    for p in lay.parts:
        path = probe.partuuid_path(p.unique_guid)
        if p.windows_side and os.path.exists(path):
            try:
                probe.flush(path)
            except OSError:
                pass


def _log_manifest(manifest: dict[str, str]) -> None:
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    with open(config.ESP_MANIFEST, "a") as f:
        f.write(f"# {time.strftime('%Y-%m-%dT%H:%M:%S%z')} private ESP refresh\n")
        for k, v in sorted(manifest.items()):
            f.write(f"{v}  {k}\n")

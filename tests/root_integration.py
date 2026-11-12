#!/usr/bin/python3 -I
"""Root-only end-to-end test of dm.build()/teardown() on a SYNTHETIC disk with the real disk's geometry.

    sudo python3 -I tests/root_integration.py

A sparse file the size of the real disk gets the real partition table with EVERY GUID randomised (`sgdisk -G`;
identical GUIDs would let udev point /dev/disk/by-partuuid/<real C:> at the fake). It is attached as a loop
device with partitions, marker bytes are written into its partitions, and the real build path runs against it:
GPT images, private ESP (from the real /boot/efi, read-only), loops, dm table, the proofs. Then it checks, from
outside the code under test:
    - the assembled disk's GPT (read by sgdisk) = synthetic table minus p2/p3, same disk GUID
    - VM sector N == partition sector N for p4/p5/p6 (markers), p2/p3 read as zeros, ESP region is FAT 5749-4E01
    - read-only build: write-open fails, `blockdev --getro` 1; read-write build: a write lands in the partition
    - teardown leaves no dm device and no loop device on our images
The real disk is never opened for writing; nothing here touches it except reading /boot/efi.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "lib"))
sys.path.insert(0, str(REPO / "tests"))

from helpers import BACKUP, PRIMARY, TOTAL, real_layout  # noqa: E402
from winvm import config, dm, gpt, layout  # noqa: E402

MIB = 1 << 20
fails: list[str] = []


def check(cond, msg):
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def sh(*argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, check=True, **kw).stdout.strip()


def main() -> int:
    if os.geteuid() != 0:
        print("run as root")
        return 2
    work = Path(tempfile.mkdtemp(prefix="winvm-itest-", dir="/var/tmp"))
    os.chmod(work, 0o700)
    img = work / "disk.img"
    link = Path(f"/dev/disk/by-id/winvm-itest-{uuid.uuid4().hex[:8]}")
    loop = None
    real = real_layout()
    try:
        with open(img, "wb") as f:
            f.truncate(TOTAL * 512)
            f.write(PRIMARY)
            f.seek((TOTAL - 33) * 512)
            f.write(BACKUP)
        sh("sgdisk", "-G", str(img))  # randomise disk + partition GUIDs
        head = open(img, "rb").read(34 * 512)
        with open(img, "rb") as f:
            f.seek((TOTAL - 33) * 512)
            tail = f.read(33 * 512)
        synth = gpt.read_table(head, tail, TOTAL)
        check(all(synth.entry(p.number).unique_guid != p.unique_guid for p in real.parts),
              "every synthetic partition GUID differs from the real disk's")
        markers = {}
        with open(img, "r+b") as f:
            for p in real.parts:
                if p.number == 1:
                    continue
                data = os.urandom(MIB) if p.number != 4 else os.urandom(64 * 1024)
                markers[p.number] = data
                f.seek(p.first_lba * 512)
                f.write(data)
        loop = sh("losetup", "--find", "--show", "--partscan", str(img))
        sh("udevadm", "settle")
        link.symlink_to(loop)
        roles = {p.number: p.role for p in real.parts}
        what = {p.number: p.what for p in real.parts}
        toml = work / "layout.toml"
        toml.write_text(layout.record(synth, str(link), 512, 512, roles, what, real.windows_partition))
        lay = layout.load(toml)

        state = work / "state"
        (state / "disk").mkdir(parents=True)
        (state / "log").mkdir()
        config.DISK_DIR = state / "disk"
        config.HEAD_IMG = config.DISK_DIR / "gpt-head.img"
        config.TAIL_IMG = config.DISK_DIR / "gpt-tail.img"
        config.ESP_IMG = config.DISK_DIR / "esp.img"
        config.LOG_DIR = state / "log"
        config.ESP_MANIFEST = config.LOG_DIR / "esp-refresh.log"
        config.DM_NAME = {config.DOMAIN: "winvmitest-rw", config.TEST_DOMAIN: "winvmitest-ro"}
        dm.RUN_DIR = work / "run"

        for domain in (config.TEST_DOMAIN, config.DOMAIN):
            ro = domain == config.TEST_DOMAIN
            print(f"--- build {domain} ({'read-only' if ro else 'read-write'})")
            dev = dm.build(domain, lay, "itest-password", log=lambda m: print("     " + m))
            p = subprocess.run(["sgdisk", "-p", dev], capture_output=True, text=True).stdout
            rows = [ln.split() for ln in p.splitlines() if ln.strip()[:1].isdigit() and len(ln.split()) > 5]
            check([r[0] for r in rows] == ["1", "2", "3", "4", "5", "6"], f"sgdisk sees all 6 partitions on {dev}")
            check(str(synth.primary.disk_guid).upper() in p, "same disk GUID as the source table")
            fd = os.open(dev, os.O_RDONLY)
            try:
                for n in (4, 5, 6):
                    part = lay.part(n)
                    got = os.pread(fd, len(markers[n]), part.first_lba * 512)
                    check(got == markers[n], f"p{n}: VM sector N == partition sector N (marker at LBA {part.first_lba})")
                for n in (2, 3):
                    got = os.pread(fd, MIB, lay.part(n).first_lba * 512)
                    check(got == bytes(MIB), f"p{n} region reads as zeros although the source has data there")
                boot = os.pread(fd, 512, lay.part(1).first_lba * 512)
                check(boot[0x52:0x5A] == b"FAT32   " and boot[0x43:0x47][::-1].hex() == config.ESP_VOLUME_ID,
                      "ESP region is the private FAT32 image (volume 5749-4E01)")
            finally:
                os.close(fd)
            if ro:
                check(sh("blockdev", "--getro", dev) == "1", "blockdev --getro = 1")
                try:
                    dm.prove_write_refused(dev, lay)
                    check(True, "a real write to the read-only device is refused by the kernel")
                except dm.DmError as e:
                    check(False, str(e))
            else:
                # positive control for the read-only proof: the same write SUCCEEDS on the read-write device
                try:
                    dm.prove_write_refused(dev, lay)
                    check(False, "the write test reported 'refused' on a read-write device")
                except dm.DmError as e:
                    check("ACCEPTED" in str(e), "positive control: the same write is accepted read-write")
                part5 = lay.part(5)
                w = os.open(dev, os.O_WRONLY)
                os.pwrite(w, b"WRITTEN-THROUGH-THE-VM-DISK", part5.first_lba * 512 + 4096)
                os.fsync(w)
                os.close(w)
                p5dev = f"/dev/disk/by-partuuid/{part5.unique_guid}"
                from winvm.probe import RealProbe
                stale = os.open(p5dev, os.O_RDONLY)
                cached = os.pread(stale, 27, 4096)
                os.close(stale)
                check(cached != b"WRITTEN-THROUGH-THE-VM-DISK",
                      "reproduced: the partition's page cache still shows the OLD bytes after the VM write")
                RealProbe().flush(p5dev)
                r = os.open(p5dev, os.O_RDONLY)
                got = os.pread(r, 27, 4096)
                os.close(r)
                check(got == b"WRITTEN-THROUGH-THE-VM-DISK", "a VM write at C: offset X lands at partition offset X")
            dm.teardown(domain, log=lambda m: print("     " + m))
            check(not Path(dev).exists(), f"{dev} removed")
            check(dm.our_loops() == [], "no loop device left on our images")
    finally:
        if link.is_symlink():
            link.unlink()
        if loop:
            subprocess.run(["losetup", "--detach", loop])
        for p in sorted(work.rglob("*"), reverse=True):
            p.unlink() if p.is_file() or p.is_symlink() else p.rmdir()
        work.rmdir()
    print(f"\n{'ALL PASSED' if not fails else f'{len(fails)} FAILED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

"""What the pre-flight looks at, read from the live host (root needed for the raw disk reads).

Everything here is READ-ONLY: O_RDONLY opens, sysfs/procfs reads, ntfs-3g's offline readers. Kept apart from
preflight.py so every refusal is unit-tested against a FakeProbe (tests/test_preflight.py), while this class
is exercised for real by `winvm preflight` and by the libvirt hook.
"""

from __future__ import annotations

import fcntl
import os
from dataclasses import dataclass
from pathlib import Path

from . import config, gpt, ntfs

BLKFLSBUF = 0x1261  # write back + invalidate a block device's buffer cache
FS_IOC_GETFLAGS = 0x80086601
FS_NOCOW_FL = 0x00800000
BTRFS_FIRST_FREE_OBJECTID = 256  # inode number of every subvolume's root directory


@dataclass(frozen=True)
class BlockDev:
    name: str        # kernel name, e.g. nvme0n1p5 (informational only, trap T21)
    majmin: str      # "259:5"
    parent: str      # kernel name of the whole disk ("" for a whole disk)
    partition: int   # partition number (0 for a whole disk)
    start: int       # start sector (512-byte units, sysfs)
    size: int        # size in 512-byte units (sysfs)


class RealProbe:
    def __init__(self, sys_root: str = "/sys", dev_root: str = "/dev"):
        self.sys = Path(sys_root)
        self.dev = Path(dev_root)

    # ---- block devices --------------------------------------------------------------------------------
    def resolve(self, path: str) -> BlockDev | None:
        p = Path(path)
        if not p.exists():
            return None
        name = p.resolve().name
        cls = self.sys / "class/block" / name
        if not cls.exists():
            return None
        majmin = (cls / "dev").read_text().strip()
        part = int((cls / "partition").read_text()) if (cls / "partition").exists() else 0
        start = int((cls / "start").read_text()) if (cls / "start").exists() else 0
        size = int((cls / "size").read_text())
        parent = cls.resolve().parent.name if part else ""
        return BlockDev(name, majmin, parent, part, start, size)

    def flush(self, path: str) -> None:
        """Drop the block device's cached pages before reading it (trap T28).

        The VM writes C: through device-mapper, i.e. BELOW /dev/<disk>p5's page cache. Pages Garuda cached from
        an earlier read (ntfs-3g, the pre-flight, a fingerprint) are stale afterwards and would be served again -
        a pre-flight judging yesterday's hiberfil.sys/$Volume/$LogFile. Garuda never writes these partitions, so
        BLKFLSBUF only invalidates clean pages."""
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            fcntl.ioctl(fd, BLKFLSBUF, 0)
        finally:
            os.close(fd)

    def partuuid_path(self, guid) -> str:
        return f"/dev/disk/by-partuuid/{str(guid).lower()}"

    def block_sizes(self, disk: BlockDev) -> tuple[int, int]:
        q = self.sys / "block" / disk.name / "queue"
        return int((q / "logical_block_size").read_text()), int((q / "physical_block_size").read_text())

    def read_gpt(self, by_id: str, logical: int, total_sectors: int, entry_sectors: int) -> gpt.Table:
        fd = os.open(by_id, os.O_RDONLY | os.O_CLOEXEC)
        try:
            head = os.pread(fd, (2 + entry_sectors) * logical, 0)
            tail = os.pread(fd, (entry_sectors + 1) * logical, (total_sectors - entry_sectors - 1) * logical)
        finally:
            os.close(fd)
        return gpt.read_table(head, tail, total_sectors, logical)

    def holders(self, dev: BlockDev) -> list[str]:
        d = self.sys / "class/block" / dev.name / "holders"
        return sorted(os.listdir(d)) if d.exists() else []

    def mounted_majmins(self) -> set[str]:
        out = set()
        with open("/proc/self/mountinfo") as f:
            for line in f:
                out.add(line.split()[2])
        return out

    def swap_devices(self) -> set[str]:
        out = set()
        with open("/proc/swaps") as f:
            next(f, None)
            for line in f:
                dev = line.split()[0]
                if dev.startswith("/dev/"):
                    bd = self.resolve(dev)
                    if bd:
                        out.add(bd.majmin)
        return out

    def dm_names(self) -> list[str]:
        out = []
        for d in sorted((self.sys / "block").glob("dm-*")):
            n = d / "dm" / "name"
            if n.exists():
                out.append(n.read_text().strip())
        return out

    def mount_source_of(self, mountpoint: str) -> str | None:
        """major:minor of what is mounted at `mountpoint`, or None."""
        with open("/proc/self/mountinfo") as f:
            for line in f:
                fields = line.split()
                if fields[4] == mountpoint:
                    return fields[2]
        return None

    # ---- NTFS (C:) ------------------------------------------------------------------------------------
    def ntfs_volume(self, dev: str) -> ntfs.VolumeInfo:
        return ntfs.volume_info(dev)

    def ntfs_file_head(self, dev: str, path: str) -> bytes | None:
        return ntfs.file_head(dev, path)

    def ntfs_listdir(self, dev: str, path: str) -> list[str] | None:
        return ntfs.listdir(dev, path)

    # ---- files ----------------------------------------------------------------------------------------
    def exists(self, path: Path) -> bool:
        return path.exists()

    def is_nocow_subvolume(self, path: Path) -> tuple[bool, bool]:
        """(is a btrfs subvolume root, has the NOCOW attribute)."""
        st = os.stat(path)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            flags = int.from_bytes(fcntl.ioctl(fd, FS_IOC_GETFLAGS, b"\0" * 8)[:4], "little")
        finally:
            os.close(fd)
        return st.st_ino == BTRFS_FIRST_FREE_OBJECTID, bool(flags & FS_NOCOW_FL)

    def saved_images(self) -> list[str]:
        return [d for d in config.DOMAINS if (config.SAVE_DIR / f"{d}.save").exists()]

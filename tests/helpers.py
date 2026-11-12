"""Shared test fixtures: the real disk's GPT sectors (captured read-only) and mutators for them."""

from __future__ import annotations

import struct
import sys
import uuid
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "lib"))

from winvm import gpt, layout  # noqa: E402

TOTAL = 8001573552
PRIMARY = (HERE / "fixtures" / "gpt-primary.bin").read_bytes()  # LBA 0..33 of the real disk
BACKUP = (HERE / "fixtures" / "gpt-backup.bin").read_bytes()    # its last 33 sectors
LAYOUT_FILE = REPO / "etc" / "layout.toml"


def real_table() -> gpt.Table:
    return gpt.read_table(PRIMARY, BACKUP, TOTAL)


def real_layout() -> layout.Layout:
    return layout.load(LAYOUT_FILE)


def mutate_entry(number: int, *, first_lba: int | None = None, unique_guid: uuid.UUID | None = None,
                 disk_guid: uuid.UUID | None = None) -> tuple[bytes, bytes]:
    """A consistent (valid-CRC) copy of the real GPT with one field changed in BOTH copies."""
    head, tail = bytearray(PRIMARY), bytearray(BACKUP)
    off = 1024 + (number - 1) * 128
    boff = (number - 1) * 128
    if first_lba is not None:
        old_first, old_last = struct.unpack_from("<QQ", head, off + 32)
        size = old_last - old_first
        for buf, o in ((head, off), (tail, boff)):
            struct.pack_into("<QQ", buf, o + 32, first_lba, first_lba + size)
    if unique_guid is not None:
        for buf, o in ((head, off), (tail, boff)):
            buf[o + 16:o + 32] = unique_guid.bytes_le
    arr = bytes(head[1024:1024 + 128 * 128])
    ecrc = zlib.crc32(arr) & 0xFFFFFFFF
    for buf, hoff in ((head, 512), (tail, 32 * 512)):
        struct.pack_into("<I", buf, hoff + 88, ecrc)
        if disk_guid is not None:
            buf[hoff + 56:hoff + 72] = disk_guid.bytes_le
        struct.pack_into("<I", buf, hoff + 16, 0)
        crc = zlib.crc32(bytes(buf[hoff:hoff + 92])) & 0xFFFFFFFF
        struct.pack_into("<I", buf, hoff + 16, crc)
    return bytes(head), bytes(tail)

"""GPT reading and rewriting, pure stdlib.

The VM's disk is stitched together from the real disk's partitions and two small images that hold the
partition table: the *head* (protective MBR, primary GPT header, primary entry array) and the *tail* (backup
entry array, backup header). Both are produced here from the real disk's own sectors, with only the entries
that must not exist in the VM (the host's btrfs root, FASTGAMES) blanked and every CRC recomputed. Nothing else in
the table changes: disk GUID, partition numbers, GUIDs, LBAs and attributes stay byte-identical, which is what
keeps Windows from "repairing" anything.

`sgdisk` is deliberately NOT used to build the table; it is used by the tests and by `winvm layout verify` as an
independent reader of what this module wrote, so the check is not the code checking itself.
"""

from __future__ import annotations

import struct
import uuid
import zlib
from dataclasses import dataclass, replace

SIGNATURE = b"EFI PART"
HEADER_SIZE = 92
EMPTY_TYPE = uuid.UUID(int=0)

# Header layout (UEFI spec 2.10, table 5.21), little endian.
_HDR = struct.Struct("<8sIIIIQQQQ16sQIII")


class GptError(ValueError):
    """The bytes are not a GPT this module will vouch for."""


@dataclass(frozen=True)
class Header:
    revision: int
    header_size: int
    header_crc: int
    current_lba: int
    backup_lba: int
    first_usable: int
    last_usable: int
    disk_guid: uuid.UUID
    entries_lba: int
    num_entries: int
    entry_size: int
    entries_crc: int

    def pack(self) -> bytes:
        """The header sector (header + zero padding to `sector` bytes is done by the caller)."""
        return _HDR.pack(SIGNATURE, self.revision, self.header_size, self.header_crc, 0, self.current_lba,
                         self.backup_lba, self.first_usable, self.last_usable, self.disk_guid.bytes_le,
                         self.entries_lba, self.num_entries, self.entry_size, self.entries_crc)

    def with_crc(self) -> "Header":
        """This header with `header_crc` recomputed over its own bytes (CRC field zeroed, as the spec says)."""
        raw = replace(self, header_crc=0).pack()[: self.header_size]
        return replace(self, header_crc=zlib.crc32(raw) & 0xFFFFFFFF)


@dataclass(frozen=True)
class Entry:
    number: int  # 1-based slot number, i.e. the Linux partition number
    type_guid: uuid.UUID
    unique_guid: uuid.UUID
    first_lba: int
    last_lba: int
    attributes: int
    name: str

    @property
    def sectors(self) -> int:
        return self.last_lba - self.first_lba + 1


def parse_header(sector: bytes) -> Header:
    if len(sector) < HEADER_SIZE:
        raise GptError("header sector too short")
    (sig, rev, hsize, hcrc, reserved, cur, bak, first, last, dguid, elba, nent, esize,
     ecrc) = _HDR.unpack_from(sector)
    if sig != SIGNATURE:
        raise GptError(f"no GPT signature (found {sig!r})")
    if hsize < HEADER_SIZE or hsize > len(sector):
        raise GptError(f"implausible header size {hsize}")
    if reserved != 0:
        raise GptError("reserved header field is not zero")
    hdr = Header(rev, hsize, hcrc, cur, bak, first, last, uuid.UUID(bytes_le=dguid), elba, nent, esize, ecrc)
    raw = bytearray(sector[:hsize])
    raw[16:20] = b"\0\0\0\0"
    if zlib.crc32(raw) & 0xFFFFFFFF != hcrc:
        raise GptError("header CRC mismatch")
    if esize != 128 or nent * esize > 1024 * 1024:
        raise GptError(f"unsupported entry array ({nent} x {esize} bytes)")
    return hdr


def parse_entries(array: bytes, hdr: Header) -> list[Entry]:
    size = hdr.num_entries * hdr.entry_size
    if len(array) < size:
        raise GptError("entry array too short")
    if zlib.crc32(array[:size]) & 0xFFFFFFFF != hdr.entries_crc:
        raise GptError("entry array CRC mismatch")
    out = []
    for i in range(hdr.num_entries):
        e = array[i * hdr.entry_size:(i + 1) * hdr.entry_size]
        tguid = uuid.UUID(bytes_le=e[0:16])
        if tguid == EMPTY_TYPE:
            continue
        first, last, attrs = struct.unpack_from("<QQQ", e, 32)
        name = e[56:128].decode("utf-16-le").rstrip("\0")
        out.append(Entry(i + 1, tguid, uuid.UUID(bytes_le=e[16:32]), first, last, attrs, name))
    return out


@dataclass(frozen=True)
class Table:
    """A whole GPT as read from a disk: both headers, the entry array, and the protective MBR."""

    sector: int
    total_sectors: int
    mbr: bytes
    primary: Header
    backup: Header
    array: bytes  # the raw entry array (identical in both copies, checked)
    entries: tuple[Entry, ...]

    def entry(self, number: int) -> Entry | None:
        return next((e for e in self.entries if e.number == number), None)


def entries_sectors(hdr: Header, sector: int) -> int:
    return -(-hdr.num_entries * hdr.entry_size // sector)


def read_table(head: bytes, tail: bytes, total_sectors: int, sector: int = 512) -> Table:
    """Parse a GPT from the first 34 and the last 33 sectors of a disk (both copies must agree).

    `head` must hold at least LBA 0..(1 + entry sectors); `tail` exactly the last (entry sectors + 1) sectors.
    """
    primary = parse_header(head[sector:2 * sector])
    if primary.current_lba != 1:
        raise GptError("primary header does not sit at LBA 1")
    if primary.backup_lba != total_sectors - 1:
        raise GptError(f"backup header LBA {primary.backup_lba} is not the last sector ({total_sectors - 1})")
    n = entries_sectors(primary, sector)
    if primary.entries_lba != 2:
        raise GptError("primary entry array does not start at LBA 2")
    arr = head[2 * sector:(2 + n) * sector]
    entries = parse_entries(arr, primary)
    if len(tail) != (n + 1) * sector:
        raise GptError(f"tail must be {(n + 1)} sectors")
    backup = parse_header(tail[n * sector:])
    if backup.current_lba != total_sectors - 1 or backup.backup_lba != 1:
        raise GptError("backup header LBAs are inconsistent")
    if backup.entries_lba != total_sectors - 1 - n:
        raise GptError("backup entry array is not directly before the backup header")
    barr = tail[:n * sector]
    parse_entries(barr, backup)
    if barr[: primary.num_entries * primary.entry_size] != arr[: primary.num_entries * primary.entry_size]:
        raise GptError("primary and backup entry arrays differ")
    for f in ("disk_guid", "first_usable", "last_usable", "num_entries", "entry_size", "entries_crc"):
        if getattr(primary, f) != getattr(backup, f):
            raise GptError(f"primary and backup headers differ in {f}")
    mbr = head[:sector]
    if mbr[510:512] != b"\x55\xaa" or mbr[450] != 0xEE:
        raise GptError("no protective MBR")
    return Table(sector, total_sectors, mbr, primary, backup, bytes(arr), tuple(entries))


def without(table: Table, numbers: set[int], head_sectors: int) -> tuple[bytes, bytes, Table]:
    """Blank the given entry slots and return (head image, tail image, the resulting Table).

    The head image is `head_sectors` long: MBR + primary header + entries, zero-filled up to the first
    partition. The slots are zeroed in place, so every other entry keeps its number. All four CRCs
    are recomputed; nothing else changes.
    """
    sector = table.sector
    hdr = table.primary
    arr = bytearray(table.array)
    for num in numbers:
        if table.entry(num) is None:
            raise GptError(f"entry {num} does not exist, refusing to blank it")
        off = (num - 1) * hdr.entry_size
        arr[off:off + hdr.entry_size] = bytes(hdr.entry_size)
    arr = bytes(arr)
    ecrc = zlib.crc32(arr[: hdr.num_entries * hdr.entry_size]) & 0xFFFFFFFF
    primary = replace(hdr, entries_crc=ecrc).with_crc()
    backup = replace(table.backup, entries_crc=ecrc).with_crc()
    n = entries_sectors(hdr, sector)
    if head_sectors < 2 + n:
        raise GptError("head region too small for the table")
    head = bytearray(head_sectors * sector)
    head[:sector] = table.mbr
    head[sector:sector + hdr.header_size] = primary.pack()[: hdr.header_size]
    head[2 * sector:2 * sector + len(arr)] = arr
    tail = bytearray((n + 1) * sector)
    tail[:len(arr)] = arr
    tail[n * sector:n * sector + hdr.header_size] = backup.pack()[: hdr.header_size]
    result = read_table(bytes(head[:(2 + n) * sector]), bytes(tail), table.total_sectors, sector)
    return bytes(head), bytes(tail), result

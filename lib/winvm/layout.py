"""The identity layout: which sector of the VM's disk is which sector of what (plan D1).

The VM's disk has exactly the real disk's size and partition table, minus the entries for Garuda's btrfs and
FASTGAMES. Its sectors come from five kinds of source:

    head    the first sectors up to the first partition: protective MBR + primary GPT (an image file)
    esp     the ESP's sectors: a PRIVATE image, never the real ESP (trap T5)
    mapped  MSR, C:, WinRE: dm `linear` onto the real partition at offset 0, so VM sector N == real sector N
    zero    everything absent (Garuda, FASTGAMES, gaps): dm `zero` - reads give zeros, writes are dropped
    tail    the last sectors: backup GPT entries + backup header (an image file)

This module is pure: it computes segments, the dm table text and the GPT images from a recorded layout and a
parsed live table. It never touches a device (dm.py does that).
"""

from __future__ import annotations

import tomllib
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import gpt

ROLES = ("esp", "mapped", "absent")
WINDOWS_DATA = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")  # Microsoft basic data


@dataclass(frozen=True)
class Part:
    number: int
    role: str
    what: str
    type_guid: uuid.UUID
    unique_guid: uuid.UUID
    first_lba: int
    sectors: int
    attributes: int
    windows_side: bool

    @property
    def last_lba(self) -> int:
        return self.first_lba + self.sectors - 1


@dataclass(frozen=True)
class Layout:
    by_id: str
    logical_block_size: int
    physical_block_size: int
    total_sectors: int
    disk_guid: uuid.UUID
    first_usable_lba: int
    last_usable_lba: int
    num_entries: int
    entry_size: int
    windows_partition: int
    parts: tuple[Part, ...]

    def part(self, number: int) -> Part:
        return next(p for p in self.parts if p.number == number)

    def by_role(self, role: str) -> list[Part]:
        return [p for p in self.parts if p.role == role]

    @property
    def entry_sectors(self) -> int:
        return -(-self.num_entries * self.entry_size // self.logical_block_size)

    @property
    def tail_start(self) -> int:
        """First sector of the backup entry array (the tail image covers it and the backup header)."""
        return self.total_sectors - self.entry_sectors - 1

    @property
    def head_sectors(self) -> int:
        """The head image runs from LBA 0 to the first partition."""
        return min(p.first_lba for p in self.parts)


class LayoutError(ValueError):
    pass


def load(path: str | Path) -> Layout:
    data = tomllib.loads(Path(path).read_text())
    d = data["disk"]
    parts = []
    for p in data["partition"]:
        if p["role"] not in ROLES:
            raise LayoutError(f"partition {p['number']}: unknown role {p['role']!r}")
        parts.append(Part(int(p["number"]), p["role"], p.get("what", ""), uuid.UUID(p["type_guid"]),
                          uuid.UUID(p["unique_guid"]), int(p["first_lba"]), int(p["sectors"]),
                          int(p["attributes"]), bool(p["windows_side"])))
    lay = Layout(d["by_id"], int(d["logical_block_size"]), int(d["physical_block_size"]), int(d["total_sectors"]),
                 uuid.UUID(d["disk_guid"]), int(d["first_usable_lba"]), int(d["last_usable_lba"]),
                 int(d["num_entries"]), int(d["entry_size"]), int(d["windows_partition"]),
                 tuple(sorted(parts, key=lambda p: p.first_lba)))
    validate(lay)
    return lay


def validate(lay: Layout) -> None:
    """Internal consistency of a recorded layout (independent of any disk)."""
    if not lay.by_id.startswith("/dev/disk/by-id/"):
        raise LayoutError("the disk must be addressed by /dev/disk/by-id (trap T21: kernel names move)")
    if len(lay.by_role("esp")) != 1:
        raise LayoutError("exactly one partition must have role 'esp'")
    if not lay.by_role("mapped"):
        raise LayoutError("no partition is mapped into the VM")
    nums = [p.number for p in lay.parts]
    if len(set(nums)) != len(nums):
        raise LayoutError("duplicate partition numbers")
    if any(p.role == "mapped" and not p.windows_side for p in lay.parts):
        raise LayoutError("every mapped partition must be windows_side (it must never be in use on Garuda)")
    if lay.windows_partition not in [p.number for p in lay.by_role("mapped")]:
        raise LayoutError("windows_partition must be one of the mapped partitions")
    prev_end = -1
    for p in lay.parts:
        if p.sectors <= 0:
            raise LayoutError(f"partition {p.number} is empty")
        if p.first_lba < lay.first_usable_lba or p.last_lba > lay.last_usable_lba:
            raise LayoutError(f"partition {p.number} lies outside the usable area")
        if p.first_lba <= prev_end:
            raise LayoutError(f"partition {p.number} overlaps the one before it")
        prev_end = p.last_lba
    if lay.head_sectors < 2 + lay.entry_sectors:
        raise LayoutError("the first partition starts inside the primary GPT")
    if lay.last_usable_lba >= lay.tail_start:
        raise LayoutError("the usable area reaches into the backup GPT")


def drift(lay: Layout, table: gpt.Table, logical: int, physical: int) -> list[str]:
    """Every difference between the recorded layout and the live disk. Empty list == identical."""
    out = []
    if logical != lay.logical_block_size:
        out.append(f"logical block size is {logical}, recorded {lay.logical_block_size} (trap T17)")
    if physical != lay.physical_block_size:
        out.append(f"physical block size is {physical}, recorded {lay.physical_block_size}")
    if table.total_sectors != lay.total_sectors:
        out.append(f"disk has {table.total_sectors} sectors, recorded {lay.total_sectors}")
    h = table.primary
    for name, live, rec in (("disk GUID", h.disk_guid, lay.disk_guid),
                            ("first usable LBA", h.first_usable, lay.first_usable_lba),
                            ("last usable LBA", h.last_usable, lay.last_usable_lba),
                            ("entry count", h.num_entries, lay.num_entries),
                            ("entry size", h.entry_size, lay.entry_size)):
        if live != rec:
            out.append(f"{name} is {live}, recorded {rec}")
    live_nums = {e.number for e in table.entries}
    rec_nums = {p.number for p in lay.parts}
    for n in sorted(live_nums - rec_nums):
        out.append(f"partition {n} exists on the disk but is not in the recorded layout")
    for n in sorted(rec_nums - live_nums):
        out.append(f"recorded partition {n} is missing from the disk")
    for p in lay.parts:
        e = table.entry(p.number)
        if e is None:
            continue
        for name, live, rec in (("type GUID", e.type_guid, p.type_guid), ("unique GUID", e.unique_guid, p.unique_guid),
                                ("first LBA", e.first_lba, p.first_lba), ("size", e.sectors, p.sectors),
                                ("attributes", e.attributes, p.attributes)):
            if live != rec:
                out.append(f"partition {p.number} ({p.what}): {name} is {live}, recorded {rec}")
    return out


@dataclass(frozen=True)
class Segment:
    start: int
    length: int
    kind: str  # head | esp | mapped | zero | tail
    part: int | None = None

    @property
    def end(self) -> int:
        return self.start + self.length


def segments(lay: Layout) -> list[Segment]:
    """The VM disk as contiguous segments covering sector 0 .. total_sectors exactly once."""
    raw: list[Segment] = [Segment(0, lay.head_sectors, "head")]
    pos = lay.head_sectors
    for p in lay.parts:
        if p.first_lba > pos:
            raw.append(Segment(pos, p.first_lba - pos, "zero"))
        kind = {"esp": "esp", "mapped": "mapped", "absent": "zero"}[p.role]
        raw.append(Segment(p.first_lba, p.sectors, kind, p.number if kind != "zero" else None))
        pos = p.first_lba + p.sectors
    if lay.tail_start > pos:
        raw.append(Segment(pos, lay.tail_start - pos, "zero"))
    raw.append(Segment(lay.tail_start, lay.total_sectors - lay.tail_start, "tail"))
    merged: list[Segment] = []
    for s in raw:
        if merged and s.kind == "zero" and merged[-1].kind == "zero":
            m = merged.pop()
            s = Segment(m.start, m.length + s.length, "zero")
        merged.append(s)
    # Self-check: a gap or overlap here would shift every later sector of C:.
    pos = 0
    for s in merged:
        if s.start != pos or s.length <= 0:
            raise LayoutError(f"segment table is not contiguous at sector {pos}")
        pos = s.end
    if pos != lay.total_sectors:
        raise LayoutError("segment table does not cover the disk exactly")
    return merged


def dm_table(lay: Layout, devices: dict[str, str]) -> str:
    """Render the device-mapper table.

    `devices` maps "head", "esp", "tail" and "part<N>" (each mapped partition) to a "major:minor" string.
    Mapped partitions are addressed at offset 0 OF THE PARTITION (identity because the segment starts at the
    partition's own LBA), so the kernel claims exactly those partitions and nothing else (trap T1).
    """
    lines = []
    for s in segments(lay):
        if s.kind == "zero":
            lines.append(f"{s.start} {s.length} zero")
            continue
        key = f"part{s.part}" if s.kind == "mapped" else s.kind
        dev = devices[key]
        if not _is_majmin(dev):
            raise LayoutError(f"device for {key} must be major:minor, got {dev!r} (trap T21)")
        lines.append(f"{s.start} {s.length} linear {dev} 0")
    return "\n".join(lines) + "\n"


def _is_majmin(s: str) -> bool:
    a, sep, b = s.partition(":")
    return bool(sep) and a.isdigit() and b.isdigit()


def vm_images(lay: Layout, table: gpt.Table) -> tuple[bytes, bytes, gpt.Table]:
    """(head image, tail image, the VM's table) from the live table: absent entries blanked, CRCs redone."""
    absent = {p.number for p in lay.by_role("absent")}
    head, tail, vm = gpt.without(table, absent, lay.head_sectors)
    expect = {p.number for p in lay.parts} - absent
    got = {e.number for e in vm.entries}
    if got != expect:
        raise LayoutError(f"VM table has entries {sorted(got)}, expected {sorted(expect)}")
    for e in vm.entries:
        if e != table.entry(e.number):
            raise LayoutError(f"entry {e.number} changed while blanking others")
    if vm.primary.disk_guid != table.primary.disk_guid:
        raise LayoutError("disk GUID changed")
    return head, tail, vm


def record(table: gpt.Table, by_id: str, logical: int, physical: int, roles: dict[int, str],
           what: dict[int, str], windows_partition: int) -> str:
    """TOML text recording a live table (for a deliberate re-record after repartitioning)."""
    h = table.primary
    out = ["[disk]", f'by_id = "{by_id}"', f"logical_block_size = {logical}", f"physical_block_size = {physical}",
           f"total_sectors = {table.total_sectors}", f'disk_guid = "{h.disk_guid}"',
           f"first_usable_lba = {h.first_usable}", f"last_usable_lba = {h.last_usable}",
           f"num_entries = {h.num_entries}", f"entry_size = {h.entry_size}",
           f"windows_partition = {windows_partition}", ""]
    for e in table.entries:
        out += ["[[partition]]", f"number = {e.number}",
                f"windows_side = {'true' if roles[e.number] == 'mapped' or e.type_guid == WINDOWS_DATA else 'false'}",
                f'role = "{roles[e.number]}"',
                f'what = "{what.get(e.number, e.name)}"', f'type_guid = "{e.type_guid}"',
                f'unique_guid = "{e.unique_guid}"', f"first_lba = {e.first_lba}", f"sectors = {e.sectors}",
                f"attributes = {e.attributes:#x}", ""]
    return "\n".join(out)

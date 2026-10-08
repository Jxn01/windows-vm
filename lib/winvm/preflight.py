"""The pre-flight: every reason the real Windows must NOT be started as a VM right now.

One module, two callers (fix the class): `winvm start` runs it first for a readable refusal, and the libvirt
qemu hook runs it again on `prepare` as the enforcement - a start from virt-manager or plain `virsh` cannot
skip it. Each check returns a Check; `ok` is False for a refusal. A check that could not look (tool error,
unreadable device) is a refusal too, never a pass.

Checks, in order (traps from the plan in brackets):
    disk            the recorded by-id disk exists and is a whole disk                         [T21]
    fresh-reads     the disk's and the Windows partitions' page cache is invalidated first     [T28]
    block-size      logical/physical sector size as recorded                                   [T17]
    gpt             both GPT copies valid and identical to the recorded layout                 [GPT drift]
    partitions      each recorded PARTUUID is that partition of THAT disk, start/size as recorded [T21]
    not-in-use      no Windows-side partition is mounted, used as swap or claimed by anything  [T1]
    no-vm-disk      no winvm-* device-mapper disk exists already (a sibling domain runs, or stale) [T1]
    no-saved-state  no libvirt managed-save image of either domain                             [saved RAM]
    hibernation     hiberfil.sys absent or its first page all zero                             [T2]
    ntfs-clean      C:'s NTFS volume flags are 0 (not dirty, no chkdsk pending)                [T2]
    no-servicing    no C:\\Windows\\WinSxS\\pending.xml                                        [T2]
    no-feature-update  no $WINDOWS.~BT\\NewOS or $WINDOWS.~BT\\Sources\\SafeOS                [T2, T22]
    ntfs-sector     NTFS sector size equals the disk's logical sector size                     [T17]
    esp-source      /boot/efi is the recorded ESP and holds Windows Boot Manager and its BCD    [T5, T7]
    state-dir       /var/lib/windows-vm is a btrfs subvolume with NOCOW                         [T16]
"""

from __future__ import annotations

from dataclasses import dataclass

from . import config, gpt, layout, ntfs


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def run(probe, lay: layout.Layout) -> list[Check]:
    out: list[Check] = []

    def add(name, ok, detail):
        out.append(Check(name, bool(ok), detail))

    def guarded(name, fn):
        """Run one check; any exception is a refusal that says what could not be looked at."""
        try:
            fn()
        except (OSError, ntfs.NtfsError, gpt.GptError, ValueError) as e:
            add(name, False, f"could not check: {e}")

    disk = probe.resolve(lay.by_id)
    if disk is None or disk.partition != 0:
        add("disk", False, f"{lay.by_id} is missing or not a whole disk")
        return out  # nothing below can be checked without the disk
    add("disk", True, f"{lay.by_id} -> {disk.name}")

    def fresh():
        # T28: every read below must see the disk, not pages cached before a VM wrote underneath them
        probe.flush(lay.by_id)
        for p in lay.parts:
            if p.windows_side and probe.resolve(probe.partuuid_path(p.unique_guid)) is not None:
                probe.flush(probe.partuuid_path(p.unique_guid))
        add("fresh-reads", True, "buffer cache of the disk and the Windows partitions invalidated")
    guarded("fresh-reads", fresh)

    def blocks():
        lo, ph = probe.block_sizes(disk)
        ok = (lo, ph) == (lay.logical_block_size, lay.physical_block_size)
        add("block-size", ok, f"logical {lo}, physical {ph} (recorded {lay.logical_block_size}/{lay.physical_block_size})")
    guarded("block-size", blocks)

    def gpt_check():
        table = probe.read_gpt(lay.by_id, lay.logical_block_size, lay.total_sectors, lay.entry_sectors)
        lo, ph = probe.block_sizes(disk)
        d = layout.drift(lay, table, lo, ph)
        add("gpt", not d, "identical to the recorded layout" if not d else "; ".join(d))
    guarded("gpt", gpt_check)

    units = lay.logical_block_size // 512  # sysfs start/size are always in 512-byte units
    parts: dict[int, object] = {}

    def partitions():
        problems = []
        for p in lay.parts:
            bd = probe.resolve(probe.partuuid_path(p.unique_guid))
            if bd is None:
                problems.append(f"PARTUUID {p.unique_guid} (p{p.number}) not found")
                continue
            parts[p.number] = bd
            if bd.parent != disk.name or bd.partition != p.number:
                problems.append(f"PARTUUID {p.unique_guid} is {bd.name}, not partition {p.number} of {disk.name}")
            if bd.start != p.first_lba * units or bd.size != p.sectors * units:
                problems.append(f"p{p.number} start/size {bd.start}/{bd.size} differ from the recorded layout")
        add("partitions", not problems, "; ".join(problems) or "every recorded PARTUUID is where it was recorded")
    guarded("partitions", partitions)

    def in_use():
        mounted = probe.mounted_majmins()
        swaps = probe.swap_devices()
        problems = []
        for p in lay.parts:
            if not p.windows_side or p.number not in parts:
                continue  # Garuda's root and the shared ESP are mounted by design and never mapped
            bd = parts[p.number]
            if bd.majmin in mounted:
                problems.append(f"p{p.number} ({p.what}) is MOUNTED")
            if bd.majmin in swaps:
                problems.append(f"p{p.number} is in use as swap")
            h = probe.holders(bd)
            if h:
                problems.append(f"p{p.number} is held by {', '.join(h)}")
        add("not-in-use", not problems, "; ".join(problems) or "no Windows partition is mounted or claimed")
    guarded("not-in-use", in_use)

    def vm_disk():
        names = [n for n in probe.dm_names() if n.startswith(config.DM_PREFIX)]
        add("no-vm-disk", not names, f"a VM disk already exists: {', '.join(names)} (is the other domain running?)"
            if names else "no winvm-* device exists")
    guarded("no-vm-disk", vm_disk)

    def saved():
        s = probe.saved_images()
        add("no-saved-state", not s, f"managed-save image(s) exist for {', '.join(s)}: resuming one after the disk "
            "changed corrupts C: - remove with `virsh managedsave-remove`" if s else "no saved VM state")
    guarded("no-saved-state", saved)

    cdev = probe.partuuid_path(lay.part(lay.windows_partition).unique_guid)

    def hib():
        state = ntfs.hibernation_state(probe.ntfs_file_head(cdev, "/hiberfil.sys"))
        add("hibernation", state in ("absent", "clear"), f"hiberfil.sys: {state}")
    guarded("hibernation", hib)

    def clean():
        v = probe.ntfs_volume(cdev)
        names = v.flag_names()
        add("ntfs-clean", not names, f"volume flags {v.flags:#06x}" + (f" ({', '.join(names)})" if names else ""))
        add("ntfs-sector", v.sector_size == lay.logical_block_size,
            f"NTFS sector size {v.sector_size}, disk logical {lay.logical_block_size}")
    guarded("ntfs-clean", clean)

    def servicing():
        names = probe.ntfs_listdir(cdev, "/Windows/WinSxS")
        if names is None:
            add("no-servicing", False, "C:\\Windows\\WinSxS not found - is this the Windows partition?")
            return
        pend = [n for n in names if n.lower() == "pending.xml"]
        add("no-servicing", not pend, "C:\\Windows\\WinSxS\\pending.xml exists (servicing in flight)" if pend
            else "no pending.xml")
    guarded("no-servicing", servicing)

    def feature_update():
        top = probe.ntfs_listdir(cdev, "/$WINDOWS.~BT")
        found = []
        if top is not None:
            if any(n.lower() == "newos" for n in top):
                found.append("$WINDOWS.~BT\\NewOS")
            if any(n.lower() == "sources" for n in top):
                src = probe.ntfs_listdir(cdev, "/$WINDOWS.~BT/Sources") or []
                if any(n.lower() == "safeos" for n in src):
                    found.append("$WINDOWS.~BT\\Sources\\SafeOS")
        add("no-feature-update", not found, f"feature update in flight: {', '.join(found)}" if found else
            ("no $WINDOWS.~BT" if top is None else "$WINDOWS.~BT is a leftover without NewOS/SafeOS (T22)"))
    guarded("no-feature-update", feature_update)

    def esp():
        src = probe.mount_source_of(str(config.REAL_ESP_MOUNT))
        espp = lay.by_role("esp")[0]
        bd = probe.resolve(probe.partuuid_path(espp.unique_guid))
        problems = []
        if bd is None or src != bd.majmin:
            problems.append(f"{config.REAL_ESP_MOUNT} is not the recorded ESP (PARTUUID {espp.unique_guid})")
        for rel in ("EFI/Microsoft/Boot/bootmgfw.efi", "EFI/Microsoft/Boot/BCD"):
            if not probe.exists(config.REAL_ESP_MOUNT / rel):
                problems.append(f"{rel} missing on the real ESP")
        add("esp-source", not problems, "; ".join(problems) or "real ESP mounted, Windows Boot Manager + BCD present")
    guarded("esp-source", esp)

    def state():
        if not probe.exists(config.STATE):
            add("state-dir", False, f"{config.STATE} does not exist (run install.sh)")
            return
        sub, nocow = probe.is_nocow_subvolume(config.STATE)
        add("state-dir", sub and nocow, f"{config.STATE}: subvolume={sub}, nocow={nocow}")
    guarded("state-dir", state)

    return out


def refusals(checks: list[Check]) -> list[Check]:
    return [c for c in checks if not c.ok]


def report(checks: list[Check]) -> str:
    return "\n".join(f"{'ok  ' if c.ok else 'FAIL'} {c.name:18} {c.detail}" for c in checks)

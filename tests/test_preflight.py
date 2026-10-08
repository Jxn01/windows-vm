"""Every pre-flight refusal, each with the all-good positive control (a FakeProbe of the real host's state)."""

from __future__ import annotations

import copy
import unittest
import uuid
from pathlib import Path

from helpers import TOTAL, mutate_entry, real_layout, real_table
from winvm import config, gpt, ntfs, preflight
from winvm.probe import BlockDev

LAY = real_layout()
DISK = BlockDev("nvme0n1", "259:0", "", 0, 0, TOTAL)


def part_dev(n: int, start: int, size: int) -> BlockDev:
    return BlockDev(f"nvme0n1p{n}", f"259:{n}", "nvme0n1", n, start, size)


class FakeProbe:
    """The real host as measured in P0/P1, every answer overridable."""

    def __init__(self):
        self.disk = DISK
        self.parts = {str(p.unique_guid): part_dev(p.number, p.first_lba, p.sectors) for p in LAY.parts}
        self.sizes = (512, 512)
        self.table = real_table()
        self.mounted = {"259:2", "259:1"}  # Garuda's root and the ESP are mounted
        self.swaps: set[str] = set()
        self.holders_map: dict[str, list[str]] = {}
        self.dms = ["luks-something"]
        self.saved: list[str] = []
        self.hiberfil: bytes | None = bytes(4096)
        self.volume = ntfs.VolumeInfo(0, "3.1", 512)
        self.dirs = {"/Windows/WinSxS": ["Manifests", "Catalogs"],
                     "/$WINDOWS.~BT": ["Sources"],
                     "/$WINDOWS.~BT/Sources": ["Diagnostics", "Panther", "SetupPlatform.ini"]}
        self.esp_src = "259:1"
        self.files = {config.REAL_ESP_MOUNT / "EFI/Microsoft/Boot/bootmgfw.efi",
                      config.REAL_ESP_MOUNT / "EFI/Microsoft/Boot/BCD", config.STATE}
        self.subvol = (True, True)
        self.raise_on: dict[str, Exception] = {}
        self.events: list[str] = []

    def resolve(self, path):
        if path == LAY.by_id:
            return self.disk
        if path.startswith("/dev/disk/by-partuuid/"):
            return self.parts.get(path.rsplit("/", 1)[1])
        return None

    def partuuid_path(self, guid):
        return f"/dev/disk/by-partuuid/{str(guid).lower()}"

    def flush(self, path):
        self.events.append(f"flush {path}")

    def block_sizes(self, disk):
        return self.sizes

    def read_gpt(self, by_id, logical, total, n):
        if "gpt" in self.raise_on:
            raise self.raise_on["gpt"]
        return self.table

    def holders(self, dev):
        return self.holders_map.get(dev.name, [])

    def mounted_majmins(self):
        return self.mounted

    def swap_devices(self):
        return self.swaps

    def dm_names(self):
        return self.dms

    def mount_source_of(self, mp):
        return self.esp_src

    def ntfs_volume(self, dev):
        self.events.append("ntfs read")
        if "volume" in self.raise_on:
            raise self.raise_on["volume"]
        return self.volume

    def ntfs_file_head(self, dev, path):
        self.events.append("ntfs read")
        if "hiberfil" in self.raise_on:
            raise self.raise_on["hiberfil"]
        return self.hiberfil

    def ntfs_listdir(self, dev, path):
        return self.dirs.get(path)

    def exists(self, path):
        return Path(path) in self.files

    def is_nocow_subvolume(self, path):
        return self.subvol

    def saved_images(self):
        return self.saved


def failing(probe) -> dict[str, str]:
    return {c.name: c.detail for c in preflight.run(probe, LAY) if not c.ok}


class Preflight(unittest.TestCase):
    def assertRefuses(self, probe, name, text=""):
        bad = failing(probe)
        self.assertIn(name, bad, f"expected {name} to refuse; refusals: {bad}")
        self.assertIn(text, bad[name])

    def test_positive_control_all_pass(self):
        checks = preflight.run(FakeProbe(), LAY)
        self.assertEqual(failing(FakeProbe()), {})
        self.assertEqual([c.name for c in checks],
                         ["disk", "fresh-reads", "block-size", "gpt", "partitions", "not-in-use", "no-vm-disk", "no-saved-state",
                          "hibernation", "ntfs-clean", "ntfs-sector", "no-servicing", "no-feature-update",
                          "esp-source", "state-dir"])

    def test_cache_invalidated_before_any_ntfs_read(self):  # T28
        p = FakeProbe()
        preflight.run(p, LAY)
        first_read = p.events.index("ntfs read")
        flushed = {e for e in p.events[:first_read] if e.startswith("flush ")}
        c = "flush " + p.partuuid_path(LAY.part(5).unique_guid)
        self.assertIn(c, flushed)
        self.assertIn("flush " + LAY.by_id, flushed)

    def test_flush_failure_is_a_refusal(self):
        p = FakeProbe()
        def boom(path):
            raise OSError("ioctl failed")
        p.flush = boom
        self.assertRefuses(p, "fresh-reads", "could not check")

    def test_disk_missing(self):
        p = FakeProbe()
        p.disk = None
        self.assertRefuses(p, "disk")

    def test_block_size(self):  # T17
        p = FakeProbe()
        p.sizes = (4096, 4096)
        self.assertRefuses(p, "block-size")

    def test_gpt_drift(self):
        p = FakeProbe()
        h, b = mutate_entry(5, first_lba=2628614145)
        p.table = gpt.read_table(h, b, TOTAL)
        self.assertRefuses(p, "gpt", "partition 5")

    def test_gpt_unreadable_is_a_refusal_not_a_pass(self):
        p = FakeProbe()
        p.raise_on["gpt"] = gpt.GptError("header CRC mismatch")
        self.assertRefuses(p, "gpt", "could not check")

    def test_partuuid_on_another_disk(self):  # T21: a clone/USB disk carrying the same GUID
        p = FakeProbe()
        g = str(LAY.part(5).unique_guid)
        p.parts[g] = BlockDev("sdx5", "8:5", "sdx", 5, p.parts[g].start, p.parts[g].size)
        self.assertRefuses(p, "partitions", "not partition 5")

    def test_partition_size_differs(self):
        p = FakeProbe()
        g = str(LAY.part(6).unique_guid)
        p.parts[g] = BlockDev("nvme0n1p6", "259:6", "nvme0n1", 6, p.parts[g].start, p.parts[g].size - 1)
        self.assertRefuses(p, "partitions", "p6")

    def test_c_mounted(self):  # T1 / goal: prove the start refuses while C: is mounted
        p = FakeProbe()
        p.mounted.add("259:5")
        self.assertRefuses(p, "not-in-use", "p5")

    def test_fastgames_mounted(self):
        p = FakeProbe()
        p.mounted.add("259:3")
        self.assertRefuses(p, "not-in-use", "p3")

    def test_winre_swap(self):
        p = FakeProbe()
        p.swaps.add("259:6")
        self.assertRefuses(p, "not-in-use", "swap")

    def test_partition_claimed(self):
        p = FakeProbe()
        p.holders_map["nvme0n1p5"] = ["dm-7"]
        self.assertRefuses(p, "not-in-use", "held by dm-7")

    def test_garuda_root_and_esp_mounted_is_fine(self):
        p = FakeProbe()
        self.assertTrue({"259:1", "259:2"} <= p.mounted)
        self.assertNotIn("not-in-use", failing(p))

    def test_vm_disk_exists(self):  # the other domain runs, or a stale disk
        p = FakeProbe()
        p.dms.append("winvm-ro")
        self.assertRefuses(p, "no-vm-disk", "winvm-ro")

    def test_saved_state(self):
        p = FakeProbe()
        p.saved = ["windows"]
        self.assertRefuses(p, "no-saved-state", "windows")

    def test_hibernated(self):  # T2
        for sig in (b"hibr", b"HIBR", b"wake", b"RSTR"):
            p = FakeProbe()
            p.hiberfil = sig + bytes(4092)
            self.assertRefuses(p, "hibernation", "signature")

    def test_hiberfil_absent_is_fine(self):
        p = FakeProbe()
        p.hiberfil = None
        self.assertNotIn("hibernation", failing(p))

    def test_hiberfil_unreadable_is_a_refusal(self):
        p = FakeProbe()
        p.raise_on["hiberfil"] = ntfs.NtfsError("ntfscat failed")
        self.assertRefuses(p, "hibernation", "could not check")

    def test_dirty(self):  # T2
        p = FakeProbe()
        p.volume = ntfs.VolumeInfo(0x0001, "3.1", 512)
        self.assertRefuses(p, "ntfs-clean", "dirty")

    def test_chkdsk_flags(self):
        p = FakeProbe()
        p.volume = ntfs.VolumeInfo(0x8000, "3.1", 512)
        self.assertRefuses(p, "ntfs-clean", "modified-by-chkdsk")

    def test_unknown_volume_flag(self):
        p = FakeProbe()
        p.volume = ntfs.VolumeInfo(0x0100, "3.1", 512)
        self.assertRefuses(p, "ntfs-clean", "unknown")

    def test_ntfs_sector_size(self):
        p = FakeProbe()
        p.volume = ntfs.VolumeInfo(0, "3.1", 4096)
        self.assertRefuses(p, "ntfs-sector")

    def test_pending_xml(self):  # T2
        p = FakeProbe()
        p.dirs["/Windows/WinSxS"] = ["Manifests", "pending.xml"]
        self.assertRefuses(p, "no-servicing", "pending.xml")

    def test_winsxs_missing(self):
        p = FakeProbe()
        del p.dirs["/Windows/WinSxS"]
        self.assertRefuses(p, "no-servicing", "not found")

    def test_feature_update_newos(self):  # T2/T22
        p = FakeProbe()
        p.dirs["/$WINDOWS.~BT"] = ["Sources", "NewOS"]
        self.assertRefuses(p, "no-feature-update", "NewOS")

    def test_feature_update_safeos(self):
        p = FakeProbe()
        p.dirs["/$WINDOWS.~BT/Sources"] = ["SafeOS", "Panther"]
        self.assertRefuses(p, "no-feature-update", "SafeOS")

    def test_bt_leftover_is_fine(self):  # T22: the real C: has exactly this leftover
        self.assertNotIn("no-feature-update", failing(FakeProbe()))

    def test_no_bt_is_fine(self):
        p = FakeProbe()
        del p.dirs["/$WINDOWS.~BT"]
        self.assertNotIn("no-feature-update", failing(p))

    def test_esp_not_mounted_from_the_recorded_partition(self):
        p = FakeProbe()
        p.esp_src = "8:1"
        self.assertRefuses(p, "esp-source", "not the recorded ESP")

    def test_esp_missing_bootmgr(self):
        p = FakeProbe()
        p.files.discard(config.REAL_ESP_MOUNT / "EFI/Microsoft/Boot/bootmgfw.efi")
        self.assertRefuses(p, "esp-source", "bootmgfw.efi")

    def test_state_dir_missing(self):
        p = FakeProbe()
        p.files.discard(config.STATE)
        self.assertRefuses(p, "state-dir", "does not exist")

    def test_state_dir_not_nocow(self):  # T16
        p = FakeProbe()
        p.subvol = (True, False)
        self.assertRefuses(p, "state-dir", "nocow=False")

    def test_state_dir_not_subvolume(self):
        p = FakeProbe()
        p.subvol = (False, True)
        self.assertRefuses(p, "state-dir", "subvolume=False")


if __name__ == "__main__":
    unittest.main()

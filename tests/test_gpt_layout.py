"""GPT parsing/rewriting and the identity layout, against the real disk's own table.

Every guard here has a positive control: the real table passes, and a mutated one (one field changed, CRCs
kept valid so the CRC check cannot be what catches it) is refused for the reason under test.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
import uuid

from helpers import BACKUP, PRIMARY, TOTAL, mutate_entry, real_layout, real_table
from winvm import gpt, layout

GOLDEN_DM = """0 4096 linear 7:10 0
4096 9003008 linear 7:11 0
9007104 2619574272 zero
2628581376 32768 linear 259:4 0
2628614144 5371123712 linear 259:5 0
7999737856 1832960 linear 259:6 0
8001570816 2703 zero
8001573519 33 linear 7:12 0
"""
DEVICES = {"head": "7:10", "esp": "7:11", "tail": "7:12", "part4": "259:4", "part5": "259:5", "part6": "259:6"}


class GptParse(unittest.TestCase):
    def test_real_table_parses(self):
        t = real_table()
        self.assertEqual(str(t.primary.disk_guid), "0897a6e9-ad1d-41ce-a152-026976da8cae")
        self.assertEqual([e.number for e in t.entries], [1, 2, 3, 4, 5, 6])
        self.assertEqual(t.entry(5).unique_guid, uuid.UUID("c52df2c1-31af-49fd-b0b0-8758c46f948d"))

    def test_header_crc_is_checked(self):
        bad = bytearray(PRIMARY)
        bad[512 + 40] ^= 1  # first usable LBA, CRC left stale
        with self.assertRaisesRegex(gpt.GptError, "header CRC"):
            gpt.read_table(bytes(bad), BACKUP, TOTAL)

    def test_entry_crc_is_checked(self):
        bad = bytearray(PRIMARY)
        bad[1024 + 4 * 128 + 40] ^= 1  # inside entry 5
        with self.assertRaisesRegex(gpt.GptError, "entry array CRC"):
            gpt.read_table(bytes(bad), BACKUP, TOTAL)

    def test_copies_must_agree(self):
        h, _ = mutate_entry(5, first_lba=2628614145)
        with self.assertRaisesRegex(gpt.GptError, "differ"):
            gpt.read_table(h, BACKUP, TOTAL)  # primary mutated, backup real

    def test_wrong_disk_size_is_refused(self):
        with self.assertRaisesRegex(gpt.GptError, "backup header LBA"):
            gpt.read_table(PRIMARY, BACKUP, TOTAL + 1)


class Blanking(unittest.TestCase):
    def test_vm_images_keep_all_entries(self):
        # The VM GPT = the full real table (entries 1..6). Blanking entries 2/3 broke ARC partition numbering
        # (multi(0)disk(0)rdisk(0)partition(5)) and bugchecked 0x7B. p2/p3 DATA is
        # zeroed by the dm, but their GPT ENTRIES stay so numbering matches the real disk.
        lay, t = real_layout(), real_table()
        head, tail, vm = layout.vm_images(lay, t)
        self.assertEqual(len(head), 4096 * 512)
        self.assertEqual(len(tail), 33 * 512)
        self.assertEqual([e.number for e in vm.entries], [1, 2, 3, 4, 5, 6])
        for e in vm.entries:
            self.assertEqual(e, t.entry(e.number))  # byte-for-byte the real table
        self.assertEqual(vm.primary.disk_guid, t.primary.disk_guid)
        self.assertEqual(head[:512], PRIMARY[:512])  # protective MBR unchanged
        # p2/p3 are STILL zeroed in the dm table even though their GPT entries remain:
        text = layout.dm_table(lay, DEVICES)
        for n in (2, 3):
            p = lay.part(n)
            covering = [ln for ln in text.splitlines()
                        if int(ln.split()[0]) <= p.first_lba < int(ln.split()[0]) + int(ln.split()[1])]
            self.assertEqual(covering[0].split()[2], "zero")

    def test_blanking_missing_entry_refuses(self):
        with self.assertRaises(gpt.GptError):
            gpt.without(real_table(), {9}, 4096)

    @unittest.skipUnless(shutil.which("sgdisk"), "sgdisk not installed")
    def test_sgdisk_reads_the_vm_table_independently(self):
        """An independent GPT implementation must see the FULL real table (all 6 entries kept; ARC numbering)."""
        lay, t = real_layout(), real_table()
        head, tail, _ = layout.vm_images(lay, t)
        with tempfile.TemporaryDirectory() as td:
            img = os.path.join(td, "disk.img")
            with open(img, "wb") as f:
                f.truncate(TOTAL * 512)  # sparse: same size as the real disk
                f.seek(0)
                f.write(head)
                f.seek((TOTAL - 33) * 512)
                f.write(tail)
            v = subprocess.run(["sgdisk", "-v", img], capture_output=True, text=True)
            self.assertIn("No problems found", v.stdout, v.stdout)
            p = subprocess.run(["sgdisk", "-p", img], capture_output=True, text=True).stdout
            self.assertIn("0897A6E9-AD1D-41CE-A152-026976DA8CAE", p)
            rows = [line.split() for line in p.splitlines() if line.strip()[:1].isdigit() and len(line.split()) > 5]
            self.assertEqual([r[0] for r in rows], ["1", "2", "3", "4", "5", "6"])
            for r in rows:
                e = t.entry(int(r[0]))
                self.assertEqual((int(r[1]), int(r[2])), (e.first_lba, e.last_lba))
            for n in (1, 2, 3, 4, 5, 6):
                info = subprocess.run(["sgdisk", "-i", str(n), img], capture_output=True, text=True).stdout
                self.assertIn(str(t.entry(n).unique_guid).upper(), info)


class Layout(unittest.TestCase):
    def test_no_drift_on_the_real_disk(self):  # positive control for every drift test below
        self.assertEqual(layout.drift(real_layout(), real_table(), 512, 512), [])

    def test_drift_partition_moved_one_sector(self):
        h, b = mutate_entry(5, first_lba=2628614145)
        d = layout.drift(real_layout(), gpt.read_table(h, b, TOTAL), 512, 512)
        self.assertTrue(any("partition 5" in x and "first LBA" in x for x in d), d)

    def test_drift_partition_guid(self):
        h, b = mutate_entry(4, unique_guid=uuid.uuid4())
        d = layout.drift(real_layout(), gpt.read_table(h, b, TOTAL), 512, 512)
        self.assertTrue(any("partition 4" in x and "unique GUID" in x for x in d), d)

    def test_drift_disk_guid(self):
        h, b = mutate_entry(1, disk_guid=uuid.uuid4())
        d = layout.drift(real_layout(), gpt.read_table(h, b, TOTAL), 512, 512)
        self.assertTrue(any("disk GUID" in x for x in d), d)

    def test_drift_block_size(self):
        d = layout.drift(real_layout(), real_table(), 4096, 4096)
        self.assertTrue(any("logical block size" in x for x in d), d)

    def test_segments_cover_the_disk_exactly(self):
        segs = layout.segments(real_layout())
        self.assertEqual(segs[0].start, 0)
        self.assertEqual(segs[-1].end, TOTAL)
        for a, b in zip(segs, segs[1:]):
            self.assertEqual(a.end, b.start)

    def test_mapped_segments_are_identity(self):
        lay = real_layout()
        for s in layout.segments(lay):
            if s.kind == "mapped":
                p = lay.part(s.part)
                self.assertEqual((s.start, s.length), (p.first_lba, p.sectors))
        self.assertEqual({s.part for s in layout.segments(lay) if s.kind == "mapped"}, {4, 5, 6})

    def test_dm_table_golden(self):
        self.assertEqual(layout.dm_table(real_layout(), DEVICES), GOLDEN_DM)

    def test_dm_table_never_maps_p2_p3_or_the_real_esp(self):
        text = layout.dm_table(real_layout(), DEVICES)
        lay = real_layout()
        for n in (2, 3):
            p = lay.part(n)
            covering = [line for line in text.splitlines()
                        if int(line.split()[0]) <= p.first_lba < int(line.split()[0]) + int(line.split()[1])]
            self.assertEqual(covering[0].split()[2], "zero", covering)
        esp_line = text.splitlines()[1]
        self.assertEqual(esp_line.split()[3], DEVICES["esp"])  # the private image, not a partition

    def test_dm_table_rejects_kernel_names(self):  # never /dev/nvme0n1p5, always major:minor
        bad = dict(DEVICES, part5="/dev/nvme0n1p5")
        with self.assertRaises(layout.LayoutError):
            layout.dm_table(real_layout(), bad)

    def test_layout_requires_by_id(self):
        lay = real_layout()
        with self.assertRaises(layout.LayoutError):
            layout.validate(layout.Layout(**{**lay.__dict__, "by_id": "/dev/nvme0n1"}))

    def test_mapped_must_be_windows_side(self):
        lay = real_layout()
        parts = tuple(p if p.number != 5 else layout.Part(**{**p.__dict__, "windows_side": False}) for p in lay.parts)
        with self.assertRaises(layout.LayoutError):
            layout.validate(layout.Layout(**{**lay.__dict__, "parts": parts}))

    def test_record_round_trips(self):
        lay, t = real_layout(), real_table()
        text = layout.record(t, lay.by_id, 512, 512, {p.number: p.role for p in lay.parts},
                             {p.number: p.what for p in lay.parts}, lay.windows_partition)
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write(text)
        try:
            again = layout.load(f.name)
        finally:
            os.unlink(f.name)
        self.assertEqual(again, lay)


if __name__ == "__main__":
    unittest.main()

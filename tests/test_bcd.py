"""BCD flag resolution and, on the committed BCD fixture, the hivex-backed apply/verify round-trip.

The private ESP's BCD can carry recovery/diagnostic flags (Safe Mode, no hypervisor) for the THROWAWAY test
VM only; these never touch real C:. Each flag maps to one OS-loader integer element.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401 - sets sys.path
from winvm import bcd

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "BCD"
HAVE_HIVEX = shutil.which("hivexsh") is not None and shutil.which("hivexget") is not None


class Resolve(unittest.TestCase):
    def test_safeboot_values(self):
        self.assertEqual(bcd.resolve({"safeboot": "minimal"}), {"25000080": 0})
        self.assertEqual(bcd.resolve({"safeboot": "network"}), {"25000080": 1})
        self.assertEqual(bcd.resolve({"safeboot": "dsrepair"}), {"25000080": 2})

    def test_hypervisor(self):
        self.assertEqual(bcd.resolve({"hypervisorlaunchtype": "off"}), {"250000f0": 0})
        self.assertEqual(bcd.resolve({"hypervisorlaunchtype": "auto"}), {"250000f0": 1})

    def test_unknown_flag_refused(self):
        with self.assertRaises(bcd.BcdError):
            bcd.resolve({"nolockdown": "1"})

    def test_bad_safeboot_refused(self):
        with self.assertRaises(bcd.BcdError):
            bcd.resolve({"safeboot": "turbo"})


@unittest.skipUnless(FIXTURE.exists() and HAVE_HIVEX, "needs the BCD fixture and hivex tools")
class ApplyRoundTrip(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.bcd = Path(self.td.name) / "BCD"
        shutil.copy(FIXTURE, self.bcd)

    def tearDown(self):
        self.td.cleanup()

    def test_default_loader_is_a_guid(self):
        g = bcd.default_loader(str(self.bcd))
        self.assertTrue(g.startswith("{") and g.endswith("}") and len(g) == 38)

    def test_apply_new_element_and_overwrite_existing(self):
        # safeboot is absent in the fixture (new key); hypervisorlaunchtype exists (overwrite).
        bcd.apply_flags(str(self.bcd), {"safeboot": "minimal", "hypervisorlaunchtype": "off"}, log=lambda m: None)
        loader = bcd.default_loader(str(self.bcd))
        bcd.verify(str(self.bcd), {"25000080": 0, "250000f0": 0}, loader)
        # changing it again must stick (overwrite path for the now-existing key)
        bcd.apply_flags(str(self.bcd), {"safeboot": "network"}, log=lambda m: None)
        bcd.verify(str(self.bcd), {"25000080": 1}, loader)

    def test_verify_detects_wrong_value(self):
        bcd.apply_flags(str(self.bcd), {"safeboot": "minimal"}, log=lambda m: None)
        with self.assertRaises(bcd.BcdError):
            bcd.verify(str(self.bcd), {"25000080": 2})


if __name__ == "__main__":
    unittest.main()

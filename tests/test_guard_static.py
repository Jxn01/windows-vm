"""Static guards on guest/guard.ps1 + install-guard.ps1 (the PowerShell itself is exercised on the real Windows).

2026-10-12, the laptop's first hardware boot after a VM session: the owner logged on two seconds before the guard's
restore finished, so every logon autostart (Zebar, wtq, Windhawk's mods) was skipped for the whole session; restored
services stayed stopped (the service manager had passed them while Disabled) and boot tasks (the EverLink tunnel)
missed the boot. And the guard hard-coded the RIG's profile (C:\\Users\\jxnpe), so on the laptop it never parked or
restored the owner's Run keys / Startup folder.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

GUEST = Path(__file__).resolve().parent.parent / "guest"
GUARD = (GUEST / "guard.ps1").read_text()
INSTALL = (GUEST / "install-guard.ps1").read_text()


def function_body(src: str, name: str) -> str:
    m = re.search(rf"^function {re.escape(name)}\b.*?^\}}", src, re.S | re.M)
    return m.group(0) if m else ""


class GuardStartsWhatTheBootSkipped(unittest.TestCase):
    def test_restore_calls_start_restored(self):
        self.assertIn("Start-Restored $state", function_body(GUARD, "Restore"))

    def test_restored_auto_services_are_started(self):
        body = function_body(GUARD, "Start-Restored")
        self.assertIn("Start-Service", body)
        self.assertRegex(body, r"Norm \$state\.services\.\$n\) -eq 'Automatic'")

    def test_boot_tasks_always_and_logon_tasks_only_for_a_logged_on_owner(self):
        body = function_body(GUARD, "Start-Restored")
        self.assertIn("Start-ScheduledTask", body)
        self.assertRegex(body, r"\$trig -match 'Boot' -or \(\$loggedOn -and \$trig -match 'Logon'\)")

    def test_startup_and_run_items_start_in_the_owners_session(self):
        body = function_body(GUARD, "Start-Restored")
        self.assertIn("-LogonType Interactive -RunLevel Limited", body)
        self.assertIn("Unregister-ScheduledTask -TaskName 'jxn-vm-late-start'", body)
        self.assertIn("conhost.exe", body)                      # headless: Windows Terminal ignores SW_HIDE
        code = [l for l in GUARD.splitlines() if not l.lstrip().startswith("#")]
        self.assertFalse([l for l in code if "-WindowStyle Hidden" in l])

    def test_positive_control(self):
        self.assertEqual(function_body("function A {\n x\n}\nfunction B {\n y\n}\n", "B"), "function B {\n y\n}")


class GuardKnowsWhoseProfile(unittest.TestCase):
    def test_guard_reads_owner_json(self):
        self.assertIn("owner.json", GUARD)

    def test_installer_records_the_owner_profile(self):
        self.assertIn("[string]$ProfilePath = $env:USERPROFILE", INSTALL)
        self.assertIn("owner.json", INSTALL)


if __name__ == "__main__":
    unittest.main()

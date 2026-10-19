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


class GuardPolicyValuesRoundTrip(unittest.TestCase):
    """2026-10-11 22:10, a VM boot: WaaSMedicSvc (protected - the service manager refuses to disable it, and DoSvc too)
    had put wuauserv back, and the Microsoft Store pulled 20 app updates inside the VM ten minutes after boot - while
    the guard's log said "WU stopped" for all four services. Every policy value the guard sets in VM mode now lives in
    ONE table ($VmPolicies) that plan, apply and restore all walk, so a new one cannot be set without being restored."""

    def test_store_auto_download_is_a_vm_policy(self):
        self.assertRegex(GUARD, r"StoreAutoDownload\s*=\s*@\{[^}]*Policies\\Microsoft\\WindowsStore'[^}]*'AutoDownload'[^}]*vm\s*=\s*2")

    def test_no_auto_update_is_a_vm_policy(self):
        self.assertRegex(GUARD, r"NoAutoUpdate\s*=\s*@\{[^}]*WindowsUpdate\\AU'[^}]*'NoAutoUpdate'[^}]*vm\s*=\s*1")

    def test_plan_apply_restore_walk_the_table(self):
        for fn in ("Plan-Suppress", "Apply-Suppress", "Restore"):
            self.assertIn("$VmPolicies", function_body(GUARD, fn), fn)

    def test_no_policy_value_written_by_hand(self):
        # a New-/Set-/Remove-ItemProperty naming one of the table's values outside the table is the one-off this
        # replaced (the old guard wrote and restored NoAutoUpdate by hand)
        names = re.findall(r"name\s*=\s*'(\w+)'\s*;\s*vm\s*=", GUARD)
        self.assertIn("NoAutoUpdate", names)
        hand = [l.strip() for l in GUARD.splitlines()
                if re.search(r"(New|Set|Remove)-ItemProperty\b.*-Name\s+'?(%s)\b" % "|".join(names), l)]
        self.assertEqual(hand, [])

    def test_a_state_file_from_an_older_guard_gets_the_original_saved_first(self):
        body = function_body(GUARD, "Apply-Suppress")
        self.assertIn("Ensure-PolicyState $state", body)
        self.assertLess(body.index("Ensure-PolicyState $state"), body.index("Set-VmPolicy"))
        self.assertIn("ConvertTo-Json", function_body(GUARD, "Ensure-PolicyState"))   # persisted before any change

    def test_restore_reads_the_old_state_shape_too(self):
        self.assertIn("NoAutoUpdate_prev", function_body(GUARD, "Saved-Policy"))


class GuardLogsWhatActuallyHappened(unittest.TestCase):
    def test_no_set_service_with_silenced_errors(self):
        # `Set-Service ... -ErrorAction SilentlyContinue; Log "... stopped"` logged success for services Windows refuses
        silenced = [l.strip() for l in GUARD.splitlines() if "Set-Service" in l and "SilentlyContinue" in l]
        self.assertEqual(silenced, [])


class GuardNeverRecreatesARegistryKey(unittest.TestCase):
    """2026-10-15: the rig's Run entries (Steam, Discord, Spotify, Everything, HASS.Agent, ...) were DESTROYED. In the
    registry provider `New-Item -Path <existing key> -Force` deletes the key's values and subkeys and recreates it
    empty. The guard did that to its park key (`New-Item -Path $RunPark -Force`) on every VM boot, so the second VM
    boot in a row (10-09 12:47) wiped what the first (12:27) had parked; it also recreated the policy keys (losing
    their other values) and the LIVE Run key on the hardware restore. Every registry key is now created only when
    missing (Ensure-Key)."""

    def test_no_forced_registry_new_item(self):
        for name, src in (("guard.ps1", GUARD), ("install-guard.ps1", INSTALL)):
            bad = [l.strip() for l in src.splitlines()
                   if not l.strip().startswith("#")
                   and re.search(r"\bNew-Item\b", l) and re.search(r"-Force\b", l)
                   and not re.search(r"-ItemType\s+Directory", l, re.I) and "Test-Path" not in l]
            self.assertEqual(bad, [], name)

    def test_positive_control_old_line_is_caught(self):
        l = "  New-Item -Path $RunPark -Force | Out-Null"
        self.assertTrue(re.search(r"\bNew-Item\b", l) and re.search(r"-Force\b", l) and "Test-Path" not in l)

    def test_ensure_key_exists_and_is_used(self):
        self.assertIn("function Ensure-Key", GUARD)
        for fn in ("Move-RunAway", "Restore-RunKey", "Set-VmPolicy"):
            self.assertIn("Ensure-Key", function_body(GUARD, fn), fn)

    def test_harness_covers_parking_twice(self):
        harness = (GUEST / "test-guard-policies.ps1").read_text()
        self.assertIn("Move-RunAway", harness)
        self.assertIn("Restore-RunKey", harness)


class GuardMovedFilesTakeTheirFoldersPermissions(unittest.TestCase):
    """2026-10-17, the rig's first hardware boot since the guard's first VM boot (10-09): no Zebar, no Tailscale tray.
    A same-volume Move-Item is a rename and keeps the file's security descriptor, and Secure-Root rewrote
    C:\\ProgramData\\jxn-vm's SYSTEM+Administrators-only ACL at every guard start, which re-propagated onto the parked
    shortcuts; the restore put zebar.exe.lnk, Tailscale.lnk and Brother iPSMonitor.lnk back into Startup unreadable to the
    owner's unelevated Explorer, which skipped them silently. (wtq and the AHK shortcuts carry an explicit owner ACE.)
    Now Secure-Root writes only when the ACL is wrong, and Unpark-File grants the folder's file permissions while the
    shortcut is still in the park. SYSTEM never writes an ACL inside a Startup folder (user-writable: a planted hard link
    or symlink would aim the write elsewhere - the first fix's in-place repair did exactly that, found by review)."""

    MOVE = re.compile(r"\bMove-Item\b")
    ACL_WRITE = re.compile(r"\b(Set-Acl|SetAccessControl|icacls)\b", re.I)

    @staticmethod
    def code(src: str, allowed: tuple[str, ...]) -> list[str]:
        for fn in allowed:
            body = function_body(src, fn)
            if body:
                src = src.replace(body, "")
        return [l.strip() for l in src.splitlines() if not l.lstrip().startswith("#")]

    def test_no_move_item_outside_park_and_unpark(self):
        for name, src in (("guard.ps1", GUARD), ("install-guard.ps1", INSTALL)):
            self.assertEqual([l for l in self.code(src, ("Park-File", "Unpark-File")) if self.MOVE.search(l)], [], name)

    def test_no_acl_write_outside_secure_root_and_unpark(self):
        self.assertEqual([l for l in self.code(GUARD, ("Secure-Root", "Unpark-File")) if self.ACL_WRITE.search(l)], [])

    def test_positive_controls(self):
        old_restore = "  foreach($f in Get-ChildItem $park -File){ Move-Item $f.FullName $to -Force }\n"
        self.assertEqual(len([l for l in self.code(old_restore, ()) if self.MOVE.search(l)]), 1)
        first_fix = "function Repair-StartupAcl {\n  (Get-Item $f).SetAccessControl($acl)\n}\n"
        self.assertEqual(len([l for l in self.code(first_fix, ("Secure-Root", "Unpark-File")) if self.ACL_WRITE.search(l)]), 1)

    def test_no_in_place_repair_of_a_startup_folder(self):
        self.assertNotIn("Repair-StartupAcl", GUARD)
        self.assertRegex(GUARD, r"'hardware'\s*\{\s*Restore\s*\}")

    def test_unpark_grants_in_the_park_then_renames(self):
        body = function_body(GUARD, "Unpark-File")
        self.assertIn("ReparsePoint", body)
        self.assertIn("(Link-Count $from) -ne 1", body)
        self.assertIn("GetAccessControl('Access')", body)              # DACL only: the owner is never rewritten
        self.assertIn("Folder-FileRules $toDir", body)
        self.assertLess(body.index("SetAccessControl"), body.index("Move-Item"))
        self.assertIn("SetAccessControl($acl)", body)
        self.assertNotIn("$to).SetAccessControl", body)

    def test_folder_rules_map_generic_rights_and_skip_creator_sids(self):
        self.assertIn("ObjectInherit", function_body(GUARD, "Folder-FileRules"))
        self.assertIn("'S-1-3-0'", function_body(GUARD, "Folder-FileRules"))
        self.assertIn("0x10000000", function_body(GUARD, "File-Rights"))

    def test_secure_root_writes_only_when_the_acl_is_wrong(self):
        body = function_body(GUARD, "Secure-Root")
        self.assertIn("if($acl.Sddl -eq (Get-Acl -Path $path).Sddl){ return $false }", body)
        self.assertLess(body.index("return $false"), body.index("Set-Acl -Path $path -AclObject"))

    def test_secure_root_outcome_is_always_logged(self):
        # "no rewrite logged" must not also be what a crash looks like: a silent catch made the two identical
        self.assertNotRegex(GUARD, r"Secure-Root \$Root \} catch \{\s*\}")
        for msg in ("WARN Secure-Root", "ACL rewritten", "already locked (unchanged)"):
            self.assertIn(msg, GUARD)

    def test_park_and_restore_use_the_primitives(self):
        self.assertIn("Park-File", function_body(GUARD, "Move-StartupAway"))
        self.assertIn("Unpark-File", function_body(GUARD, "Restore-Parked"))

    def test_reparse_points_on_startup_folders_are_refused(self):
        # A Startup folder is under the owner's profile: the owner can junction it (or a parent) to redirect a SYSTEM
        # move/ACL write (LPE). Both the park source and the restore destination go through Test-SafeDir first.
        body = function_body(GUARD, "Test-SafeDir")
        self.assertIn("ReparsePoint", body)
        self.assertIn("$cur.Parent", body)                             # every component, up to the volume root
        self.assertIn("Test-SafeDir", function_body(GUARD, "Move-StartupAway"))
        self.assertIn("Test-SafeDir", function_body(GUARD, "Restore-Parked"))
        self.assertIn("ReparsePoint", function_body(GUARD, "Unpark-File"))   # the destination name itself

    def test_a_refused_restore_keeps_the_park(self):
        # Unpark-File returns $null on refusal and the park subdir is removed only after a real restore, so a refused
        # label is not silently wiped by the end-of-restore cleanup.
        body = function_body(GUARD, "Restore-Parked")
        self.assertIn("if($to){", body)
        self.assertNotRegex(body, r"Remove-Item -Path \$StartupPark -Recurse -Force -ErrorAction SilentlyContinue\s*\n\}")
        self.assertIn("-not (Get-ChildItem $StartupPark -Recurse -File", body)

    def test_harness_exercises_the_round_trip_and_a_planted_link(self):
        harness = (GUEST / "test-guard-policies.ps1").read_text()
        for name in ("Move-StartupAway", "Restore-Parked", "Lock-Dir $parkRoot", "ItemType HardLink", "targetBefore"):
            self.assertIn(name, harness)

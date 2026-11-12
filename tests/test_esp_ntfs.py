"""The private ESP builder (unprivileged: mkfs.fat + mtools on a sparse file) and the ntfs-3g output parsers."""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401
from winvm import config, esp, ntfs

HAVE_MTOOLS = not esp.which_missing()


def fake_real_esp(root: Path) -> None:
    """A miniature real ESP: Windows' tree plus GRUB's files, which must NOT reach the VM."""
    files = {
        "EFI/Microsoft/Boot/bootmgfw.efi": b"MZ windows boot manager",
        "EFI/Microsoft/Boot/BCD": b"regf bcd",
        "EFI/Microsoft/Boot/en-US/bootmgfw.efi.mui": b"mui",
        "EFI/Microsoft/Recovery/BCD": b"regf recovery bcd",
        "EFI/Boot/bootx64.efi": b"MZ grub fallback",
        "EFI/Garuda/grubx64.efi": b"MZ grub",
        "385dfe70ff5f495f8354262b1bd89641/6.18.2-arch2-1/initrd": b"initrd",
    }
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


@unittest.skipUnless(HAVE_MTOOLS, "mkfs.fat/mtools not installed")
class PrivateEsp(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        self.real = self.root / "real"
        fake_real_esp(self.real)
        self.img = self.root / "esp.img"
        self.built = esp.build(self.real, self.img, 9003008, "pw-for-tests")

    def tearDown(self):
        self.td.cleanup()

    def extracted(self) -> dict[str, bytes]:
        out = self.root / "out"
        out.mkdir()
        esp.extract(self.img, out)
        return {str(p.relative_to(out)).lower(): p.read_bytes() for p in out.rglob("*") if p.is_file()}

    def test_contents_exactly(self):
        got = self.extracted()
        self.assertEqual(set(got), {"efi/microsoft/boot/bootmgfw.efi", "efi/microsoft/boot/bcd",
                                    "efi/microsoft/boot/en-us/bootmgfw.efi.mui", "efi/microsoft/recovery/bcd",
                                    "efi/boot/bootx64.efi", "jxn-vm/marker", "jxn-vm/smb.cred"})

    def test_fallback_is_windows_boot_manager_not_grub(self):
        got = self.extracted()
        self.assertEqual(got["efi/boot/bootx64.efi"], b"MZ windows boot manager")

    def test_no_garuda_files(self):
        got = self.extracted()
        self.assertFalse([k for k in got if "garuda" in k or "initrd" in k or "grub" in k])

    def test_own_volume_id(self):  # never the real ESP's 772D-AEDF (fstab mounts /boot/efi by it)
        vid = esp.volume_id(self.img)
        self.assertEqual(vid, config.ESP_VOLUME_ID)
        self.assertNotEqual(vid, "772daedf")

    def test_credential_and_marker(self):
        got = self.extracted()
        self.assertEqual(got["jxn-vm/smb.cred"].decode(), esp.cred_text("pw-for-tests"))
        self.assertIn(b"jxn-windows-vm-marker-v1", got["jxn-vm/marker"])
        self.assertEqual(self.built.manifest[esp.CRED], "(secret)")  # never hashed into a log

    def test_image_is_private_and_sparse(self):
        st = os.stat(self.img)
        self.assertEqual(st.st_mode & 0o777, 0o600)
        self.assertEqual(st.st_size, 9003008 * 512)
        self.assertLess(st.st_blocks * 512, 64 << 20)

    def test_verify_catches_an_extra_file(self):  # positive control: verify() can fail
        extra = self.root / "evil.efi"
        extra.write_bytes(b"x")
        subprocess.run(["mcopy", "-i", str(self.img), str(extra), "::/EFI/evil.efi"], check=True,
                       env=dict(os.environ, MTOOLS_SKIP_CHECK="1"))
        with self.assertRaisesRegex(esp.EspError, "unexpected file"):
            esp.verify(self.img, self.real, "pw-for-tests")

    def test_verify_catches_stale_content(self):  # the real boot manager changed since the image was built
        (self.real / "EFI/Microsoft/Boot/bootmgfw.efi").write_bytes(b"MZ updated boot manager")
        with self.assertRaisesRegex(esp.EspError, "content differs|not a copy"):
            esp.verify(self.img, self.real, "pw-for-tests")

    def test_multiline_password_refused(self):
        with self.assertRaises(esp.EspError):
            esp.cred_text("a\nb")


SAMPLE_NTFSINFO = """Volume Information
\tName of device: /dev/disk/by-partuuid/c52df2c1-31af-49fd-b0b0-8758c46f948d
\tDevice state: 11
\tVolume Name:
\tVolume State: 91
\tVolume Flags: 0x0000
\tVolume Version: 3.1
\tSector Size: 512
\tCluster Size: 4096
"""


class FakeRun:
    def __init__(self, rc, out=b"", err=b""):
        self.rc, self.out, self.err = rc, out, err

    def __call__(self, argv):
        return subprocess.CompletedProcess(argv, self.rc, self.out, self.err)


class FakePopen:
    def __init__(self, data: bytes, rc: int, err: bytes):
        self.data, self.rc, self.err = data, rc, err

    def __call__(self, argv, stdout=None, stderr=None):
        outer = self

        class P:
            def __init__(self):
                self.stdout = io.BytesIO(outer.data)
                self.stderr = io.BytesIO(outer.err)
                self.returncode = None

            def poll(self):
                return None

            def kill(self):
                pass

            def wait(self):
                self.returncode = outer.rc
                return outer.rc
        return P()


class NtfsParsing(unittest.TestCase):
    def test_volume_info_real_sample(self):
        v = ntfs.parse_volume_info(SAMPLE_NTFSINFO)
        self.assertEqual((v.flags, v.version, v.sector_size), (0, "3.1", 512))
        self.assertEqual(v.flag_names(), [])

    def test_flag_names(self):
        self.assertEqual(ntfs.VolumeInfo(0x8001, "3.1", 512).flag_names(), ["dirty", "modified-by-chkdsk"])

    def test_unparseable_output_is_an_error(self):
        with self.assertRaises(ntfs.NtfsError):
            ntfs.parse_volume_info("something else entirely")

    def test_volume_info_tool_failure(self):
        with self.assertRaises(ntfs.NtfsError):
            ntfs.volume_info("/dev/x", run=FakeRun(1, err=b"Failed to open"))

    def test_hibernation_states(self):
        self.assertEqual(ntfs.hibernation_state(None), "absent")
        self.assertEqual(ntfs.hibernation_state(bytes(4096)), "clear")
        self.assertIn("HIBR", ntfs.hibernation_state(b"HIBR" + bytes(4092)))
        self.assertIn("wake", ntfs.hibernation_state(b"wake" + bytes(4092)))

    def test_file_head_absent_vs_error(self):
        self.assertIsNone(ntfs.file_head("/dev/x", "/hiberfil.sys",
                                         popen=FakePopen(b"", 1, b"ERROR: Couldn't open inode: No such file or directory")))
        # ntfs-3g 2022+ (Arch/EndeavourOS): a missing path exits non-zero with EMPTY stderr - still "absent".
        self.assertIsNone(ntfs.file_head("/dev/x", "/hiberfil.sys", popen=FakePopen(b"", 3, b"")))
        with self.assertRaises(ntfs.NtfsError):  # "cannot see" must never read as "not there"
            ntfs.file_head("/dev/x", "/hiberfil.sys", popen=FakePopen(b"", 1, b"Failed to mount: Permission denied"))
        self.assertEqual(ntfs.file_head("/dev/x", "/f", popen=FakePopen(bytes(5000), 0, b"")), bytes(4096))

    def test_listdir(self):
        self.assertEqual(ntfs.listdir("/dev/x", "/d", run=FakeRun(0, b".\n..\nSources\n")), ["Sources"])
        self.assertIsNone(ntfs.listdir("/dev/x", "/d", run=FakeRun(1, err=b"Couldn't find path")))
        # ntfs-3g 2022+ (Arch/EndeavourOS): `ntfsls /NoSuchDir` -> exit 3, EMPTY stderr. Must read as absent,
        # not as an error, or every absent-path pre-flight check (no-feature-update, ...) false-fails.
        self.assertIsNone(ntfs.listdir("/dev/x", "/d", run=FakeRun(3, err=b"")))
        with self.assertRaises(ntfs.NtfsError):  # a real failure DOES print to stderr - must still raise
            ntfs.listdir("/dev/x", "/d", run=FakeRun(1, err=b"Permission denied"))
        with self.assertRaises(ntfs.NtfsError):  # non-zero + stderr text that isn't a not-found message
            ntfs.listdir("/dev/x", "/d", run=FakeRun(3, err=b"Input/output error"))


if __name__ == "__main__":
    unittest.main()

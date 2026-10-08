"""The VM's PRIVATE EFI system partition, rebuilt from the real one at every start (traps T5, T7).

Contents, and nothing else:
    \\EFI\\Microsoft\\**          byte-identical copy of the real ESP's \\EFI\\Microsoft (Boot, Recovery, BCD, ...)
    \\EFI\\Boot\\bootx64.efi      a copy of \\EFI\\Microsoft\\Boot\\bootmgfw.efi - the firmware's fallback path.
                                 The REAL ESP's bootx64.efi is GRUB's; a fresh OVMF has no boot entries and falls
                                 back to this path, so it must be Windows Boot Manager here.
    \\jxn-vm\\marker             "jxn-windows-vm-marker-v1" - a second VM-mode signal for the guard
    \\jxn-vm\\smb.cred           the VM's credential for \\\\192.168.122.1\\Shared (S:). Exists ONLY in this image,
                                 so Windows can only ever read it while running as this VM (plan P1, D2).

The image is FAT32 with its OWN volume ID (config.ESP_VOLUME_ID), never the real 772D-AEDF: two filesystems
with one UUID would let udev point /dev/disk/by-uuid/772D-AEDF - by which fstab mounts /boot/efi - at the copy.

Built with mkfs.fat + mtools on a sparse file: no mount, no loop device, runs unprivileged in the tests. The
real ESP is only READ. After building, every file is read back out of the image and compared by sha256.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import config

MS_DIR = "EFI/Microsoft"
BOOTMGR = "EFI/Microsoft/Boot/bootmgfw.efi"
FALLBACK = "EFI/Boot/bootx64.efi"
MARKER = f"{config.ESP_SECRET_DIR}/marker"
CRED = f"{config.ESP_SECRET_DIR}/smb.cred"
MARKER_TEXT = config.SMBIOS_FAMILY + "\r\n"


class EspError(RuntimeError):
    pass


@dataclass(frozen=True)
class Built:
    path: Path
    manifest: dict[str, str]  # image path -> sha256 (the credential is listed as "(secret)")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cred_text(password: str) -> str:
    """The credential file the guard parses (CRLF, key=value)."""
    if not password or any(c in password for c in "\r\n"):
        raise EspError("SMB password is empty or multi-line")
    return (f"share=\\\\{config.HOST_IP}\\{config.SMB_SHARE}\r\n"
            f"user={config.SMB_USER}\r\n"
            f"password={password}\r\n")


def _run(argv, env=None):
    cp = subprocess.run(argv, capture_output=True, env=env)
    if cp.returncode != 0:
        raise EspError(f"{argv[0]} failed ({cp.returncode}): {cp.stderr.decode(errors='replace').strip()[:400]}")
    return cp


def build(real_esp: Path, out: Path, sectors: int, password: str, sector_size: int = 512) -> Built:
    """Build the private ESP image at `out` (atomically) from the real ESP mounted at `real_esp`."""
    src_ms = real_esp / MS_DIR
    if not (real_esp / BOOTMGR).is_file():
        raise EspError(f"{real_esp / BOOTMGR} not found")
    env = dict(os.environ, MTOOLS_SKIP_CHECK="1", MTOOLS_NO_VFAT="0", LC_ALL="C")
    tmp = out.with_name(out.name + ".new")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.ftruncate(fd, sectors * sector_size)
    finally:
        os.close(fd)
    try:
        _run(["mkfs.fat", "-F", "32", "-S", str(sector_size), "-i", config.ESP_VOLUME_ID, "-n", config.ESP_LABEL,
              str(tmp)], env)
        img = f"{tmp}"
        _run(["mmd", "-i", img, "::/EFI", "::/EFI/Boot", f"::/{config.ESP_SECRET_DIR}"], env)
        _run(["mcopy", "-s", "-p", "-m", "-Q", "-i", img, str(src_ms), "::/EFI/"], env)
        _run(["mcopy", "-p", "-m", "-Q", "-i", img, str(real_esp / BOOTMGR), f"::/{FALLBACK}"], env)
        with tempfile.TemporaryDirectory(prefix="winvm-esp-") as td:
            os.chmod(td, 0o700)
            m = Path(td) / "marker"
            m.write_text(MARKER_TEXT, newline="")
            c = Path(td) / "smb.cred"
            fdc = os.open(c, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fdc, "w", newline="") as f:
                f.write(cred_text(password))
            _run(["mcopy", "-Q", "-i", img, str(m), f"::/{MARKER}"], env)
            _run(["mcopy", "-Q", "-i", img, str(c), f"::/{CRED}"], env)
        manifest = verify(tmp, real_esp, password)
        os.replace(tmp, out)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return Built(out, manifest)


def extract(image: Path, dest: Path) -> None:
    env = dict(os.environ, MTOOLS_SKIP_CHECK="1", LC_ALL="C")
    _run(["mcopy", "-s", "-p", "-m", "-Q", "-n", "-i", str(image), "::/*", str(dest)], env)


def verify(image: Path, real_esp: Path, password: str) -> dict[str, str]:
    """Read the whole image back and prove it holds exactly what the docstring above promises."""
    with tempfile.TemporaryDirectory(prefix="winvm-espchk-") as td:
        os.chmod(td, 0o700)
        root = Path(td)
        extract(image, root)
        got = {str(p.relative_to(root)): p for p in root.rglob("*") if p.is_file()}
        want: dict[str, Path] = {}
        for p in (real_esp / MS_DIR).rglob("*"):
            if p.is_file():
                want[str(Path(MS_DIR) / p.relative_to(real_esp / MS_DIR))] = p
        problems = []
        lower_got = {k.lower(): k for k in got}
        manifest: dict[str, str] = {}
        for rel, src in sorted(want.items()):
            k = lower_got.get(rel.lower())
            if k is None:
                problems.append(f"missing {rel}")
                continue
            hs = sha256(src)
            if sha256(got[k]) != hs:
                problems.append(f"content differs: {rel}")
            manifest[rel] = hs
        fb = lower_got.get(FALLBACK.lower())
        if fb is None or sha256(got[fb]) != sha256(real_esp / BOOTMGR):
            problems.append(f"{FALLBACK} is not a copy of {BOOTMGR}")
        else:
            manifest[FALLBACK] = sha256(got[fb])
        mk = lower_got.get(MARKER.lower())
        if mk is None or got[mk].read_bytes() != MARKER_TEXT.encode():
            problems.append("marker missing or wrong")
        else:
            manifest[MARKER] = sha256(got[mk])
        ck = lower_got.get(CRED.lower())
        if ck is None or got[ck].read_bytes() != cred_text(password).encode():
            problems.append("credential missing or wrong")
        else:
            manifest[CRED] = "(secret)"
        expected = {k.lower() for k in want} | {FALLBACK.lower(), MARKER.lower(), CRED.lower()}
        for k in sorted(set(lower_got) - expected):
            problems.append(f"unexpected file {lower_got[k]}")
        if problems:
            raise EspError("private ESP verification failed: " + "; ".join(problems[:10]))
        return manifest


def volume_id(image: Path) -> str:
    """The FAT32 volume serial (boot sector offset 0x43), as 8 lowercase hex digits."""
    with open(image, "rb") as f:
        f.seek(0x43)
        return f.read(4)[::-1].hex()


def which_missing() -> list[str]:
    return [t for t in ("mkfs.fat", "mmd", "mcopy") if shutil.which(t) is None]

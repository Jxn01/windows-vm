"""Read-only NTFS facts about C: WITHOUT mounting it (goal rule: never mount p5 on Linux).

ntfs-3g's offline tools open the partition device O_RDONLY and parse NTFS themselves:
    ntfsinfo -m DEV        volume information ("Volume Flags: 0x0000")
    ntfscat DEV PATH       a file's bytes on stdout (we read only the first 4 KiB of hiberfil.sys)
    ntfsls -p DIR DEV      a directory listing

Every function takes a `run` callable so the parsing is unit-tested on recorded outputs; the real runner is
`subprocess`. A tool failure that is not a clean "no such file" is an ERROR, never "absent": a check that
could not look must not read as "nothing there" (KB 20-working-rules: "cannot see is not is not there").
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

# $Volume flags (ntfs-3g layout.h). Any set bit refuses a start; the name goes into the message.
VOLUME_FLAGS = {
    0x0001: "dirty",
    0x0002: "resize-logfile",
    0x0004: "upgrade-on-mount",
    0x0008: "mounted-on-nt4",
    0x0010: "delete-usn-underway",
    0x0020: "repair-object-id",
    0x4000: "chkdsk-underway",
    0x8000: "modified-by-chkdsk",
}

NOT_FOUND = re.compile(r"No such file or directory|Couldn't (find|open inode)", re.I)


class NtfsError(RuntimeError):
    """A tool could not answer; the caller must treat the question as unanswered (refuse)."""


@dataclass(frozen=True)
class VolumeInfo:
    flags: int
    version: str
    sector_size: int

    def flag_names(self) -> list[str]:
        names = [n for bit, n in VOLUME_FLAGS.items() if self.flags & bit]
        rest = self.flags & ~sum(VOLUME_FLAGS)
        if rest:
            names.append(f"unknown-{rest:#06x}")
        return names


def _default_run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, timeout=120)


def volume_info(dev: str, run=_default_run) -> VolumeInfo:
    cp = run(["ntfsinfo", "-m", dev])
    out = cp.stdout.decode(errors="replace")
    if cp.returncode != 0:
        raise NtfsError(f"ntfsinfo failed ({cp.returncode}): {cp.stderr.decode(errors='replace').strip()[:300]}")
    return parse_volume_info(out)


def parse_volume_info(text: str) -> VolumeInfo:
    m = re.search(r"^\s*Volume Flags:\s*(0x[0-9a-fA-F]+)\s*$", text, re.M)
    v = re.search(r"^\s*Volume Version:\s*(\S+)\s*$", text, re.M)
    s = re.search(r"^\s*Sector Size:\s*(\d+)\s*$", text, re.M)
    if not (m and v and s):
        raise NtfsError("ntfsinfo output not understood (no Volume Flags / Version / Sector Size)")
    return VolumeInfo(int(m.group(1), 16), v.group(1), int(s.group(1)))


def file_head(dev: str, path: str, size: int = 4096, popen=subprocess.Popen) -> bytes | None:
    """First `size` bytes of a file, or None if the file does not exist. Reads only what it needs."""
    p = popen(["ntfscat", dev, path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        data = p.stdout.read(size)
    finally:
        if p.poll() is None:
            p.kill()
        p.wait()
        err = p.stderr.read().decode(errors="replace")
        p.stdout.close()
        p.stderr.close()
    if len(data) == size:
        return data
    if p.returncode != 0 and NOT_FOUND.search(err):
        return None
    if p.returncode == 0:
        return data  # a file shorter than `size`
    raise NtfsError(f"ntfscat {path} failed ({p.returncode}): {err.strip()[:300]}")


def listdir(dev: str, path: str, run=_default_run) -> list[str] | None:
    """Names in a directory (without . and ..), or None if the directory does not exist."""
    cp = run(["ntfsls", "-p", path, dev])
    err = cp.stderr.decode(errors="replace")
    if cp.returncode != 0:
        if NOT_FOUND.search(err):
            return None
        raise NtfsError(f"ntfsls {path} failed ({cp.returncode}): {err.strip()[:300]}")
    return [n for n in cp.stdout.decode(errors="replace").splitlines() if n not in (".", "..", "")]


def hibernation_state(head: bytes | None) -> str:
    """Classify hiberfil.sys's first page: 'absent', 'clear' (all zero) or the signature found.

    Windows writes 'hibr'/'HIBR' (hibernated), 'wake'/'WAKE' (resumed, not yet cleared), 'rstr'/'RSTR' or
    'link' into the first bytes. Anything other than all-zero means "do not boot this elsewhere" (trap T2).
    """
    if head is None:
        return "absent"
    if not any(head):
        return "clear"
    sig = head[:4]
    try:
        text = sig.decode("ascii")
    except UnicodeDecodeError:
        text = sig.hex()
    return f"signature {text!r}"

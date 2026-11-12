"""Every file install.sh installs must also be compared by `install.sh --check`.

A step that installs files the check block never looks at would let `--check` report nothing for a missing launcher.
This test fails when an `install` destination has no matching `chk`.
"""

from __future__ import annotations

import re
import shlex
import unittest
from pathlib import Path

INSTALL_SH = Path(__file__).resolve().parent.parent / "install.sh"


def _logical_lines(text: str) -> list[str]:
    return text.replace("\\\n", " ").splitlines()


def installed(text: str) -> set[str]:
    """Destinations of every file-installing `install` (not `install -d`), quotes stripped."""
    out = set()
    for line in _logical_lines(text):
        m = re.search(r"(?:^|;|do)\s*install\s+(?!-d\b)(.*?)(?:;|$)", line)
        if m:
            out.add(m.group(1).split()[-1].strip('"'))
    return out


def checked(text: str) -> set[str]:
    """The LAST argument of every `chk` call (quote-aware: the first one may be a `<(sed '…')` substitution)."""
    out = set()
    for line in _logical_lines(text):
        for m in re.finditer(r"\bchk\s+", line):
            lex = shlex.shlex(line[m.end():], posix=True, punctuation_chars=";")
            lex.whitespace_split = True
            args = []
            for tok in lex:
                if tok == ";":
                    break
                args.append(tok)
            if len(args) >= 2:
                out.add(args[-1])
    return out


def unchecked(text: str) -> set[str]:
    inst, chk = installed(text), checked(text)
    # the lib loop installs into a directory (`"$LIB/winvm/"`); its check names each file in the same directory
    return {d for d in inst if d not in chk and not (d.endswith("/") and any(c.startswith(d) for c in chk))}


class InstallCheckCoversEveryInstall(unittest.TestCase):
    def test_positive_control(self):
        sample = 'chk "$REPO/a" /usr/local/bin/a\ninstall -m 0755 "$REPO/a" /usr/local/bin/a\n' \
                 'install -m 0755 "$REPO/b" /usr/local/bin/b\ninstall -d -m 0755 /x\n'
        self.assertEqual(unchecked(sample), {"/usr/local/bin/b"})

    def test_every_install_is_checked(self):
        text = INSTALL_SH.read_text()
        self.assertGreaterEqual(len(installed(text)), 12)        # the parser really saw the installer
        self.assertEqual(unchecked(text), set(), "add a `chk` line for these to the --check block")


if __name__ == "__main__":
    unittest.main()

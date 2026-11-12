"""The repository is public: it carries no development notes.

No dated decisions or incidents, no attributions to whoever commissioned a change, no references to private notes,
plans or knowledge bases, no alarm-emoji diaries — in code, comments, docs or tests. The reasoning a reader needs stays
in one plain comment; the history lives in git. Each pattern has a positive control below.
"""
from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    "alarm emoji": re.compile("\U0001F6A8"),
    "a dated note": re.compile(r"(?<![\w.-])20\d\d-(?:0[1-9]|1[0-2])-[0-3]\d(?![\dT:])"),
    "an attribution": re.compile(r"\(owner[,)]|\bowner's (?:list|request|decision|call|rule|rig|machine)\b"
                                 r"|\bthe owner (?:asked|said|wants|wanted|decided|chose|confirmed|watched)\b"),
    "a private reference": re.compile(r"(?<!\d )(?<!\d)\bKB\b(?! ?/s)|claude-kb|superpowers|EXECUTION-LOG|\bspec §|§\d"),
}
#: path -> names of PATTERNS allowed there, for real data (keep this short and say why)
EXEMPT: dict[str, set[str]] = {}
SELF = Path(__file__).relative_to(ROOT).as_posix()


def tracked() -> list[str]:
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "ls-files"], capture_output=True, encoding="utf-8")
    except OSError:                                         # no git (e.g. the suite under Wine)
        raise unittest.SkipTest("git is not available") from None
    if out.returncode != 0:
        raise unittest.SkipTest("not a git checkout")
    return [p for p in out.stdout.splitlines() if p and p != SELF]


def hits(path: str, text: str) -> list[str]:
    found = []
    for name, rx in PATTERNS.items():
        if name in EXEMPT.get(path, set()):
            continue
        for m in rx.finditer(text):
            found.append(f"{path}:{text.count(chr(10), 0, m.start()) + 1}: {name}: {m.group(0)!r}")
    return found


class NoDevelopmentNotes(unittest.TestCase):
    def test_no_tracked_file_carries_development_notes(self) -> None:
        bad = []
        for path in tracked():
            p = ROOT / path
            if not p.is_file():
                continue
            data = p.read_bytes()
            if b"\0" in data[:4096]:
                continue                                    # binary
            bad += hits(path, data.decode("utf-8", errors="ignore"))
        self.assertEqual(bad, [], "\n" + "\n".join(bad))

    def test_positive_controls(self) -> None:
        samples = {
            "alarm emoji": "# \U0001F6A8 never do this",
            "a dated note": "# found 2026-10-11 on the box",
            "an attribution": "# chosen by the owner's decision",
            "a private reference": "# see KB 14-kiosk.md",
        }
        for name, sample in samples.items():
            with self.subTest(pattern=name):
                self.assertTrue(PATTERNS[name].search(sample))
        self.assertFalse(PATTERNS["a dated note"].search('started_at = "2026-10-11T12:00:00+00:00"'))   # data, not a note
        self.assertFalse(PATTERNS["a private reference"].search("a 64 KB receive buffer"))               # a size
        self.assertFalse(PATTERNS["an attribution"].search("recorded in (owner.json)"))                  # a file name
        self.assertTrue(PATTERNS["an attribution"].search("# a soft chime (owner, 2026-10-11)"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

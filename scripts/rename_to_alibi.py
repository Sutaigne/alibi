"""One-shot rename: pc-check → alibi. Run from repo root.

Bumps versions: scanner v3.8 → v4.0, console-rig v1.2 → v4.0 (sync).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Ordered most-specific to least-specific.
REPLACEMENTS: list[tuple[str, str]] = [
    # Output filenames the PS / Python drivers emit
    ("PCForensicCheck", "AlibiReport"),
    ("ConsoleRigAudit", "AlibiRigReport"),
    # Tool banner / version copy
    ("PC Forensic Check v3.8", "Alibi v4.0"),
    ("PC Forensic Check 3.8", "Alibi 4.0"),
    ("PC FORENSIC CHECK v3.8", "ALIBI v4.0"),
    ("PC Forensic Check", "Alibi"),
    ("PC FORENSIC CHECK", "ALIBI"),
    ("Console Rig Audit v1.2", "Alibi v4.0 (console-rig mode)"),
    ("CONSOLE RIG AUDIT v1.2", "ALIBI v4.0 (CONSOLE-RIG MODE)"),
    ("Console Rig Audit", "Alibi (console-rig mode)"),
    ("CONSOLE RIG AUDIT", "ALIBI (CONSOLE-RIG MODE)"),
    # Internal version markers
    ("SCANNER_VERSION = \"v3.8\"", 'SCANNER_VERSION = "v4.0"'),
    ("CONSOLE_RIG_VERSION = \"v1.2\"", 'CONSOLE_RIG_VERSION = "v4.0"'),
    ("\"3.8.0\"", "\"4.0.0\""),
    ("v3.8.0", "v4.0.0"),
    ("v3.8 / console-rig v1.2", "v4.0"),
    ("pc-check 3.8", "alibi 4.0"),
    ("pc-check 3.8 (python)", "alibi 4.0 (python)"),
    # Specific named files / temp paths
    ("pc-check-safety-card", "alibi-safety-card"),
    ("pc-check-pc.summary", "alibi-pc.summary"),
    ("pc-check-console.summary", "alibi-console.summary"),
    ("pc-check-loldb", "alibi-loldb"),
    # Console-script names
    ("pc-check-console-rig", "alibi-rig"),
    # Python module
    ("pc_check", "alibi"),
    # General brand (must come AFTER all hyphenated subtypes)
    ("pc-check", "alibi"),
    ("PC Check", "Alibi"),
    ("PC-Check", "Alibi"),
]

# Don't touch these — historical / dev-internal / binary.
EXCLUDE_DIRS = {
    ".git", "__pycache__", ".pytest_cache", "node_modules",
    "design-handoff-2026-05",   # vendor handoff, preserve as-shipped
    "archive",                  # historical zips
    "_extracted_style.css", "_extracted_script.js", "_extracted_body.html",
}
EXCLUDE_FILE_SUFFIXES = {".zip", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf"}
EXCLUDE_FILES = {
    "rename_to_alibi.py",        # this script itself
    "memory-suggested.md",        # dev-internal note, preserve
    "handoff.md",                 # dev history, will get a separate note appended
}

# Files that are pure data (HTML reference designs) — don't rewrite.
EXCLUDE_PATH_FRAGMENTS = ["design-handoff-2026-05"]


def should_skip(path: Path) -> bool:
    for part in path.parts:
        if part in EXCLUDE_DIRS:
            return True
    if path.name in EXCLUDE_FILES:
        return True
    if path.suffix.lower() in EXCLUDE_FILE_SUFFIXES:
        return True
    for frag in EXCLUDE_PATH_FRAGMENTS:
        if frag in str(path):
            return True
    return False


def transform(text: str) -> str:
    for old, new in REPLACEMENTS:
        text = text.replace(old, new)
    return text


def main(root: Path) -> int:
    changed = 0
    scanned = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if should_skip(path.relative_to(root)):
            continue
        try:
            original = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        scanned += 1
        replaced = transform(original)
        if replaced != original:
            path.write_text(replaced, encoding="utf-8")
            changed += 1
            print(f"  edited {path.relative_to(root)}")
    print(f"\nScanned {scanned} text files; edited {changed}.")
    return 0


if __name__ == "__main__":
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    sys.exit(main(root))

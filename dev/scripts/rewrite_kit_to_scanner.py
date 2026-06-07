"""One-shot path-rewrite kit → scanner across docs + copy files."""
from __future__ import annotations
import pathlib

FILES = [
    "README.md", "SECURITY.md", "docs/for-reviewers.md", "python/README.md",
    "START HERE.txt",
    "scanner/alibi-safety-card.html", "scanner/one-page-guide.html",
    "scanner/README.txt",
    ".github/workflows/ci.yml",
]

REPLACEMENTS = [
    ("kit\\", "scanner\\"),
    ("kit/", "scanner/"),
    ('"kit"', '"scanner"'),
    ("`kit`", "`scanner`"),
    ("[`kit/`]", "[`scanner/`]"),
    ("(./kit)", "(./scanner)"),
    ("ready-to-flash", "scanner"),  # any lingering refs
]

edits = 0
for f in FILES:
    p = pathlib.Path(f)
    if not p.exists():
        continue
    txt = p.read_text(encoding="utf-8")
    orig = txt
    for old, new in REPLACEMENTS:
        txt = txt.replace(old, new)
    if txt != orig:
        p.write_text(txt, encoding="utf-8")
        edits += 1
        print(f"  edited {f}")
print(f"total: {edits} files")

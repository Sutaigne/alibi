"""Shared utility helpers: keyword matching, path-risk classification,
score computation, admin check, FileTime conversion.

Mirrors the utility functions in forensic-common.ps1:
  Add-Finding, Test-IsAdmin, Match-Keyword, Match-Allowlist,
  Classify-PathRisk, Score-Item, Convert-FileTimeBytes, Score-And-Add.
"""
from __future__ import annotations

import ctypes
import os
import re
import struct
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from alibi.findings import Finding, SEV_HIGH, SEV_MEDIUM
from alibi.keywords import KNOWN_GOOD


# ---------------------------------------------------------------------------
# Engine state container — holds the composite keyword arrays and the
# findings list. Constructed by each driver before scans run.
# ---------------------------------------------------------------------------
class Engine:
    """Mutable scan-time state. Each driver creates one and passes it to
    every scan function. Replaces PowerShell's parent-scope variable lookup.
    """

    def __init__(
        self,
        *,
        keywords_high_cheats: list[str],
        keywords_high_input: list[str],
        keywords_medium: list[str],
        keywords_script_high: list[str],
        keywords_mouse_macro: list[str],
        lol_db: dict[str, Any] | None = None,
    ) -> None:
        self.findings: list[Finding] = []
        self.keywords_high_cheats = [k.lower() for k in keywords_high_cheats]
        self.keywords_high_input = [k.lower() for k in keywords_high_input]
        self.keywords_medium = [k.lower() for k in keywords_medium]
        self.keywords_script_high = [k.lower() for k in keywords_script_high]
        self.keywords_mouse_macro = [k.lower() for k in keywords_mouse_macro]
        self.lol_db = lol_db

    def add(
        self,
        category: str,
        source: str,
        detail: str,
        severity: str = "INFO",
        kind: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.findings.append(
            Finding(
                category=category,
                source=source,
                detail=detail,
                severity=severity,
                kind=kind,
                metadata=metadata or {},
            )
        )


# ---------------------------------------------------------------------------
# Keyword matching (case-insensitive substring; preserves PowerShell semantics
# of [regex]::Escape applied to a lowercased pattern then -match against a
# lowercased target).
# ---------------------------------------------------------------------------
def match_keyword(
    text: str, patterns: Iterable[str], *, bounded: bool = False
) -> str | None:
    """Case-insensitive keyword match.

    bounded=False (default) — substring match. Right for long specific brand
    names ('engineowning', 'phantomoverlay') where vendors append/prefix
    garbage to evade detection.

    bounded=True — wrap each pattern with non-letter/digit lookaround so
    short generic keywords ('esp', 'bypass', 'loader', 'hoic', 'hping')
    don't false-match inside larger words ('hoic' inside CHOICE.EXE,
    'hping' inside PATHPING.EXE, 'esp' inside espresso-recipes). Callers
    opt in per-context.
    """
    if not text or not text.strip():
        return None
    lc = text.lower()
    if not bounded:
        for p in patterns:
            if not p:
                continue
            if p.lower() in lc:
                return p
        return None
    for p in patterns:
        if not p:
            continue
        rx = r"(?<![a-z0-9])" + re.escape(p.lower()) + r"(?![a-z0-9])"
        if re.search(rx, lc):
            return p
    return None


def match_allowlist(text: str) -> bool:
    if not text or not text.strip():
        return False
    lc = text.lower()
    return any(g in lc for g in KNOWN_GOOD)


# ---------------------------------------------------------------------------
# Path-risk classification
# ---------------------------------------------------------------------------
_EXE_PREFIX_RE = re.compile(r'^([^"]+\.exe)', re.IGNORECASE)


def classify_path_risk(path: str | None) -> str:
    if not path or not path.strip():
        return "unknown"
    p = path.lower().strip().strip('"').strip()
    m = _EXE_PREFIX_RE.match(p)
    if m:
        p = m.group(1)
    if re.match(r"^c:\\windows\\system32", p):
        return "standard"
    if re.match(r"^c:\\windows\\syswow64", p):
        return "standard"
    if re.match(r"^c:\\windows\\systemapps", p):
        return "standard"
    if re.match(r"^c:\\windows\\microsoft\.net", p):
        return "standard"
    if re.match(r"^c:\\windows\\servicing", p):
        return "standard"
    if re.match(r"^c:\\windows\\", p):
        return "standard"
    if re.match(r"^c:\\program files \(x86\)\\", p):
        return "typical"
    if re.match(r"^c:\\program files\\", p):
        return "typical"
    if re.match(r"^c:\\programdata\\", p):
        return "user-writable"
    if "\\appdata\\local\\" in p:
        return "user-writable"
    if "\\appdata\\roaming\\" in p:
        return "user-writable"
    if "\\appdata\\locallow\\" in p:
        return "user-writable"
    if "\\temp\\" in p:
        return "user-writable"
    if re.match(r"^c:\\users\\", p):
        return "user-writable"
    return "unknown"


# ---------------------------------------------------------------------------
# Score-Item and Score-And-Add — both depend on engine-time composite arrays.
# ---------------------------------------------------------------------------
def score_item(engine: Engine, name: str, path: str, extra: str = "") -> dict[str, str]:
    combined = f"{name} {path} {extra}"
    hit = match_keyword(combined, engine.keywords_high_cheats)
    if hit:
        return {"score": "HIGH", "kind": "cheat", "pattern": hit,
                "reason": f"matches '{hit}' (cheat keyword)"}
    hit = match_keyword(combined, engine.keywords_high_input)
    if hit:
        return {"score": "HIGH", "kind": "input", "pattern": hit,
                "reason": f"matches '{hit}' (input device)"}
    hit = match_keyword(combined, engine.keywords_medium)
    if hit:
        return {"score": "MEDIUM", "kind": "dual-use", "pattern": hit,
                "reason": f"matches '{hit}' (dual-use tool)"}
    bucket = classify_path_risk(path)
    if bucket == "user-writable":
        if match_allowlist(f"{path} {name}"):
            return {"score": "CLEAN", "kind": "other", "pattern": "",
                    "reason": "user-writable but known-good vendor"}
        return {"score": "MEDIUM", "kind": "other", "pattern": "",
                "reason": "user-writable location, no allowlist match"}
    if bucket == "unknown":
        return {"score": "LOW", "kind": "other", "pattern": "",
                "reason": "image path not recorded"}
    if bucket == "typical":
        return {"score": "LOW", "kind": "other", "pattern": "",
                "reason": "runs from Program Files"}
    return {"score": "CLEAN", "kind": "other", "pattern": "",
            "reason": "standard system location"}


def score_and_add(
    engine: Engine,
    category: str,
    source: str,
    text: str,
    detail_prefix: str = "",
    metadata: dict[str, Any] | None = None,
) -> None:
    metadata = dict(metadata or {})
    hit = match_keyword(text, engine.keywords_high_cheats)
    if hit:
        metadata["Pattern"] = hit
        engine.add(category, source, f"{detail_prefix}[{hit}] {text}", SEV_HIGH, "cheat", metadata)
        return
    hit = match_keyword(text, engine.keywords_high_input)
    if hit:
        metadata["Pattern"] = hit
        engine.add(category, source, f"{detail_prefix}[{hit}] {text}", SEV_HIGH, "input", metadata)
        return
    hit = match_keyword(text, engine.keywords_medium)
    if hit:
        metadata["Pattern"] = hit
        engine.add(category, source, f"{detail_prefix}[{hit}] {text}", SEV_MEDIUM, "dual-use", metadata)
        return


# ---------------------------------------------------------------------------
# Admin check + Windows FileTime conversion
# ---------------------------------------------------------------------------
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


# Windows FileTime epoch: 1601-01-01 UTC, 100-ns ticks.
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def convert_filetime_bytes(data: bytes | bytearray | None, offset: int = 0) -> datetime | None:
    if not data or len(data) < offset + 8:
        return None
    try:
        ft = struct.unpack_from("<q", bytes(data), offset)[0]
        if ft <= 0:
            return None
        return _FILETIME_EPOCH + timedelta(microseconds=ft // 10)
    except (struct.error, OverflowError):
        return None


def filetime_to_dt(ft: int) -> datetime | None:
    if ft <= 0:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=ft // 10)
    except OverflowError:
        return None


def iso(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S") if dt else "unknown"


# ---------------------------------------------------------------------------
# Path / output helpers
# ---------------------------------------------------------------------------
def resolve_desktop() -> str:
    """Mirror the PS Environment.GetFolderPath('Desktop') + OneDrive fallback.

    Returns the path of the user's Desktop. Falls back to OneDrive Desktop
    redirects and finally to the user profile root.
    """
    candidates: list[str] = []
    onedrive = os.environ.get("OneDrive")
    onedrive_consumer = os.environ.get("OneDriveConsumer")
    onedrive_commercial = os.environ.get("OneDriveCommercial")
    user_profile = os.environ.get("USERPROFILE", os.path.expanduser("~"))

    # The shell32 SHGetKnownFolderPath is the right Windows answer, but the
    # plain env var + a few well-known fallbacks cover the same cases the PS
    # kit covers and stay stdlib-only.
    primary = os.path.join(user_profile, "Desktop")
    if os.path.isdir(primary):
        candidates.append(primary)
    for od in (onedrive, onedrive_consumer, onedrive_commercial):
        if od:
            p = os.path.join(od, "Desktop")
            if os.path.isdir(p):
                candidates.append(p)
    if os.path.isdir(user_profile):
        candidates.append(user_profile)
    if candidates:
        return candidates[0]
    os.makedirs(user_profile, exist_ok=True)
    return user_profile


def safe_listdir(path: str) -> list[str]:
    try:
        return os.listdir(path)
    except OSError:
        return []


def walk_files(root: str, *, recursive: bool = True) -> Iterable[str]:
    if not os.path.isdir(root):
        return
    if recursive:
        for dirpath, _dirnames, filenames in os.walk(root, onerror=lambda _e: None):
            for name in filenames:
                yield os.path.join(dirpath, name)
    else:
        for name in safe_listdir(root):
            full = os.path.join(root, name)
            if os.path.isfile(full):
                yield full

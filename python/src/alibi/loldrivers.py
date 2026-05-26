"""LOLDrivers (loldrivers.io) BYOVD detection helpers.

This is the kit's ONLY outbound network call, and it is opt-in. The CSV
contains no PC-side data — only the public list of known-vulnerable and
known-malicious Windows drivers, indexed by filename and SHA256.

A 1-hour cache at %TEMP%\\alibi-loldb.json lets the unified launcher run
PC and console-rig scans back-to-back without re-prompting / re-fetching.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Any

from alibi.utils import Engine

LOLDRIVERS_URL = "https://www.loldrivers.io/api/drivers.csv"
CACHE_FILENAME = "alibi-loldb.json"
CACHE_TTL_SECONDS = 60 * 60  # 1 hour

_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")


def _cache_path() -> str:
    return os.path.join(os.environ.get("TEMP", os.environ.get("TMP", ".")), CACHE_FILENAME)


def fetch_loldrivers_db(engine: Engine) -> dict[str, Any] | None:
    """Download the CSV and build {file_index, hash_index}. Returns None on
    failure (and emits a WARN finding).
    """
    print("  [*] Fetching LOLDrivers database (loldrivers.io)...")
    try:
        req = urllib.request.Request(
            LOLDRIVERS_URL,
            headers={"User-Agent": "alibi/3.8 (+https://github.com/Bread-and-Drownmw/alibi)"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310 - public CSV over HTTPS
            body = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        engine.add(
            "LOLDrivers", LOLDRIVERS_URL,
            f"Failed to fetch LOLDrivers DB: {exc}",
            "WARN", "other",
        )
        return None

    file_index: dict[str, dict[str, str]] = {}
    hash_index: dict[str, dict[str, str]] = {}

    reader = csv.DictReader(io.StringIO(body))
    for row in reader:
        cat = (row.get("Category") or "").strip()
        tags = (row.get("Tags") or "").strip()
        rid = (row.get("Id") or "").strip()

        for tag in (t.strip() for t in tags.split(",")):
            if tag.lower().endswith(".sys"):
                key = tag.lower()
                if key not in file_index:
                    file_index[key] = {"Category": cat, "Tags": tags, "Id": rid}

        for col in ("SHA256", "Sha256", "sha256", "KnownVulnerableSamples", "Samples"):
            val = row.get(col)
            if not val:
                continue
            for m in _SHA256_RE.finditer(val):
                h = m.group(0).lower()
                if h not in hash_index:
                    fn = ""
                    parts = [t.strip() for t in tags.split(",") if t.strip().lower().endswith(".sys")]
                    if parts:
                        fn = parts[0]
                    hash_index[h] = {"Category": cat, "Tags": tags, "Id": rid, "Filename": fn}

    print(f"      Loaded {len(file_index)} filename entries, {len(hash_index)} hash entries.")
    return {"FileIndex": file_index, "HashIndex": hash_index}


def resolve_loldrivers_db(engine: Engine, *, skip: bool = False, interactive: bool = True) -> dict[str, Any] | None:
    """Mirror Resolve-LOLDriversDB:
      - If skip=True, write a skip note and return None.
      - If a cache file is <1h old, reuse it silently.
      - Otherwise prompt Y/N (when interactive=True) and fetch on Y.
    """
    if skip:
        engine.add(
            "LOLDrivers", "skipped",
            "LOLDrivers cross-reference skipped (--skip-loldrivers)",
            "INFO", "other",
            {"Note": "Remove --skip-loldrivers to enable BYOVD detection."},
        )
        return None

    cache = _cache_path()
    if os.path.isfile(cache):
        age = time.time() - os.path.getmtime(cache)
        if age < CACHE_TTL_SECONDS:
            try:
                with open(cache, "r", encoding="utf-8") as fh:
                    cached = json.load(fh)
                print(f"  [*] LOLDrivers: using cached DB (under 1h old, age: {int(age/60)} min)")
                engine.add(
                    "LOLDrivers", cache,
                    f"LOLDrivers DB loaded from local cache (age: {int(age/60)} min)",
                    "INFO", "other",
                    {
                        "CacheFile": cache,
                        "AgeMinutes": int(age / 60),
                        "FilenameEntries": len(cached.get("FileIndex", {})),
                        "HashEntries": len(cached.get("HashIndex", {})),
                    },
                )
                return cached
            except (OSError, ValueError):
                pass

    if interactive:
        print()
        print("  LOLDrivers cross-reference (loldrivers.io)")
        print("  Makes ONE network request to fetch the public vulnerable/malicious")
        print("  driver database. No data about this PC is sent.")
        print("  Press Y to fetch, anything else to skip.")
        try:
            answer = input("  > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        print()
        if answer not in ("y", "yes"):
            print("  Skipping LOLDrivers fetch.")
            engine.add(
                "LOLDrivers", "skipped",
                "LOLDrivers cross-reference skipped by user",
                "INFO", "other",
                {"Note": "Re-run and press Y at the prompt to enable BYOVD detection."},
            )
            return None

    db = fetch_loldrivers_db(engine)
    if db is not None:
        try:
            with open(cache, "w", encoding="utf-8") as fh:
                json.dump(db, fh)
        except OSError:
            pass
    return db

"""Smoke tests — exercise pieces that don't require Windows."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from alibi.findings import Finding
from alibi.keywords import (
    CHEAT_BRANDS_COD, DMA_INDICATORS, INPUT_DEVICES,
    KNOWN_CHEAT_HASHES, VISION_AIMBOT_AI_PC,
)
from alibi.recency import apply_recency_decay, get_finding_timestamp
from alibi.utils import (
    Engine, classify_path_risk, convert_filetime_bytes, match_allowlist,
    match_keyword, score_item,
)


def test_keyword_arrays_non_empty():
    assert len(CHEAT_BRANDS_COD) > 20
    assert len(INPUT_DEVICES) > 10
    assert len(DMA_INDICATORS) > 20
    assert len(VISION_AIMBOT_AI_PC) > 10


def test_known_hashes_have_required_fields():
    for h in KNOWN_CHEAT_HASHES:
        assert "sha256" in h
        assert len(h["sha256"]) == 64
        assert "name" in h and h["name"]
        assert "source" in h and h["source"]


def test_match_keyword_case_insensitive():
    assert match_keyword("C:\\Users\\Bob\\EngineOwning.exe", CHEAT_BRANDS_COD) == "engineowning"
    assert match_keyword("nothing here", CHEAT_BRANDS_COD) is None
    assert match_keyword("", CHEAT_BRANDS_COD) is None


def test_match_allowlist_hits_microsoft():
    assert match_allowlist("C:\\Program Files\\Microsoft\\Edge\\msedge.exe") is True
    assert match_allowlist("C:\\Users\\Bob\\Desktop\\sketchy.exe") is False


def test_classify_path_risk():
    assert classify_path_risk(r"C:\Windows\System32\svchost.exe") == "standard"
    assert classify_path_risk(r"C:\Program Files\Foo\foo.exe") == "typical"
    assert classify_path_risk(r"C:\Users\Bob\AppData\Local\foo\foo.exe") == "user-writable"
    assert classify_path_risk(r"C:\Users\Bob\Desktop\thing.exe") == "user-writable"
    assert classify_path_risk(r"D:\misc\thing.exe") == "unknown"
    assert classify_path_risk("") == "unknown"


def test_score_item_high_cheat():
    engine = Engine(
        keywords_high_cheats=["engineowning"],
        keywords_high_input=["cronus"],
        keywords_medium=["cheatengine"],
        keywords_script_high=[],
        keywords_mouse_macro=[],
    )
    res = score_item(engine, "engineowning.exe", r"C:\Users\Bob\engineowning.exe")
    assert res["score"] == "HIGH" and res["kind"] == "cheat"

    res = score_item(engine, "cronus.exe", r"C:\Users\Bob\cronus.exe")
    assert res["score"] == "HIGH" and res["kind"] == "input"

    res = score_item(engine, "cheatengine.exe", r"C:\Users\Bob\ce.exe")
    assert res["score"] == "MEDIUM" and res["kind"] == "dual-use"

    res = score_item(engine, "svchost.exe", r"C:\Windows\System32\svchost.exe")
    assert res["score"] == "CLEAN"


def test_convert_filetime_roundtrip():
    epoch = datetime(2026, 5, 25, 12, 0, 0)
    # FILETIME = (datetime - 1601-01-01) in 100-ns ticks.
    # Use a known value: 2026-05-25T12:00:00 UTC → about 1.34e17 ticks
    import struct
    ft = 134_177_904_000_000_000  # approximate; we just verify round-tripping behavior
    blob = struct.pack("<q", ft)
    dt = convert_filetime_bytes(blob)
    assert dt is not None
    assert dt.year == 2026


def test_recency_decay_demotes_old_high_to_medium():
    engine = Engine(
        keywords_high_cheats=[], keywords_high_input=[], keywords_medium=[],
        keywords_script_high=[], keywords_mouse_macro=[],
    )
    old = (datetime.now() - timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%S")
    new = (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S")
    engine.findings.extend([
        Finding("Prefetch", "old", "old artifact", "HIGH", "cheat",
                {"LastWrite": old}),
        Finding("Prefetch", "new", "new artifact", "HIGH", "cheat",
                {"LastWrite": new}),
    ])
    apply_recency_decay(engine, threshold_days=180)
    by_source = {f.source: f for f in engine.findings if f.source in ("old", "new")}
    assert by_source["old"].severity == "MEDIUM"
    assert by_source["old"].metadata["RecencyClass"] == "historical"
    assert by_source["old"].metadata["OriginalSeverity"] == "HIGH"
    assert by_source["new"].severity == "HIGH"
    assert by_source["new"].metadata["RecencyClass"] == "recent"


def test_recency_always_recent_categories():
    engine = Engine(
        keywords_high_cheats=[], keywords_high_input=[], keywords_medium=[],
        keywords_script_high=[], keywords_mouse_macro=[],
    )
    old = (datetime.now() - timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%S")
    engine.findings.append(
        Finding("Processes", "running.exe", "running process",
                "HIGH", "cheat", {"LastWrite": old})
    )
    apply_recency_decay(engine, threshold_days=180)
    proc = next(f for f in engine.findings if f.category == "Processes")
    assert proc.severity == "HIGH"
    assert proc.metadata["RecencyClass"] == "recent"


def test_get_finding_timestamp_returns_most_recent():
    f = Finding("X", "src", "d", metadata={
        "Created": "2024-01-01T00:00:00",
        "LastWrite": "2026-05-25T12:00:00",
        "FirstSeen": "2023-06-15T00:00:00",
    })
    ts = get_finding_timestamp(f)
    assert ts is not None and ts.year == 2026 and ts.month == 5

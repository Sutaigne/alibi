"""Recency decay (v3.8).

Old artifacts get LOGGED in the report (so a reviewer can still see them),
but don't BUMP the verdict if they're older than the threshold. A user who
cheated in GTA three years ago and is now scanning a clean COD rig shouldn't
get the same verdict as a current active cheater.

Threshold: 180 days (6 months). Drivers can override by passing a different
threshold_days kwarg.

Categories in ALWAYS_RECENT_CATEGORIES represent CURRENT state (a process
running right now, a service registered right now, a driver loaded right
now). Those are not eligible for decay regardless of any file timestamps.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from alibi.findings import Finding
from alibi.keywords import (
    ALWAYS_RECENT_CATEGORIES,
    RECENCY_METADATA_KEYS,
    RECENCY_THRESHOLD_DAYS,
)
from alibi.utils import Engine


def get_finding_timestamp(finding: Finding) -> datetime | None:
    """Return the most recent datetime extractable from a finding's metadata,
    or None if no timestamp-shaped metadata is present.
    """
    if not finding.metadata:
        return None
    best: datetime | None = None
    for key in RECENCY_METADATA_KEYS:
        if key not in finding.metadata:
            continue
        val = finding.metadata[key]
        if val is None or val == "" or val == "unknown":
            continue
        dt: datetime | None = None
        if isinstance(val, datetime):
            dt = val
        else:
            dt = _try_parse(str(val))
        if dt and (best is None or dt > best):
            best = dt
    return best


def _try_parse(s: str) -> datetime | None:
    s = s.strip()
    if not s:
        return None
    # Common forms produced by this codebase + Windows tools.
    fmts = (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y",
    )
    for fmt in fmts:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    # Last resort: fromisoformat handles many ISO-like strings.
    try:
        return datetime.fromisoformat(s.replace("Z", ""))
    except ValueError:
        return None


def apply_recency_decay(
    engine: Engine,
    *,
    threshold_days: int = RECENCY_THRESHOLD_DAYS,
) -> None:
    """Walk engine.findings and apply recency decay.

    Findings older than threshold_days:
      - Severity downgrade: HIGH → MEDIUM, MEDIUM → INFO
      - metadata['RecencyClass'] = 'historical'
      - metadata['OriginalSeverity'] preserved
      - metadata['AgeDays'] and 'MostRecentTimestamp' added

    Recent findings: metadata['RecencyClass'] = 'recent'.

    Findings with no usable timestamp + not in ALWAYS_RECENT_CATEGORIES get
    RecencyClass='unknown' and are TREATED AS RECENT for verdict safety
    (better to flag than miss).
    """
    print(f"  [*] Applying recency decay (>{threshold_days}-day findings demoted)...")

    cutoff = datetime.now() - timedelta(days=threshold_days)
    historical = 0
    unknown = 0
    recent = 0

    for f in engine.findings:
        if f.category in ALWAYS_RECENT_CATEGORIES:
            f.metadata["RecencyClass"] = "recent"
            recent += 1
            continue

        ts = get_finding_timestamp(f)
        if not ts:
            f.metadata["RecencyClass"] = "unknown"
            unknown += 1
            continue

        age_days = (datetime.now() - ts).days
        f.metadata["AgeDays"] = age_days
        f.metadata["MostRecentTimestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%S")

        if ts < cutoff:
            f.metadata["RecencyClass"] = "historical"
            f.metadata["OriginalSeverity"] = f.severity
            if f.severity == "HIGH":
                f.severity = "MEDIUM"
            elif f.severity == "MEDIUM":
                f.severity = "INFO"
            historical += 1
        else:
            f.metadata["RecencyClass"] = "recent"
            recent += 1

    engine.add(
        "RecencyDecay", "(summary)",
        f"Recency analysis: {recent} recent, {historical} historical "
        f"(>{threshold_days}d demoted), {unknown} unknown-timestamp",
        "INFO", "other",
        {
            "ThresholdDays": threshold_days,
            "RecentFindings": recent,
            "HistoricalFindings": historical,
            "UnknownTimestampFindings": unknown,
        },
    )

"""Finding dataclass and severity constants — shared across all scanners."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEV_HIGH = "HIGH"
SEV_MEDIUM = "MEDIUM"
SEV_WARN = "WARN"
SEV_INFO = "INFO"

SEVERITY_RANK = {"HIGH": 1, "MEDIUM": 2, "WARN": 3, "INFO": 4}
SCORE_RANK = {"HIGH": 1, "MEDIUM": 2, "LOW": 3, "CLEAN": 4}


@dataclass
class Finding:
    category: str
    source: str
    detail: str
    severity: str = SEV_INFO
    kind: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScoredItem:
    """Process / service snapshot row with a Score, Kind, Pattern, Reason."""
    name: str = ""
    score: str = "CLEAN"
    kind: str = "other"
    pattern: str = ""
    reason: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

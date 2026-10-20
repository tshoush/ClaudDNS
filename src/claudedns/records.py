"""Normalized DNS query record shared by all readers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class QueryRecord:
    timestamp: float | None  # Unix seconds; None if the source has no time
    client: str
    qname: str  # lowercased, no trailing dot
    qtype: str  # e.g. "A", "AAAA", "TYPE99"


@dataclass
class ParseStats:
    """Counts of input units that could not be turned into a QueryRecord."""

    parsed: int = 0
    skipped: int = 0

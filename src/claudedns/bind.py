"""Reader for BIND/ISC-style DNS query logs (also used by Infoblox NIOS).

Example line:
    09-Oct-2026 12:00:00.123 client 10.0.0.5#53211 (example.com): query: example.com IN A + (10.0.0.1)
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import datetime
from typing import BinaryIO

from .records import ParseStats, QueryRecord

_LINE = re.compile(
    r"^(?:(?P<ts>\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+)?"
    r".*?client (?:@0x[0-9a-fA-F]+ )?(?P<client>[0-9a-fA-F:.]+)#\d+"
    r"(?: \([^)]*\))?: (?:view \S+: )?query: (?P<qname>\S+) (?P<qclass>\S+) (?P<qtype>\S+)"
)

_TIME_FORMATS = ("%d-%b-%Y %H:%M:%S.%f", "%d-%b-%Y %H:%M:%S")


def _parse_timestamp(text: str | None) -> float | None:
    if not text:
        return None
    for fmt in _TIME_FORMATS:
        try:
            return datetime.strptime(text, fmt).timestamp()
        except ValueError:
            continue
    return None


def parse_line(line: str) -> QueryRecord | None:
    """Parse one query log line. Returns None if it is not a query line."""
    match = _LINE.search(line)
    if match is None:
        return None
    qname = match.group("qname").lower().rstrip(".") or "."
    return QueryRecord(
        timestamp=_parse_timestamp(match.group("ts")),
        client=match.group("client"),
        qname=qname,
        qtype=match.group("qtype").upper(),
    )


def read_bind(f: BinaryIO, stats: ParseStats | None = None) -> Iterator[QueryRecord]:
    """Yield query records from an open BIND-style query log.

    Lines that are not query lines (startup messages, notices) are ignored and
    not counted as skipped; they are expected in real logs.
    """
    stats = stats if stats is not None else ParseStats()
    for raw in f:
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        record = parse_line(line)
        if record is not None:
            stats.parsed += 1
            yield record

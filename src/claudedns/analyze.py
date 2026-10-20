"""Traffic summary: volume, rates, and top domains/clients/query types."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field

from .records import QueryRecord


@dataclass
class Summary:
    total_queries: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    timed_queries: int = 0
    peak_qps: int | None = None
    avg_qps: float | None = None
    top_domains: list[tuple[str, int]] = field(default_factory=list)
    top_clients: list[tuple[str, int]] = field(default_factory=list)
    query_types: list[tuple[str, int]] = field(default_factory=list)
    skipped: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def summarize(records: Iterable[QueryRecord], top: int = 10) -> Summary:
    domains: Counter[str] = Counter()
    clients: Counter[str] = Counter()
    qtypes: Counter[str] = Counter()
    per_second: Counter[int] = Counter()

    summary = Summary()
    for record in records:
        summary.total_queries += 1
        domains[record.qname] += 1
        clients[record.client] += 1
        qtypes[record.qtype] += 1
        if record.timestamp is not None:
            summary.timed_queries += 1
            per_second[int(record.timestamp)] += 1
            if summary.first_timestamp is None or record.timestamp < summary.first_timestamp:
                summary.first_timestamp = record.timestamp
            if summary.last_timestamp is None or record.timestamp > summary.last_timestamp:
                summary.last_timestamp = record.timestamp

    if per_second:
        summary.peak_qps = max(per_second.values())
        span_seconds = int(summary.last_timestamp) - int(summary.first_timestamp) + 1
        summary.avg_qps = round(summary.timed_queries / span_seconds, 2)

    summary.top_domains = domains.most_common(top)
    summary.top_clients = clients.most_common(top)
    summary.query_types = qtypes.most_common()
    return summary

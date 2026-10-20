"""Minimal DNS wire-format parsing, enough to read the question section."""

from __future__ import annotations

import struct

QTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    64: "SVCB",
    65: "HTTPS",
    255: "ANY",
}


def parse_question(message: bytes) -> tuple[str, str] | None:
    """Return (qname, qtype) from a DNS query message, or None if malformed."""
    if len(message) < 12:
        return None
    (qdcount,) = struct.unpack(">H", message[4:6])
    if qdcount < 1:
        return None

    pos = 12
    labels: list[str] = []
    while True:
        if pos >= len(message):
            return None
        length = message[pos]
        pos += 1
        if length == 0:
            break
        if length & 0xC0:  # compression pointers are not valid in a question
            return None
        if pos + length > len(message):
            return None
        labels.append(message[pos : pos + length].decode("ascii", errors="replace"))
        pos += length

    if pos + 2 > len(message):
        return None
    (qtype_num,) = struct.unpack(">H", message[pos : pos + 2])
    name = ".".join(labels).lower() or "."
    return name, QTYPES.get(qtype_num, f"TYPE{qtype_num}")

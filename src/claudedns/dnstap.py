"""Reader for dnstap capture files.

A dnstap file is a Frame Streams container whose data frames are protobuf
encoded ``Dnstap`` messages carrying the raw DNS wire message.

Field numbers below come from the upstream dnstap.proto schema.
"""

from __future__ import annotations

import ipaddress
import struct
from collections.abc import Iterator
from typing import BinaryIO

from .dnswire import parse_question
from .records import ParseStats, QueryRecord

# dnstap.Dnstap
DNSTAP_MESSAGE = 14

# dnstap.Message
MSG_TYPE = 1
MSG_QUERY_ADDRESS = 4
MSG_QUERY_TIME_SEC = 8
MSG_QUERY_TIME_NSEC = 9  # fixed32
MSG_QUERY_MESSAGE = 10

# Message.Type values that represent queries (AUTH_QUERY, RESOLVER_QUERY,
# CLIENT_QUERY, FORWARDER_QUERY, STUB_QUERY).
QUERY_TYPES = {1, 3, 5, 7, 9}


class FrameError(ValueError):
    """Raised when a dnstap file or protobuf payload is malformed."""


def _read_exact(f: BinaryIO, n: int) -> bytes:
    data = f.read(n)
    if len(data) != n:
        raise FrameError("truncated frame")
    return data


def iter_frames(f: BinaryIO) -> Iterator[bytes]:
    """Yield data-frame payloads, skipping Frame Streams control frames."""
    while True:
        header = f.read(4)
        if not header:
            return
        if len(header) < 4:
            raise FrameError("truncated frame length")
        (length,) = struct.unpack(">I", header)
        if length == 0:
            # Escape: a control frame follows as length + payload. Control
            # frames (START/READY/STOP/...) carry no DNS data, so skip them.
            (control_len,) = struct.unpack(">I", _read_exact(f, 4))
            _read_exact(f, control_len)
            continue
        yield _read_exact(f, length)


def _varint(buf: bytes, pos: int) -> tuple[int, int]:
    shift = 0
    result = 0
    while True:
        if pos >= len(buf):
            raise FrameError("truncated varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise FrameError("varint too long")


def _proto_fields(buf: bytes) -> Iterator[tuple[int, object]]:
    """Iterate (field_number, value) pairs of a protobuf message.

    Length-delimited values are returned as bytes, varints as int, and
    fixed-width values as their raw little-endian bytes.
    """
    pos = 0
    while pos < len(buf):
        key, pos = _varint(buf, pos)
        field_number, wire_type = key >> 3, key & 0x7
        if wire_type == 0:
            value, pos = _varint(buf, pos)
        elif wire_type == 1:
            value, pos = buf[pos : pos + 8], pos + 8
        elif wire_type == 2:
            length, pos = _varint(buf, pos)
            value, pos = buf[pos : pos + length], pos + length
        elif wire_type == 5:
            value, pos = buf[pos : pos + 4], pos + 4
        else:
            raise FrameError(f"unsupported protobuf wire type {wire_type}")
        yield field_number, value


def decode_frame(frame: bytes) -> QueryRecord | None:
    """Decode one dnstap payload. Returns None for non-query messages."""
    message = None
    for number, value in _proto_fields(frame):
        if number == DNSTAP_MESSAGE:
            message = value
    if message is None:
        return None

    fields = dict(_proto_fields(message))
    if fields.get(MSG_TYPE) not in QUERY_TYPES:
        return None
    wire = fields.get(MSG_QUERY_MESSAGE)
    if not isinstance(wire, bytes):
        return None

    question = parse_question(wire)
    if question is None:
        raise FrameError("malformed DNS query message")
    qname, qtype = question

    address = fields.get(MSG_QUERY_ADDRESS)
    try:
        client = str(ipaddress.ip_address(address)) if isinstance(address, bytes) else "unknown"
    except ValueError:
        client = "unknown"

    sec = fields.get(MSG_QUERY_TIME_SEC)
    nsec = fields.get(MSG_QUERY_TIME_NSEC)
    timestamp = None
    if isinstance(sec, int):
        nanos = int.from_bytes(nsec, "little") if isinstance(nsec, bytes) else 0
        timestamp = sec + nanos / 1e9

    return QueryRecord(timestamp=timestamp, client=client, qname=qname, qtype=qtype)


def read_dnstap(f: BinaryIO, stats: ParseStats | None = None) -> Iterator[QueryRecord]:
    """Yield query records from an open dnstap file.

    Non-query messages are ignored. Malformed frames are counted in ``stats``
    as skipped and do not stop the read.
    """
    stats = stats if stats is not None else ParseStats()
    for frame in iter_frames(f):
        try:
            record = decode_frame(frame)
        except (FrameError, IndexError, struct.error):
            stats.skipped += 1
            continue
        if record is not None:
            stats.parsed += 1
            yield record

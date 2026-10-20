import ipaddress
import json
import struct

from claudedns.analyze import summarize
from claudedns.bind import parse_line, read_bind
from claudedns.cli import main
from claudedns.dnstap import read_dnstap
from claudedns.formats import detect_format
from claudedns.records import ParseStats


# ---- helpers to build synthetic inputs -------------------------------------

def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _f_varint(num: int, value: int) -> bytes:
    return _varint(num << 3) + _varint(value)


def _f_bytes(num: int, value: bytes) -> bytes:
    return _varint((num << 3) | 2) + _varint(len(value)) + value


def _f_fixed32(num: int, value: int) -> bytes:
    return _varint((num << 3) | 5) + struct.pack("<I", value)


def _dns_query(name: str, qtype: int) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    labels = name.rstrip(".").split(".")
    question = b"".join(bytes([len(p)]) + p.encode() for p in labels) + b"\x00"
    return header + question + struct.pack(">HH", qtype, 1)


def _dnstap_payload(client: str, name: str, qtype: int, sec: int, msg_type: int = 5) -> bytes:
    message = (
        _f_varint(1, msg_type)
        + _f_bytes(4, ipaddress.ip_address(client).packed)
        + _f_varint(8, sec)
        + _f_fixed32(9, 250_000_000)
        + _f_bytes(10, _dns_query(name, qtype))
    )
    return _f_varint(15, 1) + _f_bytes(14, message)


def _frame_stream(payloads: list[bytes]) -> bytes:
    start_control = struct.pack(">I", 2)  # START control type, no fields
    out = b"\x00\x00\x00\x00" + struct.pack(">I", len(start_control)) + start_control
    for payload in payloads:
        out += struct.pack(">I", len(payload)) + payload
    return out


# ---- tests ------------------------------------------------------------------

def test_dnstap_round_trip(tmp_path):
    path = tmp_path / "capture.fstrm"
    path.write_bytes(
        _frame_stream(
            [
                _dnstap_payload("10.0.0.5", "Example.COM.", 1, 1_700_000_000),
                _dnstap_payload("2001:db8::1", "example.org", 28, 1_700_000_001),
                _dnstap_payload("10.0.0.5", "ignored.net", 1, 1_700_000_002, msg_type=6),
            ]
        )
    )
    with open(path, "rb") as f:
        stats = ParseStats()
        records = list(read_dnstap(f, stats))

    assert [(r.qname, r.qtype, r.client) for r in records] == [
        ("example.com", "A", "10.0.0.5"),
        ("example.org", "AAAA", "2001:db8::1"),
    ]
    assert records[0].timestamp == 1_700_000_000 + 0.25
    assert stats.skipped == 0


def test_dnstap_malformed_frame_is_counted_not_fatal(tmp_path):
    path = tmp_path / "bad.fstrm"
    path.write_bytes(_frame_stream([b"\xff\xff\xff", _dnstap_payload("10.0.0.9", "a.test", 1, 1)]))
    with open(path, "rb") as f:
        stats = ParseStats()
        records = list(read_dnstap(f, stats))
    assert len(records) == 1
    assert stats.skipped == 1


def test_bind_line_parsing():
    line = (
        "09-Oct-2026 12:00:00.123 client 10.0.0.5#53211 (Example.com): "
        "query: Example.com IN A + (10.0.0.1)"
    )
    record = parse_line(line)
    assert record is not None
    assert record.client == "10.0.0.5"
    assert record.qname == "example.com"
    assert record.qtype == "A"
    assert record.timestamp is not None

    assert parse_line("09-Oct-2026 12:00:00 general: zone loaded") is None


def test_detect_format(tmp_path):
    dnstap_path = tmp_path / "a.fstrm"
    dnstap_path.write_bytes(_frame_stream([_dnstap_payload("10.0.0.1", "x.test", 1, 1)]))
    bind_path = tmp_path / "query.log"
    bind_path.write_text(
        "09-Oct-2026 12:00:00.000 client 10.0.0.5#1 (a.test): query: a.test IN A + (10.0.0.1)\n"
    )
    assert detect_format(dnstap_path) == "dnstap"
    assert detect_format(bind_path) == "bind"


def test_summary_rates_and_top_lists():
    lines = [
        "09-Oct-2026 12:00:00.000 client 10.0.0.1#1 (a.test): query: a.test IN A + (x)",
        "09-Oct-2026 12:00:00.500 client 10.0.0.1#2 (a.test): query: a.test IN A + (x)",
        "09-Oct-2026 12:00:01.000 client 10.0.0.2#3 (b.test): query: b.test IN AAAA + (x)",
    ]
    import io

    records = list(read_bind(io.BytesIO("\n".join(lines).encode())))
    summary = summarize(records, top=5)
    assert summary.total_queries == 3
    assert summary.peak_qps == 2
    assert summary.top_domains[0] == ("a.test", 2)
    assert summary.top_clients[0] == ("10.0.0.1", 2)


def test_cli_json_output(tmp_path, capsys):
    path = tmp_path / "query.log"
    path.write_text(
        "09-Oct-2026 12:00:00.000 client 10.0.0.5#1 (a.test): query: a.test IN A + (x)\n"
    )
    assert main(["analyze", str(path), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["format"] == "bind"
    assert out["total_queries"] == 1

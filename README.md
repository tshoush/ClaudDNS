# claudeDNS

Cloud-based project to analyze DNS traffic, with the longer-term goal of
installing InfoBlox Advanced DNS Protection (ADP) in our environment.

## Goals

1. Collect and analyze DNS traffic (query volume, rates, top domains, top
   clients, query types, suspicious patterns).
2. Use those findings to inform an InfoBlox ADP rollout.

## Supported inputs

| Format | Source | Notes |
|---|---|---|
| dnstap | Frame Streams capture files (`.fstrm`, `.dnstap`) | Reads query messages (AUTH, RESOLVER, CLIENT, FORWARDER, STUB). Responses are ignored. |
| BIND/ISC query log | BIND `queries` channel, Infoblox NIOS query logs | Parses `client ... query: ...` lines. Startup and other log lines are ignored. |

The format is auto-detected by default. Use `--format dnstap` or `--format bind`
to override detection.

## Usage

```
claudedns analyze capture.fstrm
claudedns analyze query.log --format bind --top 20
claudedns analyze query.log --json
```

Output covers total queries, average and peak queries per second (when the
input has timestamps), and top-N tables for domains, clients, and query types.
The count of malformed input units skipped is reported as well.

## Layout

```
src/claudedns/
  dnstap.py     dnstap reader (Frame Streams + protobuf)
  dnswire.py    DNS question-section parser
  bind.py       BIND/NIOS query-log reader
  formats.py    input format detection
  analyze.py    traffic summary
  cli.py        `claudedns` command
tests/          synthetic-data tests
```

## Development

```
python -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"
pytest
```

## Status

- Analysis of dnstap and BIND-style logs: implemented, covered by synthetic tests.
- Not yet verified against real Infoblox NIOS query-log samples. Check the
  parser against a real sample before relying on the numbers.
- Not yet started: cloud deployment (Terraform/Docker), InfoBlox ADP planning.

# claudeDNS

Cloud-based project to analyze DNS traffic, with the longer-term goal of
installing InfoBlox Advanced DNS Protection (ADP) in our environment.

## Goals

1. Collect and analyze DNS traffic (query volume, top domains, top clients,
   suspicious patterns).
2. Use those findings to inform an InfoBlox ADP rollout.

## Status

Initial scaffold. No ingestion or analysis code yet.

## Layout

```
src/claudedns/   Python package (analysis code goes here)
```

## Development

```
python -m venv .venv && . .venv/bin/activate
pip install -e .
```

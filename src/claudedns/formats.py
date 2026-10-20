"""Input format detection."""

from __future__ import annotations

from pathlib import Path

from .bind import parse_line

FORMATS = ("dnstap", "bind")


def detect_format(path: str | Path) -> str:
    """Guess the format of a capture or log file.

    dnstap files start with a Frame Streams escape (four zero bytes), which
    is never valid as the start of a text log. Otherwise the first lines are
    checked for BIND-style query lines.
    """
    with open(path, "rb") as f:
        head = f.read(8192)

    if head[:4] == b"\x00\x00\x00\x00":
        return "dnstap"

    for raw in head.decode("utf-8", errors="replace").splitlines()[:200]:
        if parse_line(raw) is not None:
            return "bind"

    raise ValueError(
        f"could not detect the format of {path}; pass --format dnstap or --format bind"
    )

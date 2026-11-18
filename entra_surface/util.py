"""Small shared parsing/formatting helpers."""
from __future__ import annotations

import datetime
import re


def parse_datetime(value):
    """Parse the timestamp formats produced by ROADrecon and Graph.

    Graph returns ISO-8601 values such as ``2026-04-17T12:17:00Z`` while older
    exports use space-separated values. Both are normalized to UTC.
    """
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    iso = text
    if iso.endswith(("Z", "z")):
        iso = iso[:-1] + "+00:00"
    # fromisoformat accepts at most six fractional digits on older Pythons.
    iso = re.sub(r"(\.\d{6})\d+", r"\1", iso)
    try:
        parsed = datetime.datetime.fromisoformat(iso)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                parsed = datetime.datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc)

def truncate(text, width=110):
    text = text or ""
    return text if len(text) <= width else text[: max(0, width - 1)] + "\u2026"

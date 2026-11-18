"""Conditional Access result table row helpers."""
from __future__ import annotations

from ..findings import severity_rank


def make_ca_rows_fn():
    """Rows function for CA-analysis result tables: substring q filtering,
    optional single-field sorting, pagination handled by the caller."""
    def rows_fn(rows, q="", sort_key=None, desc=False, start=0, stop=None):
        items = rows
        if q:
            needle = q.lower()
            items = [r for r in items if needle in (r.get("_text") or "")]
        if sort_key:
            if sort_key == "severity":
                items = sorted(items, key=lambda r: severity_rank(
                    (r.get("fields") or {}).get("severity", "Info")), reverse=desc)
            else:
                items = sorted(items, key=lambda r: str(
                    (r.get("fields") or {}).get(sort_key, "")).lower(), reverse=desc)
        if stop is None:
            stop = len(items)
        return [r["_html"] for r in items[start:stop]], len(items)
    return rows_fn



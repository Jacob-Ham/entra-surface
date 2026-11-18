"""HTML escaping and small badge/cell primitives."""
from __future__ import annotations

import html

from ..roles import role_display_name

DASH_INNER = '<span class="muted">&mdash;</span>'
EXPAND_BUTTON_HTML = '<button type="button" class="icon-btn expand-btn" aria-label="View full details">+</button>'


def esc(value):
    return html.escape(str(value)) if value is not None else ""


def severity_class(severity):
    return {"Critical": "sev-critical", "High": "sev-high", "Medium": "sev-medium",
            "Low": "sev-low", "Info": "sev-info"}.get(severity, "sev-info")


def severity_badge(severity):
    return f'<span class="badge {severity_class(severity)}">{esc(severity)}</span>'


def bool_badge(value, true_label="Enabled", false_label="Disabled"):
    cls = "badge-enabled" if value else "badge-disabled"
    label = true_label if value else false_label
    return f'<span class="badge {cls}">{esc(label)}</span>'


def status_cell(status):
    if not status:
        return '<span class="muted">&mdash;</span>'
    label = status.get("label", "")
    if label == "Enabled":
        return bool_badge(True)
    if label == "Disabled":
        return bool_badge(False)
    if label == "Reporting":
        return '<span class="badge badge-hybrid" title="Report-only: policy does not enforce">Reporting</span>'
    if label == "Unknown":
        return '<span class="muted">Unknown</span>'
    if isinstance(status.get("enabled"), bool):
        return bool_badge(status["enabled"])
    return f'<span class="muted">{esc(label)}</span>'


def count_cell(value):
    if value is None:
        return '<span class="muted">&mdash;</span>'
    return f'<span class="mono">{esc(str(value))}</span>'


EXPAND_BUTTON_HTML = '<button type="button" class="icon-btn expand-btn" aria-label="View full details">+</button>'


def cap_annotate(items):
    """'Group — Role (severity); …' annotations for capable-group tooltips."""
    out = []
    for c in items:
        line = c.get("name") or ""
        roles = c.get("roles") or []
        if roles:
            line += " — " + ", ".join(f"{role_display_name(r)} ({r['severity']})" for r in roles)
        out.append(line)
    return out


def drawer_for_html(key, colspan):
    return (f'<tr class="drawer" data-detail-for="{esc(key)}">'
            f'<td colspan="{colspan}"><div class="drawer-body"></div></td></tr>')

def _serve_pager():
    """Pager markup for serve-mode tables (Prev/Next + rows-per-page select)."""
    return ('<div class="table-pager hidden">'
            '<button type="button" class="icon-btn tp-prev">&#8592; Prev</button>'
            '<span class="tp-info muted"></span>'
            '<button type="button" class="icon-btn tp-next">Next &#8594;</button>'
            '<label class="muted">Rows '
            '<select class="tp-size">'
            '<option value="25" selected>25</option><option value="50">50</option><option value="100">100</option><option value="250">250</option>'
            '<option value="500">500</option><option value="1000">1000</option>'
            '</select></label></div>')

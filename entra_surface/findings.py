"""Finding shape and severity helpers shared by checks and the report.

Pure module: no imports from the report, graph, config, or serving layers.
"""
from __future__ import annotations

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def severity_rank(severity):
    return SEVERITY_ORDER.get(severity, 9)


PRIVILEGED_MAX_RANK = 1  # Critical (0) and High (1)


def is_privileged(severity):
    """True when `severity` is Critical or High."""
    return severity_rank(severity) <= PRIVILEGED_MAX_RANK


ELIGIBLE_SEVERITY_STEP = {
    "Critical": "High",
    "High": "Medium",
    "Medium": "Low",
    "Low": "Info",
    "Info": "Info",
}


def eligible_severity(severity):
    """PIM-eligible roles are rated one notch below the same role held
    actively: an eligible Global Administrator is High, not Critical, until
    the role is activated."""
    return ELIGIBLE_SEVERITY_STEP.get(severity, "Info")


def make_finding(check_id, category, severity, title, evidence, primary_id,
                 object_ids=None, remediation="", target=None, status=None):
    return {
        "check_id": check_id,
        "category": category,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "remediation": remediation,
        "primary_id": primary_id,
        "object_ids": {
            "sp": set(object_ids.get("sp", set())) if object_ids else set(),
            "app": set(object_ids.get("app", set())) if object_ids else set(),
            "user": set(object_ids.get("user", set())) if object_ids else set(),
            "device": set(object_ids.get("device", set())) if object_ids else set(),
        },
        "target": target if target else {"type": "", "name": "", "id": primary_id},
        "status": status,
    }

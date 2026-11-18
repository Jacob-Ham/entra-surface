"""Conditional Access policy inventory check."""
from __future__ import annotations

import json
from collections import defaultdict

from ..findings import is_privileged, make_finding, severity_rank
from ..policy import policy_detail_normalized
from ..roles import direct_directory_roles_by_user, resolve_group_role_paths


def check_ca_exposure(ctx):
    """Conditional Access policy inventory: per-policy posture (state, scope,
    exclusions) plus a full policy profile (included/excluded users, roles,
    groups, applications, controls, conditions) for the drawer. Per-user
    exclusion gaps are evaluated on demand in the CA coverage analysis."""
    graph = ctx["graph"]
    role_sev = ctx["check_cfg"]["directory_roles"]

    def policy_inner(pol_id):
        rec = graph["policy"].get(pol_id)
        return policy_detail_normalized(rec.get("policyDetail") if rec else None)

    def policy_state(pol_id):
        return ((policy_inner(pol_id).get("State")) or "").strip() or "Unknown"

    def label_fn(oid, table):
        rec = graph[table].get(oid)
        return rec.get("displayName") if rec else oid

    def user_label(uid):
        u = graph["user"].get(uid)
        return (u.get("userPrincipalName") or u.get("displayName") or uid) if u else uid

    def resolve_items(oids, table):
        out = []
        for oid in sorted(set(oid for oid in oids if oid)):
            name = label_fn(oid, table)
            if table == "directory_role" or table == "role_definition":
                sev = role_sev.get(name, "Info")
                out.append({"name": name, "severity": sev})
            else:
                out.append({"name": name})
        return out

    def app_label(app_id):
        for sp_oid in graph["sp_by_appid"].get(app_id, []):
            rec = graph["sp"].get(sp_oid)
            if rec and (rec.get("displayName") or rec.get("appDisplayName")):
                return rec.get("displayName") or rec.get("appDisplayName")
        return app_id

    def flatten_conditions(inner, key, field):
        items = []
        for block in ((inner.get("Conditions") or {}).get(key) or {}).get("Include") or []:
            items.extend(block.get(field) or [])
        return items

    def exclude_items(inner, field):
        items = []
        for block in ((inner.get("Conditions") or {}).get("Users") or {}).get("Exclude") or []:
            items.extend(block.get(field) or [])
        return items

    findings = []
    ca_policies = [oid for oid, rec in graph["policy"].items()
                   if rec.get("policyType") == 18]

    excludes_by_policy = defaultdict(set)
    for pol, uid in graph["policy_user_exclude"]:
        excludes_by_policy[pol].add(uid)

    # per-policy posture rows
    for pol in ca_policies:
        rec = graph["policy"][pol]
        name = rec.get("displayName") or pol
        inner = policy_inner(pol)
        state = policy_state(pol)
        is_mfa = "multifactor" in name.lower()
        if pol in graph["policy_include_allusers"]:
            scope = "all users"
        else:
            inc_ids = {uid for p, uid in graph["policy_user_include"] if p == pol}
            scope = f"{len(inc_ids)} included user(s)" if inc_ids else "no user scope captured"

        included_uids = sorted({uid for p, uid in graph["policy_user_include"] if p == pol})
        excluded_uids = sorted(excludes_by_policy.get(pol, set()))
        excluded = len(excluded_uids)
        bits = [f"state {state}", f"scope: {scope}"]
        if excluded:
            bits.append(f"{excluded} excluded user(s)")
        if is_mfa:
            bits.append("MFA policy")

        apps = ["All" if v == "All" else app_label(v)
                for v in flatten_conditions(inner, "Applications", "Applications")]
        inc_roles = resolve_items(flatten_conditions(inner, "Users", "Roles"), "role_definition")
        inc_groups = resolve_items(flatten_conditions(inner, "Users", "Groups"), "group")
        exc_groups = resolve_items(exclude_items(inner, "Groups"), "group")
        controls = [c for block in (inner.get("Controls") or [])
                    for c in block.get("Control") or [] if isinstance(c, str)]

        f = make_finding(
            check_id="ca_exposure", category="configs", severity="Info",
            title=f"Conditional Access policy: {name}",
            evidence=" · ".join(bits),
            remediation=("Confirm the policy state, scope, and exclusions; Reporting "
                         "policies do not enforce, and excluded users bypass the "
                         "policy's sign-on requirements. Use the CA coverage "
                         "analysis to evaluate per-user exclusion gaps."),
            primary_id=pol,
            object_ids={},
            target={"type": "Policy", "name": name, "id": pol},
            status={"label": state, "enabled": state == "Enabled", "raw": state},
        )
        f["policy_id"] = pol
        f["policy_name"] = name
        f["policy_type"] = rec.get("policyType")
        f["state"] = state
        f["scope"] = scope
        f["conditions_html"] = {
            "controls": controls,
            "apps": apps,
            "inc_roles": inc_roles,
            "inc_groups": inc_groups,
            "exc_groups": exc_groups,
        }
        f["included"] = [user_label(u) for u in included_uids]
        f["excluded"] = [user_label(u) for u in excluded_uids if u in graph["user"]]
        f["conditions_raw"] = json.dumps(inner, indent=2)
        f["created"] = inner.get("CreatedDateTime", "")
        f["modified"] = inner.get("ModifiedDateTime", "")
        f["template_id"] = inner.get("TemplateId", "")
        findings.append(f)

    findings.sort(key=lambda f: (severity_rank(f["severity"]),
                                 (f["target"]["name"] or "").lower()))
    return findings

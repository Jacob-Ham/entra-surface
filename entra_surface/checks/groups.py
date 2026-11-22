"""Group roster and membership checks."""
from __future__ import annotations

import re
from collections import defaultdict

from ..findings import is_privileged, make_finding, severity_rank
from ..graph import (
    compute_effective_group_membership, group_owner_chain,
    group_parents_index, json_list,
)
# Which role class can fabricate membership in a dynamic group by editing the
# referenced user attribute (Entra's rule grammar: `user.<attribute>`). A group
# is tagged per category only when EVERY attribute referenced by its rule is
# modifiable by that role class.
DYN_USER_MODIFIABLE = {
    "givenName", "surname", "streetAddress", "state", "postalCode", "country",
    "telephoneNumber", "mobile", "otherMails",
}
DYN_DIRECTORY_WRITER = {
    "displayName", "city", "companyName", "country", "department",
    "facsimileTelephoneNumber", "givenName", "jobTitle", "mailNickname", "mobile",
    "physicalDeliveryOfficeName", "postalCode", "state", "streetAddress", "surname",
    "telephoneNumber", "proxyAddresses",
}
DYN_USER_ADMINISTRATOR = {
    "accountEnabled", "mail", "userPrincipalName", "userType", "usageLocation",
    "employeeId", "employeeHireDate", "passwordPolicies", "preferredLanguage",
    "sipProxyAddress", "otherMails",
}
DYN_PEOPLE_ADMINISTRATOR = {
    "displayName", "givenName", "surname", "department", "jobTitle", "mobile",
    "telephoneNumber", "physicalDeliveryOfficeName", "city", "state", "postalCode",
    "country", "streetAddress", "companyName",
}

DYNAMIC_RULE_CATEGORIES = [
    ("User modifiable", DYN_USER_MODIFIABLE),
    ("Directory Writer", DYN_DIRECTORY_WRITER),
    ("User Administrator", DYN_USER_ADMINISTRATOR),
    ("People Administrator", DYN_PEOPLE_ADMINISTRATOR),
]


def classify_dynamic_rule(rule):
    """Extract user-attribute references from an Entra membership rule and map
    them onto the role classes that could modify those attributes.

    A role class is only tagged when it can modify EVERY attribute referenced
    by the rule; attributes outside all known sets tag nothing."""
    rule = rule or ""
    attrs = set(re.findall(r"user\.([A-Za-z]+)", rule))
    # also catch bare attribute tokens (rules without the user. prefix)
    for name in set().union(*[c for _, c in DYNAMIC_RULE_CATEGORIES]):
        if re.search(rf"(?<![A-Za-z]){re.escape(name)}(?![A-Za-z])", rule):
            attrs.add(name)
    matched = sorted(attrs)
    mods = [label for label, cat in DYNAMIC_RULE_CATEGORIES
            if attrs and attrs <= cat]
    return matched, mods

from ..roles import (
    _pim_role_def_name, compute_group_eligible_roles, compute_group_roles,
    direct_directory_roles_by_sp, direct_directory_roles_by_user,
    is_pim_directory_assignment, merge_role_entry, resolve_group_role_paths,
    role_display_name, role_rating_severity,
)


def check_groups(ctx):
    """One row per group: directory roles carried by the group, role-capability
    (assignable / role-bearing / nested), dynamic membership rules, owners, and
    privileged / service-principal members. User members carry role tags for
    their own directory roles plus the roles the group grants them, resolved
    through nested group membership with the group path to each role."""
    graph = ctx["graph"]
    role_sev = ctx["check_cfg"]["directory_roles"]
    capable = ctx["capable_groups"]
    group_roles = ctx["group_roles"]
    group_eligible_roles = ctx.get("group_eligible_roles") or {}
    analysis_indexes = ctx.get("analysis_indexes") or {}
    parents_by_child = analysis_indexes.get("parents_by_child") or graph.get(
        "group_parents") or group_parents_index(graph["group_member_group"])
    effective = analysis_indexes.get("effective_membership") \
        or compute_effective_group_membership(graph)

    # direct directory roles per user (drives the privileged-member column)
    user_roles = ctx.get("direct_user_roles")
    if user_roles is None:
        user_roles = direct_directory_roles_by_user(graph, role_sev)

    def user_primary(uid):
        u = graph["user"].get(uid)
        if not u:
            return uid
        return u.get("userPrincipalName") or u.get("displayName") or uid

    def group_label(gid):
        rec = graph["group"].get(gid)
        return rec.get("displayName") if rec else gid

    def sp_label(sp_oid):
        rec = graph["sp"].get(sp_oid)
        return (rec.get("displayName") or rec.get("appDisplayName") or sp_oid) if rec else sp_oid

    # Roles members inherit through nested group membership, with the group
    # path from the viewed group to each role-bearing group.
    role_path_cache = {}

    def role_paths_for(gid):
        if gid not in role_path_cache:
            role_path_cache[gid] = resolve_group_role_paths(
                gid, group_roles, graph["group_member_group"], group_label,
                parents_by_child=parents_by_child)
        return role_path_cache[gid]

    # A member's group-derived roles come from their own *direct* groups and
    # keep the real intermediate path (Helpdesk -> Tier 2 -> Root).
    direct_groups_by_user = defaultdict(set)
    for direct_gid, uids in graph["group_member_user"].items():
        for uid in uids:
            direct_groups_by_user[uid].add(direct_gid)
    member_roles_cache = {}

    def member_group_roles(uid):
        if uid not in member_roles_cache:
            merged = {}
            for direct_gid in direct_groups_by_user.get(uid, ()):
                for r in role_paths_for(direct_gid):
                    if r["name"] not in merged:
                        merged[r["name"]] = dict(r)
                    else:
                        merge_role_entry(merged[r["name"]], r)
            member_roles_cache[uid] = list(merged.values())
        return member_roles_cache[uid]

    # direct directory roles per SP (memberships + role assignments)
    sp_dir_roles = ctx.get("direct_sp_roles")
    if sp_dir_roles is None:
        sp_dir_roles = direct_directory_roles_by_sp(graph, role_sev)
    sp_resolver = ctx.get("sp_dir_resolver")

    # privileged app-role assignments per SP, rated by the resources config
    # (same criticality tags as the priv_app_ownership findings)
    sp_priv_grants = defaultdict(list)
    for ra in graph["role_assigns"]:
        if ra["principal_type"] != "ServicePrincipal":
            continue
        info = ctx["resource_index"].get(ra["resource_id"], {}).get(ra["app_role_id"])
        if info:
            sp_priv_grants[ra["principal_id"]].append({
                "name": info["value"],
                "severity": info["severity"],
                "resource": ctx["resource_names"].get(ra["resource_id"], ra["resource_id"]),
            })

    findings = []
    for gid, rec in graph["group"].items():
        name = rec.get("displayName") or gid
        types = [t for t in json_list(rec.get("groupTypes")) if isinstance(t, str)]
        visibility = rec.get("visibility") or ""
        is_public = rec.get("isPublic") in (1, True)
        mail = rec.get("mailEnabled") in (1, True)
        synced = (rec.get("dirSyncEnabled") in (1, True)
                  or bool(rec.get("onPremisesSecurityIdentifier")))
        rule = (rec.get("membershipRule") or "").strip()
        dynamic = bool(rule) and rule not in ("[]",)
        if dynamic:
            dyn_attrs, dyn_mods = classify_dynamic_rule(rule)
        else:
            dyn_attrs, dyn_mods = [], []
        assignable = rec.get("isAssignableToRole") in (1, True)
        az_roles = sorted(ctx["graph"]["az_roles"].get(gid, []),
                          key=lambda a: (a.get("eligible", False), a["role"].lower()))

        dir_roles = group_roles.get(gid, [])
        eligible_roles = [dict(r) for r in group_eligible_roles.get(gid, [])]
        # enrich group eligibility with scope + PIM v2 schedule details
        for r in eligible_roles:
            for a in (graph.get("pim_role_assignments") or []):
                if (a.get("assignment_state") or "").lower() != "eligible":
                    continue
                if not is_pim_directory_assignment(graph, a):
                    continue
                subject = graph["pim_assign_subject"].get(a["id"]) or a.get("subject_id")
                if subject != gid:
                    continue
                if _pim_role_def_name(graph, a.get("role_definition_id")) != r["name"]:
                    continue
                r["schedule"] = {
                    "permanent": bool(a.get("is_permanent")),
                    "member_type": a.get("member_type") or "",
                    "start": str(a.get("start") or "")[:10],
                    "end": str(a.get("end") or "")[:10],
                    "assignment_state": a.get("assignment_state") or "",
                    "status": a.get("status") or "",
                }
                break
        group_role_tags = role_paths_for(gid)
        parents = sorted((graph["group"].get(p) or {}).get("displayName") or p
                         for p in parents_by_child.get(gid, ()))
        children = sorted((graph["group"].get(c) or {}).get("displayName") or c
                          for c in graph["group_member_group"].get(gid, ()))
        sp_members = []
        for s in sorted(effective["sps_by_group"].get(gid, set())):
            if s not in graph["sp"]:
                continue
            tags = {}
            if sp_resolver is not None:
                sp_roles = [r for r in sp_resolver(s) if not r.get("eligible")]
            else:
                sp_roles = list(sp_dir_roles.get(s, []))
            for r in sp_roles:
                tags[r["name"]] = {
                    "name": r["name"], "severity": r["severity"],
                    "path": list(r["path"]) if r.get("path") is not None else None,
                    "kind": "dir", "scope": r.get("scope"),
                    "scope_limited": r.get("scope_limited", False),
                    "disabled": r.get("disabled", False),
                }
            for r in group_role_tags:
                if r["name"] not in tags:
                    tags[r["name"]] = {
                        "name": r["name"], "severity": r["severity"],
                        "path": list(r["path"]), "kind": "dir",
                        "scope": r.get("scope"),
                        "scope_limited": r.get("scope_limited", False),
                        "disabled": r.get("disabled", False),
                    }
            for g in sp_priv_grants.get(s, []):
                key = f"app:{g['name']}"
                if key not in tags:
                    tags[key] = {"name": g["name"], "severity": g["severity"],
                                 "path": None, "kind": "app", "resource": g["resource"]}
            sp_members.append({
                "id": s,
                "name": graph["sp"][s].get("displayName") or s,
                "enabled": bool(graph["sp"][s].get("accountEnabled")),
                "roles": sorted(tags.values(),
                                key=lambda r: severity_rank(role_rating_severity(r))
                                if r.get("kind") == "dir" else severity_rank(r["severity"])),
            })
        sp_members.sort(key=lambda m: (m["name"] or "").lower())

        owner_sps, owner_users = group_owner_chain(graph, gid)
        owners = sorted(user_primary(u) for u in owner_users if u in graph["user"])
        owner_sp_names = sorted(sp_label(s) for s in owner_sps if s in graph["sp"])

        members = []
        for uid in sorted(effective["users_by_group"].get(gid, set())):
            if uid not in graph["user"]:
                continue
            u = graph["user"][uid]
            merged = {}
            for r in user_roles.get(uid, []):
                entry = dict(r)
                entry["path"] = None
                merged[r["name"]] = entry
            for r in member_group_roles(uid):
                if r["name"] not in merged:
                    merged[r["name"]] = dict(r)
                else:
                    merge_role_entry(merged[r["name"]], r)
            roles = sorted(merged.values(),
                           key=lambda r: severity_rank(role_rating_severity(r)))
            members.append({
                "name": u.get("displayName") or uid,
                "upn": u.get("userPrincipalName") or "",
                "roles": roles,
                "privileged": any(is_privileged(role_rating_severity(r)) for r in roles),
            })
        members.sort(key=lambda m: (not m["privileged"], (m["name"] or "").lower()))
        priv_members = [m for m in members if m["privileged"]]

        role_sevs = [role_rating_severity(r) for r in dir_roles]
        if role_sevs:
            severity = min(role_sevs, key=severity_rank)
        elif assignable:
            severity = "High"
        elif gid in capable:
            severity = "Medium"
        else:
            severity = "Info"

        parts = []
        if dir_roles:
            parts.append("grants " + ", ".join(sorted({r["name"] for r in dir_roles})))
        if eligible_roles:
            parts.append(f"{len(eligible_roles)} PIM-eligible role(s)")
        if assignable:
            parts.append("assignable to role")
        if dynamic:
            parts.append("auto-membership rule")
        if priv_members:
            parts.append(f"{len(priv_members)} privileged member(s)")
        if sp_members:
            parts.append(f"{len(sp_members)} SP member(s)")
        if az_roles:
            parts.append("ARM roles: " + ", ".join(sorted({a["role"] for a in az_roles})))

        f = make_finding(
            check_id="groups", category="groups",
            severity=severity,
            title=f"Group: {name}",
            evidence=" · ".join(parts) or "no privilege signals captured",
            remediation=("Review the group's membership, owners, and role assignments; "
                         "members inherit directory roles placed on the group, so restrict "
                         "both the roles and who can join."),
            primary_id=gid,
            object_ids={},
            target={"type": "Group", "name": name, "id": gid},
            status=None,
        )
        f["group_id"] = gid
        f["group_name"] = name
        f["group_source"] = "AD" if synced else "Cloud"
        f["group_synced"] = synced
        f["types"] = types
        f["visibility"] = visibility
        f["is_public"] = is_public
        f["mail"] = mail
        f["rule"] = rule
        f["dynamic"] = dynamic
        f["assignable"] = assignable
        f["dir_roles"] = dir_roles
        f["eligible_roles"] = eligible_roles
        f["parents"] = parents
        f["children"] = children
        f["owners"] = owners + [f"{n} (service principal)" for n in owner_sp_names]
        f["owner_sps"] = owner_sp_names
        f["members"] = members
        f["sp_members"] = sp_members
        device_members = effective["devices_by_group"].get(gid, set())
        f["device_member_count"] = len(device_members)
        f["nested_group_count"] = len(effective["groups_by_group"].get(gid, set()))
        f["member_count"] = len(members) + len(sp_members) + len(device_members)
        f["user_member_count"] = len(members)
        f["priv_member_count"] = len(priv_members)
        f["dyn_rule"] = rule if dynamic else ""
        f["dyn_attrs"] = dyn_attrs
        f["dyn_mods"] = dyn_mods
        f["az_roles"] = az_roles
        findings.append(f)

    findings.sort(key=lambda f: (severity_rank(f["severity"]), (f["group_name"] or "").lower()))
    return findings



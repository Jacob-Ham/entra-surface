"""Privileged-user roster check."""
from __future__ import annotations

from collections import defaultdict

from ..findings import eligible_severity, is_privileged, make_finding, severity_rank
from ..graph import (
    app_owner_chain, compute_effective_group_membership, group_owner_chain,
    group_parents_index, json_list, role_assignment_count_for_sp,
    role_assignments_for_sp, sp_owner_details,
)
from ..policy import policy_state_from_record
from ..roles import (
    _directory_role_disabled, _pim_role_def_name, _role_def_disabled,
    direct_directory_roles_by_user, is_pim_directory_assignment,
    make_directory_role_entry, merge_role_entry, pim_scope_label,
    resolve_group_role_paths, role_display_name, role_rating_severity,
)


def check_privileged_users(ctx):
    """Aggregate every privilege signal we can attribute per user into one finding.

    Signals: directory roles (lnk_role_member_user + RoleAssignments), PIM-eligible
    roles (rated one notch below the same role held actively), ownership of
    apps/SPs that hold privileged grants (from the app-permission config) or
    directory roles, and membership/ownership of role-capable groups.
    On-prem sync is recorded as context, never rated.
    """
    graph = ctx["graph"]
    role_sev = ctx["check_cfg"]["directory_roles"]
    include_disabled = ctx["include_disabled"]
    resource_index, resource_names = ctx["resource_index"], ctx["resource_names"]

    def sev_of(name):
        return role_sev.get(name, "Info")

    def def_name(oid):
        rec = graph["role_definition"].get(oid)
        return rec.get("displayName") if rec else oid

    def sp_name(sp):
        return sp.get("displayName") or sp.get("appDisplayName") or sp.get("objectId")

    # ---- role-capable groups (shared with the groups check) ---------------
    capable = ctx["capable_groups"]
    group_roles = ctx["group_roles"]
    group_eligible_roles = ctx.get("group_eligible_roles") or {}

    # ---- privileged app grants per SP ------------------------------------
    grants_by_sp = {}  # sp_oid -> [(permission, severity, resource)]
    for ra in graph["role_assigns"]:
        if ra["principal_type"] != "ServicePrincipal":
            continue
        ri = resource_index.get(ra["resource_id"], {}).get(ra["app_role_id"])
        if ri:
            grants_by_sp.setdefault(ra["principal_id"], []).append(
                (ri["value"], ri["severity"], resource_names.get(ra["resource_id"], ra["resource_id"])))

    profiles = {}

    def ensure(uid):
        p = profiles.get(uid)
        if p is None:
            p = profiles[uid] = {
                "roles": [], "eligible_roles": [], "priv_apps": [], "dir_sp_roles": [],
                "cap_member": [], "owned_cap": [], "member_count": 0, "owned_count": 0,
                "groups": [], "hybrid": False, "enabled": True, "owned_objects": [],
            }
        return p

    def group_name(gid):
        rec = graph["group"].get(gid)
        return rec.get("displayName") if rec else gid

    # ---- CA policy exclusions (per-user attribute with drill-down data) ----
    def _policy_state(prec):
        return policy_state_from_record(prec)

    def _user_label(uid):
        u = graph["user"].get(uid)
        return (u.get("userPrincipalName") or u.get("displayName") or uid) if u else uid

    ca_policy_info = {}
    ca_exclusions = defaultdict(list)
    for pol, uid in graph["policy_user_exclude"]:
        prec = graph["policy"].get(pol)
        if not prec or prec.get("policyType") != 18:
            continue
        if _policy_state(prec) == "Disabled":
            continue
        if pol not in ca_policy_info:
            inc = {u2 for p2, u2 in graph["policy_user_include"] if p2 == pol}
            exc = {u2 for p2, u2 in graph["policy_user_exclude"] if p2 == pol}
            ca_policy_info[pol] = {
                "name": prec.get("displayName") or pol,
                "state": _policy_state(prec),
                "scope": ("all users" if pol in graph["policy_include_allusers"]
                          else f"{len(inc)} included user(s)" if inc else "no user scope captured"),
                "excluded": sorted(_user_label(u2) for u2 in exc if u2 in graph["user"]),
                "included": sorted(_user_label(u2) for u2 in inc if u2 in graph["user"]),
            }
        ca_exclusions[uid].append(ca_policy_info[pol])

    # seed the roster: every user, linked or not
    for uid in graph["user"]:
        ensure(uid)

    # device ownership (user -> devices), per lnk_device_owner
    user_devices = defaultdict(list)
    for did, uids in graph["device_owners"].items():
        for uid in uids:
            user_devices[uid].append(did)

    # ---- direct directory roles ------------------------------------------
    direct_user_roles = ctx.get("direct_user_roles")
    if direct_user_roles is None:
        direct_user_roles = direct_directory_roles_by_user(graph, role_sev)
    for uid, roles in direct_user_roles.items():
        if uid not in graph["user"]:
            continue
        p = ensure(uid)
        p["roles"].extend(roles)

    # ---- directory roles on owned SPs (direct, legacy role membership, and
    # group-inherited incl. nesting) ----------------------------------------
    analysis_indexes = ctx.get("analysis_indexes") or {}
    assignments_by_principal = analysis_indexes.get("assignments_by_principal")
    role_members_by_sp = analysis_indexes.get("role_members_by_sp")
    groups_by_sp = analysis_indexes.get("groups_by_sp")
    parents_by_child = analysis_indexes.get("parents_by_child") or graph.get(
        "group_parents") or group_parents_index(graph["group_member_group"])

    def sp_dir_roles(sp_oid):
        """Active directory roles of an SP: direct assignments, classic role
        memberships, and roles inherited through group memberships (nested)."""
        merged = {}

        def add(entry):
            if entry["name"] not in merged:
                merged[entry["name"]] = entry
            else:
                merge_role_entry(merged[entry["name"]], entry)

        assignments = assignments_by_principal.get(sp_oid, ()) \
            if assignments_by_principal is not None else \
            [ra for ra in graph["directory_role_assigns"] if ra["principal_id"] == sp_oid]
        for ra in assignments:
            name = def_name(ra["role_definition_id"])
            role_rec = graph["role_definition"].get(ra["role_definition_id"]) or {}
            add(make_directory_role_entry(
                graph, name, sev_of(name), scopes=ra.get("resource_scopes"),
                disabled=_role_def_disabled(role_rec)))
        role_oids = role_members_by_sp.get(sp_oid, ()) \
            if role_members_by_sp is not None else \
            [r for r, sid in graph["role_member_sp"] if sid == sp_oid]
        for role_oid in role_oids:
            rec = graph["directory_role"].get(role_oid) or {}
            name = rec.get("displayName") or role_oid
            add(make_directory_role_entry(
                graph, name, sev_of(name), scopes="/",
                disabled=_directory_role_disabled(rec)))
        direct_groups = groups_by_sp.get(sp_oid, set()) \
            if groups_by_sp is not None else \
            {gid for gid, sps in graph["group_member_sp"].items() if sp_oid in sps}
        stack = list(direct_groups)
        seen = set()
        while stack:
            gid = stack.pop()
            if gid in seen:
                continue
            seen.add(gid)
            for r in group_roles.get(gid) or []:
                add(dict(r))
            stack.extend(parents_by_child.get(gid, ()))
        return list(merged.values())

    for sp_oid, sp in graph["sp"].items():
        roles = sp_dir_roles(sp_oid)
        if not roles:
            continue
        entries = [{"sp_name": sp_name(sp), "role": role_display_name(r),
                    "severity": role_rating_severity(r),
                    "base_severity": r.get("severity"), "scope": r.get("scope")}
                   for r in roles]
        _, owners = sp_owner_details(graph, sp_oid)
        # owners of the app registration behind the SP inherit the same
        # takeover (they can add credentials to the SP)
        for a_oid in graph["app_by_appid"].get(sp.get("appId"), []):
            _, app_users = app_owner_chain(graph, a_oid)
            owners |= app_users
        for owner in owners:
            if owner not in graph["user"]:
                continue
            for entry in entries:
                ensure(owner)["dir_sp_roles"].append(dict(entry))

    for ea in graph["eligible_role_assigns"]:
        pid = ea["principal_id"]
        if pid in graph["user"]:
            p = ensure(pid)
            name = def_name(ea["role_definition_id"])
            role_rec = graph["role_definition"].get(ea["role_definition_id"]) or {}
            entry = make_directory_role_entry(
                graph, name, eligible_severity(sev_of(name)),
                scopes=ea.get("resource_scopes"), source="PIM eligible",
                disabled=_role_def_disabled(role_rec), eligible=True)
            p["eligible_roles"].append(entry)

    # v2-only eligible assignments (roadrecon pimgather) when the legacy v1
    # tables don't carry them. Only aadroles rows are directory roles.
    for a in graph.get("pim_role_assignments") or []:
        if (a.get("assignment_state") or "").lower() != "eligible":
            continue
        if not is_pim_directory_assignment(graph, a):
            continue
        subject = graph.get("pim_assign_subject", {}).get(a["id"]) or a.get("subject_id")
        if not subject or subject not in graph["user"]:
            continue
        name = _pim_role_def_name(graph, a.get("role_definition_id"))
        p = ensure(subject)
        if any(r["name"] == name for r in p["eligible_roles"]):
            continue
        role_rec = graph["role_definition"].get(a.get("role_definition_id")) or {}
        entry = make_directory_role_entry(
            graph, name, eligible_severity(sev_of(name)),
            scopes=a.get("scoped_resource_id"), source="PIM eligible",
            disabled=_role_def_disabled(role_rec), eligible=True)
        p["eligible_roles"].append(entry)

    # ---- group memberships / ownership -------------------------------------
    group_path_cache = {}

    def path_roles_for(gid):
        if gid not in group_path_cache:
            group_path_cache[gid] = resolve_group_role_paths(
                gid, group_roles, graph["group_member_group"], group_name)
        return group_path_cache[gid]

    eligible_path_cache = {}

    def eligible_paths_for(gid):
        if gid not in eligible_path_cache:
            eligible_path_cache[gid] = resolve_group_role_paths(
                gid, group_eligible_roles, graph["group_member_group"], group_name)
        return eligible_path_cache[gid]

    effective = analysis_indexes.get("effective_membership") \
        or compute_effective_group_membership(graph)

    # Membership lists/counts use effective membership (nested groups included),
    # while hierarchy and role paths stay on the direct containment edges.
    for uid, gids in effective["groups_by_user"].items():
        if uid not in graph["user"]:
            continue
        p = ensure(uid)
        for gid in sorted(gids):
            rec = graph["group"].get(gid)
            if not rec:
                continue
            gname = rec.get("displayName") or gid
            p["groups"].append({
                "name": gname,
                "group_id": gid,
                "capable": gid in capable,
                "roles": path_roles_for(gid) or group_roles.get(gid, []),
            })
            if gid in capable:
                p["cap_member"].append({
                    "name": gname,
                    "roles": path_roles_for(gid) or group_roles.get(gid, []),
                })
        p["member_count"] = len(p["groups"])

    # Inherited privileges are attributed from each *direct* group membership,
    # which keeps the real intermediate groups in the via path.
    for gid, uids in graph["group_member_user"].items():
        inherited = path_roles_for(gid)
        inherited_eligible = eligible_paths_for(gid)
        for uid in uids:
            if uid not in graph["user"]:
                continue
            p = ensure(uid)
            # directory roles inherited through this group (incl. nesting),
            # with the group path — same treatment as service principals
            for r in inherited:
                entry = dict(r)
                entry["source"] = "via " + " \u2192 ".join(r["path"])
                p["roles"].append(entry)
            # PIM-eligible roles inherited through this group (incl. nesting)
            for r in inherited_eligible:
                entry = dict(r)
                entry["source"] = "PIM eligible via " + " \u2192 ".join(r["path"])
                entry["path"] = list(r["path"])
                entry["path_ids"] = list(r.get("path_ids") or [])
                p["eligible_roles"].append(entry)

    # Group ownership includes users who own an SP that owns the group, and
    # inherits roles carried by ancestor groups (B-034 / B-035).
    owned_group_ids = set(graph["group_owner_user"]) | set(graph.get("group_owner_sp") or {})
    for gid in owned_group_ids:
        _, owners = group_owner_chain(graph, gid)
        for uid in owners:
            if uid not in graph["user"]:
                continue
            p = ensure(uid)
            p["owned_count"] += 1
            if gid in capable:
                p["owned_cap"].append({
                    "name": group_name(gid),
                    "roles": path_roles_for(gid) or group_roles.get(gid, []),
                })

    # ---- ownership of privileged objects -----------------------------------
    seen_owner_sp = set()  # (uid, sp_oid) already attributed via the app
    for app_oid in set(graph["app_owners"]) | set(graph.get("app_owner_sp") or {}):
        app = graph["app"].get(app_oid)
        if not app:
            continue
        sp_oids = graph["sp_by_appid"].get(app.get("appId"), [])
        app_grants = []
        for sp_oid in sp_oids:
            if sp_oid in grants_by_sp:
                app_grants += [{"permission": g[0], "severity": g[1], "resource": g[2]}
                               for g in grants_by_sp[sp_oid]]
        if not app_grants:
            continue
        _, owner_users = app_owner_chain(graph, app_oid)
        for uid in owner_users:
            if uid not in graph["user"]:
                continue
            for sp_oid in sp_oids:
                seen_owner_sp.add((uid, sp_oid))
            ensure(uid)["priv_apps"].append(
                {"app_name": app.get("displayName") or app_oid, "grants": app_grants,
                 "kind": "application"})

    for sp_oid in set(graph["sp_owners"]) | set(graph.get("sp_owner_sp") or {}):
        if sp_oid not in grants_by_sp:
            continue
        grants = [{"permission": g[0], "severity": g[1], "resource": g[2]} for g in grants_by_sp[sp_oid]]
        sp = graph["sp"].get(sp_oid) or {}
        label = sp_name(sp) if sp else sp_oid
        _, owner_users = sp_owner_details(graph, sp_oid)
        for uid in owner_users:
            if uid not in graph["user"]:
                continue
            if (uid, sp_oid) in seen_owner_sp:
                continue
            seen_owner_sp.add((uid, sp_oid))
            ensure(uid)["priv_apps"].append(
                {"app_name": label, "grants": grants, "kind": "service principal"})

    # ---- owned objects (full inventory, not only privileged) --------------
    def creds_of(record):
        return (len(json_list(record.get("passwordCredentials"))),
                len(json_list(record.get("keyCredentials"))))

    for app_oid in set(graph["app_owners"]) | set(graph.get("app_owner_sp") or {}):
        app = graph["app"].get(app_oid)
        if not app:
            continue
        sp_oids = graph["sp_by_appid"].get(app.get("appId"), [])
        grants = []
        sp_status = None
        for sp_oid in sp_oids:
            for g in grants_by_sp.get(sp_oid, []):
                grants.append({"permission": g[0], "severity": g[1], "resource": g[2]})
            sp = graph["sp"].get(sp_oid)
            if sp is not None and sp_status is None:
                sp_status = bool(sp.get("accountEnabled"))
        pw, key = creds_of(app)
        entry = {
            "type": "Application",
            "name": app.get("displayName") or app_oid,
            "object_id": app_oid,
            "app_id": app.get("appId") or "",
            "grants": grants,
            "pw": pw, "key": key,
            "status": sp_status,
        }
        _, owner_users = app_owner_chain(graph, app_oid)
        for uid in owner_users:
            if uid in graph["user"]:
                ensure(uid)["owned_objects"].append(entry)

    for sp_oid in set(graph["sp_owners"]) | set(graph.get("sp_owner_sp") or {}):
        sp = graph["sp"].get(sp_oid)
        if not sp:
            continue
        pw, key = creds_of(sp)
        entry = {
            "type": "Service Principal",
            "name": sp.get("displayName") or sp.get("appDisplayName") or sp_oid,
            "object_id": sp_oid,
            "app_id": sp.get("appId") or "",
            "grants": [{"permission": g[0], "severity": g[1], "resource": g[2]}
                       for g in grants_by_sp.get(sp_oid, [])],
            "pw": pw, "key": key,
            "status": bool(sp.get("accountEnabled")),
        }
        _, owner_users = sp_owner_details(graph, sp_oid)
        for uid in owner_users:
            if uid in graph["user"]:
                ensure(uid)["owned_objects"].append(entry)

    for gid in set(graph["group_owner_user"]) | set(graph.get("group_owner_sp") or {}):
        grp = graph["group"].get(gid)
        if not grp:
            continue
        entry = {
            "type": "Group",
            "name": grp.get("displayName") or gid,
            "object_id": gid,
            "app_id": "",
            "grants": [],
            "pw": 0, "key": 0,
            "status": None,
        }
        _, owner_users = group_owner_chain(graph, gid)
        for uid in owner_users:
            if uid in graph["user"]:
                ensure(uid)["owned_objects"].append(entry)

    # ---- hybrid / context ---------------------------------------------------
    def dedupe_roles(roles):
        merged = {}
        for r in roles:
            key = r["name"]
            src = r.get("source") or "assigned"
            entry = dict(r)
            entry["source"] = src
            if key not in merged:
                merged[key] = entry
            else:
                merge_role_entry(merged[key], entry)
        return sorted(merged.values(),
                      key=lambda r: severity_rank(role_rating_severity(r)))

    for p in profiles.values():
        p["roles"] = dedupe_roles(p["roles"])
        p["eligible_roles"] = dedupe_roles(p["eligible_roles"])

    for uid, p in profiles.items():
        user = graph["user"].get(uid) or {}
        p["hybrid"] = user.get("dirSyncEnabled") in (1, True)
        p["enabled"] = bool(user.get("accountEnabled"))
        p["user_type"] = user.get("userType") or "Member"
        p["ca_exclusions"] = sorted(ca_exclusions.get(uid, ()), key=lambda x: x["name"])
        # PIM v2 schedule details (permanence / member type / activation
        # window) when `roadrecon pimgather` governance data is present.
        # Group-inherited eligibility matches the eligibility on the group.
        if graph.get("pim_role_assignments"):
            for r in p["eligible_roles"]:
                # Match the PIM subject by object ID: path_ids also contains
                # the real intermediate groups (B-081).
                subjects = {uid} | set(r.get("path_ids") or [])
                for a in graph["pim_role_assignments"]:
                    if (a.get("assignment_state") or "").lower() != "eligible":
                        continue
                    if not is_pim_directory_assignment(graph, a):
                        continue
                    subject = graph["pim_assign_subject"].get(a["id"]) or a.get("subject_id")
                    if subject not in subjects:
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
        p["owned_objects"] = sorted(p.get("owned_objects", []),
                                    key=lambda o: (o["type"], (o["name"] or "").lower()))
        seen_oids = set()
        uniq = []
        for o in p["owned_objects"]:
            if o["object_id"] in seen_oids:
                continue
            seen_oids.add(o["object_id"])
            uniq.append(o)
        p["owned_objects"] = uniq
        devices = []
        for did in user_devices.get(uid, []):
            dev = graph["device"].get(did)
            if not dev:
                continue
            devices.append({
                "name": dev.get("displayName") or did,
                "object_id": did,
                "os": dev.get("deviceOSType") or "",
                "ad_bound": bool(dev.get("onPremisesSecurityIdentifier")),
                "last_logon": dev.get("approximateLastLogonTimestamp") or "",
                "enabled": bool(dev.get("accountEnabled")),
            })
        devices.sort(key=lambda d: (d["name"] or "").lower())
        p["devices"] = devices

    # ---- findings ------------------------------------------------------------
    findings = []
    for uid, p in profiles.items():
        user = graph["user"].get(uid)
        if not user:
            continue  # stale links must not create unresolved user findings (B-082)
        if user.get("deletionTimestamp"):
            continue  # soft-deleted users are excluded; disabled users stay listed (status column)
        sevs = [role_rating_severity(r) for r in p["roles"]] \
            + [role_rating_severity(r) for r in p["eligible_roles"]]
        sevs += [g["severity"] for app in p["priv_apps"] for g in app["grants"]]
        sevs += [s["severity"] for s in p["dir_sp_roles"]]
        if p["cap_member"]:
            sevs.append("Medium")
        # owning a role-capable group is a takeover path: rate by the roles
        # the group actually carries; capable-but-unassigned groups stay High
        for g in p["owned_cap"]:
            role_sevs = [role_rating_severity(r) for r in (g.get("roles") or [])]
            if role_sevs:
                sevs += role_sevs
            else:
                sevs.append("High")
        display = user.get("displayName") or user.get("userPrincipalName") or uid
        upn = user.get("userPrincipalName") or ""

        if not sevs:
            severity = "Info"
            parts = ["no privilege signals captured"]
        else:
            severity = min(sevs, key=severity_rank)
            parts = []
            if p["roles"]:
                parts.append(f"{len(p['roles'])} directory role(s)")
            if p["eligible_roles"]:
                parts.append(f"{len(p['eligible_roles'])} eligible role(s)")
            if p["priv_apps"]:
                parts.append(f"owns {len(p['priv_apps'])} privileged object(s)")
            if p["cap_member"]:
                parts.append(f"member of {len(p['cap_member'])} role-capable group(s)")
            if p["owned_cap"]:
                parts.append(f"owns {len(p['owned_cap'])} role-capable group(s)")

        f = make_finding(
            check_id="privileged_users", category="users",
            severity=severity,
            title=(f"Privileged user: {display}" if severity != "Info" or parts != ["no privilege signals captured"]
                   else f"User: {display}"),
            evidence=" · ".join(parts) or "privilege signal(s) present",
            remediation=(("No privilege signals observed — listed for completeness. "
                          "Nothing to remediate for this account.") if severity == "Info" and not p["roles"] and not p["priv_apps"]
                         else ("Review the user's role assignments, eligibility, and owned objects; "
                               "apply least privilege and require MFA on privileged accounts.")),
            primary_id=uid,
            object_ids={"user": {uid}},
            target={"type": "User", "name": display, "id": uid},
            status={"label": "Enabled" if p["enabled"] else "Disabled", "enabled": p["enabled"]},
        )
        f["user_id"] = uid
        f["user_display"] = display
        f["user_upn"] = upn
        f["user_type"] = p["user_type"]
        f["user_enabled"] = p["enabled"]
        f["hybrid"] = p["hybrid"]
        f["roles"] = sorted(p["roles"], key=lambda r: severity_rank(r["severity"]))
        f["eligible_roles"] = p["eligible_roles"]
        f["priv_apps"] = p["priv_apps"]
        f["dir_sp_roles"] = p["dir_sp_roles"]
        f["cap_member"] = sorted(p["cap_member"], key=lambda c: (c.get("name") or "").lower())
        f["owned_cap"] = sorted(p["owned_cap"], key=lambda c: (c.get("name") or "").lower())
        f["groups"] = sorted(p["groups"], key=lambda g: (g.get("name") or "").lower())
        f["member_count"] = p["member_count"]
        f["owned_count"] = p["owned_count"]
        f["owned_objects"] = p.get("owned_objects", [])
        f["devices"] = p.get("devices", [])
        f["ca_exclusions"] = p.get("ca_exclusions", [])
        findings.append(f)

    findings.sort(key=lambda f: (severity_rank(f["severity"]), (f["user_display"] or "").lower()))
    return findings



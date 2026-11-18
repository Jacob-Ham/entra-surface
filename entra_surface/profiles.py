"""On-demand entity detail and drawer-profile builders.

Pure module: reads details from a database cursor and builds SP/app profiles
from the entity graph. Shared by the HTTP endpoints.
"""
from __future__ import annotations

from collections import defaultdict

from .graph import (
    app_owner_chain, chunked, compute_effective_group_membership, fetch_by_ids,
    group_parents_index, json_list, json_safe_value, sp_owner_details,
)
from .roles import (
    compute_group_eligible_roles, compute_group_roles, make_sp_dir_resolver,
)

SYSTEM_DEFAULT_ROLE_ID = "00000000-0000-0000-0000-000000000000"
SYSTEM_DEFAULT_ROLE = {"value": "Default", "description": "Default Role"}


# ---------------------------------------------------------------------------
# Detail-view fields (drilldown modal)
# ---------------------------------------------------------------------------

DEVICE_DETAIL_FIELDS = [
    "displayName", "objectId", "accountEnabled", "deviceOSType", "deviceOSVersion",
    "deviceModel", "deviceManufacturer", "deviceCategory", "deviceOwnership",
    "deviceTrustType", "enrollmentType", "enrollmentProfileName", "managementType",
    "isCompliant", "isManaged", "isRooted", "dirSyncEnabled",
    "onPremisesSecurityIdentifier", "hostnames", "domainName",
    "approximateLastLogonTimestamp", "lastDirSyncTime", "alternativeSecurityIds",
]

USER_DETAIL_FIELDS = [
    "displayName", "userPrincipalName", "mail", "objectId", "accountEnabled", "userType",
    "jobTitle", "department", "companyName", "officeLocation", "city", "country",
    "createdDateTime", "dirSyncEnabled",
    "onPremisesUserPrincipalName", "onPremisesObjectIdentifier", "onPremisesSecurityIdentifier",
    "onPremisesDistinguishedName", "onPremisesPasswordChangeTimestamp", "lastDirSyncTime",
    "immutableId", "hasOnPremisesShadow", "isResourceAccount", "creationType",
    "provisioningErrors",
    "lastPasswordChangeDateTime", "refreshTokensValidFromDateTime", "isCompromised",
    "strongAuthenticationDetail", "employeeId", "employeeType", "usageLocation",
]


def fetch_full_details(cur, sp_ids, app_ids, user_ids, device_ids=None):
    """Fetch attributes for the 'expand' drawers. SPs and applications get every
    captured column (for the Raw tab); users and devices keep a curated set.
    SP raw records additionally carry the linked Application row and the raw
    ARM role assignments, so the Raw tab shows everything captured about the
    principal."""
    def fetch_all(table, id_column, ids, wanted_fields):
        ids = {i for i in ids if i}
        if not ids:
            return {}
        cur.execute(f"PRAGMA table_info({table})")
        available = {r[1] for r in cur.fetchall()}
        if wanted_fields is None:
            fields = [c for c in available if c != id_column]
        else:
            fields = [f for f in wanted_fields if f in available]
        fields = [id_column] + fields
        try:
            rows = fetch_by_ids(cur, table, id_column, fields, ids)
        except sqlite3.OperationalError:
            return {}
        id_index = fields.index(id_column)
        result = {}
        for row in rows:
            record = {}
            for col, val in zip(fields, row):
                if val is None or val == "":
                    continue
                parsed = json_safe_value(val)
                if parsed == [] or parsed == {}:
                    continue
                record[col] = parsed
            result[row[id_index]] = record
        return result

    def clean(record):
        return {c: v for c, v in record.items()
                if v is not None and v != "" and v != [] and v != {}}

    def enrich_sp_raw(sp_records):
        """Add 'application' (full Applications row behind the SP) and
        'azure_roles' (raw ARM role assignments incl. eligibility) to every SP
        raw record. Defensive: AZ* tables only exist after azgather."""
        try:
            cur.execute("PRAGMA table_info(Applications)")
            app_cols = {r[1] for r in cur.fetchall()}
            if {"appId", "objectId"}.issubset(app_cols):
                for rec in sp_records.values():
                    app_id = rec.get("appId")
                    if not app_id or "application" in rec:
                        continue
                    cur.execute("SELECT * FROM Applications WHERE appId=? LIMIT 1",
                                (app_id,))
                    row = cur.fetchone()
                    if row is None:
                        continue
                    cols = [d[0] for d in cur.description]
                    app = clean({c: json_safe_value(v) for c, v in zip(cols, row)})
                    if app:
                        rec["application"] = app
        except sqlite3.OperationalError:
            pass
        rd_roles = {}
        try:
            # AZroleDefinitions.name holds the bare GUID while assignment
            # role_definition_id is the full provider path — map in Python
            cur.execute("SELECT name, role_name FROM AZroleDefinitions")
            rd_roles = {guid: rname for guid, rname in cur.fetchall()
                        if guid and rname}
        except sqlite3.OperationalError:
            pass
        try:
            cur.execute("PRAGMA table_info(AZroleAssignments)")
            ra_cols = {r[1] for r in cur.fetchall()}
            if {"id", "scope", "role_definition_id"}.issubset(ra_cols):
                cur.execute(
                    "SELECT sp.ServicePrincipal, ra.id, ra.scope, ra.role_definition_id, "
                    "ra.created_on, ra.condition "
                    "FROM lnk_az_roleassignment_serviceprincipal sp "
                    "JOIN AZroleAssignments ra ON ra.id = sp.AZroleAssignment")
                for oid, ra_id, scope, rd_id, created, cond in cur.fetchall():
                    rec = sp_records.get(oid)
                    if rec is None:
                        continue
                    rec.setdefault("azure_roles", []).append(clean({
                        "id": ra_id, "scope": scope,
                        "role_definition_id": rd_id,
                        "role": rd_roles.get((rd_id or "").rsplit("/", 1)[-1], ""),
                        "created_on": created, "condition": cond,
                    }))
        except sqlite3.OperationalError:
            pass
        try:
            cur.execute("PRAGMA table_info(AZroleEligibilityScheduleInstances)")
            ec_cols = {r[1] for r in cur.fetchall()}
            if {"id", "scope", "role_definition_id"}.issubset(ec_cols):
                cur.execute(
                    "SELECT sp.ServicePrincipal, e.id, e.scope, e.role_definition_id, "
                    "e.status, e.start_date_time, e.end_date_time "
                    "FROM lnk_az_roleassignment_eligible_serviceprincipal sp "
                    "JOIN AZroleEligibilityScheduleInstances e "
                    "  ON e.id = sp.AZroleEligibilityScheduleInstance")
                for oid, eid, scope, rd_id, status, start, end in cur.fetchall():
                    rec = sp_records.get(oid)
                    if rec is None:
                        continue
                    rec.setdefault("azure_roles", []).append(clean({
                        "id": eid, "scope": scope,
                        "role_definition_id": rd_id,
                        "role": rd_roles.get((rd_id or "").rsplit("/", 1)[-1], ""),
                        "eligible": True, "status": status,
                        "start": start, "end": end,
                    }))
        except sqlite3.OperationalError:
            pass
        return sp_records

    sp_records = fetch_all("ServicePrincipals", "objectId", sp_ids, None)
    sp_records = enrich_sp_raw(sp_records)
    device_records = fetch_all("Devices", "objectId", device_ids or set(),
                               DEVICE_DETAIL_FIELDS)
    if device_records:
        # Device drawers carry the registered owners (name / UPN / object id)
        # alongside the device record so the drawer is useful without opening
        # each owner separately.
        try:
            owner_by_device = {}
            for chunk in chunked(list(device_records), SQLITE_IN_CHUNK):
                placeholders = ",".join("?" * len(chunk))
                cur.execute(f'SELECT Device, "User" FROM lnk_device_owner '
                            f'WHERE Device IN ({placeholders})', chunk)
                for did, uid in cur.fetchall():
                    if did and uid:
                        owner_by_device.setdefault(did, set()).add(uid)
            owner_ids = set()
            for ids in owner_by_device.values():
                owner_ids |= ids
            owner_records = fetch_all("Users", "objectId", owner_ids,
                                      USER_DETAIL_FIELDS)
            for did, rec in device_records.items():
                owners = []
                for uid in sorted(owner_by_device.get(did, ())):
                    user = owner_records.get(uid) or {}
                    owners.append({
                        "name": user.get("displayName") or uid,
                        "upn": user.get("userPrincipalName") or "",
                        "objectId": uid,
                        "enabled": bool(user.get("accountEnabled")),
                    })
                if owners:
                    rec["owners"] = owners
        except sqlite3.OperationalError:
            pass
    return {
        "sp": sp_records,
        "app": fetch_all("Applications", "objectId", app_ids, None),
        "user": fetch_all("Users", "objectId", user_ids, USER_DETAIL_FIELDS),
        "device": device_records,
    }


def make_profile_builder(graph, check_cfg, group_roles=None, group_eligible_roles=None,
                         sp_dir_resolver=None):
    """On-demand builder for the tabbed SP/app 'more info' drawer profiles.

    Indexes the app-role assignment list (by resource and by principal) and
    the group memberships (SP -> groups) once, so building a single profile
    costs O(roles of that principal) instead of full-table scans. Profiles are
    memoized."""
    role_sev = check_cfg["directory_roles"]
    role_labels = check_cfg.get("role_labels") or {}
    dir_role_desc = check_cfg.get("directory_role_descriptions") or {}
    if group_roles is None:
        group_roles = compute_group_roles(graph, check_cfg)
    if group_eligible_roles is None:
        group_eligible_roles = compute_group_eligible_roles(graph, check_cfg)
    if sp_dir_resolver is None:
        sp_dir_resolver = make_sp_dir_resolver(graph, group_roles, role_sev,
                                               group_eligible_roles)
    app_roles_cache = {}   # sp_oid -> {role_id: {value, description}}
    profile_cache = {}     # sp_oid / app_oid -> profile

    ra_by_resource = defaultdict(list)
    ra_by_principal = defaultdict(list)
    for ra in graph["role_assigns"]:
        ra_by_resource[ra["resource_id"]].append(ra)
        if ra["principal_type"] == "ServicePrincipal":
            ra_by_principal[ra["principal_id"]].append(ra)
    sp_groups = defaultdict(set)
    group_parents = graph.get("group_parents") or group_parents_index(
        graph.get("group_member_group"))
    for gid, members in graph["group_member_sp"].items():
        for sid in members:
            sp_groups[sid].add(gid)
    # The drawer lists effective group memberships (direct + ancestors); the
    # role paths themselves still use the direct containment edges.
    for sid, gids in list(sp_groups.items()):
        stack = list(gids)
        seen = set(gids)
        while stack:
            gid = stack.pop()
            for parent in group_parents.get(gid, ()):
                if parent not in seen:
                    seen.add(parent)
                    stack.append(parent)
        sp_groups[sid] = seen

    def catalog_entry(value, description):
        return {"value": value,
                "description": role_labels.get(value) or (description or "")}

    def resource_roles(sp_oid):
        if sp_oid not in app_roles_cache:
            rec = graph["sp"].get(sp_oid)
            index = {}
            for role in json_list(rec.get("appRoles") if rec else None):
                if isinstance(role, dict) and role.get("id"):
                    index[role["id"]] = catalog_entry(
                        role.get("value") or role["id"], role.get("description") or "")
            # ApplicationRefs role catalog by appId (fallback when the SP column is sparse)
            if rec and rec.get("appId"):
                for rid, entry in graph["appref_roles"].get(rec["appId"], {}).items():
                    if rid not in index:
                        index[rid] = catalog_entry(entry["value"], entry["description"])
            # Microsoft system role exposed by every application
            index.setdefault(SYSTEM_DEFAULT_ROLE_ID,
                             catalog_entry(SYSTEM_DEFAULT_ROLE["value"],
                                           SYSTEM_DEFAULT_ROLE["description"]))
            app_roles_cache[sp_oid] = index
        return app_roles_cache[sp_oid]

    def sp_label(sp_oid):
        rec = graph["sp"].get(sp_oid)
        return (rec.get("displayName") or rec.get("appDisplayName") or sp_oid) if rec else sp_oid

    def app_label(app_id):
        oids = graph["app_by_appid"].get(app_id, [])
        if not oids:
            return ""
        rec = graph["app"].get(oids[0])
        return rec.get("displayName") if rec else ""

    def principal_label(pid, ptype):
        if ptype == "User" and pid in graph["user"]:
            return graph["user"][pid].get("displayName") or pid
        return sp_label(pid)

    def dir_roles_for(sp_oid):
        return [{**role, "description": dir_role_desc.get(role["name"], "")}
                for role in sp_dir_resolver(sp_oid)]

    def groups_for(sp_oid):
        groups = []
        for g in sp_groups.get(sp_oid, ()):
            rec = graph["group"].get(g)
            if rec is None:
                continue  # stale link to a group that was not collected
            groups.append({"id": g, "name": rec.get("displayName") or g})
        return groups

    def _human_owner_entries(owner_ids):
        owners = []
        for uid in owner_ids:
            user = graph["user"].get(uid)
            if not user:
                continue
            owners.append({
                "name": user.get("displayName") or uid,
                "upn": user.get("userPrincipalName") or "",
                "type": user.get("userType") or "Member",
                "enabled": bool(user.get("accountEnabled")),
            })
        return owners

    def _sp_owner_entries(owner_sps):
        entries = []
        for sid in owner_sps:
            rec = graph["sp"].get(sid)
            if not rec:
                continue
            entries.append({
                "name": rec.get("displayName") or rec.get("appDisplayName") or sid,
                "upn": "",
                "type": "ServicePrincipal",
                "enabled": bool(rec.get("accountEnabled")),
            })
        return entries

    def owners_for(sp_oid, app_oids):
        owner_ids = set()
        owner_sps = set()
        for app_oid in app_oids:
            app_sps, app_users = app_owner_chain(graph, app_oid)
            owner_sps |= app_sps
            owner_ids |= app_users
        sp_sps, sp_users = sp_owner_details(graph, sp_oid)
        owner_sps |= sp_sps
        owner_ids |= sp_users
        owners = _human_owner_entries(owner_ids) + _sp_owner_entries(owner_sps)
        owners.sort(key=lambda o: (o["name"] or "").lower())
        return owners

    def role_label(sp_oid, role_id):
        role = resource_roles(sp_oid).get(role_id)
        if role:
            return role["value"]
        return role_id

    effective_membership = ((graph.get("analysis_indexes") or {})
                            .get("effective_membership"))

    def assignment_summary(sp_oid):
        nonlocal effective_membership
        users, groups, sps = set(), set(), set()
        for ra in ra_by_resource.get(sp_oid, ()):
            pid = ra.get("principal_id") or ""
            if not pid:
                continue
            kind = ra.get("principal_type") or ""
            if pid in graph["user"]:
                kind = "User"
            elif pid in graph["group"]:
                kind = "Group"
            elif pid in graph["sp"]:
                kind = "ServicePrincipal"
            if kind == "User":
                users.add(pid)
            elif kind == "Group":
                groups.add(pid)
            elif kind == "ServicePrincipal":
                sps.add(pid)
        effective_users = set(users)
        if groups:
            if effective_membership is None:
                effective_membership = compute_effective_group_membership(graph)
            users_by_group = effective_membership.get("users_by_group") or {}
            for gid in groups:
                effective_users |= set(users_by_group.get(gid) or ())
        return {"users": len(users), "groups": len(groups), "sps": len(sps),
                "effective_users": len(effective_users)}

    def sp_profile(sp_oid):
        if sp_oid in profile_cache:
            return profile_cache[sp_oid]
        if sp_oid not in graph["sp"]:
            return None
        granted = []   # roles this SP exposes, held by other principals
        for ra in ra_by_resource.get(sp_oid, ()):
            role = resource_roles(sp_oid).get(ra["app_role_id"])
            granted.append({
                "principal_name": principal_label(ra["principal_id"], ra["principal_type"]),
                "principal_type": ra["principal_type"] or "ServicePrincipal",
                "role": role_label(sp_oid, ra["app_role_id"]),
                "description": role["description"] if role else "",
            })
        assigned = []  # roles other SPs expose, held by this SP
        for ra in ra_by_principal.get(sp_oid, ()):
            resource_rec = graph["sp"].get(ra["resource_id"])
            role = resource_roles(ra["resource_id"]).get(ra["app_role_id"])
            resource_app = app_label(resource_rec.get("appId")) if resource_rec else ""
            assigned.append({
                "principal_name": sp_label(sp_oid),
                "principal_type": "ServicePrincipal",
                "role": role_label(ra["resource_id"], ra["app_role_id"]),
                "application": resource_app or sp_label(ra["resource_id"]),
                "description": role["description"] if role else "",
            })
        granted.sort(key=lambda r: (r["principal_name"] or "").lower())
        assigned.sort(key=lambda r: (r["role"] or "").lower())
        app_oids = graph["app_by_appid"].get(graph["sp"][sp_oid].get("appId"), []) if sp_oid in graph["sp"] else []
        application = (graph["app"][app_oids[0]].get("displayName") or "") if app_oids else ""
        assignment = assignment_summary(sp_oid)
        prof = {
            "kind": "sp",
            "application": application,
            "app_oid": app_oids[0] if app_oids else "",
            "owners": owners_for(sp_oid, app_oids),
            "dir_roles": dir_roles_for(sp_oid),
            "groups": groups_for(sp_oid),
            "granted_roles": granted,
            "assigned_roles": assigned,
            "az_roles": sorted(graph["az_sp_roles"].get(sp_oid, []),
                               key=lambda a: (a.get("eligible", False), a["role"].lower())),
            "sso_assigned_users": assignment["users"],
            "sso_assigned_groups": assignment["groups"],
            "sso_assigned_sps": assignment["sps"],
            "sso_assigned_user_count": assignment["effective_users"],
        }
        profile_cache[sp_oid] = prof
        return prof

    def app_profile(app_oid):
        if app_oid in profile_cache:
            return profile_cache[app_oid]
        app = graph["app"].get(app_oid)
        if not app:
            return None
        sp_oids = graph["sp_by_appid"].get(app.get("appId"), [])
        granted, assigned, dir_roles, groups = [], [], [], []
        owner_ids = set()
        owner_sps = set()
        app_sps, app_users = app_owner_chain(graph, app_oid)
        owner_sps |= app_sps
        owner_ids |= app_users
        for sp_oid in sp_oids:
            prof = sp_profile(sp_oid)
            if prof is None:
                continue  # stale app -> SP link; skip rather than fail the drawer
            granted += prof["granted_roles"]
            assigned += prof["assigned_roles"]
            dir_roles += prof["dir_roles"]
            groups += prof["groups"]
            sp_sps, sp_users = sp_owner_details(graph, sp_oid)
            owner_sps |= sp_sps
            owner_ids |= sp_users

        def _dedupe(items):
            seen_items = set()
            deduped = []
            for item in items:
                key = (item.get("principal_name"), item.get("role"),
                       item.get("application"), item.get("description"))
                if key not in seen_items:
                    seen_items.add(key)
                    deduped.append(item)
            return deduped

        granted = _dedupe(granted)
        assigned = _dedupe(assigned)
        owner_list = _human_owner_entries(owner_ids) + _sp_owner_entries(owner_sps)
        owner_list.sort(key=lambda o: (o["name"] or "").lower())
        # Directory roles and groups are separate namespaces: a group whose
        # display name equals a role must not be dropped.
        role_seen = set()
        uniq_roles = []
        for r in dir_roles:
            if r["name"] not in role_seen:
                role_seen.add(r["name"])
                uniq_roles.append(r)
        group_seen = set()
        uniq_groups = []
        for g in groups:
            key = g.get("id") or g.get("name")
            if key not in group_seen:
                group_seen.add(key)
                uniq_groups.append(g)
        az_roles = []
        for sp_oid in sp_oids:
            for a in graph["az_sp_roles"].get(sp_oid, []):
                entry = dict(a)
                sp_rec = graph["sp"].get(sp_oid)
                entry["sp_name"] = (sp_rec.get("displayName") or sp_oid) if sp_rec else sp_oid
                az_roles.append(entry)
        az_roles.sort(key=lambda a: (a.get("eligible", False), a["role"].lower()))
        sp_list = []
        for sp_oid in sp_oids:
            sp_rec = graph["sp"].get(sp_oid)
            sp_list.append({
                "object_id": sp_oid,
                "display_name": (sp_rec.get("displayName") or sp_rec.get("appDisplayName")
                                 or sp_oid) if sp_rec else sp_oid,
                "app_id": (sp_rec.get("appId") or "") if sp_rec else "",
            })
        entry = {
            "kind": "app",
            "application": app.get("displayName") or app_oid,
            "owners": owner_list,
            "dir_roles": uniq_roles,
            "groups": uniq_groups,
            "granted_roles": [x for x in granted],
            "assigned_roles": [x for x in assigned],
            "az_roles": az_roles,
            "sp_oids": sp_oids,
            "sp_list": sp_list,
        }
        profile_cache[app_oid] = entry
        return entry

    return {"sp": sp_profile, "app": app_profile}



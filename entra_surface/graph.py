"""SQLite entity graph loader and graph-level indexes.

Pure module: reads a ROADrecon database into the in-memory graph and provides
adjacency/ownership helpers. It does not import checks or the report.
"""
from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from pathlib import Path

SQLITE_IN_CHUNK = 500  # stay well under SQLite's default 999 bound-parameter limit

def chunked(seq, size):
    seq = list(seq)
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def fetch_by_ids(cur, table, id_column, columns, ids):
    """SELECT `columns` FROM `table` WHERE `id_column` IN (ids), batched. Returns list of rows."""
    ids = [i for i in set(ids) if i is not None]
    if not ids:
        return []
    col_sql = ", ".join(columns)
    rows = []
    for chunk in chunked(ids, SQLITE_IN_CHUNK):
        placeholders = ",".join("?" * len(chunk))
        cur.execute(f"SELECT {col_sql} FROM {table} WHERE {id_column} IN ({placeholders})", chunk)
        rows.extend(cur.fetchall())
    return rows


def prune_empty(value):
    """Recursively drop null/empty members so the expanded detail view only shows populated data."""
    if isinstance(value, dict):
        return {k: prune_empty(v) for k, v in value.items() if v not in (None, "", [], {})}
    if isinstance(value, list):
        return [prune_empty(v) for v in value if v not in (None, "")]
    return value


def json_safe_value(value):
    """Parse DB columns that hold JSON-encoded text (appRoles, keyCredentials, etc.) into real objects."""
    if isinstance(value, str) and value[:1] in "[{":
        try:
            return prune_empty(json.loads(value))
        except (json.JSONDecodeError, ValueError):
            return value
    return value


def json_list(value):
    parsed = json_safe_value(value)
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        return [parsed]
    return []


SP_GRAPH_FIELDS = [
    "objectId", "appId", "displayName", "appDisplayName", "accountEnabled",
    "deletionTimestamp", "servicePrincipalType", "appOwnerTenantId",
    "microsoftFirstParty", "appRoleAssignmentRequired", "passwordCredentials",
    "keyCredentials", "appRoles", "publicClient",
    "tags", "managedIdentityResourceId", "alternativeNames", "publisherName",
    # SSO / enterprise-app configuration
    "preferredSingleSignOnMode", "samlSingleSignOnSettings", "samlMetadataUrl",
    "notificationEmailAddresses", "preferredTokenSigningKeyThumbprint",
    "preferredTokenSigningKeyEndDateTime", "useCustomTokenSigningKey",
    "tokenEncryptionKeyId", "replyUrls", "homepage", "logoutUrl",
    "verifiedPublisher", "certification", "applicationTemplateId",
    "disabledByMicrosoftStatus", "oauth2Permissions",
    "resourceSpecificApplicationPermissions", "servicePrincipalNames",
]
APP_GRAPH_FIELDS = [
    "objectId", "appId", "displayName", "publicClient", "oauth2AllowImplicitFlow",
    "oauth2AllowIdTokenImplicitFlow", "availableToOtherTenants", "publisherDomain",
    "verifiedPublisher", "passwordCredentials", "keyCredentials",
    "requiredResourceAccess", "appRoles",
    # sign-in / SSO-adjacent registration fields
    "signInAudience", "identifierUris", "replyUrls", "oauth2Permissions",
    "homepage", "logoutUrl", "disabledByMicrosoftStatus", "applicationTemplateId",
]
USER_GRAPH_FIELDS = [
    "objectId", "displayName", "userPrincipalName", "userType",
    "accountEnabled", "deletionTimestamp", "dirSyncEnabled",
    "onPremisesSecurityIdentifier",
    "onPremisesDistinguishedName", "onPremisesPasswordChangeTimestamp",
    "lastPasswordChangeDateTime", "lastDirSyncTime", "isResourceAccount",
    "immutableId",
]
GROUP_GRAPH_FIELDS = [
    "objectId", "displayName", "isAssignableToRole", "membershipRule",
    "groupTypes", "visibility", "isPublic", "mailEnabled", "deletionTimestamp",
]
DEVICE_GRAPH_FIELDS = [
    "objectId", "displayName", "hostnames", "deviceOSType", "dirSyncEnabled",
    "onPremisesSecurityIdentifier", "accountEnabled", "approximateLastLogonTimestamp",
]
POLICY_GRAPH_FIELDS = [
    "objectId", "displayName", "policyType", "policyIdentifier", "policyDetail",
]


def group_parents_index(group_member_group):
    """{child_group: {direct_parent_group, ...}} from direct containment."""
    parents = defaultdict(set)
    for parent, children in (group_member_group or {}).items():
        for child in children or ():
            if parent and child:
                parents[child].add(parent)
    return parents


def compute_effective_group_membership(graph):
    """Effective group membership derived from the direct containment edges.

    The collector stores direct ``lnk_group_member_*`` links. This builds the
    transitive closure once per analysis run and returns effective member sets
    per group plus reverse group sets per principal. Group hierarchy consumers
    (parents/children, role paths) must keep using the direct edges.
    """
    direct_users = graph.get("group_member_user") or {}
    direct_groups = graph.get("group_member_group") or {}
    direct_sps = graph.get("group_member_sp") or {}
    direct_devices = graph.get("group_member_device") or {}
    group_ids = set(graph.get("group") or {})
    for mapping in (direct_users, direct_groups, direct_sps, direct_devices):
        group_ids.update(mapping)
    for children in direct_groups.values():
        group_ids.update(children or ())

    memo = {}

    def resolve(root):
        if root in memo:
            return memo[root]
        stack = [(root, False)]
        visiting = set()
        while stack:
            gid, processed = stack.pop()
            if gid in memo:
                continue
            if not processed:
                if gid in visiting:
                    continue  # containment cycle: ignore the back-edge
                visiting.add(gid)
                stack.append((gid, True))
                for child in direct_groups.get(gid, ()):
                    if child not in memo:
                        stack.append((child, False))
                continue
            users = set(direct_users.get(gid, ()))
            groups = set()
            sps = set(direct_sps.get(gid, ()))
            devices = set(direct_devices.get(gid, ()))
            for child in direct_groups.get(gid, ()):
                child_members = memo.get(child)
                if child_members is None:
                    continue  # containment cycle: ignore the back-edge
                users |= child_members[0]
                groups.add(child)
                groups |= child_members[1]
                sps |= child_members[2]
                devices |= child_members[3]
            memo[gid] = (users, groups, sps, devices)
            visiting.discard(gid)
        return memo.get(root, (set(), set(), set(), set()))

    for gid in group_ids:
        resolve(gid)

    users_by_user = defaultdict(set)
    groups_by_group = {}
    sps_by_group = {}
    devices_by_group = {}
    for gid, (users, groups, sps, devices) in memo.items():
        groups_by_group[gid] = groups
        sps_by_group[gid] = sps
        devices_by_group[gid] = devices
        for uid in users:
            users_by_user[uid].add(gid)
    groups_by_sp = defaultdict(set)
    for gid, sps in sps_by_group.items():
        for sid in sps:
            groups_by_sp[sid].add(gid)
    groups_by_device = defaultdict(set)
    for gid, devices in devices_by_group.items():
        for did in devices:
            groups_by_device[did].add(gid)
    return {
        "users_by_group": {gid: users for gid, (users, _, _, _) in memo.items()},
        "groups_by_group": groups_by_group,
        "sps_by_group": sps_by_group,
        "devices_by_group": devices_by_group,
        "groups_by_user": dict(users_by_user),
        "groups_by_sp": dict(groups_by_sp),
        "groups_by_device": dict(groups_by_device),
    }


# ---------------------------------------------------------------------------
# Ownership helpers (human owners + service-principal owners)
# ---------------------------------------------------------------------------

def sp_owner_chain(graph, sp_ids):
    """Return (owner_sp_ids, owner_user_ids) reachable through SP owners."""
    owner_sps = set()
    owner_users = set()
    stack = [sid for sid in sp_ids if sid]
    while stack:
        sid = stack.pop()
        if sid in owner_sps:
            continue
        owner_sps.add(sid)
        owner_users |= set((graph.get("sp_owners") or {}).get(sid, ()))
        stack.extend(set((graph.get("sp_owner_sp") or {}).get(sid, ())) - owner_sps)
    return owner_sps, owner_users


def app_owner_chain(graph, app_oid):
    """Return (owner_sp_ids, owner_user_ids) for an application."""
    owner_users = set((graph.get("app_owners") or {}).get(app_oid, ()))
    owner_sps, sp_users = sp_owner_chain(
        graph, (graph.get("app_owner_sp") or {}).get(app_oid, ()))
    return owner_sps, owner_users | sp_users


def sp_owner_details(graph, sp_oid):
    """(owner_sp_ids without the SP itself, owner_user_ids) for an SP."""
    owner_sps, owner_users = sp_owner_chain(graph, [sp_oid])
    owner_sps.discard(sp_oid)
    return owner_sps, owner_users


def group_owner_chain(graph, gid):
    """Return (owner_sp_ids, owner_user_ids) for a group."""
    owner_users = set((graph.get("group_owner_user") or {}).get(gid, ()))
    owner_sps, sp_users = sp_owner_chain(
        graph, (graph.get("group_owner_sp") or {}).get(gid, ()))
    return owner_sps, owner_users | sp_users


def is_foreign_sp(graph, rec):
    """True only when the SP belongs to a different tenant."""
    owner_tid = rec.get("appOwnerTenantId")
    if not owner_tid:
        return False
    if graph.get("app_by_appid", {}).get(rec.get("appId")):
        return False
    tenant_id = (graph.get("tenant") or {}).get("object_id")
    if not tenant_id:
        return True
    return str(owner_tid).lower() != str(tenant_id).lower()


def role_assignments_for_sp(ctx, sp_oid):
    """App-role assignments for one SP, using the precomputed index when present."""
    index = (ctx.get("analysis_indexes") or {}).get("role_assigns_by_sp")
    if index is not None:
        return index.get(sp_oid, ())
    return [ra for ra in ctx["graph"]["role_assigns"]
            if ra.get("principal_type") == "ServicePrincipal"
            and ra.get("principal_id") == sp_oid]


def role_assignment_count_for_sp(ctx, sp_oid):
    index = (ctx.get("analysis_indexes") or {}).get("role_assign_count_by_sp")
    if index is not None:
        return index.get(sp_oid, 0)
    return len(role_assignments_for_sp(ctx, sp_oid))


def build_analysis_indexes(graph):
    """Precomputed lookups shared by the checks (avoids per-SP full scans)."""
    indexes = {
        "assignments_by_principal": defaultdict(list),
        "role_members_by_sp": defaultdict(list),
        "role_members_by_user": defaultdict(list),
        "groups_by_sp": defaultdict(set),
        "role_assigns_by_sp": defaultdict(list),
        "role_assign_count_by_sp": defaultdict(int),
        "parents_by_child": graph.get("group_parents") or group_parents_index(
            graph.get("group_member_group")),
    }
    for ra in graph.get("directory_role_assigns") or []:
        if ra.get("principal_id"):
            indexes["assignments_by_principal"][ra["principal_id"]].append(ra)
    for role_oid, sp_oid in graph.get("role_member_sp") or []:
        indexes["role_members_by_sp"][sp_oid].append(role_oid)
    for role_oid, uid in graph.get("role_member_user") or []:
        indexes["role_members_by_user"][uid].append(role_oid)
    for gid, sps in (graph.get("group_member_sp") or {}).items():
        for sid in sps:
            indexes["groups_by_sp"][sid].add(gid)
    for ra in graph.get("role_assigns") or []:
        if ra.get("principal_type") == "ServicePrincipal" and ra.get("principal_id"):
            indexes["role_assigns_by_sp"][ra["principal_id"]].append(ra)
            indexes["role_assign_count_by_sp"][ra["principal_id"]] += 1
    indexes["effective_membership"] = compute_effective_group_membership(graph)
    for key in ("groups_by_user", "groups_by_sp", "groups_by_device"):
        indexes[key] = indexes["effective_membership"][key]
    return indexes


def build_graph(cur):
    """Load every security-relevant object and adjacency list once.

    Returns a dict with:
      tenant      {object_id, display_name}
      appref_roles {appId: {role_id: {value, description}}} (ApplicationRefs catalog)
      sp          {sp_object_id: {column: value, ...}}
      app         {app_object_id: {column: value, ...}}
      user        {user_object_id: {column: value, ...}}
      app_by_appid {appId: [app_object_id, ...]}
      sp_by_appid  {appId: [service_principal_object_id, ...]}
      app_owners  {app_object_id: {user_object_id, ...}}
      sp_owners   {sp_object_id: {user_object_id, ...}}
      role_assigns [{principal_id, principal_type, resource_id, app_role_id}]
      group       {group_object_id: {column: value, ...}}
      device      {device_object_id: {column: value, ...}}
      policy      {policy_object_id: {displayName, policyType, ...}}
      directory_role {role_object_id: {displayName, ...}}
      role_definition {definition_object_id: {displayName, ...}}
      role_member_user/sp/group  [(role_object_id, principal_object_id), ...]
      group_member_user      {group_object_id: {user_object_id, ...}}
      group_member_group     {group_object_id: {child_group_object_id, ...}}
      group_owner_user       {group_object_id: {user_object_id, ...}}
      group_member_sp        {group_object_id: {service_principal_object_id, ...}}
      directory_role_assigns [{principal_id, role_definition_id, resource_scopes}]
      eligible_role_assigns  [{principal_id, role_definition_id, resource_scopes}]
      policy_user_exclude / policy_user_include  [(policy_object_id, user_object_id), ...]
      policy_include_allusers {policy_object_id, ...}
    """
    graph = {"tenant": {}, "sp": {}, "app": {}, "user": {}, "group": {}, "device": {}, "policy": {},
             "directory_role": {}, "role_definition": {}, "appref_roles": {},
             "directory_settings": {},
             "app_by_appid": defaultdict(list), "sp_by_appid": defaultdict(list), "app_owners": defaultdict(set),
             "sp_owners": defaultdict(set), "role_assigns": [],
             "role_member_user": [], "role_member_sp": [], "role_member_group": [],
             "group_member_user": defaultdict(set), "group_member_group": defaultdict(set),
             "group_owner_user": defaultdict(set), "device_owners": defaultdict(set),
             "group_member_sp": defaultdict(set),
             "directory_role_assigns": [], "eligible_role_assigns": []}

    try:
        cur.execute("PRAGMA table_info(TenantDetails)")
        td_cols = {r[1] for r in cur.fetchall()}
        td_fields = ["objectId", "displayName"]
        if "verifiedDomains" in td_cols:
            td_fields.append("verifiedDomains")
        cur.execute(f"SELECT {', '.join(td_fields)} FROM TenantDetails LIMIT 1")
        row = cur.fetchone()
        if row:
            graph["tenant"] = {"object_id": row[0], "display_name": row[1]}
            if len(td_fields) > 2:
                graph["tenant"]["verified_domains"] = row[2]
    except sqlite3.OperationalError:
        pass

    def load_table(table, id_column, wanted):
        out = {}
        try:
            cur.execute(f"PRAGMA table_info({table})")
            available = {r[1] for r in cur.fetchall()}
            cols = [c for c in wanted if c in available]
            if id_column not in cols:
                cols = [id_column] + cols
            # Quote identifiers: some collected columns (e.g. DirectorySettings
            # "values") are SQL keywords.
            col_sql = ", ".join(f'"{c}"' for c in cols)
            cur.execute(f"SELECT {col_sql} FROM {table}")
            for row in cur.fetchall():
                rec = {col: val for col, val in zip(cols, row)}
                out[row[cols.index(id_column)]] = rec
        except sqlite3.OperationalError:
            pass
        return out

    graph["sp"] = load_table("ServicePrincipals", "objectId", SP_GRAPH_FIELDS)
    graph["app"] = load_table("Applications", "objectId", APP_GRAPH_FIELDS)
    graph["user"] = load_table("Users", "objectId", USER_GRAPH_FIELDS)

    for oid, rec in graph["app"].items():
        if rec.get("appId"):
            graph["app_by_appid"][rec["appId"]].append(oid)

    for oid, rec in graph["sp"].items():
        if rec.get("appId"):
            graph["sp_by_appid"][rec["appId"]].append(oid)

    def load_owner_links(table, left_col, right_col):
        out = defaultdict(set)
        try:
            # quote identifiers: 'Group' is a SQLite reserved word
            cur.execute(f'SELECT "{left_col}", "{right_col}" FROM {table}')
            for a, b in cur.fetchall():
                if a and b:
                    out[a].add(b)
        except sqlite3.OperationalError:
            pass
        return out

    graph["app_owners"] = load_owner_links("lnk_application_owner_user", "Application", "User")
    graph["sp_owners"] = load_owner_links("lnk_serviceprincipal_owner_user", "ServicePrincipal", "User")
    # Service principals can own applications, other service principals, and
    # groups. Keep those links so non-human ownership is visible and the human
    # owners of the owning SP inherit the takeover path (B-034).
    graph["app_owner_sp"] = load_owner_links(
        "lnk_application_owner_serviceprincipal", "Application", "ServicePrincipal")
    graph["sp_owner_sp"] = load_owner_links(
        "lnk_serviceprincipal_owner_serviceprincipal", "ServicePrincipal", "childServicePrincipal")
    graph["group_owner_sp"] = load_owner_links(
        "lnk_group_owner_serviceprincipal", "Group", "ServicePrincipal")

    graph["group"] = load_table("Groups", "objectId", GROUP_GRAPH_FIELDS)
    graph["administrative_unit"] = load_table(
        "AdministrativeUnits", "objectId", ["objectId", "displayName"])
    graph["device"] = load_table("Devices", "objectId", DEVICE_GRAPH_FIELDS)
    graph["policy"] = load_table("Policys", "objectId", POLICY_GRAPH_FIELDS)

    try:  # ApplicationRefs: app role catalogs for known applications (by appId)
        cur.execute("SELECT appId, appRoles FROM ApplicationRefs")
        for app_id, roles_json in cur.fetchall():
            if not app_id:
                continue
            index = {}
            for role in json_list(roles_json):
                if isinstance(role, dict) and role.get("id"):
                    index[role["id"]] = {
                        "value": role.get("value") or role["id"],
                        "description": role.get("description") or "",
                    }
            if index:
                graph["appref_roles"][app_id] = index
    except sqlite3.OperationalError:
        pass
    graph["directory_role"] = load_table(
        "DirectoryRoles", "objectId", ["objectId", "displayName", "isSystem", "roleDisabled"])
    graph["role_definition"] = load_table(
        "RoleDefinitions", "objectId", ["objectId", "displayName", "isBuiltIn", "isEnabled", "resourceScopes"])
    graph["directory_settings"] = load_table(
        "DirectorySettings", "id", ["id", "displayName", "templateId", "values"])

    def load_member_links(table, left_col, right_col):
        out = []
        try:
            cur.execute(f'SELECT "{left_col}", "{right_col}" FROM {table}')
            out = [(a, b) for a, b in cur.fetchall() if a and b]
        except sqlite3.OperationalError:
            pass
        return out

    graph["role_member_user"] = load_member_links("lnk_role_member_user", "DirectoryRole", "User")
    graph["role_member_sp"] = load_member_links("lnk_role_member_serviceprincipal", "DirectoryRole", "ServicePrincipal")
    graph["role_member_group"] = load_member_links("lnk_role_member_group", "DirectoryRole", "Group")
    graph["group_member_user"] = load_owner_links("lnk_group_member_user", "Group", "User")
    graph["group_member_group"] = load_owner_links("lnk_group_member_group", "Group", "childGroup")
    graph["group_owner_user"] = load_owner_links("lnk_group_owner_user", "Group", "User")
    graph["group_member_sp"] = load_owner_links("lnk_group_member_serviceprincipal", "Group", "ServicePrincipal")
    graph["group_member_device"] = load_owner_links("lnk_group_member_device", "Group", "Device")
    graph["device_owners"] = load_owner_links("lnk_device_owner", "Device", "User")
    # Cheap reverse index reused by every role-path walk.
    graph["group_parents"] = group_parents_index(graph["group_member_group"])

    graph["policy_user_exclude"] = load_member_links("lnk_policy_user_exclude", "Policy", "User")
    graph["policy_user_include"] = load_member_links("lnk_policy_user_include", "Policy", "User")
    try:
        cur.execute("SELECT Policy FROM lnk_policy_user_include_allusers")
        graph["policy_include_allusers"] = {r[0] for r in cur.fetchall() if r[0]}
    except sqlite3.OperationalError:
        graph["policy_include_allusers"] = set()

    try:
        cur.execute("SELECT principalId, roleDefinitionId, resourceScopes FROM RoleAssignments")
        graph["directory_role_assigns"] = [
            {"principal_id": r[0], "role_definition_id": r[1], "resource_scopes": r[2]}
            for r in cur.fetchall()]
    except sqlite3.OperationalError:
        pass

    try:
        cur.execute("SELECT principalId, roleDefinitionId, resourceScopes FROM EligibleRoleAssignments")
        graph["eligible_role_assigns"] = [
            {"principal_id": r[0], "role_definition_id": r[1], "resource_scopes": r[2]}
            for r in cur.fetchall()]
    except sqlite3.OperationalError:
        pass

    try:
        cur.execute("SELECT id, principalId, principalType, resourceId FROM AppRoleAssignments")
        for row in cur.fetchall():
            graph["role_assigns"].append({
                "app_role_id": row[0], "principal_id": row[1],
                "principal_type": row[2] or "", "resource_id": row[3],
            })
    except sqlite3.OperationalError:
        pass

    # ---- Azure Resource Manager (ARM) role assignments per group -----------
    # Populated only when 'roadrecon azgather' has run with ARM read access;
    # empty AZ* tables => empty map, report renders unchanged.
    graph["az_roles"] = defaultdict(list)
    rd_roles, sub_names = {}, {}
    assignments, elig = {}, {}
    try:
        cur.execute("PRAGMA table_info(AZroleDefinitions)")
        if {"name", "role_name"}.issubset({r[1] for r in cur.fetchall()}):
            cur.execute("SELECT name, role_name FROM AZroleDefinitions")
            rd_roles = {guid: rname for guid, rname in cur.fetchall() if guid and rname}
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute("PRAGMA table_info(AZsubscriptions)")
        if "subscription_id" in {r[1] for r in cur.fetchall()}:
            cur.execute("SELECT subscription_id, display_name FROM AZsubscriptions")
            sub_names = {sid: disp for sid, disp in cur.fetchall() if sid and disp}
    except sqlite3.OperationalError:
        pass
    graph["az_sub_names"] = sub_names

    def az_role_label(role_def_id):
        guid = (role_def_id or "").rsplit("/", 1)[-1]
        return rd_roles.get(guid, guid)

    def az_scope_parse(scope):
        parts = [p for p in (scope or "").split("/") if p]
        out = {"type": "Root", "sub": "", "rg": "", "mgmt": "", "provider": "", "resource": ""}
        if not parts:
            return out
        pl = [p.lower() for p in parts]
        if pl[0] == "subscriptions" and len(parts) > 1:
            out["sub"] = parts[1]
            out["type"] = "Subscription" if len(parts) == 2 else "Scope"
        elif "managementgroups" in pl:
            i = pl.index("managementgroups")
            out["type"] = "Management group"
            if i + 1 < len(parts):
                out["mgmt"] = parts[i + 1]
        else:
            out["type"] = "Scope"
        if "resourcegroups" in pl:
            i = pl.index("resourcegroups")
            if i + 1 < len(parts):
                out["rg"] = parts[i + 1]
            out["type"] = "Resource group"
            if i + 2 < len(parts) and pl[i + 2] == "providers":
                out["type"] = "Resource"
                if i + 3 < len(parts):
                    out["provider"] = parts[i + 3]
                tail = parts[i + 4:]
                if len(tail) >= 2:
                    out["resource"] = tail[-2] + "/" + tail[-1]
        if not out["provider"]:
            for i, p in enumerate(pl):
                if p == "providers" and i + 1 < len(parts):
                    out["provider"] = parts[i + 1]
                    break
        return out

    def az_scope_label(scope):
        p = az_scope_parse(scope)
        if p["type"] == "Management group":
            return f"Management group {p['mgmt']}" if p["mgmt"] else (scope or "")
        label = sub_names.get(p["sub"]) or p["sub"] or (scope or "")
        if p["rg"]:
            label = f"{label} / {p['rg']}"
            if p["resource"]:
                label = f"{label} / {p['resource']}"
        elif not p["sub"] and not p["rg"]:
            return p["provider"] or (scope or "")
        return label

    def az_assign_entry(extra, eligible=False):
        """Build an ARM assignment record (defensive against schema drift)."""
        p = az_scope_parse(extra.get("scope"))
        entry = {
            "role": az_role_label(extra.get("role_definition_id")),
            "role_def_id": (extra.get("role_definition_id") or "").rsplit("/", 1)[-1],
            "scope": extra.get("scope") or "",
            "scope_type": p["type"],
            "scope_sub": p["sub"],
            "scope_sub_name": sub_names.get(p["sub"], ""),
            "scope_rg": p["rg"],
            "scope_mgmt": p["mgmt"],
            "scope_provider": p["provider"],
            "scope_resource": p["resource"],
            "scope_label": az_scope_label(extra.get("scope")),
            "created_on": str(extra.get("created_on") or "")[:10],
            "condition": extra.get("condition") or "",
            "eligible": bool(eligible),
        }
        if eligible:
            entry["status"] = extra.get("status") or ""
            entry["start"] = str(extra.get("start") or "")[:10]
            entry["end"] = str(extra.get("end") or "")[:10]
        return entry

    try:
        cur.execute("PRAGMA table_info(AZroleAssignments)")
        ra_cols = {r[1] for r in cur.fetchall()}
        if {"id", "scope", "role_definition_id"}.issubset(ra_cols):
            assignments = {}
            cur.execute("SELECT id, scope, role_definition_id, created_on, condition FROM AZroleAssignments")
            for ra_id, scope, rd_id, created, cond in cur.fetchall():
                if ra_id:
                    assignments[ra_id] = {
                        "scope": scope, "role_definition_id": rd_id,
                        "created_on": created, "condition": cond,
                    }
            try:
                # 'Group' is a SQLite reserved word - quote it
                cur.execute('SELECT "Group", AZroleAssignment FROM lnk_az_roleassignment_group')
                for gid, ra_id in cur.fetchall():
                    if gid and ra_id and ra_id in assignments:
                        graph["az_roles"][gid].append(az_assign_entry(assignments[ra_id]))
            except sqlite3.OperationalError:
                pass
    except sqlite3.OperationalError:
        pass

    try:
        cur.execute("PRAGMA table_info(AZroleEligibilityScheduleInstances)")
        ec_cols = {r[1] for r in cur.fetchall()}
        if {"id", "scope", "role_definition_id"}.issubset(ec_cols):
            elig = {}
            cur.execute("SELECT id, scope, role_definition_id, status, start_date_time, end_date_time "
                        "FROM AZroleEligibilityScheduleInstances")
            for eid, scope, rd_id, status, start_dt, end_dt in cur.fetchall():
                if eid:
                    elig[eid] = {
                        "scope": scope, "role_definition_id": rd_id, "status": status,
                        "start": start_dt, "end": end_dt,
                    }
            try:
                cur.execute('SELECT "Group", AZroleEligibilityScheduleInstance '
                            "FROM lnk_az_roleassignment_eligible_group")
                for gid, eid in cur.fetchall():
                    if gid and eid and eid in elig:
                        graph["az_roles"][gid].append(
                            az_assign_entry(elig[eid], eligible=True))
            except sqlite3.OperationalError:
                pass
    except sqlite3.OperationalError:
        pass

    # Service principals with ARM role assignments (same entry shape as groups)
    graph["az_sp_roles"] = defaultdict(list)
    try:
        cur.execute("SELECT ServicePrincipal, AZroleAssignment "
                    "FROM lnk_az_roleassignment_serviceprincipal")
        for sp_id, ra_id in cur.fetchall():
            if sp_id and ra_id and ra_id in assignments:
                graph["az_sp_roles"][sp_id].append(az_assign_entry(assignments[ra_id]))
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute("SELECT ServicePrincipal, AZroleEligibilityScheduleInstance "
                    "FROM lnk_az_roleassignment_eligible_serviceprincipal")
        for sp_id, eid in cur.fetchall():
            if sp_id and eid and eid in elig:
                graph["az_sp_roles"][sp_id].append(az_assign_entry(elig[eid], eligible=True))
    except sqlite3.OperationalError:
        pass

    # Users with ARM role assignments (same entry shape)
    graph["az_user_roles"] = defaultdict(list)
    try:
        cur.execute('SELECT "User", AZroleAssignment FROM lnk_az_roleassignment_user')
        for uid, ra_id in cur.fetchall():
            if uid and ra_id and ra_id in assignments:
                graph["az_user_roles"][uid].append(az_assign_entry(assignments[ra_id]))
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('SELECT "User", AZroleEligibilityScheduleInstance '
                    "FROM lnk_az_roleassignment_eligible_user")
        for uid, eid in cur.fetchall():
            if uid and eid and eid in elig:
                graph["az_user_roles"][uid].append(az_assign_entry(elig[eid], eligible=True))
    except sqlite3.OperationalError:
        pass

    # ---- PIM (privileged identity management) -------------------------------
    # The legacy v1 tables (RoleAssignments / EligibleRoleAssignments, AAD
    # Graph) are always loaded above. The richer PIM v2 governance data comes
    # from `roadrecon pimgather` (api.azrbac.mspim.azure.com) and is frequently
    # absent: every table here loads defensively so empty databases render the
    # same as before. Populated tables upgrade the PIM checks below.
    graph["pim_providers"] = []
    try:
        cur.execute("SELECT id FROM PIMprivilegedAccesss")
        graph["pim_providers"] = [r[0] for r in cur.fetchall() if r[0]]
    except sqlite3.OperationalError:
        pass

    graph["pim_resources"] = {}
    try:
        cur.execute('SELECT id, "displayName", type, status FROM PIMgovernanceResources')
        graph["pim_resources"] = {
            r[0]: {"display_name": r[1], "type": r[2], "status": r[3]}
            for r in cur.fetchall() if r[0]}
    except sqlite3.OperationalError:
        pass

    graph["pim_role_defs"] = {}
    try:
        cur.execute('SELECT id, "resourceId", "displayName", "templateId" '
                    "FROM PIMgovernanceRoleDefinitions")
        graph["pim_role_defs"] = {
            r[0]: {"resource_id": r[1], "display_name": r[2], "template_id": r[3]}
            for r in cur.fetchall() if r[0]}
    except sqlite3.OperationalError:
        pass

    def _load_pim_settings_table(table, columns):
        out = {}
        try:
            cur.execute(f"PRAGMA table_info({table})")
            available = {r[1] for r in cur.fetchall()}
            cols = [c for c in columns if c in available]
            if cols:
                cur.execute(f"SELECT {', '.join(cols)} FROM {table}")
                for row in cur.fetchall():
                    rec = dict(zip(cols, row))
                    if rec.get("id"):
                        out[rec["id"]] = rec
        except sqlite3.OperationalError:
            pass
        return out

    graph["pim_role_settings"] = _load_pim_settings_table(
        "PIMgovernanceRoleSettings",
        ["id", "resourceId", "roleDefinitionId", "isDefault", "lastUpdatedDateTime",
         "adminEligibleSettings", "adminMemberSettings",
         "userEligibleSettings", "userMemberSettings"])
    graph["pim_role_settings_v2"] = _load_pim_settings_table(
        "PIMgovernanceRoleSettingV2s",
        ["id", "resourceId", "roleDefinitionId", "isDefault", "lastUpdatedDateTime",
         "lifeCycleManagement"])

    graph["pim_role_assignments"] = []
    try:
        try:
            cur.execute("SELECT id, resourceId, roleDefinitionId, subjectId, "
                        "linkedEligibleRoleAssignmentId, isPermanent, startDateTime, "
                        "endDateTime, memberType, assignmentState, status, scopedResourceId "
                        "FROM PIMgovernanceRoleAssignments")
            columns = ("id", "resource_id", "role_definition_id", "subject_id",
                       "linked_eligible_id", "is_permanent", "start", "end",
                       "member_type", "assignment_state", "status", "scoped_resource_id")
        except sqlite3.OperationalError:
            cur.execute("SELECT id, resourceId, roleDefinitionId, subjectId, "
                        "linkedEligibleRoleAssignmentId, isPermanent, startDateTime, "
                        "endDateTime, memberType, assignmentState, status "
                        "FROM PIMgovernanceRoleAssignments")
            columns = ("id", "resource_id", "role_definition_id", "subject_id",
                       "linked_eligible_id", "is_permanent", "start", "end",
                       "member_type", "assignment_state", "status")
        for row in cur.fetchall():
            if not row[0]:
                continue
            rec = dict(zip(columns, row))
            rec["is_permanent"] = bool(rec.get("is_permanent"))
            rec.setdefault("scoped_resource_id", None)
            graph["pim_role_assignments"].append(rec)
    except sqlite3.OperationalError:
        pass

    graph["pim_alerts"] = []
    try:
        cur.execute("SELECT id, resourceId, alertName, alertDescription, "
                    "numberOfAffectedItems, severityLevel, isActive, status, "
                    "mitigationSteps, howToPrevent, lastScannedDateTime "
                    "FROM PIMgovernanceAlerts")
        for row in cur.fetchall():
            if not row[0]:
                continue
            graph["pim_alerts"].append({
                "id": row[0], "resource_id": row[1], "name": row[2],
                "description": row[3], "affected": row[4], "severity_level": row[5],
                "is_active": bool(row[6]), "status": row[7],
                "mitigation": row[8], "prevention": row[9], "scanned": row[10],
            })
    except sqlite3.OperationalError:
        pass

    # PIM-governance role assignment subjects -> users/groups/SPs (v2 links)
    def _load_pim_subjects(table, column):
        out = {}
        try:
            cur.execute(f'SELECT "{column}", PIMgovernanceRoleAssignment '
                        f"FROM {table}")
            for subject_id, assign_id in cur.fetchall():
                if subject_id and assign_id:
                    out[assign_id] = subject_id
        except sqlite3.OperationalError:
            pass
        return out

    graph["pim_assign_subject"] = {}
    graph["pim_assign_subject"].update(
        _load_pim_subjects("lnk_pim_roleassignment_subjectuser", "User"))
    graph["pim_assign_subject"].update(
        _load_pim_subjects("lnk_pim_roleassignment_subjectgroup", "Group"))
    graph["pim_assign_subject"].update(
        _load_pim_subjects("lnk_pim_roleassignment_subjectserviceprincipal",
                           "ServicePrincipal"))

    return graph


# ---------------------------------------------------------------------------
# Database validation
# ---------------------------------------------------------------------------

AUDIT_REQUIRED_TABLES = ("TenantDetails", "Users", "ServicePrincipals")


def open_audit_database(db_path):
    """Open a collected database read-only and reject non-SQLite or non-
    ROADrecon files with a clear ValueError instead of a late empty report."""
    path = Path(db_path)
    try:
        conn = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise ValueError(f"cannot open database {path}: {exc}") from exc
    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        tables = {row[0] for row in cur.fetchall()}
    except sqlite3.DatabaseError as exc:
        conn.close()
        raise ValueError(f"not a valid SQLite database: {path} ({exc})") from exc
    missing = [name for name in AUDIT_REQUIRED_TABLES if name not in tables]
    if missing:
        conn.close()
        raise ValueError(
            f"not a ROADrecon database: {path} is missing required table(s): "
            + ", ".join(missing))
    return conn





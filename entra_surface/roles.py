"""Directory-role resolution, scopes, and PIM helpers.

Pure module: operates on the entity graph and config values. Shared by checks,
the severity bump, and entity profiles.
"""
from __future__ import annotations

import re
from collections import defaultdict

from .findings import eligible_severity, severity_rank
from .graph import group_parents_index, json_list, json_safe_value


def normalize_role_scopes(raw):
    """Normalize resourceScopes/scopedResourceId into a list of scope IDs."""
    parsed = json_safe_value(raw)
    if isinstance(parsed, list):
        scopes = [str(v).strip() for v in parsed if isinstance(v, str) and v.strip()]
    elif isinstance(parsed, str) and parsed.strip():
        scopes = [parsed.strip()]
    else:
        scopes = []
    return scopes or ["/"]


def role_scope_ids(graph, scopes):
    """Administrative Unit object IDs among the raw role scope values.

    Directory role assignments are either tenant-wide or scoped to an
    Administrative Unit. ROADrecon/AAD Graph exports may store the scope as a
    bare object ID instead of a path, so only values that match an AU path or
    resolve to a collected AU are treated as limited. Everything else — ``/``,
    the tenant object ID, a principal/object ID such as the service principal
    the role was assigned to — is tenant-wide. Treating those as scoped would
    downgrade legitimate tenant-wide roles to Info.
    """
    aus = (graph or {}).get("administrative_unit") or {}
    out = []
    for scope in normalize_role_scopes(scopes):
        norm = str(scope).strip()
        if norm.rstrip("/") == "":
            continue
        match = re.search(r"/administrativeUnits/([^/]+)", norm, re.IGNORECASE)
        if match:
            out.append(match.group(1))
            continue
        candidate = norm.rstrip("/").rsplit("/", 1)[-1]
        if candidate in aus:
            out.append(candidate)
    return out


def role_scopes_tenant_wide(graph, scopes):
    return not role_scope_ids(graph, scopes)


def role_scope_label(graph, scopes):
    aus = (graph or {}).get("administrative_unit") or {}
    labels = []
    for au_id in role_scope_ids(graph, scopes):
        rec = aus.get(au_id) or {}
        labels.append(f"AU: {rec.get('displayName') or au_id}")
    return ", ".join(dict.fromkeys(labels)) or "Tenant-wide"


def make_directory_role_entry(graph, name, severity, scopes=None, source=None,
                              path=None, path_ids=None, disabled=False,
                              eligible=False):
    """Build one role entry carrying display severity plus rating metadata."""
    normalized = normalize_role_scopes(scopes)
    entry = {"name": name, "severity": severity}
    if source:
        entry["source"] = source
    entry["path"] = list(path) if path is not None else None
    if path_ids is not None:
        entry["path_ids"] = list(path_ids)
    if eligible:
        entry["eligible"] = True
    entry["scope"] = role_scope_label(graph, normalized)
    entry["scope_ids"] = normalized
    entry["scope_limited"] = not role_scopes_tenant_wide(graph, normalized)
    if disabled:
        entry["disabled"] = True
    return entry


def role_rating_severity(role):
    """Severity used for ratings. AU-scoped and disabled roles never rate."""
    if not role or role.get("disabled") or role.get("scope_limited"):
        return "Info"
    return role.get("severity", "Info")


def role_display_name(role):
    """Display label with the non-tenant-wide scope / disabled marker."""
    name = role.get("name") or ""
    if role.get("disabled"):
        name += " (disabled role)"
    elif role.get("scope_limited") and role.get("scope"):
        name += f" [{role['scope']}]"
    return name


def merge_role_entry(existing, incoming):
    """Merge a duplicate role entry, keeping the widest/enabled variant."""
    if incoming.get("source"):
        srcs = [s.strip() for s in (existing.get("source") or "").split("\u00b7")]
        for src in incoming["source"].split("\u00b7"):
            src = src.strip()
            if src and src not in srcs:
                srcs.append(src)
        existing["source"] = " \u00b7 ".join(s for s in srcs if s)
    if existing.get("scope_limited") and not incoming.get("scope_limited"):
        for key in ("scope", "scope_ids", "scope_limited"):
            if key in incoming:
                existing[key] = incoming[key]
            else:
                existing.pop(key, None)
    if existing.get("disabled") and not incoming.get("disabled"):
        existing.pop("disabled", None)
    if "path" not in existing and incoming.get("path"):
        existing["path"] = incoming["path"]
        existing["path_ids"] = incoming.get("path_ids") or []
    if severity_rank(incoming.get("severity", "Info")) < severity_rank(existing.get("severity", "Info")):
        existing["severity"] = incoming["severity"]
    return existing


def _role_def_disabled(role_definition):
    return role_definition.get("isEnabled") in (0, False)


def _directory_role_disabled(role_record):
    return role_record.get("roleDisabled") in (1, True)



def resolve_group_role_paths(gid, group_roles, group_member_group, group_label,
                             parents_by_child=None):
    """Directory roles members of `gid` inherit through nested group membership.

    Walks up the *direct* containment chain (gid is a member of parent groups,
    which may themselves be nested in further groups) and returns one entry per
    role with the shortest group path from `gid` to the role-bearing group, e.g.
    {"name": "Global Administrator", "severity": "Critical",
     "path": ["Team A", "Team A - Admins", "Root Admins"],
     "path_ids": ["<gid A>", "<gid B>", "<gid Root>"]}.
    """
    parents = parents_by_child or group_parents_index(group_member_group)
    found = {}
    seen = {gid}
    queue = [(gid, [gid])]
    while queue:
        cur, path = queue.pop(0)
        for r in group_roles.get(cur, []):
            if r["name"] not in found:
                entry = dict(r)
                entry["path"] = [group_label(g) for g in path]
                entry["path_ids"] = list(path)
                found[r["name"]] = entry
        for parent in sorted(parents.get(cur, ())):
            if parent not in seen:
                seen.add(parent)
                queue.append((parent, path + [parent]))
    return sorted(found.values(), key=lambda r: severity_rank(role_rating_severity(r)))


def direct_directory_roles_by_user(graph, role_sev):
    """{user_id: [{name, severity, source}]} directly-assigned directory roles
    per user (role memberships + role assignments), deduped by name with merged
    sources. Shared by the privileged-users and groups checks."""
    out = defaultdict(list)

    def _role_name(oid):
        rec = graph["directory_role"].get(oid)
        return rec.get("displayName") if rec else oid

    def _def_name(oid):
        rec = graph["role_definition"].get(oid)
        return rec.get("displayName") if rec else oid

    for role_oid, uid in graph["role_member_user"]:
        if uid not in graph["user"]:
            continue
        name = _role_name(role_oid)
        role_rec = graph["directory_role"].get(role_oid) or {}
        out[uid].append(make_directory_role_entry(
            graph, name, role_sev.get(name, "Info"), scopes="/",
            source="role member", disabled=_directory_role_disabled(role_rec)))
    for ra in graph["directory_role_assigns"]:
        if ra["principal_id"] in graph["user"]:
            name = _def_name(ra["role_definition_id"])
            role_rec = graph["role_definition"].get(ra["role_definition_id"]) or {}
            out[ra["principal_id"]].append(make_directory_role_entry(
                graph, name, role_sev.get(name, "Info"),
                scopes=ra.get("resource_scopes"), source="role assignment",
                disabled=_role_def_disabled(role_rec)))
    for uid in list(out):
        merged = {}
        for r in out[uid]:
            key = r["name"]
            if key not in merged:
                merged[key] = r
            else:
                merge_role_entry(merged[key], r)
        out[uid] = sorted(merged.values(),
                          key=lambda r: severity_rank(role_rating_severity(r)))
    return dict(out)


def direct_directory_roles_by_sp(graph, role_sev):
    """{sp_id: [{name, severity}]} directly-assigned directory roles per service
    principal (lnk_role_member_serviceprincipal + RoleAssignments), deduped by
    name. Shared by sp_directory_roles and the groups member tags."""
    out = defaultdict(list)

    def _role_name(oid):
        rec = graph["directory_role"].get(oid)
        return rec.get("displayName") if rec else oid

    def _def_name(oid):
        rec = graph["role_definition"].get(oid)
        return rec.get("displayName") if rec else oid

    for role_oid, sp_oid in graph["role_member_sp"]:
        name = _role_name(role_oid)
        role_rec = graph["directory_role"].get(role_oid) or {}
        out[sp_oid].append(make_directory_role_entry(
            graph, name, role_sev.get(name, "Info"), scopes="/",
            disabled=_directory_role_disabled(role_rec)))
    for ra in graph["directory_role_assigns"]:
        if ra["principal_id"] in graph["sp"]:
            name = _def_name(ra["role_definition_id"])
            role_rec = graph["role_definition"].get(ra["role_definition_id"]) or {}
            out[ra["principal_id"]].append(make_directory_role_entry(
                graph, name, role_sev.get(name, "Info"),
                scopes=ra.get("resource_scopes"),
                disabled=_role_def_disabled(role_rec)))
    for sp_oid in list(out):
        merged = {}
        for r in out[sp_oid]:
            if r["name"] not in merged:
                merged[r["name"]] = r
            else:
                merge_role_entry(merged[r["name"]], r)
        out[sp_oid] = sorted(merged.values(),
                             key=lambda r: severity_rank(role_rating_severity(r)))
    return dict(out)


def compute_group_roles(graph, check_cfg):
    """{group_id: [{"name", "severity"}]} - directory roles carried by each group:
    direct role memberships (lnk_role_member_group) plus role assignments whose
    principal is a group (RoleAssignments). Shared by the user/groups checks and
    the SP/app profile drawer."""
    role_sev = check_cfg["directory_roles"]

    def _grole_name(oid):
        rec = graph["directory_role"].get(oid)
        return rec.get("displayName") if rec else oid

    def _gdef_name(oid):
        rec = graph["role_definition"].get(oid)
        return rec.get("displayName") if rec else oid

    def _gsev(name):
        return role_sev.get(name, "Info")

    group_roles = defaultdict(list)
    for role_oid, gid in graph["role_member_group"]:
        name = _grole_name(role_oid)
        role_rec = graph["directory_role"].get(role_oid) or {}
        group_roles[gid].append(make_directory_role_entry(
            graph, name, _gsev(name), scopes="/",
            disabled=_directory_role_disabled(role_rec)))
    for ra in graph["directory_role_assigns"]:
        if ra["principal_id"] in graph["group"]:
            name = _gdef_name(ra["role_definition_id"])
            role_rec = graph["role_definition"].get(ra["role_definition_id"]) or {}
            group_roles[ra["principal_id"]].append(make_directory_role_entry(
                graph, name, _gsev(name), scopes=ra.get("resource_scopes"),
                disabled=_role_def_disabled(role_rec)))
    for gid in list(group_roles):
        merged = {}
        for r in group_roles[gid]:
            if r["name"] not in merged:
                merged[r["name"]] = r
            else:
                merge_role_entry(merged[r["name"]], r)
        group_roles[gid] = sorted(merged.values(),
                                  key=lambda r: severity_rank(role_rating_severity(r)))
    return group_roles


def is_pim_directory_assignment(graph, assignment):
    """True when a PIM v2 assignment belongs to the aadroles resource.

    PIM-for-groups schedules are stored in the same table with the group ID as
    resourceId and ``member``/``owner`` as roleDefinitionId; they must never be
    interpreted as directory-role eligibility (B-037).
    """
    resource_id = assignment.get("resource_id")
    if not resource_id:
        return False
    if resource_id == "aadroles":
        return True
    rec = (graph.get("pim_resources") or {}).get(resource_id) or {}
    resource_type = str(rec.get("type") or "").strip().lower()
    return resource_type in {"aadroles", "aadrole", "directoryrole", "directoryroles"}


def sp_directory_roles(graph, group_roles, sp_oid, role_sev, group_eligible_roles=None,
                       direct_sp_roles=None, groups_by_sp=None, parents_by_child=None):
    """Directory roles held by a service principal: direct memberships and
    assignments plus roles inherited through group membership (incl. nesting).
    Each entry carries the group path to the role-bearing group (None when
    assigned directly) and an 'eligible' flag — PIM-eligible roles are marker
    data and never affect severity ratings."""
    def _def_name(oid):
        rec = graph["role_definition"].get(oid)
        return rec.get("displayName") if rec else oid

    def _group_label(gid):
        rec = graph["group"].get(gid)
        return rec.get("displayName") if rec else gid

    if direct_sp_roles is None:
        direct_sp_roles = direct_directory_roles_by_sp(graph, role_sev)
    parents_by_child = parents_by_child or graph.get("group_parents") or group_parents_index(
        graph.get("group_member_group"))
    if groups_by_sp is None:
        groups_by_sp = defaultdict(set)
        for gid, members in (graph.get("group_member_sp") or {}).items():
            for sid in members:
                groups_by_sp[sid].add(gid)
    roles = []
    by_name = {}
    for r in direct_sp_roles.get(sp_oid, []):
        entry = dict(r)
        entry["path"] = None
        entry["eligible"] = False
        roles.append(entry)
        by_name[entry["name"]] = entry
    for gid in sorted(groups_by_sp.get(sp_oid, ())):
        for r in resolve_group_role_paths(
                gid, group_roles, graph["group_member_group"], _group_label,
                parents_by_child=parents_by_child):
            existing = by_name.get(r["name"])
            if existing is not None:
                merge_role_entry(existing, r)
                continue
            entry = dict(r)
            entry["path"] = list(r["path"])
            entry["path_ids"] = list(r.get("path_ids") or [])
            entry["eligible"] = False
            roles.append(entry)
            by_name[entry["name"]] = entry
    # PIM-eligible directory roles (direct assignments + via groups): marker
    # only — shown with an '(eligible)' marker, rated one notch below active.
    if group_eligible_roles is not None:
        for ea in graph["eligible_role_assigns"]:
            if ea["principal_id"] == sp_oid:
                name = _def_name(ea["role_definition_id"])
                if name not in by_name:
                    role_rec = graph["role_definition"].get(ea["role_definition_id"]) or {}
                    entry = make_directory_role_entry(
                        graph, name, eligible_severity(role_sev.get(name, "Info")),
                        scopes=ea.get("resource_scopes"), eligible=True,
                        disabled=_role_def_disabled(role_rec))
                    entry["path"] = None
                    by_name[name] = entry
                    roles.append(entry)
        # v2-only direct eligibility (pimgather)
        for a in graph.get("pim_role_assignments") or []:
            if (a.get("assignment_state") or "").lower() != "eligible":
                continue
            if not is_pim_directory_assignment(graph, a):
                continue
            subject = graph.get("pim_assign_subject", {}).get(a["id"]) or a.get("subject_id")
            if subject != sp_oid:
                continue
            name = _pim_role_def_name(graph, a.get("role_definition_id"))
            if name not in by_name:
                role_rec = graph["role_definition"].get(a.get("role_definition_id")) or {}
                entry = make_directory_role_entry(
                    graph, name, eligible_severity(role_sev.get(name, "Info")),
                    scopes=a.get("scoped_resource_id"), eligible=True,
                    disabled=_role_def_disabled(role_rec))
                entry["path"] = None
                by_name[name] = entry
                roles.append(entry)
        for gid in sorted(groups_by_sp.get(sp_oid, ())):
            for r in resolve_group_role_paths(
                    gid, group_eligible_roles, graph["group_member_group"], _group_label,
                    parents_by_child=parents_by_child):
                if r["name"] not in by_name:
                    entry = dict(r)
                    entry["path"] = list(r["path"])
                    entry["path_ids"] = list(r.get("path_ids") or [])
                    entry["eligible"] = True
                    by_name[r["name"]] = entry
                    roles.append(entry)
    return roles


def make_sp_dir_resolver(graph, group_roles, role_sev, group_eligible_roles=None,
                         direct_sp_roles=None, groups_by_sp=None,
                         parents_by_child=None):
    """Memoized resolver of a service principal's directory roles (active +
    PIM-eligible, with group paths). Shared across the checks, the severity
    bump and the entity profiles so the group walks run once per SP per run."""
    if direct_sp_roles is None:
        direct_sp_roles = direct_directory_roles_by_sp(graph, role_sev)
    cache = {}

    def resolve(sp_oid):
        if sp_oid not in cache:
            cache[sp_oid] = sp_directory_roles(
                graph, group_roles, sp_oid, role_sev, group_eligible_roles,
                direct_sp_roles=direct_sp_roles, groups_by_sp=groups_by_sp,
                parents_by_child=parents_by_child)
        return cache[sp_oid]

    return resolve



def compute_group_eligible_roles(graph, check_cfg):
    """{group_id: [{"name", "severity"}]} - PIM-eligible directory roles carried
    by each group (EligibleRoleAssignments whose principal is a group). Marker
    data rated one notch below the active severity of the same role."""
    role_sev = check_cfg["directory_roles"]

    def _gdef_name(oid):
        rec = graph["role_definition"].get(oid)
        return rec.get("displayName") if rec else oid

    def _gsev(name):
        return eligible_severity(role_sev.get(name, "Info"))

    out = defaultdict(list)
    for ea in graph["eligible_role_assigns"]:
        if ea["principal_id"] in graph["group"]:
            name = _gdef_name(ea["role_definition_id"])
            role_rec = graph["role_definition"].get(ea["role_definition_id"]) or {}
            out[ea["principal_id"]].append(make_directory_role_entry(
                graph, name, _gsev(name), scopes=ea.get("resource_scopes"),
                eligible=True, disabled=_role_def_disabled(role_rec)))
    # v2-only group eligibility (pimgather) when the v1 tables don't carry it
    for a in graph.get("pim_role_assignments") or []:
        if (a.get("assignment_state") or "").lower() != "eligible":
            continue
        if not is_pim_directory_assignment(graph, a):
            continue
        subject = graph.get("pim_assign_subject", {}).get(a["id"]) or a.get("subject_id")
        if not subject or subject not in graph["group"]:
            continue
        name = _pim_role_def_name(graph, a.get("role_definition_id"))
        if not any(r["name"] == name for r in out.get(subject, [])):
            role_rec = graph["role_definition"].get(a.get("role_definition_id")) or {}
            out[subject].append(make_directory_role_entry(
                graph, name, _gsev(name), scopes=a.get("scoped_resource_id"),
                eligible=True, disabled=_role_def_disabled(role_rec)))
    for gid in list(out):
        merged = {}
        for r in out[gid]:
            if r["name"] not in merged:
                merged[r["name"]] = r
            else:
                merge_role_entry(merged[r["name"]], r)
        out[gid] = list(merged.values())
    return out



# ---------------------------------------------------------------------------
# PIM helpers (eligible-role drawer enrichment: scope + schedule details)
# ---------------------------------------------------------------------------

def _pim_role_def_name(graph, role_def_id):
    """Display name of a PIM role definition (v2 governance id or v1 object id)."""
    rec = graph["pim_role_defs"].get(role_def_id)
    if rec and rec.get("display_name"):
        return rec["display_name"]
    rec = graph["role_definition"].get(role_def_id)
    if rec:
        return rec.get("displayName") or role_def_id
    return role_def_id


def pim_scope_label(raw):
    parts = [p for p in json_list(raw) if isinstance(p, str)]
    if not parts:
        return "Tenant-wide"
    return "Tenant-wide" if parts == ["/"] else ", ".join(parts)



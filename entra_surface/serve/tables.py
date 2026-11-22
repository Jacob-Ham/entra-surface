"""Server-side table filtering, sorting and pagination."""
from __future__ import annotations

import threading
from collections import OrderedDict

from ..checks.registry import CHECK_ID_CATEGORY
from ..filters import (
    AdvancedParseError, evaluate_advanced, extract_uniq_fields,
    parse_advanced_query,
)
from ..graph import json_list
from ..report.fields import (
    graph_user_record, group_source_value, grp_type_value, row_owner_dict,
    sp_app_id, sp_owner_dict,
)
from ..report.tables import (
    TABLE_SPECS, allowed_fields, parse_cols_param, table_colgroup_inner_html,
    table_spec, table_thead_row_html,
)
from ..state import SERVE_STATE, serve_generation


def _serve_table_id(res_id):
    return {
        "priv_app_ownership": "owned-table",
        "privileged_users": "privileged-users-table",
        "groups": "groups-table",
        "ad_sync_users": "ad-sync-users-table",
        "app_dir_roles": "app-dir-roles-table",
        "app_inventory": "app-inventory-table",
        "enterprise_apps": "enterprise-apps-table",
        "authentication_methods": "authentication-methods-table",
        "certificate_auth_users": "certificate-auth-users-table",
        "ca_exposure": "table-ca_exposure",
        "azure_arc_machines": "arc-machines-table",
        "azure_arc_sps": "arc-principals-table",
        "azure_arc_providers": "arc-providers-table",
    }.get(res_id, f"table-{res_id}")


def _owner_field_map(owners, ctx=None):
    """Owner columns for a row, aligned with the DOM renderers. When several
    owners exist the values are comma-joined; owned-table rows pass exactly one
    owner so the filter/drilldown value matches the displayed cell."""
    graph = (ctx or {}).get("graph") or {}
    values = {key: [] for key in
              ("owner", "ownerUpn", "ownerStatus", "ownerSource",
               "ownerAdDn", "ownerAdSid", "ownerImmutableId")}
    for owner in owners or ():
        if not owner:
            continue
        rec = graph_user_record(graph, owner.get("object_id")) or {}
        values["owner"].append(owner.get("display_name")
                               or rec.get("displayName") or "")
        values["ownerUpn"].append(owner.get("upn")
                                  or rec.get("userPrincipalName") or "")
        enabled = owner.get("enabled")
        if enabled is None:
            enabled = rec.get("accountEnabled") in (1, True)
        values["ownerStatus"].append("Enabled" if enabled else "Disabled")
        values["ownerSource"].append(
            owner.get("source")
            or ("AD" if rec.get("dirSyncEnabled") in (1, True) else "Cloud"))
        values["ownerAdDn"].append(
            owner.get("ad_dn") or rec.get("onPremisesDistinguishedName") or "")
        values["ownerAdSid"].append(
            owner.get("ad_sid") or rec.get("onPremisesSecurityIdentifier") or "")
        values["ownerImmutableId"].append(
            owner.get("immutable_id") or rec.get("immutableId") or "")
    return {key: ", ".join(part for part in parts if part is not None)
            for key, parts in values.items()}


def serve_field_map(table_id, f, owner=None, ctx=None):
    """Field map for one finding row in a serve table — mirrors the DOM
    data-field/data-value model plus the implicit 'check' and 'category'
    fields. Used by the advanced filter, table search and drilldown records.

    Every field advertised by TABLE_SPECS is present in the returned map; a
    module-level validation below fails import if a catalog field is missing,
    so the server can never silently filter on a non-existent column."""
    fields = {"check": f.get("check_id", ""),
              "category": CHECK_ID_CATEGORY.get(f.get("check_id", ""), "")}
    if table_id.startswith("ca-"):
        # CA-analysis rows carry their own field map
        fields.update(f.get("fields") or {})
        return fields
    for field in allowed_fields(table_id) or ():
        fields.setdefault(field, "")
    graph = (ctx or {}).get("graph") or {}
    if table_id == "privileged-users-table":
        user = graph_user_record(graph, f.get("user_id")) or {}
        fields.update({
            "user": f.get("user_display") or "", "userUpn": f.get("user_upn") or "",
            "roles": ", ".join(r["name"] for r in f.get("roles", [])),
            "eligible": ", ".join(r["name"] for r in f.get("eligible_roles", [])),
            "privApps": str(len(f.get("priv_apps", []))),
            "capGroups": str(len(f.get("cap_member", []))),
            "grpOwned": str(f.get("owned_count", 0)),
            "caExcl": str(len(f.get("ca_exclusions", []))),
            "hybrid": "AD" if f.get("hybrid") else "Cloud",
            "userStatus": "Enabled" if f.get("user_enabled") else "Disabled",
            "adDn": user.get("onPremisesDistinguishedName") or "",
            "adSid": user.get("onPremisesSecurityIdentifier") or "",
            "immutableId": user.get("immutableId") or "",
            "severity": f.get("severity", "Info"),
        })
    elif table_id == "groups-table":
        rule = (f.get("dyn_rule") or "").strip()
        fields.update({
            "group": f.get("group_name") or "",
            "grpType": grp_type_value(f),
            "groupSource": group_source_value(f, {"graph": graph}),
            "grpRoles": ", ".join(r["name"] for r in f.get("dir_roles", [])),
            "eligible": ", ".join(r["name"] for r in f.get("eligible_roles", [])),
            "grpMembers": str(f.get("member_count", 0)),
            "grpPriv": str(f.get("priv_member_count", 0)),
            "grpOwners": str(len(f.get("owners", []))),
            "dynRule": rule if rule not in ("", "[]") else "",
            "severity": f.get("severity", "Info"),
        })
    elif table_id == "dynamic-groups-table":
        rule = (f.get("dyn_rule") or "").strip()
        fields.update({
            "dynGroup": f.get("group_name") or "",
            "dynRule": rule if rule not in ("", "[]") else "",
            "dynAttrs": ", ".join(f.get("dyn_attrs", [])),
            "dynMods": ", ".join(f.get("dyn_mods", [])),
            "grpMembers": str(f.get("member_count", 0)),
            "grpOwners": str(len(f.get("owners", []))),
        })
    elif table_id in ("owned-table", "unowned-table"):
        owners = [owner] if owner is not None else f.get("owners", [])
        fields.update(_owner_field_map(owners, ctx))
        fields.update({
            "app": f.get("display_name") or "",
            "pw": str(f.get("pw")) if f.get("pw") is not None else "",
            "keys": str(f.get("keys")) if f.get("keys") is not None else "",
            "resource": f.get("resource_name") or "",
            "permission": f.get("permission") or "",
            "spStatus": "Enabled" if f.get("sp_enabled") else "Disabled",
            "appId": sp_app_id(f.get("principal_id"), f.get("app_object_id"), graph),
            "spType": ((graph.get("sp") or {}).get(f.get("principal_id")) or {}
                       ).get("servicePrincipalType") or "",
            "severity": f.get("severity", "Info"),
        })
    elif table_id == "ad-sync-users-table":
        user = graph_user_record(graph, f.get("user_id")) or {}
        fields.update({
            "adUser": f.get("user_display") or "", "adUpn": f.get("user_upn") or "",
            "adCn": f.get("ad_cn") or "", "adDn": f.get("ad_dn") or "",
            "adSid": f.get("ad_sid") or "", "adPw": f.get("pw_change") or "",
            "adTags": ", ".join(f.get("tags", [])),
            "caExcl": str(len(f.get("ca_exclusions", []))),
            "adStatus": "Enabled" if (f.get("status") or {}).get("enabled") else "Disabled",
            "immutableId": user.get("immutableId") or "",
        })
    elif table_id == "table-ca_exposure":
        fields.update({
            "polName": f.get("policy_name") or "", "polState": f.get("state") or "",
            "polScope": f.get("scope") or "",
            "polApps": ", ".join((f.get("conditions_html") or {}).get("apps") or []),
            "polControls": ", ".join((f.get("conditions_html") or {}).get("controls") or []),
            "polInc": str(len(f.get("included", []))),
            "polExc": str(len(f.get("excluded", []))),
            "polType": ("" if f.get("policy_type") is None
                        else str(f.get("policy_type"))),
            "polCreated": f.get("created") or "",
            "polModified": f.get("modified") or "",
            "severity": f.get("severity", "Info"),
        })
    elif table_id == "app-dir-roles-table":
        t = f.get("target") or {}
        sp_id = f.get("sp_id") or (t.get("id") if t.get("type") == "ServicePrincipal" else "")
        sp_rec = (graph.get("sp") or {}).get(sp_id) or {}
        fields.update(_owner_field_map([sp_owner_dict(sp_id, graph)] if sp_id else [], ctx))
        fields.update({
            "app": t.get("name") or "", "id": t.get("id") or "",
            "appDirRoles": ", ".join(r["name"] for r in f.get("dir_role_tags", [])),
            "status": (f.get("status") or {}).get("label") or "",
            "appId": sp_app_id(sp_id, "", graph),
            "spType": sp_rec.get("servicePrincipalType") or "",
            "severity": f.get("severity", "Info"),
        })
    elif table_id == "enterprise-apps-table":
        owners = (f.get("owners") or [])[:1]
        fields.update(_owner_field_map(owners, ctx))
        fields.update({
            "app": f.get("display_name") or "",
            "ssoProtocol": f.get("sso_protocol") or "",
            "ssoPublisher": f.get("sso_publisher") or "",
            "ssoAudience": f.get("sso_audience") or "",
            "ssoAssignment": ("Required" if f.get("sso_assignment_required")
                              else "Not required"),
            "ssoAssigned": (f.get("sso_assigned_label")
                            or str(f.get("sso_assigned_user_count") or "")),
            "ssoCertExpiry": (
                "Expired"
                if (f.get("sso_cert_days") is not None
                    and f.get("sso_cert_days") < 0)
                else (f.get("sso_cert_end") or "")),
            "ssoHomeTenant": f.get("sso_home_tenant") or "",
            "ssoVerified": ("Verified" if f.get("sso_verified")
                            else ("Unverified" if f.get("sso_publisher") else "")),
            "ssoReplyUrls": str(len(f.get("sso_reply_urls") or [])),
            "ssoNotify": str(len(f.get("sso_notification_emails") or [])),
            "ssoCertThumb": f.get("sso_cert_thumbprint") or "",
            "appId": f.get("app_id") or "",
            "spType": "Application",
            "id": f.get("sp_id") or "",
            "status": (f.get("status") or {}).get("label") or "",
        })
    elif table_id == "certificate-auth-users-table":
        fields.update({
            "severity": f.get("severity", "Info"),
            "user": f.get("user_display") or "",
            "userUpn": f.get("user_upn") or "",
            "authUserType": f.get("user_type") or "",
            "userStatus": "Enabled" if f.get("user_enabled") else "Disabled",
            "hybrid": "AD" if f.get("hybrid") else "Cloud",
            "authCbaScope": f.get("auth_cba_scope") or "",
            "authCbaMode": f.get("auth_cba_mode") or "",
            "authCbaBindings": f.get("auth_cba_bindings") or "",
            "id": (f.get("target") or {}).get("id") or "",
        })
    elif table_id == "authentication-methods-table":
        fields.update({
            "authMethod": f.get("auth_method_label") or "",
            "authState": f.get("auth_state") or "",
            "authScope": f.get("auth_scope") or "",
            "authRegistration": f.get("auth_registration_label") or "",
            "authSettings": f.get("auth_settings_summary") or "",
            "authSource": f.get("auth_source") or "",
            "authId": f.get("auth_source_id") or "",
        })
    elif table_id == "app-inventory-table":
        t = f.get("target") or {}
        owners = (f.get("inventory_owners") or [])[:1]
        fields.update(_owner_field_map(owners, ctx))
        fields.update({
            "app": f.get("display_name") or t.get("name") or "",
            "targetType": f.get("inventory_type") or t.get("type") or "",
            "appId": f.get("inventory_app_id") or "",
            "spType": f.get("inventory_sp_type") or "",
            "status": (f.get("status") or {}).get("label") or "",
            "pw": str(f.get("pw")) if f.get("pw") is not None else "",
            "keys": str(f.get("keys")) if f.get("keys") is not None else "",
            "roleCount": str(f.get("roles")) if f.get("roles") is not None else "",
            "appDirRoles": ", ".join(r["name"] for r in f.get("dir_role_tags", [])),
            "id": t.get("id") or "",
            "severity": f.get("severity", "Info"),
        })
    elif table_id == "arc-machines-table":
        oid = (f.get("target") or {}).get("id") or ""
        fields.update({
            "arcMachine": f.get("machine_name") or "",
            "arcSub": f.get("arc_sub") or "",
            "arcRg": f.get("arc_rg") or "",
            "arcResourceId": f.get("arc_resource_id") or "",
            "arcStatus": (f.get("arc_status") or {}).get("label") or "",
            "appId": sp_app_id(oid, "", graph),
            "id": oid,
        })
    elif table_id == "arc-principals-table":
        oid = (f.get("target") or {}).get("id") or ""
        kind = f.get("arc_principal_type") or ""
        fields.update({
            "arcPrincipal": f.get("arc_principal") or "",
            "arcPrincipalType": kind,
            "arcTag": "AzureArcSPN" if f.get("arc_tagged") else "",
            "arcAzRoles": ", ".join(a.get("role", "") for a in f.get("arc_roles", [])),
            "pw": str(f.get("pw")) if f.get("pw") is not None else "",
            "pwLastSet": (f.get("pw_last_set") or "")[:10],
            "pwExpiry": (f.get("pw_expiry") or "")[:10],
            "arcStatus": (f.get("arc_status") or {}).get("label") or "",
            "appId": sp_app_id(oid, "", graph) if kind == "Service Principal" else "",
        })
        if kind == "Service Principal":
            fields.update(_owner_field_map([sp_owner_dict(oid, graph)], ctx))
    elif table_id == "arc-providers-table":
        oid = (f.get("target") or {}).get("id") or ""
        fields.update({
            "arcProvider": f.get("arc_provider") or "",
            "arcStatus": (f.get("arc_status") or {}).get("label") or "",
            "appId": sp_app_id(oid, "", graph),
            "id": oid,
        })
    else:  # generic table-<check_id>
        t = f.get("target") or {}
        o = f.get("object_ids") or {}
        sp_id = next(iter(o.get("sp") or ()), "")
        app_oid = next(iter(o.get("app") or ()), "")
        owner = row_owner_dict(f, ctx)
        fields.update(_owner_field_map([owner] if owner else [], ctx))
        fields.update({
            "target": t.get("name") or "", "targetType": t.get("type") or "",
            "id": t.get("id") or "",
            "pw": str(f.get("pw")) if f.get("pw") is not None else "",
            "keys": str(f.get("keys")) if f.get("keys") is not None else "",
            "roleCount": str(f.get("roles")) if f.get("roles") is not None else "",
            "status": (f.get("status") or {}).get("label") or "",
            "appId": sp_app_id(sp_id, app_oid, graph),
            "spType": ((graph.get("sp") or {}).get(sp_id) or {}
                       ).get("servicePrincipalType") or "",
            "severity": f.get("severity", "Info"),
        })
    return fields


def serve_search_text(table_id, f, owner=None, ctx=None):
    """Plain search text derived from the same field map that powers advanced
    filters, so every rendered/selectable value is searchable (B-020)."""
    field_map = serve_field_map(table_id, f, owner=owner, ctx=ctx)
    return " ".join(str(value) for value in field_map.values() if value).lower()


def validate_serve_field_maps():
    """Fail at import when a table advertises a column the server field map
    cannot provide; this is the drift guard for B-022/B-099."""
    errors = []
    for table_id in ["table-generic"] + list(TABLE_SPECS):
        keys = {str(key).lower() for key in serve_field_map(table_id, {}).keys()}
        missing = [field for field in (allowed_fields(table_id) or [])
                   if str(field).lower() not in keys]
        if missing:
            errors.append(f"{table_id}: {', '.join(missing)}")
    if errors:
        raise RuntimeError("serve field map is missing catalog fields:\n  "
                           + "\n  ".join(errors))


validate_serve_field_maps()


def build_serve_records(results, graph=None):
    """All findings as drilldown records, mirroring the DOM record model so
    serve-mode drilldowns match over the full dataset (not just loaded pages)."""
    records = []
    ctx = {"graph": graph or {}}

    def add(fields, sp="", app="", owner="", gid="", pid=""):
        rec = {"__ids": {"sp": sp, "app": app, "owner": owner}, "__gid": gid, "__pid": pid}
        rec.update(fields)
        records.append(rec)

    for res in results:
        for f in res["findings"]:
            o = f.get("object_ids") or {}
            sp_id = next(iter(o.get("sp", set())), "")
            app_id = next(iter(o.get("app", set())), "")
            owner_id = next(iter(o.get("user", set())), "")
            if res["id"] == "priv_app_ownership":
                owners = f.get("owners") or []
                if owners:
                    for owner in owners:
                        add(serve_field_map("owned-table", f, owner, ctx),
                            sp=f.get("principal_id", ""), app=f.get("app_object_id") or "",
                            owner=owner.get("object_id", ""))
                else:
                    # Unowned findings have no owner row in the owned table,
                    # but still need a record so permission/app/resource
                    # drilldowns can find them (e.g. app-role permissions on
                    # service principals with no recorded owner).
                    add(serve_field_map("owned-table", f, ctx=ctx),
                        sp=f.get("principal_id", ""), app=f.get("app_object_id") or "")
            elif res["id"] == "groups":
                gid = f.get("group_id", "")
                add(serve_field_map("groups-table", f, ctx=ctx), gid=gid)
                if f.get("dynamic") and (f.get("dyn_rule") or "").strip() not in ("", "[]"):
                    add(serve_field_map("dynamic-groups-table", f, ctx=ctx), gid=gid)
            elif res["id"] == "ad_sync_users":
                add(serve_field_map("ad-sync-users-table", f, ctx=ctx),
                    owner=f.get("user_id", ""))
            elif res["id"] == "ca_exposure":
                add(serve_field_map("table-ca_exposure", f, ctx=ctx),
                    pid=f.get("policy_id", ""))
            else:
                t = f.get("target") or {}
                add(serve_field_map(_serve_table_id(res["id"]), f, ctx=ctx),
                    sp=sp_id, app=app_id, owner=owner_id,
                    pid=t.get("id", "") if t.get("type") == "Policy" else "")
    return records


def _serve_int(qs, key, default, lo, hi):
    try:
        return min(hi, max(lo, int((qs.get(key) or [str(default)])[0] or default)))
    except (ValueError, TypeError):
        return default


_ADV_CACHE_MAX = 16
_ADV_CACHE = OrderedDict()
_ADV_CACHE_LOCK = threading.RLock()


def _adv_cache_get(key):
    with _ADV_CACHE_LOCK:
        if key in _ADV_CACHE:
            _ADV_CACHE.move_to_end(key)
            return _ADV_CACHE[key]
    return None


def _adv_cache_put(key, findings):
    with _ADV_CACHE_LOCK:
        generation = key[0]
        for old_key in list(_ADV_CACHE):
            if old_key[0] != generation:
                del _ADV_CACHE[old_key]
        _ADV_CACHE[key] = findings
        _ADV_CACHE.move_to_end(key)
        while len(_ADV_CACHE) > _ADV_CACHE_MAX:
            _ADV_CACHE.popitem(last=False)


def _ast_has_text(ast):
    if not isinstance(ast, dict):
        return False
    if ast.get("op") == "text":
        return True
    if ast.get("op") == "not":
        return _ast_has_text(ast.get("child"))
    return any(_ast_has_text(child) for child in ast.get("children") or ())


def _advanced_filter(entry, table_id, ast, row_ctx):
    """Filter findings once per row and reuse the field map for uniq keys."""
    findings = entry["findings"]
    uniq_fields = extract_uniq_fields(ast)
    search = entry["search"] if _ast_has_text(ast) else None

    def field_key(field_map):
        return tuple((field_map.get(field) or "").lower()
                     for field in uniq_fields)

    if table_id == "owned-table":
        out = []
        seen = set()
        for f in findings:
            full_text = search(f) if search else ""
            owners = []
            for owner in f.get("owners", []):
                field_map = serve_field_map("owned-table", f, owner, row_ctx)
                if not evaluate_advanced(ast, field_map, full_text):
                    continue
                if uniq_fields:
                    lowered = {str(k).lower(): v for k, v in field_map.items()}
                    key = field_key(lowered)
                    if key in seen:
                        continue
                    seen.add(key)
                owners.append(owner)
            if owners:
                f2 = dict(f)
                f2["owners"] = owners
                out.append(f2)
        return out

    out = []
    seen = set()
    for f in findings:
        field_map = serve_field_map(table_id, f, ctx=row_ctx)
        full_text = search(f) if search else ""
        if not evaluate_advanced(ast, field_map, full_text):
            continue
        if uniq_fields:
            lowered = {str(k).lower(): v for k, v in field_map.items()}
            key = field_key(lowered)
            if key in seen:
                continue
            seen.add(key)
        out.append(f)
    return out


def serve_table_response(table_id, qs):
    entry = SERVE_STATE["tables"].get(table_id)
    if not entry:
        return {"error": f"unknown table: {table_id}"}, 404
    spec = table_spec(table_id)
    q = (qs.get("q") or [""])[0]
    mode = (qs.get("mode") or [""])[0]
    page = _serve_int(qs, "page", 1, 1, 10 ** 9)
    size = _serve_int(qs, "size", 25, 25, 2000)
    sort = (qs.get("sort") or [""])[0]
    desc = ((qs.get("dir") or ["asc"])[0]).lower() == "desc"
    row_kwargs = {}
    thead_html = None
    colgroup_html = None
    if spec is not None:
        fields = parse_cols_param((qs.get("cols") or [""])[0], table_id)
        sort_key = sort if sort in allowed_fields(table_id) else ""
        row_kwargs = {"columns": fields, "ctx": entry.get("ctx")}
        thead_html = table_thead_row_html(table_id, fields)
        colgroup_html = table_colgroup_inner_html(fields)
    else:
        skmap = entry.get("sort_keys") or {}
        sort_key = skmap.get(sort, sort)
    findings = entry["findings"]
    row_q = q
    if mode == "advanced" and q:
        try:
            ast = parse_advanced_query(q)
        except AdvancedParseError as exc:
            # Do not silently filter by the raw query as a substring: the
            # client already rejected it and must keep the previous rows.
            return {"error": f"invalid advanced filter: {exc}"}, 400
        if ast is not None:
            row_ctx = entry.get("ctx")
            cache_key = (serve_generation(), table_id,
                         id(entry["findings"]), q)
            filtered = _adv_cache_get(cache_key)
            if filtered is None:
                filtered = _advanced_filter(entry, table_id, ast, row_ctx)
                _adv_cache_put(cache_key, filtered)
            findings = filtered
            row_q = ""
    payload = {}
    if thead_html is not None:
        payload["fields"] = fields
        payload["thead_html"] = thead_html
        payload["colgroup_html"] = colgroup_html
    start = (page - 1) * size
    rows, total = entry["rows"](
        findings, q=row_q, sort_key=sort_key, desc=desc,
        start=start, stop=start + size, **row_kwargs)
    pages = max(1, -(-total // size))
    if page > pages:
        page = pages
        start = (page - 1) * size
        rows, total = entry["rows"](
            findings, q=row_q, sort_key=sort_key, desc=desc,
            start=start, stop=start + size, **row_kwargs)
    payload.update({
        "rows_html": "".join(rows),
        "total": total,
        "page": page,
        "pages": pages,
        "size": size,
    })
    return payload, 200



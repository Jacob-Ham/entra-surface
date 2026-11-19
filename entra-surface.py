#!/usr/bin/env python3
"""
Entra ID attack-surface.

Reads a roadrecon SQLite database (https://github.com/dirkjanm/ROADtools) and
runs a registry of checks that surface dangerous users, applications, service
principals, and tenant configuration. Each check emits structured findings
(check_id, category, severity, evidence, object ids); a single renderer turns
them into a sortable/filterable HTML report with drilldown and entity details,
served interactively over HTTP (rows, profiles and drilldowns are fetched on
demand, so it scales to large tenants). Without --db, it serves the GUI shell
with no analysis data. The tool always runs every enabled check and serves the
whole report; check selection lives in the config.

Checks (config: privileged_roles.json -> "checks"):
  priv_app_ownership      - privileged application (app-only) permission grants
                            resolved to the human owners of the app / SP
  enterprise_apps         - SSO-focused enterprise application inventory:
                            protocol, publisher/tenant, audience, assignment
                            posture, effective assigned users, signing-cert
                            expiry and ownership
  no_role_approval        - non-Microsoft apps with appRoleAssignmentRequired
                            = false (no explicit assignment required)
  public_client_privileged - public clients holding privileged roles
  foreign_principal       - SPs owned by another tenant with privileged roles
  app_dir_roles           - applications (service principals) holding directory
                            roles, assigned directly or via group membership
                            (incl. nesting); rated by the most critical role
  app_inventory           - full application / service-principal roster: every
                            service principal plus any application registration
                            without a local SP (unprivileged objects stay Info)
  privileged_users        - full user roster: one row per user; privileged users are
                            rated by directory roles (assigned and eligible), owned
                            privileged apps / role-carrying SPs, and role-capable group
                            membership or ownership. Unrated users stay Info.
                            Directory role severities come from 'directory_roles'.
  groups                  - full group roster: one row per group with the directory
                            roles it carries, role-capability, dynamic rules, owners,
                            and privileged / SP members
  authentication_methods  - authentication methods extracted from collected
                            authentication-method policy configurations
  certificate_auth_users  - users whose authentication-method policy scope
                            allows certificate-based authentication
  ca_exposure             - Conditional Access policy inventory: states, scopes,
                            conditions and exclusions
  ad_sync_summary         - sync summary card: engine in use (Entra Connect on-prem
                            vs likely Cloud Sync), connector host, password-writeback
                            channel, Desktop SSO status
  ad_sync_users           - AD-synced user roster (flagged users only) plus a realm
                            card: SID / DN / on-prem password change / divergence,
                            with synced-privileged, spray, service-account and
                            no-SID tags
  ad_sync_infra           - AD sync attack surface: ADSync groups, sync service
                            principals, hybrid/legacy auth policies, Windows devices
  azure_arc_machines      - Arc-enabled servers (Microsoft.HybridCompute managed
                            identities), with subscription and resource group
  azure_arc_sps           - principals holding Azure Arc ARM roles (matched by
                            built-in role-definition GUIDs) and service principals
                            created by the Arc deployment wizard (AzureArcSPN tag)
  azure_arc_providers     - first-party Microsoft Arc service principals present
                            in the tenant (subscription configured for Arc)
"""
import argparse
import datetime
import gc
import gzip
import hashlib
import html
import http.server
import itertools
import json
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.parse
from collections import defaultdict, Counter
from pathlib import Path

from entra_surface import analysis
from entra_surface import collect as collect_backend
from entra_surface import settings as surface_settings
from entra_surface.config import (
    AZ_SCOPE_TYPES, DEFAULT_AZURE_CONFIG, DEFAULT_CHECK_CFG, DEFAULT_CONFIG,
    ConfigError, apply_azure_severity, azure_severity_for, load_azure_roles,
    load_config,
)
from entra_surface.findings import (
    ELIGIBLE_SEVERITY_STEP, PRIVILEGED_MAX_RANK, SEVERITY_ORDER,
    eligible_severity, is_privileged, make_finding, severity_rank,
)
from entra_surface.filters import (
    ADV_COLUMN_ALIASES, ADV_DISPLAY_PHRASES, ADV_LIST_FIELDS, ADV_PHRASE_CANON,
    ADV_PHRASE_RES, AdvancedParseError, _glob_matches, _normalize_field,
    _rewrite_column_phrases, evaluate_advanced, extract_uniq_fields,
    parse_advanced_query, resolve_advanced_fields, tokenize_advanced,
)
from entra_surface.graph import (
    AUDIT_REQUIRED_TABLES, SQLITE_IN_CHUNK, app_owner_chain,
    build_analysis_indexes, build_graph, chunked,
    compute_effective_group_membership, fetch_by_ids, group_owner_chain,
    group_parents_index, is_foreign_sp, json_list, json_safe_value,
    open_audit_database, prune_empty, role_assignment_count_for_sp,
    role_assignments_for_sp, sp_owner_chain, sp_owner_details,
)
from entra_surface.profiles import (
    DEVICE_DETAIL_FIELDS, SYSTEM_DEFAULT_ROLE, SYSTEM_DEFAULT_ROLE_ID,
    USER_DETAIL_FIELDS, fetch_full_details, make_profile_builder,
)
from entra_surface.policy import (
    _ca_state_label, _normalize_ca_policy, policy_detail_inner,
    policy_detail_normalized, policy_state_from_record,
)
from entra_surface.report.assets import JS_FILTER_MODULE, REPORT_CSS, REPORT_JS
from entra_surface.report.fields import (
    FIELD_META, FIELD_RENDERERS, OWNER_FIELDS, OWNER_USER_FIELDS, _dash_pair,
    _cell_dyn_rule, _graph_of, _graph_user, _owner_user_record, ad_tag_chips,
    app_dir_role_chip, graph_user_record, grp_type_value, row_owner_dict,
    sp_app_id, sp_owner_dict,
)
from entra_surface.report.html import (
    DASH_INNER, EXPAND_BUTTON_HTML, _serve_pager, bool_badge, cap_annotate,
    count_cell, drawer_for_html, esc, severity_badge, severity_class,
    status_cell,
)
from entra_surface.ca.dataset import (
    CA_ALL_PLATFORMS, CA_CLIENT_APP_TYPES, CA_GUEST_TOKENS,
    CA_LEGACY_CLIENT_TYPES, CA_LEGACY_CLIENT_VALUES, CA_OFFICE365_APP_IDS,
    CA_OFFICE365_NAME_PREFIXES, CA_PATH_GLOBAL_SCENARIO_BUDGET, _ca_blocks,
    _ca_policy_inner, ca_app_covered, ca_app_is_office365, ca_client_matches,
    ca_location_verdict, ca_policy_blocks_legacy, ca_policy_excludes_user,
    ca_policy_includes_user, ca_user_is_guest, fmt_platforms, load_ca_dataset,
)
from entra_surface.ca.engine import run_ca_analysis
from entra_surface.ca.tables import make_ca_rows_fn
from entra_surface.cache import (
    CACHE_DIR, CACHE_FINGERPRINT_TABLES, CACHE_VERSION, _finding_identity,
    _index_findings, _json_default, _restore_object_ids, cache_fresh,
    cache_paths, cache_payload_valid, compute_config_fingerprint,
    compute_db_fingerprint, compute_diff, load_cache, load_cache_sidecar,
    save_cache, save_cache_sidecar, write_analysis_cache,
)
from entra_surface.serve.drilldowns import (
    SERVE_CONTAINS_FIELDS, SERVE_DRILLDOWN_COLUMNS, SERVE_FIELD_LABELS,
    serve_drilldown_response,
)
from entra_surface.serve.profiles import (
    DETAIL_LRU_MAX, PROFILE_LRU_MAX, _fetch_one_detail, _lru_get, _lru_put,
    _profile_builder, serve_details_response, serve_profile_response,
)
from entra_surface.serve.tables import (
    _owner_field_map, _serve_int, _serve_table_id, build_serve_records,
    serve_field_map, serve_search_text, serve_table_response,
    validate_serve_field_maps,
)
from entra_surface.state import (
    CA_LOCK, SERVE_STATE, SERVE_STATE_LOCK, serve_generation,
)
from entra_surface.report.tables import (
    GENERIC_SPEC, SORT_TITLE, TABLE_SPECS, USER_OWNER_EXTRAS, allowed_fields,
    catalog_entry, cell_cls, default_fields, field_label, parse_cols_param,
    row_html, table_colgroup_inner_html, table_head_html,
    table_thead_row_html, table_spec, validate_table_specs,
)
from entra_surface.util import parse_datetime, truncate
from entra_surface.roles import (
    _directory_role_disabled, _pim_role_def_name, _role_def_disabled,
    compute_group_eligible_roles, compute_group_roles,
    direct_directory_roles_by_sp, direct_directory_roles_by_user,
    is_pim_directory_assignment, make_directory_role_entry,
    make_sp_dir_resolver, merge_role_entry, normalize_role_scopes,
    pim_scope_label, resolve_group_role_paths, role_display_name,
    role_rating_severity, role_scope_ids, role_scope_label,
    role_scopes_tenant_wide, sp_directory_roles,
)
from entra_surface.checks.ad import (
    PASSWORD_RULE_SETTINGS_TEMPLATE_ID, PHS_ENFORCE_SETTING,
    check_ad_sync_infra, check_ad_sync_summary, check_ad_sync_users,
    parse_desktop_sso,
)
from entra_surface.checks.apps import (
    app_role_grant_severity, build_resource_role_index,
    check_app_directory_roles, check_app_inventory, check_enterprise_apps,
    check_foreign_principal, check_no_role_approval, check_priv_app_ownership,
    check_public_client_privileged, sp_display_name,
)
from entra_surface.checks.arc import (
    check_azure_arc_machines, check_azure_arc_providers, check_azure_arc_sps,
)
from entra_surface.checks.ca import check_ca_exposure
from entra_surface.checks.registry import CHECK_ID_CATEGORY, CHECK_SPECS
from entra_surface.checks.groups import check_groups
from entra_surface.checks.users import check_privileged_users


CATEGORY_ORDER = ["apps", "users", "ad", "groups", "auth", "configs", "arc"]
CATEGORY_LABELS = {
    "apps": "Apps / Service principals",
    "users": "Users",
    "ad": "Active Directory / On-prem",
    "groups": "Groups",
    "auth": "Authentication",
    "configs": "Conditional Access Policies",
    "arc": "Azure Arc",
}

# ---------------------------------------------------------------------------
# SQL / JSON helpers
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Directory-role scopes / state
# ---------------------------------------------------------------------------
# A role assignment scoped to an administrative unit (AU) only grants the
# role over that AU. It must stay visible, but it is not a tenant-wide
# privileged role and must never escalate a finding's rating.

# ---------------------------------------------------------------------------
# Entity graph
# ---------------------------------------------------------------------------

def build_role_applications(graph, group_roles, group_eligible_roles=None):
    """Directory role displayName -> service principals holding that role
    (direct memberships/assignments, plus via group membership incl. nesting).
    Each entry: {"id", "name", "path", "eligible"} where path is the group
    chain to the role-bearing group (None = assigned directly) and eligible
    marks PIM-eligible assignments (marker-only). Drives the 'Applications'
    tab of the directory-role drilldown."""
    def _sp_label(sp_oid):
        rec = graph["sp"].get(sp_oid)
        return (rec.get("displayName") or rec.get("appDisplayName") or sp_oid) if rec else sp_oid

    def _group_label(gid):
        rec = graph["group"].get(gid)
        return rec.get("displayName") if rec else gid

    def _role_name(oid):
        rec = graph["directory_role"].get(oid)
        return rec.get("displayName") if rec else oid

    def _def_name(oid):
        rec = graph["role_definition"].get(oid)
        return rec.get("displayName") if rec else oid

    index = defaultdict(list)

    def add(role, sp_oid, path, eligible=False):
        for existing in index[role]:
            if existing["id"] == sp_oid and existing["path"] == path \
                    and existing.get("eligible") == eligible:
                return
        index[role].append({"id": sp_oid, "name": _sp_label(sp_oid), "path": path,
                            "eligible": eligible})

    for role_oid, sp_oid in graph["role_member_sp"]:
        add(_role_name(role_oid), sp_oid, None)
    for ra in graph["directory_role_assigns"]:
        if ra["principal_id"] in graph["sp"]:
            add(_def_name(ra["role_definition_id"]), ra["principal_id"], None)
    parents_by_child = graph.get("group_parents") or group_parents_index(
        graph["group_member_group"])
    for gid, sp_ids in graph["group_member_sp"].items():
        for r in resolve_group_role_paths(gid, group_roles,
                                          graph["group_member_group"], _group_label,
                                          parents_by_child=parents_by_child):
            for sp_oid in sp_ids:
                if sp_oid in graph["sp"]:
                    add(r["name"], sp_oid, r["path"])
    if group_eligible_roles:
        for ea in graph["eligible_role_assigns"]:
            if ea["principal_id"] in graph["sp"]:
                name = _def_name(ea["role_definition_id"])
                # eligible marker only matters when the role isn't held actively
                if not any(e["id"] == ea["principal_id"] and not e.get("eligible")
                           for e in index[name]):
                    add(name, ea["principal_id"], None, eligible=True)
        for gid, sp_ids in graph["group_member_sp"].items():
            for r in resolve_group_role_paths(gid, group_eligible_roles,
                                              graph["group_member_group"], _group_label,
                                              parents_by_child=parents_by_child):
                for sp_oid in sp_ids:
                    if sp_oid in graph["sp"] and not any(
                            e["id"] == sp_oid and not e.get("eligible")
                            for e in index[r["name"]]):
                        add(r["name"], sp_oid, r["path"], eligible=True)
    for role in index:
        index[role].sort(key=lambda e: (e["name"] or "").lower())
    return dict(index)


def build_permission_applications(results):
    """Permission value -> principals holding it for the permission drilldown.

    Mirrors build_role_applications for app-role permissions: drives the
    'Applications' tab of the permission drilldown, with the recorded owners
    of each principal in the 'Users' tab."""
    priv = next((res for res in results
                 if res.get("id") == "priv_app_ownership"), None)
    index = {}
    if not priv:
        return index
    for f in priv.get("findings") or []:
        permission = f.get("permission") or ""
        principal_id = f.get("principal_id") or ""
        if not permission or not principal_id:
            continue
        resource = f.get("resource_name") or ""
        entries = index.setdefault(permission, [])
        entry = next((e for e in entries
                      if e["id"] == principal_id and e["resource"] == resource), None)
        if entry is None:
            entry = {
                "id": principal_id,
                "name": (f.get("display_name") or f.get("sp_display_name")
                         or principal_id),
                "app_object_id": f.get("app_object_id") or "",
                "resource": resource,
                "owners": [],
            }
            entries.append(entry)
        seen = {(o.get("object_id"), o.get("upn")) for o in entry["owners"]}
        for owner in f.get("owners") or []:
            key = (owner.get("object_id"), owner.get("upn"))
            if key not in seen:
                entry["owners"].append(owner)
                seen.add(key)
    for entries in index.values():
        entries.sort(key=lambda e: (e.get("name") or "").lower())
    return index


def run_checks(graph, config_resources, check_cfg,
               group_roles=None, group_eligible_roles=None, sp_dir_resolver=None,
               include_disabled=None):
    """Run every enabled check and return the list of {spec, findings} results."""
    check_config = dict(check_cfg)
    if include_disabled is None:
        include_disabled = check_config.get("include_disabled", True)
    opts = {"include_disabled": bool(include_disabled)}

    # ---- selection from the config only (the tool always serves the full
    # report: every check that the config has not explicitly disabled) ------
    selected = [spec for spec in CHECK_SPECS
                if not (spec["id"] in check_config["enabled"]
                        and not check_config["enabled"][spec["id"]])]

    min_rank = SEVERITY_ORDER.get(check_config.get("min_severity", "Info"), 4)
    suppress = set(check_config.get("suppress", []) or [])

    # ---- shared analysis context ----------------------------------------
    resource_index, resource_names = build_resource_role_index(graph, config_resources)
    priv_sp_ids = set()
    role_sp_ids = set()
    for ra in graph["role_assigns"]:
        if ra["principal_type"] != "ServicePrincipal":
            continue
        role_sp_ids.add(ra["principal_id"])
        if ra["resource_id"] in resource_index and ra["app_role_id"] in resource_index[ra["resource_id"]]:
            priv_sp_ids.add(ra["principal_id"])

    ctx = {
        "graph": graph,
        "config_resources": config_resources,
        "check_cfg": check_config,
        "resource_index": resource_index,
        "resource_names": resource_names,
        "priv_sp_ids": priv_sp_ids,
        "role_sp_ids": role_sp_ids,
        "include_disabled": opts["include_disabled"],
    }

    # ---- role-capable groups + roles carried by groups (shared) ----------
    capable_groups = set()
    for gid, rec in graph["group"].items():
        if rec.get("isAssignableToRole") in (1, True):
            capable_groups.add(gid)
    for _, gid in graph["role_member_group"]:
        capable_groups.add(gid)
    for ra in graph["directory_role_assigns"]:
        if ra["principal_id"] in graph["group"]:
            capable_groups.add(ra["principal_id"])
    for ea in graph["eligible_role_assigns"]:
        if ea["principal_id"] in graph["group"]:
            capable_groups.add(ea["principal_id"])
    changed = True
    while changed:
        changed = False
        for parent, children in graph["group_member_group"].items():
            if parent in capable_groups:
                for child in children:
                    if child not in capable_groups:
                        capable_groups.add(child)
                        changed = True

    if group_roles is None:
        group_roles = compute_group_roles(graph, check_config)
    if group_eligible_roles is None:
        group_eligible_roles = compute_group_eligible_roles(graph, check_config)
    analysis_indexes = build_analysis_indexes(graph)
    # Keep the shared membership indexes with the graph so the lazy SP profile
    # builder can reuse them instead of recomputing the closure per drawer.
    graph["analysis_indexes"] = analysis_indexes
    direct_user_roles = direct_directory_roles_by_user(
        graph, check_config["directory_roles"])
    direct_sp_roles = direct_directory_roles_by_sp(
        graph, check_config["directory_roles"])
    if sp_dir_resolver is None:
        sp_dir_resolver = make_sp_dir_resolver(
            graph, group_roles, check_config["directory_roles"], group_eligible_roles,
            direct_sp_roles=direct_sp_roles,
            groups_by_sp=analysis_indexes["groups_by_sp"],
            parents_by_child=analysis_indexes["parents_by_child"])

    ctx["capable_groups"] = capable_groups
    ctx["group_roles"] = group_roles
    ctx["group_eligible_roles"] = group_eligible_roles
    ctx["sp_dir_resolver"] = sp_dir_resolver
    ctx["analysis_indexes"] = analysis_indexes
    ctx["direct_user_roles"] = direct_user_roles
    ctx["direct_sp_roles"] = direct_sp_roles

    # ---- post-processing shared by every check ---------------------------
    def _az_sorted(roles):
        seen = set()
        out = []
        for a in roles:
            key = (a.get("role"), a.get("scope_label"), bool(a.get("eligible")))
            if key in seen:
                continue
            seen.add(key)
            out.append(a)
        out.sort(key=lambda a: (bool(a.get("eligible")), a["role"].lower()))
        return out

    def postprocess(findings):
        # ARM (Azure RBAC) roles per finding (marker only, never rated).
        for f in findings:
            if f.get("az_roles") is not None:
                continue
            o = f.get("object_ids") or {}
            roles = []
            for sid in o.get("sp", set()):
                roles.extend(graph["az_sp_roles"].get(sid, []))
            for uid in o.get("user", set()):
                roles.extend(graph["az_user_roles"].get(uid, []))
            if roles:
                f["az_roles"] = _az_sorted(roles)
        # Directory roles per SP: the finding's severity is raised to the most
        # critical active directory role its principals hold.
        for f in findings:
            o = f.get("object_ids") or {}
            sp_ids = o.get("sp", set())
            if not sp_ids:
                continue
            merged = {}
            for sp_oid in sorted(sp_ids):
                for r in sp_dir_resolver(sp_oid):
                    if r["name"] not in merged:
                        merged[r["name"]] = dict(r)
                    else:
                        merge_role_entry(merged[r["name"]], r)
            if not merged:
                continue
            f["dir_role_tags"] = sorted(
                merged.values(), key=lambda r: severity_rank(r["severity"]))
            # eligible (PIM) roles are marker-only: rate by active roles alone;
            # AU-scoped/disabled roles never raise a tenant-wide finding.
            active = [r for r in f["dir_role_tags"] if not r.get("eligible")]
            if not active:
                continue
            best_rank = min(severity_rank(role_rating_severity(r)) for r in active)
            if best_rank < severity_rank(f["severity"]):
                f["severity"] = next(
                    sev for sev, rank in SEVERITY_ORDER.items() if rank == best_rank)
        return findings

    def filter_findings(findings):
        # severity/suppress filtering runs *after* all severity escalation
        filtered = []
        for f in findings:
            if severity_rank(f["severity"]) > min_rank:
                continue
            key = f"{f['check_id']}:{f['primary_id']}"
            if key in suppress or f["check_id"] in suppress:
                continue
            filtered.append(f)
        return filtered

    results = []
    for spec in selected:
        sys.stdout.write(f"Running {spec['id']}...")
        sys.stdout.flush()
        try:
            findings = spec["run"](ctx)
            postprocess(findings)
            filtered = filter_findings(findings)
        except Exception:
            sys.stdout.write(" error\n")
            raise
        sys.stdout.write(f" {len(filtered)}\n")
        if filtered:
            results.append({"id": spec["id"], "category": spec["category"],
                            "title": spec["title"], "description": spec["description"],
                            "findings": filtered,
                            "meta": ctx.get("ad_realm", {})})
            if spec["id"] == "privileged_users":
                # Later checks can reuse the user rating without recomputing
                # the full privilege graph.
                ctx["user_findings"] = filtered
    return results

# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Column catalog
# ---------------------------------------------------------------------------
# Every main table declares an ordered list of default columns plus add-on
# columns ("extras"). Each field maps to a renderer returning (inner_html,
# data_value); cells are assembled by row_html() so the default output stays
# byte-identical to the legacy per-table templates. The same catalog drives:
#   * serve mode (the `cols=` request parameter renders any subset/order),
#   * shell-rendered azure-roles tables (extras delivered via data blobs),
#   * the client-side column manager (window.__TABLE_CATALOG).
#
# Extra columns are declared per table in TABLE_SPECS.

def user_search_text(f, ctx=None):
    return serve_search_text("privileged-users-table", f, ctx=ctx)


def user_sort_value(f, key, ctx=None):
    if key == "severity":
        return SEVERITY_ORDER.get(f.get("severity", "Info"), 4)
    if key == "user":
        return (f.get("user_display") or "").lower()
    if key == "userUpn":
        return (f.get("user_upn") or "").lower()
    if key == "roles":
        return ", ".join(r["name"] for r in f.get("roles", [])).lower()
    if key == "eligible":
        return len(f.get("eligible_roles", []))
    if key == "privApps":
        return len(f.get("priv_apps", []))
    if key == "capGroups":
        return len(f.get("cap_member", []))
    if key == "grpOwned":
        return f.get("owned_count", 0)
    if key == "caExcl":
        return len(f.get("ca_exclusions", []))
    if key == "hybrid":
        return "AD" if f.get("hybrid") else "Cloud"
    if key == "userStatus":
        return 0 if f.get("user_enabled") else 1
    if key in ("adDn", "adSid", "immutableId"):
        rec = graph_user_record((ctx or {}).get("graph"), f.get("user_id")) or {}
        if key == "adDn":
            return (rec.get("onPremisesDistinguishedName") or "").lower()
        if key == "adSid":
            return (rec.get("onPremisesSecurityIdentifier") or "").lower()
        return (rec.get("immutableId") or "").lower()
    return 0


def user_rows_html(findings, start=0, stop=None, q="", sort_key=None, desc=False,
                   columns=None, ctx=None):
    """Pre-rendered <tr> html for the privileged-users table (served by the
    table endpoint)."""
    tid = "privileged-users-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    items = findings
    if q:
        q = q.lower()
        items = [f for f in items if q in serve_search_text(tid, f, ctx=ctx)]
    if sort_key:
        items = sorted(items, key=lambda f: user_sort_value(f, sort_key, ctx),
                       reverse=bool(desc))
    else:
        items = sorted(items, key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "Info"), 4),
                                             (f.get("user_display") or "").lower()))
    if stop is None:
        stop = len(items)
    out = []
    for f in items[start:stop]:
        key = f"row-{len(out)}"
        r = {"graph": (ctx or {}).get("graph"), "user_id": f["user_id"], "tid": tid}
        tr_attrs = (f'data-sp-id="" data-app-id="" '
                    f'data-owner-id="{esc(f["user_id"])}" '
                    f'data-profile-id="{esc(f["user_id"])}"')
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, len(items)


def page_rows(findings, q, sort_key, desc, start, stop, search_text, sort_value):
    """Shared q/sort/page pipeline for the serve-mode table endpoints."""
    items = findings
    if q:
        q = q.lower()
        items = [f for f in items if q in search_text(f)]
    if sort_key:
        items = sorted(items, key=lambda f: sort_value(f, sort_key), reverse=bool(desc))
    else:
        items = sorted(items, key=lambda f: (severity_rank(f.get("severity", "Info")),
                                             (str(f.get("title") or "")).lower()))
    if stop is None:
        stop = len(items)
    return items[start:stop], len(items)


# ---- legacy owned/unowned rows ---------------------------------------------

def legacy_search_text(f, owner=None, ctx=None):
    return serve_search_text("owned-table", f, owner=owner, ctx=ctx)


def sp_extra_sort_value(sp_id, app_id, key, ctx):
    graph = (ctx or {}).get("graph")
    if key == "appId":
        return sp_app_id(sp_id, app_id, graph).lower()
    rec = ((graph or {}).get("sp") or {}).get(sp_id)
    return ((rec or {}).get("servicePrincipalType") or "").lower()


def owner_attr_sort_value(rec, key):
    """Sort key for owner-resolved user attribute columns (rec = graph user)."""
    rec = rec or {}
    if key == "ownerSource":
        return 0 if rec.get("dirSyncEnabled") in (1, True) else 1
    if key == "ownerAdDn":
        return (rec.get("onPremisesDistinguishedName") or "").lower()
    if key == "ownerAdSid":
        return (rec.get("onPremisesSecurityIdentifier") or "").lower()
    return (rec.get("immutableId") or "").lower()




def legacy_sort_value(f, key, ctx=None, owner=None):
    owner = owner if owner is not None else (f.get("owners") or [{}])[0]
    if key == "severity":
        return severity_rank(f.get("severity", "Info"))
    if key == "owner":
        return (owner.get("display_name") or "").lower()
    if key == "ownerUpn":
        return (owner.get("upn") or "").lower()
    if key == "ownerStatus":
        return 0 if owner.get("enabled") else 1
    if key in OWNER_FIELDS:
        return owner_attr_sort_value(
            graph_user_record((ctx or {}).get("graph"), owner.get("object_id")), key)
    if key == "app":
        return (f.get("display_name") or "").lower()
    if key == "pw":
        return f.get("pw") or 0
    if key == "keys":
        return f.get("keys") or 0
    if key == "resource":
        return (f.get("resource_name") or "").lower()
    if key == "permission":
        return (f.get("permission") or "").lower()
    if key == "spStatus":
        return 0 if f.get("sp_enabled") else 1
    if key in ("appId", "spType"):
        return sp_extra_sort_value(f.get("principal_id"), f.get("app_object_id"),
                                   key, ctx)
    return 0


def legacy_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                     columns=None, ctx=None):
    tid = "owned-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    # One row per (finding, owner), filtered and sorted at the same row level
    # as the rendered table. Previously plain search matched any owner of a
    # finding and then emitted every owner row (B-052).
    rows = [(f, owner) for f in findings for owner in (f.get("owners") or [])]
    if q:
        needle = q.lower()
        rows = [(f, owner) for f, owner in rows
                if needle in serve_search_text(tid, f, owner=owner, ctx=ctx)]
    if sort_key:
        rows = sorted(rows, key=lambda pair: legacy_sort_value(
            pair[0], sort_key, ctx, owner=pair[1]), reverse=bool(desc))
    else:
        rows = sorted(
            rows,
            key=lambda pair: (severity_rank(pair[0].get("severity", "Info")),
                              str(pair[0].get("title") or "").lower()))
    total = len(rows)
    if stop is None:
        stop = total
    out = []
    for row_index, (f, owner) in enumerate(rows[start:stop]):
        key = f"row-{start + row_index}"
        r = {"graph": (ctx or {}).get("graph"), "owner": owner,
             "tid": tid, "sp_id": f.get("principal_id"),
             "app_id": f.get("app_object_id")}
        tr_attrs = (f'data-sp-id="{esc(f["principal_id"])}" '
                    f'data-app-id="{esc(f["app_object_id"] or "")}" '
                    f'data-owner-id="{esc(owner["object_id"])}"')
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


def unowned_search_text(f, ctx=None):
    return serve_search_text("unowned-table", f, ctx=ctx)


def unowned_sort_value(f, key, ctx=None):
    if key == "severity":
        return severity_rank(f.get("severity", "Info"))
    if key == "app":
        return (f.get("display_name") or "").lower()
    if key == "pw":
        return f.get("pw") or 0
    if key == "keys":
        return f.get("keys") or 0
    if key == "resource":
        return (f.get("resource_name") or "").lower()
    if key == "permission":
        return (f.get("permission") or "").lower()
    if key == "spStatus":
        return 0 if f.get("sp_enabled") else 1
    if key in ("appId", "spType"):
        return sp_extra_sort_value(f.get("principal_id"), f.get("app_object_id"),
                                   key, ctx)
    return 0


def legacy_unowned_rows_html(findings, q="", sort_key=None, desc=False, start=0,
                             stop=None, columns=None, ctx=None):
    tid = "unowned-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                            lambda f: serve_search_text(tid, f, ctx=ctx),
                            lambda f, k: unowned_sort_value(f, k, ctx))
    out = []
    for f in selected:
        key = f"row-{len(out)}"
        r = {"graph": (ctx or {}).get("graph"), "tid": tid,
             "sp_id": f.get("principal_id"), "app_id": f.get("app_object_id")}
        tr_attrs = (f'data-sp-id="{esc(f["principal_id"])}" '
                    f'data-app-id="{esc(f["app_object_id"] or "")}" '
                    f'data-owner-id=""')
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


# ---- generic (per-check) rows ----------------------------------------------

def generic_search_text(f, ctx=None):
    return serve_search_text("table-generic", f, ctx=ctx)


def generic_sort_value(f, key, ctx=None):
    t = f.get("target") or {}
    if key == "severity":
        return severity_rank(f.get("severity", "Info"))
    if key == "target":
        return (t.get("name") or "").lower()
    if key == "targetType":
        return (t.get("type") or "").lower()
    if key == "id":
        return (t.get("id") or "").lower()
    if key == "pw":
        return f.get("pw") or 0
    if key == "keys":
        return f.get("keys") or 0
    if key == "roleCount":
        return f.get("roles") or 0
    if key == "status":
        return ((f.get("status") or {}).get("label") or "").lower()
    o = f.get("object_ids") or {}
    if key in OWNER_FIELDS:
        owner = row_owner_dict(f, ctx) or {}
        if key == "owner":
            return (owner.get("display_name") or "").lower()
        if key == "ownerUpn":
            return (owner.get("upn") or "").lower()
        if key == "ownerStatus":
            return 0 if owner.get("enabled") else 1
        return owner_attr_sort_value(
            graph_user_record((ctx or {}).get("graph"), owner.get("object_id")), key)
    if key in ("appId", "spType"):
        return sp_extra_sort_value(next(iter(o.get("sp", ()) or ()), ""),
                                   next(iter(o.get("app", ()) or ()), ""), key, ctx)
    return 0


def generic_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                      columns=None, ctx=None):
    tid = "table-generic"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                            lambda f: serve_search_text(tid, f, ctx=ctx),
                            lambda f, k: generic_sort_value(f, k, ctx))
    out = []
    for f in selected:
        o = f.get("object_ids") or {}
        sp_id = next(iter(o.get("sp", set())), "")
        app_id = next(iter(o.get("app", set())), "")
        owner_id = next(iter(o.get("user", set())), "")
        device_id = next(iter(o.get("device", set())), "")
        t = f.get("target") or {}
        key = f"row-{len(out)}"
        policy_id = esc(t.get("id", "")) if t.get("type") == "Policy" else ""
        r = {"graph": (ctx or {}).get("graph"), "tid": tid,
             "owner": row_owner_dict(f, ctx), "sp_id": sp_id, "app_id": app_id}
        tr_attrs = (f'data-sp-id="{esc(sp_id)}" data-app-id="{esc(app_id)}" '
                    f'data-owner-id="{esc(owner_id)}" data-device-id="{esc(device_id)}" '
                    f'data-policy-id="{policy_id}" data-check-id="{esc(f["check_id"])}"')
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


# ---- azure arc rows ---------------------------------------------------------

def arc_search_text(f, table_id="arc-principals-table", ctx=None):
    return serve_search_text(table_id, f, ctx=ctx)


def arc_sort_value(f, key, ctx=None):
    if key == "severity":
        return severity_rank(f.get("severity", "Info"))
    if key in ("arcMachine", "arcPrincipal", "arcProvider"):
        return (f.get("machine_name") or f.get("arc_principal")
                or f.get("arc_provider") or "").lower()
    if key == "arcSub":
        return (f.get("arc_sub") or "").lower()
    if key == "arcRg":
        return (f.get("arc_rg") or "").lower()
    if key == "arcResourceId":
        return (f.get("arc_resource_id") or "").lower()
    if key == "arcPrincipalType":
        return (f.get("arc_principal_type") or "").lower()
    if key == "arcTag":
        return 0 if f.get("arc_tagged") else 1
    if key == "arcAzRoles":
        return ", ".join(a.get("role", "") for a in f.get("arc_roles", [])).lower()
    if key == "pw":
        return f.get("pw") or 0
    if key == "pwLastSet":
        return (f.get("pw_last_set") or "").lower()
    if key == "pwExpiry":
        return (f.get("pw_expiry") or "").lower()
    if key == "arcStatus":
        st = f.get("arc_status") or {}
        return (st.get("label") or "").lower()
    if key == "appId":
        o = f.get("object_ids") or {}
        return sp_extra_sort_value(next(iter(o.get("sp", ()) or ()), ""), "", key, ctx)
    if key == "id":
        return ((f.get("target") or {}).get("id") or "").lower()
    if key in OWNER_FIELDS:
        oid = (f.get("target") or {}).get("id") or ""
        owner = ({}
                 if (f.get("arc_principal_type") or "") != "Service Principal"
                 else (sp_owner_dict(oid, (ctx or {}).get("graph")) or {}))
        if key == "owner":
            return (owner.get("display_name") or "").lower()
        if key == "ownerUpn":
            return (owner.get("upn") or "").lower()
        if key == "ownerStatus":
            return 0 if owner.get("enabled") else 1
        return owner_attr_sort_value(
            graph_user_record((ctx or {}).get("graph"), owner.get("object_id")), key)
    return 0


def arc_machines_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                           columns=None, ctx=None):
    tid = "arc-machines-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                                lambda f: serve_search_text(tid, f, ctx=ctx),
                                lambda f, k: arc_sort_value(f, k, ctx))
    out = []
    for f in selected:
        sp_id = (f.get("target") or {}).get("id") or ""
        key = f"row-{len(out)}"
        r = {"graph": (ctx or {}).get("graph"), "tid": tid, "sp_id": sp_id}
        tr_attrs = f'data-sp-id="{esc(sp_id)}" data-check-id="{esc(f["check_id"])}"'
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


def arc_principals_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                             columns=None, ctx=None):
    tid = "arc-principals-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                                lambda f: serve_search_text(tid, f, ctx=ctx),
                                lambda f, k: arc_sort_value(f, k, ctx))
    out = []
    graph = (ctx or {}).get("graph")
    for f in selected:
        oid = (f.get("target") or {}).get("id") or ""
        kind = f.get("arc_principal_type") or ""
        key = f"row-{len(out)}"
        r = {"graph": graph, "tid": tid}
        if kind == "Service Principal":
            r["sp_id"] = oid
            r["owner"] = sp_owner_dict(oid, graph)
            tr_attrs = f'data-sp-id="{esc(oid)}" data-check-id="{esc(f["check_id"])}"'
        elif kind == "User":
            tr_attrs = f'data-profile-id="{esc(oid)}" data-check-id="{esc(f["check_id"])}"'
        else:
            gid = f.get("arc_group_id") or oid
            tr_attrs = f'data-group-id="{esc(gid)}" data-check-id="{esc(f["check_id"])}"'
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


def arc_providers_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                            columns=None, ctx=None):
    tid = "arc-providers-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                                lambda f: serve_search_text(tid, f, ctx=ctx),
                                lambda f, k: arc_sort_value(f, k, ctx))
    out = []
    for f in selected:
        sp_id = (f.get("target") or {}).get("id") or ""
        key = f"row-{len(out)}"
        r = {"graph": (ctx or {}).get("graph"), "tid": tid, "sp_id": sp_id}
        tr_attrs = f'data-sp-id="{esc(sp_id)}" data-check-id="{esc(f["check_id"])}"'
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


ARC_TABLE_ROWS = {
    "arc-machines-table": arc_machines_rows_html,
    "arc-principals-table": arc_principals_rows_html,
    "arc-providers-table": arc_providers_rows_html,
}


# ---- app directory roles rows ------------------------------------------------

def app_dir_search_text(f, ctx=None):
    return serve_search_text("app-dir-roles-table", f, ctx=ctx)


def app_dir_sort_value(f, key, ctx=None):
    t = f.get("target") or {}
    if key == "severity":
        return severity_rank(f.get("severity", "Info"))
    if key == "app":
        return (t.get("name") or "").lower()
    if key == "id":
        return (t.get("id") or "").lower()
    if key == "appDirRoles":
        return ", ".join(r["name"] for r in f.get("dir_role_tags", [])).lower()
    if key == "status":
        return 0 if (f.get("status") or {}).get("enabled") else 1
    if key in OWNER_FIELDS:
        owner = sp_owner_dict(f.get("sp_id"), (ctx or {}).get("graph")) or {}
        if key == "owner":
            return (owner.get("display_name") or "").lower()
        if key == "ownerUpn":
            return (owner.get("upn") or "").lower()
        if key == "ownerStatus":
            return 0 if owner.get("enabled") else 1
        return owner_attr_sort_value(
            graph_user_record((ctx or {}).get("graph"), owner.get("object_id")), key)
    if key in ("appId", "spType"):
        sp_id = f.get("sp_id") or (t.get("id")
                                   if t.get("type") == "ServicePrincipal" else "")
        return sp_extra_sort_value(sp_id, "", key, ctx)
    return 0


def app_dir_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                      columns=None, ctx=None):
    tid = "app-dir-roles-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    need_owner = any(x in fields for x in OWNER_FIELDS)
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                                lambda f: serve_search_text(tid, f, ctx=ctx),
                                lambda f, k: app_dir_sort_value(f, k, ctx))
    out = []
    for f in selected:
        key = f"row-{len(out)}"
        sp_id = f.get("sp_id") or ""
        r = {"graph": (ctx or {}).get("graph"), "tid": tid, "sp_id": sp_id}
        if need_owner:
            r["owner"] = sp_owner_dict(sp_id, (ctx or {}).get("graph"))
        tr_attrs = f'data-sp-id="{esc(sp_id)}"'
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


# ---- app / service-principal inventory rows ----------------------------------

def app_inventory_search_text(f, ctx=None):
    return serve_search_text("app-inventory-table", f, ctx=ctx)


def app_inventory_sort_value(f, key, ctx=None):
    t = f.get("target") or {}
    owners = f.get("inventory_owners") or []
    owner = owners[0] if owners else {}
    if key == "severity":
        return severity_rank(f.get("severity", "Info"))
    if key == "app":
        return (t.get("name") or f.get("display_name") or "").lower()
    if key == "targetType":
        return (f.get("inventory_type") or "").lower()
    if key == "appId":
        return (f.get("inventory_app_id") or "").lower()
    if key == "spType":
        return (f.get("inventory_sp_type") or "").lower()
    if key == "status":
        return 0 if (f.get("status") or {}).get("enabled") else 1
    if key == "pw":
        return f.get("pw") or 0
    if key == "keys":
        return f.get("keys") or 0
    if key == "roleCount":
        return f.get("roles") or 0
    if key == "appDirRoles":
        return ", ".join(r["name"] for r in f.get("dir_role_tags", [])).lower()
    if key == "id":
        return (t.get("id") or "").lower()
    if key in OWNER_FIELDS:
        if key == "owner":
            return (owner.get("display_name") or "").lower()
        if key == "ownerUpn":
            return (owner.get("upn") or "").lower()
        if key == "ownerStatus":
            return 0 if owner.get("enabled") else 1
        return owner_attr_sort_value(
            graph_user_record((ctx or {}).get("graph"), owner.get("object_id")), key)
    return 0


def app_inventory_rows_html(findings, q="", sort_key=None, desc=False, start=0,
                            stop=None, columns=None, ctx=None):
    tid = "app-inventory-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                                lambda f: serve_search_text(tid, f, ctx=ctx),
                                lambda f, k: app_inventory_sort_value(f, k, ctx))
    out = []
    for f in selected:
        o = f.get("object_ids") or {}
        sp_id = next(iter(sorted(o.get("sp") or ())), "")
        app_id = next(iter(sorted(o.get("app") or ())), "")
        owners = f.get("inventory_owners") or []
        owner_id = owners[0].get("object_id") if owners else ""
        r = {"graph": (ctx or {}).get("graph"), "tid": tid, "sp_id": sp_id,
             "app_id": app_id, "owner": owners[0] if owners else None}
        tr_attrs = (f'data-sp-id="{esc(sp_id)}" data-app-id="{esc(app_id)}" '
                    f'data-owner-id="{esc(owner_id)}"')
        out.append(row_html(tid, tr_attrs, f"row-{len(out)}", fields, f, r))
    return out, total


# ---- enterprise apps (SSO) ---------------------------------------------------

def enterprise_apps_search_text(f, ctx=None):
    return serve_search_text("enterprise-apps-table", f, ctx=ctx)


def enterprise_apps_sort_value(f, key, ctx=None):
    owners = f.get("owners") or []
    owner = owners[0] if owners else {}
    if key == "severity":
        return severity_rank(f.get("severity", "Info"))
    if key == "app":
        return (f.get("display_name") or "").lower()
    if key == "ssoProtocol":
        return (f.get("sso_protocol") or "").lower()
    if key == "ssoPublisher":
        return (f.get("sso_publisher") or "").lower()
    if key == "ssoAudience":
        return (f.get("sso_audience") or "").lower()
    if key == "ssoAssignment":
        return 0 if f.get("sso_assignment_required") else 1
    if key == "ssoAssigned":
        return f.get("sso_assigned_user_count") or 0
    if key == "ssoCertExpiry":
        days = f.get("sso_cert_days")
        return days if days is not None else 10 ** 9
    if key == "ssoHomeTenant":
        return (f.get("sso_home_tenant") or "").lower()
    if key == "ssoVerified":
        return 0 if f.get("sso_verified") else 1
    if key == "ssoReplyUrls":
        return len(f.get("sso_reply_urls") or [])
    if key == "ssoNotify":
        return len(f.get("sso_notification_emails") or [])
    if key == "ssoCertThumb":
        return (f.get("sso_cert_thumbprint") or "").lower()
    if key == "appId":
        return (f.get("app_id") or "").lower()
    if key == "id":
        return (f.get("sp_id") or "").lower()
    if key == "spType":
        return "application"
    if key == "status":
        return 0 if (f.get("status") or {}).get("enabled") else 1
    if key in OWNER_FIELDS:
        if key == "owner":
            return (owner.get("display_name") or "").lower()
        if key == "ownerUpn":
            return (owner.get("upn") or "").lower()
        if key == "ownerStatus":
            return 0 if owner.get("enabled") else 1
        return owner_attr_sort_value(
            graph_user_record((ctx or {}).get("graph"), owner.get("object_id")), key)
    return 0


def enterprise_apps_rows_html(findings, q="", sort_key=None, desc=False, start=0,
                              stop=None, columns=None, ctx=None):
    tid = "enterprise-apps-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                                lambda f: serve_search_text(tid, f, ctx=ctx),
                                lambda f, k: enterprise_apps_sort_value(f, k, ctx))
    out = []
    for f in selected:
        owners = f.get("owners") or []
        owner = owners[0] if owners else None
        sp_id = f.get("sp_id") or ""
        app_object_id = f.get("app_object_id") or ""
        owner_id = (owner or {}).get("object_id") or ""
        r = {"graph": (ctx or {}).get("graph"), "tid": tid, "sp_id": sp_id,
             "app_id": app_object_id, "owner": owner}
        # Enterprise-app rows always open the service-principal drawer; the
        # linked application registration is reachable from inside that drawer.
        tr_attrs = (f'data-sp-id="{esc(sp_id)}" '
                    f'data-owner-id="{esc(owner_id)}"')
        out.append(row_html(tid, tr_attrs, f"row-{len(out)}", fields, f, r))
    return out, total


# ---- authentication methods -------------------------------------------------

def authentication_methods_search_text(f, ctx=None):
    return serve_search_text("authentication-methods-table", f, ctx=ctx)


def authentication_methods_sort_value(f, key, ctx=None):
    if key == "authMethod":
        return (f.get("auth_method_label") or "").lower()
    if key == "authState":
        return 0 if f.get("auth_enabled") else 1
    if key == "authScope":
        return (f.get("auth_scope") or "").lower()
    if key == "authRegistration":
        label = f.get("auth_registration_label") or ""
        return 0 if label == "Required" else (1 if label == "Not required" else 2)
    if key == "authSettings":
        return (f.get("auth_settings_summary") or "").lower()
    if key == "authSource":
        return (f.get("auth_source") or "").lower()
    if key == "authId":
        return (f.get("auth_source_id") or "").lower()
    return 0


def authentication_methods_rows_html(findings, q="", sort_key=None, desc=False,
                                     start=0, stop=None, columns=None, ctx=None):
    tid = "authentication-methods-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    extras = {field for field, _family in spec["extras"]}
    items = list(findings)
    if q:
        needle = q.lower()
        items = [f for f in items
                 if needle in serve_search_text(tid, f, ctx=ctx)]
    if sort_key:
        items = sorted(items,
                       key=lambda f: authentication_methods_sort_value(f, sort_key, ctx),
                       reverse=bool(desc))
    else:
        items = sorted(items, key=lambda f: (
            f.get("auth_method_order", 999),
            (f.get("auth_method_label") or "").lower()))
    if stop is None:
        stop = len(items)
    out = []
    for f in items[start:stop]:
        key = f"auth-{len(out)}"
        cells = [f'<td class="expand-cell">{EXPAND_BUTTON_HTML}</td>']
        for field in fields:
            inner, value = FIELD_RENDERERS[field](f, {"tid": tid})
            cls = cell_cls(tid, field, field in extras)
            cls_attr = f' class="{cls}"' if cls else ""
            cells.append(f'<td{cls_attr} data-field="{field}" '
                         f'data-value="{esc(value)}">{inner}</td>')
        settings = f.get("auth_settings") or {}
        settings_html = (
            f'<pre>{esc(json.dumps(settings, indent=2, sort_keys=True, default=str))}</pre>'
            if settings else '<p class="muted">No method-specific settings captured.</p>')
        summary_rows = [
            ("Method", esc(f.get("auth_method_label") or "")),
            ("State", esc(f.get("auth_state") or "")),
            ("Scope", esc(f.get("auth_scope") or "")),
            ("Registration", esc(f.get("auth_registration_label") or "—")),
            ("Source", esc(f.get("auth_source") or "")),
        ]
        if f.get("auth_source_id"):
            summary_rows.append(
                ("Policy ID", f'<span class="mono">{esc(f["auth_source_id"])}</span>'))
        drawer_body = (
            '<table class="kv-table">'
            + "".join(f"<tr><th>{esc(label)}</th><td>{value}</td></tr>"
                      for label, value in summary_rows)
            + '</table><div class="detail-section"><h4>Settings</h4>'
            + settings_html + "</div>")
        drawer = (f'<tr class="drawer" data-detail-for="{key}" '
                  f'data-prefilled="1"><td colspan="{len(fields) + 1}">'
                  f'<div class="drawer-body">{drawer_body}</div></td></tr>')
        out.append(f'<tr data-detail-key="{key}">{"".join(cells)}</tr>{drawer}')
    return out, len(items)


# ---- certificate authentication users ----------------------------------------

def certificate_auth_users_search_text(f, ctx=None):
    return serve_search_text("certificate-auth-users-table", f, ctx=ctx)


def certificate_auth_users_sort_value(f, key, ctx=None):
    if key == "severity":
        return severity_rank(f.get("severity", "Info"))
    if key == "user":
        return (f.get("user_display") or "").lower()
    if key == "userUpn":
        return (f.get("user_upn") or "").lower()
    if key == "authUserType":
        return (f.get("user_type") or "").lower()
    if key == "userStatus":
        return 0 if f.get("user_enabled") else 1
    if key == "hybrid":
        return 0 if f.get("hybrid") else 1
    if key == "authCbaScope":
        return (f.get("auth_cba_scope") or "").lower()
    if key == "authCbaMode":
        return (f.get("auth_cba_mode") or "").lower()
    if key == "authCbaBindings":
        return (f.get("auth_cba_bindings") or "").lower()
    if key == "id":
        return ((f.get("target") or {}).get("id") or "").lower()
    return 0


def certificate_auth_users_rows_html(findings, q="", sort_key=None, desc=False,
                                     start=0, stop=None, columns=None, ctx=None):
    tid = "certificate-auth-users-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(
        findings, q, sort_key, desc, start, stop,
        lambda f: serve_search_text(tid, f, ctx=ctx),
        lambda f, k: certificate_auth_users_sort_value(f, k, ctx))
    out = []
    for f in selected:
        uid = f.get("primary_id") or ""
        r = {"graph": (ctx or {}).get("graph"), "tid": tid, "user_id": uid}
        tr_attrs = (f'data-profile-id="{esc(uid)}" '
                    f'data-owner-id="{esc(uid)}"')
        out.append(row_html(tid, tr_attrs, f"cba-user-{len(out)}", fields, f, r))
    return out, total


# ---- groups / dynamic rows ---------------------------------------------------

def group_search_text(f, ctx=None):
    return serve_search_text("groups-table", f, ctx=ctx)


def group_sort_value(f, key, ctx=None):
    if key == "severity":
        return severity_rank(f.get("severity", "Info"))
    if key == "group":
        return (f.get("group_name") or "").lower()
    if key == "grpType":
        return " ".join(f.get("types", [])).lower()
    if key == "grpRoles":
        return ", ".join(r["name"] for r in f.get("dir_roles", [])).lower()
    if key == "eligible":
        return len(f.get("eligible_roles", []))
    if key == "grpMembers":
        return f.get("member_count", 0)
    if key == "grpPriv":
        return f.get("priv_member_count", 0)
    if key == "grpOwners":
        return len(f.get("owners", []))
    if key == "dynRule":
        return (f.get("dyn_rule") or "").lower()
    return 0


def group_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                    columns=None, ctx=None):
    tid = "groups-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                            lambda f: serve_search_text(tid, f, ctx=ctx),
                            lambda f, k: group_sort_value(f, k, ctx))
    out = []
    for f in selected:
        key = f"row-{len(out)}"
        r = {"graph": (ctx or {}).get("graph"), "group_id": f.get("group_id"),
             "tid": tid}
        tr_attrs = f'data-group-id="{esc(f["group_id"])}"'
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


def dynamic_search_text(f, ctx=None):
    return serve_search_text("dynamic-groups-table", f, ctx=ctx)


def dynamic_sort_value(f, key, ctx=None):
    if key == "dynGroup":
        return (f.get("group_name") or "").lower()
    if key == "dynRule":
        return (f.get("dyn_rule") or "").lower()
    if key == "dynAttrs":
        return " ".join(f.get("dyn_attrs", [])).lower()
    if key == "dynMods":
        return " ".join(f.get("dyn_mods", [])).lower()
    if key == "grpMembers":
        return f.get("member_count", 0)
    if key == "grpOwners":
        return len(f.get("owners", []))
    return 0


def dynamic_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                      columns=None, ctx=None):
    tid = "dynamic-groups-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                            lambda f: serve_search_text(tid, f, ctx=ctx),
                            lambda f, k: dynamic_sort_value(f, k, ctx))
    out = []
    for f in selected:
        key = f"row-{len(out)}"
        r = {"graph": (ctx or {}).get("graph"), "group_id": f.get("group_id"),
             "tid": tid}
        tr_attrs = f'data-group-id="{esc(f["group_id"])}"'
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


# ---- AD roster rows -----------------------------------------------------------

def ad_search_text(f, ctx=None):
    return serve_search_text("ad-sync-users-table", f, ctx=ctx)


def ad_sort_value(f, key, ctx=None):
    if key == "adUser":
        return (f.get("user_display") or "").lower()
    if key == "adUpn":
        return (f.get("user_upn") or "").lower()
    if key == "adCn":
        return (f.get("ad_cn") or "").lower()
    if key == "adDn":
        return (f.get("ad_dn") or "").lower()
    if key == "adSid":
        return (f.get("ad_sid") or "").lower()
    if key == "adPw":
        return (f.get("pw_change") or "").lower()
    if key == "adTags":
        return " ".join(f.get("tags", [])).lower()
    if key == "caExcl":
        return len(f.get("ca_exclusions", []))
    if key == "adStatus":
        return 0 if (f.get("status") or {}).get("enabled") else 1
    if key == "immutableId":
        rec = graph_user_record((ctx or {}).get("graph"), f.get("user_id")) or {}
        return (rec.get("immutableId") or "").lower()
    return 0


def ad_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                 columns=None, ctx=None):
    tid = "ad-sync-users-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                            lambda f: serve_search_text(tid, f, ctx=ctx),
                            lambda f, k: ad_sort_value(f, k, ctx))
    out = []
    for f in selected:
        key = f"row-{len(out)}"
        r = {"graph": (ctx or {}).get("graph"), "user_id": f.get("user_id"),
             "tid": tid}
        tr_attrs = (f'data-sp-id="" data-app-id="" '
                    f'data-owner-id="{esc(f["user_id"])}" '
                    f'data-profile-id="{esc(f["user_id"])}"')
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


def realm_card_html(meta):
    """Realm summary above the AD-synced users table: realm, SID prefix, synced
    count, and AD-bound hosts — hosts are capped at 10 with a dropdown for the rest."""
    parts = []
    if meta.get("domain"):
        parts.append(f"Realm: <b>{esc(meta['domain'])}</b>")
    if meta.get("sid_prefix"):
        parts.append(f"Domain SID: <b>{esc(meta['sid_prefix'].rstrip('-'))}-x</b>")
    if meta.get("synced_count"):
        parts.append(f"{meta['synced_count']} synced user(s)")
    hosts = meta.get("dc_hosts") or []
    if hosts:
        host_html = f"<b>{esc(', '.join(hosts[:10]))}</b>"
        if len(hosts) > 10:
            host_html += (f' <details class="inline-more"><summary>+{len(hosts) - 10} more</summary>'
                          f'<span> {esc(", ".join(hosts[10:]))}</span></details>')
        parts.append("AD-bound hosts: " + host_html)
    if not parts:
        return ""
    return '<div class="realm">' + " \u00b7 ".join(parts) + "</div>"





# ---- conditional-access policy rows ------------------------------------------

def ca_search_text(f, ctx=None):
    return serve_search_text("table-ca_exposure", f, ctx=ctx)


def ca_sort_value(f, key, ctx=None):
    ch = f.get("conditions_html") or {}
    if key == "severity":
        return severity_rank(f.get("severity", "Info"))
    if key == "polName":
        return (f.get("policy_name") or "").lower()
    if key == "polState":
        return (f.get("state") or "").lower()
    if key == "polScope":
        return (f.get("scope") or "").lower()
    if key == "polApps":
        return ", ".join(ch.get("apps") or []).lower()
    if key == "polControls":
        return ", ".join(ch.get("controls") or []).lower()
    if key == "polInc":
        return len(f.get("included", []))
    if key == "polExc":
        return len(f.get("excluded", []))
    if key == "polType":
        v = f.get("policy_type")
        return ("" if v is None else str(v)).lower()
    if key == "polCreated":
        return (f.get("created") or "").lower()
    if key == "polModified":
        return (f.get("modified") or "").lower()
    return 0


def ca_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                 columns=None, ctx=None):
    tid = "table-ca_exposure"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                                lambda f: serve_search_text(tid, f, ctx=ctx),
                                lambda f, k: ca_sort_value(f, k, ctx))
    out = []
    for f in selected:
        key = f"row-{len(out)}"
        r = {"graph": (ctx or {}).get("graph"), "tid": tid,
             "policy_id": f.get("policy_id")}
        tr_attrs = f'data-policy-id="{esc(f.get("policy_id", ""))}"'
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


def render_report(results, tenant_name, db_path, config_path,
                  tenant_summary=None, graph=None,
                  serve_tables=None, group_roles=None,
                  group_eligible_roles=None, cache_meta=None, diff=None):
    all_findings = [f for res in results for f in res["findings"]]

    category_counts = Counter(res["category"] for res in results for _ in res["findings"])

    serve_pager = _serve_pager
    col_ctx = {"graph": graph}
    extras_blobs = {}
    catalog_tids = []

    def register_catalog_table(tid, findings, rows_fn, search_fn=None):
        """Register a catalog-driven table for serving and the column catalog.
        Search text is derived from the same field map as the rendered cells
        (search_fn is accepted for call-site compatibility)."""
        if serve_tables is not None:
            serve_tables[tid] = {"findings": findings, "rows": rows_fn,
                                 "search": lambda f, _tid=tid: serve_search_text(
                                     _tid, f, ctx=col_ctx),
                                 "ctx": col_ctx}
        if tid not in catalog_tids:
            catalog_tids.append(tid)

    def catalog_rows(tid, findings, rows_fn, search_fn):
        """Register a catalog table; rows are fetched from the table endpoint."""
        register_catalog_table(tid, findings, rows_fn, search_fn)
        return ""

    # ---- Azure Roles tables (one per principal section) -------------------
    def az_sub(a):
        name, sid = a.get("scope_sub_name") or "", a.get("scope_sub") or ""
        if name or sid:
            return f"{name} ({sid})" if name and sid else (name or sid)
        if a.get("scope_type") == "Management group":
            return a.get("scope_mgmt") or "—"
        return "—"

    def azure_roles_section(title, table_id, category, rows):
        if not rows:
            return ""
        spec = table_spec(table_id)
        fields = list(spec["defaults"])
        blob = {}
        body = []
        for label, rid, kind, a in rows:
            key = f"az-{table_id}-{len(body)}"
            if kind == "sp":
                data = f'data-sp-id="{esc(rid)}"'
            elif kind == "group":
                data = f'data-group-id="{esc(rid)}"'
            else:
                data = f'data-profile-id="{esc(rid)}"'
            row = {
                "severity": a.get("severity") or "Info",
                "principal": label,
                "role": a["role"],
                "eligible": bool(a.get("eligible")),
                "scope_type": a.get("scope_type") or "",
                "sub": az_sub(a),
                "scope_rg": a.get("scope_rg") or "",
                "scope_provider": a.get("scope_provider") or "",
                "scope_resource": a.get("scope_resource") or "",
            }
            r = {"graph": graph, "tid": table_id,
                 "sp_id": rid if kind == "sp" else "",
                 "group_id": rid if kind == "group" else "",
                 "user_id": rid if kind == "user" else ""}
            if kind == "sp":
                r["owner"] = sp_owner_dict(rid, graph)
            body.append(row_html(table_id, data, key, fields, row, r, blob))
        if blob:
            extras_blobs[table_id] = blob
        if table_id not in catalog_tids:
            catalog_tids.append(table_id)
        return f"""
  <section data-category="{esc(category)}">
    <h2>{esc(title)}</h2>
    <div class="table-scroll">
    <table id="{esc(table_id)}" class="findings">
      {table_head_html(table_id)}
      <tbody>{''.join(body)}</tbody>
    </table>
    </div>
  </section>
"""

    def az_rows_for(mapping, kind, name_fn):
        """(label, principal_id, kind, entry) rows from an az_roles mapping."""
        rows = []
        for pid, roles in sorted(mapping.items()):
            label = name_fn(pid)
            if label is None:
                continue
            for a in sorted(roles, key=lambda x: (bool(x.get("eligible")), x["role"].lower())):
                rows.append((label, pid, kind, a))
        return rows

    # ---- legacy privileged-ownership sections ----------------------------
    def legacy_owned_section():
        priv = next((res for res in results if res["id"] == "priv_app_ownership"), None)
        if not priv:
            return ""
        owned = [f for f in priv["findings"] if f["owners"]]
        owned_rows = catalog_rows("owned-table", owned, legacy_rows_html, legacy_search_text)
        owned_pager = serve_pager()
        return f"""
  <section data-category="apps">
    <h2>{esc(priv["title"])}</h2>
    <div class="table-scroll">
    <table id="owned-table" class="findings" data-serve="1">
      {table_head_html("owned-table")}
      <tbody>{owned_rows}</tbody>
    </table>
    </div>
    {owned_pager}
    {'<div class="empty">No owned applications matched the configured privileged roles.</div>' if not owned else ''}
  </section>
"""

    def legacy_unowned_section():
        priv = next((res for res in results if res["id"] == "priv_app_ownership"), None)
        if not priv:
            return ""
        unowned = [f for f in priv["findings"] if not f["owners"]]
        unowned_rows = catalog_rows("unowned-table", unowned, legacy_unowned_rows_html,
                                   unowned_search_text)
        unowned_pager = serve_pager()
        return f"""
  <section data-category="apps">
    <h2>Privileged applications / service principals with no recorded owner</h2>
    <div class="table-scroll">
    <table id="unowned-table" class="findings" data-serve="1">
      {table_head_html("unowned-table")}
      <tbody>{unowned_rows}</tbody>
    </table>
    </div>
    {unowned_pager}
    {'<div class="empty">No unowned privileged applications found.</div>' if not unowned else ''}
  </section>
"""

    # ---- generic findings sections ---------------------------------------
    def generic_section(res):
        tid = f"table-{res['id']}"
        rows_html = catalog_rows(tid, res["findings"], generic_rows_html, generic_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="{esc(res["category"])}">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="{esc(tid)}" class="findings" data-serve="1">
      {table_head_html(tid)}
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    # ---- azure arc sections ------------------------------------------------
    def arc_section(res, table_id):
        rows_fn = ARC_TABLE_ROWS[table_id]
        rows_html = catalog_rows(table_id, res["findings"], rows_fn, arc_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="arc">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="{esc(table_id)}" class="findings" data-serve="1">
      {table_head_html(table_id)}
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    # ---- conditional-access policies section ----------------------------------
    def ca_section(res):
        rows_html = catalog_rows("table-ca_exposure", res["findings"], ca_rows_html,
                               ca_search_text)
        pager = serve_pager()
        caview = ' data-caview="main"'
        return f"""
  <section data-category="configs"{caview}>
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="table-ca_exposure" class="findings" data-serve="1">
      {table_head_html("table-ca_exposure")}
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    # ---- authentication methods -------------------------------------------
    def authentication_methods_section(res):
        rows_html = catalog_rows("authentication-methods-table", res["findings"],
                                 authentication_methods_rows_html,
                                 authentication_methods_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="auth">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="authentication-methods-table" class="findings" data-serve="1">
      {table_head_html("authentication-methods-table")}
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    # ---- certificate authentication users ---------------------------------
    def certificate_auth_users_section(res):
        rows_html = catalog_rows(
            "certificate-auth-users-table", res["findings"],
            certificate_auth_users_rows_html, certificate_auth_users_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="auth">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="certificate-auth-users-table" class="findings" data-serve="1">
      {table_head_html("certificate-auth-users-table")}
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    # ---- groups section ----------------------------------------
    def groups_section(res):
        rows_html = catalog_rows("groups-table", res["findings"], group_rows_html,
                               group_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="groups">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="groups-table" class="findings" data-serve="1">
      {table_head_html("groups-table")}
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    def dynamic_groups_table(res):
        dyn = [f for f in res["findings"]
               if f.get("dynamic") and (f.get("dyn_rule") or "").strip() not in ("", "[]")]
        if not dyn:
            return ""
        rows_html = catalog_rows("dynamic-groups-table", dyn, dynamic_rows_html,
                               dynamic_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="groups">
    <h2>Dynamic membership groups ({len(dyn)})</h2>
    <div class="table-scroll">
    <table id="dynamic-groups-table" class="findings" data-serve="1">
      {table_head_html("dynamic-groups-table")}
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    def users_section(res):
        rows = catalog_rows("privileged-users-table", res["findings"], user_rows_html,
                            user_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="users">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="privileged-users-table" class="findings" data-serve="1">
      {table_head_html("privileged-users-table")}
      <tbody>{rows}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    # ---- app directory roles section --------------------------------------
    def app_dir_roles_section(res):
        rows_html = catalog_rows("app-dir-roles-table", res["findings"], app_dir_rows_html,
                               app_dir_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="apps">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="app-dir-roles-table" class="findings" data-serve="1">
      {table_head_html("app-dir-roles-table")}
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    # ---- all applications / service principals ---------------------------
    def app_inventory_section(res):
        rows_html = catalog_rows("app-inventory-table", res["findings"],
                               app_inventory_rows_html, app_inventory_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="apps">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="app-inventory-table" class="findings" data-serve="1">
      {table_head_html("app-inventory-table")}
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    # ---- enterprise apps (SSO) -------------------------------------------
    def enterprise_apps_section(res):
        rows_html = catalog_rows("enterprise-apps-table", res["findings"],
                               enterprise_apps_rows_html, enterprise_apps_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="apps">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="enterprise-apps-table" class="findings" data-serve="1">
      {table_head_html("enterprise-apps-table")}
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    # ---- ad_sync_engine assessment card --------------------------------------
    def ad_summary_card(res):
        f = res["findings"][0]
        verdict = f.get("verdict") or "Undetermined"
        hosts = f.get("connector_host") or []
        wb = f.get("writeback") or {}
        auth = f.get("auth_mode") or {}
        sso = f.get("desktop_sso") or {}
        indicators = {i["label"]: i for i in (f.get("indicators") or [])}

        def v(label):
            i = indicators.get(label)
            return i["detail"] if i else ""

        rows = []
        rows.append(f"<tr><th>Engine</th><td><b>{esc(verdict)}</b></td></tr>")
        if auth.get("mode"):
            rows.append(f'<tr><th>Authentication</th><td><b>{esc(auth["mode"])}</b>'
                        + (f' <span class="muted">({esc(auth["detail"])})</span>'
                           if auth.get("detail") else "") + "</td></tr>")
        if hosts:
            rows.append(f'<tr><th>Connector host</th><td class="mono">{esc(", ".join(hosts))}</td></tr>')
        if wb.get("count"):
            detail = f"Enabled \u2014 {wb['count']} role assignment(s) on {', '.join(wb['resources'])}"
            rows.append(f"<tr><th>Password writeback</th><td>{esc(detail)}</td></tr>")
        if sso.get("enabled"):
            bits = [" \u00b7 ".join(sso.get("domains") or ["unknown realm"])]
            if sso.get("spns"):
                bits.append("new SPNs auto-added")
            rows.append(f"<tr><th>Desktop SSO</th><td>{esc(bits[0])}"
                        + (f' <span class="muted">({esc(bits[1])})</span>' if len(bits) > 1 else "") + "</td></tr>")
        if f.get("sync_count"):
            imm = f.get("immutable_count", 0)
            if imm >= f["sync_count"]:
                label = f"{f['sync_count']} users, all with immutableId"
            else:
                label = f"{f['sync_count']} users ({imm} with immutableId)"
            rows.append(f"<tr><th>Synced users</th><td>{esc(label)}</td></tr>")
        adsync = v("ADSync* system groups")
        if adsync and not adsync.startswith("none"):
            rows.append(f"<tr><th>Sync groups</th><td>{esc(adsync)}</td></tr>")
        sps = []
        conn = v("Entra Connect connector app")
        if conn and not conn.startswith("none"):
            sps.append(conn.split(" \u2014 ")[0])
        fabric = v("SyncFabric sync identity")
        if fabric and fabric != "not observed":
            sps.append(fabric)
        if v("Office365 directory sync app") == "present":
            sps.append("Office365DirectorySynchronizationService")
        if sps:
            rows.append(f'<tr><th>Sync service principals</th><td>{esc(" \u00b7 ".join(sorted(set(sps))))}</td></tr>')

        return f"""
  <section data-category="ad">
    <h2>{esc(res["title"])} {severity_badge(f["severity"])}</h2>
    <div class="engine-card">
      <table class="kv-table">{''.join(rows)}</table>
    </div>
  </section>
"""

    # ---- ad_sync_users section (realm card + flag roster) -----------------
    def ad_users_section(res):
        realm_html = realm_card_html(res.get("meta") or {})

        rows_html = catalog_rows("ad-sync-users-table", res["findings"], ad_rows_html,
                               ad_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="ad">
    <h2>{esc(res["title"])}</h2>
    {realm_html}
    <div class="table-scroll">
    <table id="ad-sync-users-table" class="findings" data-serve="1">
      {table_head_html("ad-sync-users-table")}
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    # ---- Azure Roles sections (independent of check result presence) ------
    def _az_map(name):
        return (graph or {}).get(name) or {}

    def azure_apps_section():
        return azure_roles_section(
            "Azure Roles (service principals)", "azure-roles-apps", "apps",
            az_rows_for(_az_map("az_sp_roles"), "sp",
                        lambda oid: ((_az_map("sp").get(oid) or {}).get("displayName")
                                     or (oid if oid in _az_map("sp") else None))))

    def azure_groups_section():
        return azure_roles_section(
            "Azure Roles (groups)", "azure-roles-groups", "groups",
            az_rows_for(_az_map("az_roles"), "group",
                        lambda gid: ((_az_map("group").get(gid) or {}).get("displayName")
                                     or (gid if gid in _az_map("group") else None))))

    def azure_users_section():
        return azure_roles_section(
            "Azure Roles (users)", "azure-roles-users", "users",
            az_rows_for(_az_map("az_user_roles"), "user",
                        lambda uid: (lambda u: ((u.get("userPrincipalName")
                                                 or u.get("displayName") or uid)
                                                if u else None))(
                            _az_map("user").get(uid))))

    def azure_ad_section():
        synced = {uid: roles for uid, roles in _az_map("az_user_roles").items()
                  if (_az_map("user").get(uid) or {}).get("dirSyncEnabled") in (1, True)}
        return azure_roles_section(
            "Azure Roles (synced users)", "azure-roles-ad", "ad",
            az_rows_for(synced, "user",
                        lambda uid: (lambda u: ((u.get("userPrincipalName")
                                                 or u.get("displayName") or uid)
                                                if u else None))(
                            _az_map("user").get(uid))))

    sections_html = []
    azure_rendered = set()

    def append_azure(table_id, builder):
        if table_id in azure_rendered:
            return
        azure_rendered.add(table_id)
        html = builder()
        if html:
            sections_html.append(html)

    diff_entries = []
    if diff:
        for f in diff.get("added") or []:
            diff_entries.append({"kind": "added", "f": f})
        for f in diff.get("removed") or []:
            diff_entries.append({"kind": "removed", "f": f})
        for old, new in diff.get("changed") or []:
            diff_entries.append({"kind": "changed", "f": new, "old": old})
        diff_entries.sort(key=lambda e: ({"added": 0, "removed": 1,
                                          "changed": 2}[e["kind"]],
                                         e["f"].get("check_id", ""),
                                         ((e["f"].get("target") or {}).get("name")
                                          or "").lower()))
    app_dir_rendered = False
    for res in results:
        if res["id"] == "priv_app_ownership":
            owned_html = legacy_owned_section()
            if owned_html:
                sections_html.append(owned_html)
            # 'Directory roles assigned to applications' renders as the
            # second table, right after the ownership table
            app_dir = next((r for r in results if r["id"] == "app_dir_roles"), None)
            if app_dir and not app_dir_rendered:
                sections_html.append(app_dir_roles_section(app_dir))
                app_dir_rendered = True
            unowned_html = legacy_unowned_section()
            if unowned_html:
                sections_html.append(unowned_html)
            append_azure("azure-roles-apps", azure_apps_section)
        elif res["id"] == "app_dir_roles":
            if not app_dir_rendered:
                sections_html.append(app_dir_roles_section(res))
                app_dir_rendered = True
        elif res["id"] == "enterprise_apps":
            sections_html.append(enterprise_apps_section(res))
        elif res["id"] == "authentication_methods":
            sections_html.append(authentication_methods_section(res))
        elif res["id"] == "certificate_auth_users":
            sections_html.append(certificate_auth_users_section(res))
        elif res["id"] == "app_inventory":
            sections_html.append(app_inventory_section(res))
        elif res["id"] == "privileged_users":
            sections_html.append(users_section(res))
            append_azure("azure-roles-users", azure_users_section)
        elif res["id"] == "groups":
            sections_html.append(groups_section(res))
            append_azure("azure-roles-groups", azure_groups_section)
            dyn_html = dynamic_groups_table(res)
            if dyn_html:
                sections_html.append(dyn_html)
        elif res["id"] == "ca_exposure":
            sections_html.append("""
  <section data-category="configs" class="ca-view-tabs-section">
    <div class="drawer-tabs" id="ca-view-tabs">
      <button type="button" class="drawer-tab active" data-caview="main">Conditional Access</button>
      <button type="button" class="drawer-tab" data-caview="single">Single user</button>
      <button type="button" class="drawer-tab" data-caview="compare">Compare users</button>
    </div>
  </section>
""")
            sections_html.append(ca_section(res))
            sections_html.append("""
  <section data-category="configs" data-caview="main">
    <h2>CA coverage analysis</h2>
    <div class="ca-analysis">
      <div class="ca-whatif" id="ca-audit-options">
        <label>Population <select id="ca-pop">
          <option value="privileged">Privileged users</option>
          <option value="all">All users</option>
          <option value="list">UPN list</option>
        </select></label>
        <label id="ca-users-wrap" class="hidden">Users <input type="text" id="ca-users-input" class="ca-small-input" placeholder="UPNs, comma-separated" autocomplete="off"></label>
        <label>Resource <input type="text" id="ca-resource" class="ca-small-input" placeholder="all, appId, or ACR" autocomplete="off"></label>
        <label>Client app <select id="ca-client">
          <option value="">All</option><option>browser</option><option>mobileAppsAndDesktopClients</option><option>exchangeActiveSync</option><option>other</option>
        </select></label>
        <label>Mode <select id="ca-mode"><option value="fast">Fast</option><option value="full">Full</option></select></label>
        <label>Max scenarios/path <input type="number" id="ca-max-scenarios" class="ca-small-input" value="24" min="0" max="500"></label>
        <label class="ca-check"><input type="checkbox" id="ca-synced"> Synced only</label>
        <label class="ca-check"><input type="checkbox" id="ca-include-disabled" checked> Include disabled</label>
      </div>
      <div class="ca-controls">
        <button type="button" class="mode-btn" id="ca-run-btn">Run analysis</button>
      </div>
      <div class="ca-status hidden" id="ca-status"><div id="ca-steps"></div></div>
      <div class="ca-results" id="ca-results"></div>
    </div>
  </section>
  <section data-category="configs" data-caview="single" class="hidden">
    <h2>Single user analysis</h2>
    <div class="ca-analysis">
      <div class="ca-controls">
        <input type="text" id="ca-user-input" class="ca-user-input" placeholder="User UPN" autocomplete="off">
        <button type="button" class="mode-btn" id="ca-user-btn">Analyze user</button>
      </div>
      <div class="ca-whatif">
        <label>Require <select id="ca-wi-require"><option value="">—</option><option value="mfa">MFA</option><option value="compliant">Compliant device</option><option value="mfa_compliant">MFA + compliant</option></select></label>
        <label>Platform <select id="ca-wi-platform"><option value="">—</option><option>windows</option><option>macos</option><option>linux</option><option>ios</option><option>android</option></select></label>
        <label>Client app <select id="ca-wi-client"><option value="">—</option><option>browser</option><option>mobileAppsAndDesktopClients</option><option>exchangeActiveSync</option><option>other</option></select></label>
        <label>Device state <select id="ca-wi-device"><option value="">—</option><option>compliant</option><option>unmanaged</option><option>domainJoined</option></select></label>
        <label>Device filter <select id="ca-wi-devfilter"><option value="">—</option><option value="true">match</option><option value="false">no match</option></select></label>
        <label>Trusted location <select id="ca-wi-location"><option value="">—</option><option value="true">trusted</option><option value="false">not trusted</option></select></label>
        <label>Sign-in risk <select id="ca-wi-signin"><option value="">—</option><option>none</option><option>low</option><option>medium</option><option>high</option></select></label>
        <label>User risk <select id="ca-wi-userrisk"><option value="">—</option><option>low</option><option>medium</option><option>high</option></select></label>
        <label>Auth flow <select id="ca-wi-authflow"><option value="">—</option><option>devicecodeflow</option><option>authtransfer</option></select></label>
        <label>Resource / app <input type="text" id="ca-app-input" class="ca-small-input" placeholder="optional" autocomplete="off"></label>
        <label>ACR / user action <input type="text" id="ca-acr-input" class="ca-small-input" placeholder="urn:user:registerdevice" autocomplete="off"></label>
        <label>Assume group(s) <input type="text" id="ca-assume-groups" class="ca-small-input" placeholder="names or IDs, comma-separated" autocomplete="off"></label>
        <label>Assume role(s) <input type="text" id="ca-assume-roles" class="ca-small-input" placeholder="names or IDs, comma-separated" autocomplete="off"></label>
      </div>
      <div class="ca-status hidden" id="ca-user-status"><div id="ca-user-steps"></div></div>
      <div class="ca-results" id="ca-user-results"></div>
    </div>
  </section>
  <section data-category="configs" data-caview="compare" class="hidden">
    <h2>Compare users</h2>
    <div class="ca-analysis">
      <div class="ca-controls">
        <input type="text" id="ca-compare-a" class="ca-user-input" placeholder="User A UPN" autocomplete="off">
        <input type="text" id="ca-compare-b" class="ca-user-input" placeholder="User B UPN" autocomplete="off">
        <button type="button" class="mode-btn" id="ca-compare-btn">Compare users</button>
      </div>
      <div class="ca-whatif">
        <label>Require <select id="ca-cmp-require"><option value="">—</option><option value="mfa">MFA</option><option value="compliant">Compliant device</option><option value="mfa_compliant">MFA + compliant</option></select></label>
        <label>Platform <select id="ca-cmp-platform"><option value="">—</option><option>windows</option><option>macos</option><option>linux</option><option>ios</option><option>android</option></select></label>
        <label>Client app <select id="ca-cmp-client"><option value="">—</option><option>browser</option><option>mobileAppsAndDesktopClients</option><option>exchangeActiveSync</option><option>other</option></select></label>
        <label>Device state <select id="ca-cmp-device"><option value="">—</option><option>compliant</option><option>unmanaged</option><option>domainJoined</option></select></label>
        <label>Device filter <select id="ca-cmp-devfilter"><option value="">—</option><option value="true">match</option><option value="false">no match</option></select></label>
        <label>Trusted location <select id="ca-cmp-location"><option value="">—</option><option value="true">trusted</option><option value="false">not trusted</option></select></label>
        <label>Sign-in risk <select id="ca-cmp-signin"><option value="">—</option><option>none</option><option>low</option><option>medium</option><option>high</option></select></label>
        <label>User risk <select id="ca-cmp-userrisk"><option value="">—</option><option>low</option><option>medium</option><option>high</option></select></label>
        <label>Auth flow <select id="ca-cmp-authflow"><option value="">—</option><option>devicecodeflow</option><option>authtransfer</option></select></label>
        <label>Resource / app <input type="text" id="ca-cmp-app" class="ca-small-input" placeholder="optional" autocomplete="off"></label>
        <label>ACR / user action <input type="text" id="ca-cmp-acr" class="ca-small-input" placeholder="urn:user:registerdevice" autocomplete="off"></label>
        <label>Assume group(s) A <input type="text" id="ca-cmp-assume-groups-a" class="ca-small-input" placeholder="names or IDs, comma-separated" autocomplete="off"></label>
        <label>Assume role(s) A <input type="text" id="ca-cmp-assume-roles-a" class="ca-small-input" placeholder="names or IDs, comma-separated" autocomplete="off"></label>
        <label>Assume group(s) B <input type="text" id="ca-cmp-assume-groups-b" class="ca-small-input" placeholder="names or IDs, comma-separated" autocomplete="off"></label>
        <label>Assume role(s) B <input type="text" id="ca-cmp-assume-roles-b" class="ca-small-input" placeholder="names or IDs, comma-separated" autocomplete="off"></label>
      </div>
      <div class="ca-status hidden" id="ca-compare-status"><div id="ca-compare-steps"></div></div>
      <div class="ca-results" id="ca-compare-results"></div>
    </div>
  </section>
""")
        elif res["id"] == "ad_sync_summary":
            sections_html.append(ad_summary_card(res))
        elif res["id"] == "ad_sync_users":
            sections_html.append(ad_users_section(res))
            append_azure("azure-roles-ad", azure_ad_section)
        elif res["id"] == "azure_arc_machines":
            sections_html.append(arc_section(res, "arc-machines-table"))
        elif res["id"] == "azure_arc_sps":
            sections_html.append(arc_section(res, "arc-principals-table"))
        elif res["id"] == "azure_arc_providers":
            sections_html.append(arc_section(res, "arc-providers-table"))
        else:
            sections_html.append(generic_section(res))

    # The Azure Roles sections are sourced from graph data, not from the check
    # that happens to render nearby: render any that were not reached because
    # the related check is disabled or produced no findings (B-057).
    append_azure("azure-roles-apps", azure_apps_section)
    append_azure("azure-roles-groups", azure_groups_section)
    append_azure("azure-roles-users", azure_users_section)
    append_azure("azure-roles-ad", azure_ad_section)

    # ---- changes since the last analysis (diff against the cache) ---------
    if diff_entries:
        check_titles = {spec["id"]: spec["title"] for spec in CHECK_SPECS}
        change_rows = []
        for e in diff_entries:
            f = e["f"]
            t = f.get("target") or {}
            sev = f.get("severity") or "Info"
            if e["kind"] == "changed":
                old_sev = e["old"].get("severity") or "Info"
                sev_html = f"{severity_badge(old_sev)} \u2192 {severity_badge(sev)}"
            else:
                sev_html = severity_badge(sev)
            kind_html = {
                "added": '<span class="badge badge-enabled">Added</span>',
                "removed": '<span class="badge sev-critical">Removed</span>',
                "changed": '<span class="badge sev-medium">Changed</span>',
            }[e["kind"]]
            target = ((t.get("name") or f.get("user_display") or f.get("display_name")
                       or f.get("group_name") or f.get("policy_name")
                       or f.get("machine_name") or f.get("arc_principal")
                       or f.get("arc_provider") or f.get("title")
                       or f.get("primary_id") or ""))
            check_label = check_titles.get(f.get("check_id"), f.get("check_id") or "")
            change_rows.append(
                f'<tr><td>{kind_html}</td>'
                f'<td>{esc(check_label)}</td>'
                f'<td title="{esc(f.get("evidence") or "")}">{esc(target)}</td>'
                f'<td>{sev_html}</td></tr>')
        changes_html = f"""
  <section data-category="changes">
    <h2>Changes since last analysis ({len(diff_entries)})</h2>
    <div class="table-scroll">
    <table class="findings" id="changes-table">
      <thead><tr>
        <th data-type="text">Change</th>
        <th data-type="text">Check</th>
        <th data-type="text">Target</th>
        <th data-type="text">Severity</th>
      </tr></thead>
      <tbody>{''.join(change_rows)}</tbody>
    </table>
    </div>
  </section>
"""
        sections_html.insert(0, changes_html)
    # directory role -> service principals holding it (drilldown 'Applications' tab);
    # small index, embedded in serve mode too
    role_apps_json = json.dumps(
        build_role_applications(graph, group_roles, group_eligible_roles),
        default=str).replace("</", "<\\/")
    permission_apps_json = json.dumps(
        build_permission_applications(results),
        default=str).replace("</", "<\\/")
    # distinct values per field for advanced-filter autocomplete (capped)
    SUGGEST_VALUE_FIELDS = {
        "severity", "category", "check", "roles", "eligible", "grproles",
        "dynmods", "dynattrs", "adtags", "targettype", "status", "hybrid",
        "userstatus", "spstatus", "ownerstatus", "adstatus", "polstate",
        "resource", "permission", "appid", "sptype", "appdirroles",
        "owner", "ownerupn", "ownersource", "owneraddn", "ownersid",
        "ownerimmutableid",
        "arcmachine", "arcprincipal", "arcprincipaltype", "arctag",
        "arcazroles", "arcprovider", "arcsub", "arcrg", "arcstatus",
        "authmethod", "authstate", "authscope", "authregistration", "authsource",
        "authusertype", "authcbascope", "authcbamode", "authcbabindings",
    }
    suggest_data = {}

    def _suggest_add(field, value):
        value = (value or "").strip()
        if not value:
            return
        bucket = suggest_data.setdefault(field, [])
        if value not in bucket and len(bucket) < 30:
            bucket.append(value)

    for res in results:
        for f in res["findings"]:
            for k, v in serve_field_map(_serve_table_id(res["id"]), f,
                                        ctx=col_ctx).items():
                if k.lower() in SUGGEST_VALUE_FIELDS:
                    for item in v.split(","):
                        _suggest_add(k.lower(), item)
            if res["id"] == "groups" and f.get("dynamic") \
                    and (f.get("dyn_rule") or "").strip() not in ("", "[]"):
                for k, v in serve_field_map("dynamic-groups-table", f,
                                            ctx=col_ctx).items():
                    if k.lower() in SUGGEST_VALUE_FIELDS:
                        for item in v.split(","):
                            _suggest_add(k.lower(), item)
    for sev in SEVERITY_ORDER:
        _suggest_add("severity", sev)
    for spec in CHECK_SPECS:
        _suggest_add("check", spec["id"])
    suggest_json = json.dumps(suggest_data, default=str).replace("</", "<\\/")

    # ---- tabs ------------------------------------------------------------
    tabs_html = ['<button type="button" class="tab-btn active" data-category="all">All</button>']
    for cat in CATEGORY_ORDER:
        count = category_counts.get(cat, 0)
        if count:
            tabs_html.append(
                f'<button type="button" class="tab-btn" data-category="{cat}">'
                f'{esc(CATEGORY_LABELS.get(cat, cat))} <span class="tab-count">{count}</span></button>')
    if db_path is not None:
        tabs_html.append(
            '<button type="button" class="tab-btn reanalyze-btn" id="reanalyze-btn">'
            'Re-analyze</button>')
    tabs_html = "\n      ".join(tabs_html)

    # ---- tenant summary bar (lean inline facts) ---------------------------
    ts = tenant_summary or {}
    bar = []
    def item(label, value_html, title=""):
        t = f' title="{esc(title)}"' if title else ""
        return f'<span class="sum-item"{t}><span class="sum-label">{esc(label)}</span>{value_html}</span>'

    bar.append(item("Tenant", f"<b>{esc(ts.get('tenant') or 'Unknown')}</b>"))
    if ts.get("tenant_id"):
        tid = ts["tenant_id"]
        bar.append(item("Tenant ID", f'<span class="mono">{esc(tid)}</span>'))
    if ts.get("domains"):
        dlist = ts["domains"]
        default = dlist[0]
        if len(dlist) > 1:
            dom_html = f'<span class="mono">{esc(default)}</span> <span class="muted">(+{len(dlist) - 1})</span>'
        else:
            dom_html = f'<span class="mono">{esc(default)}</span>'
        bar.append(item("Domains", dom_html, ", ".join(dlist)))
    if ts.get("realm"):
        sid_title = ts.get("sid_prefix", "").rstrip("-") + "-x" if ts.get("sid_prefix") else ""
        bar.append(item("Realm", f'<span class="mono">{esc(ts["realm"])}</span>', sid_title))
    if ts.get("engine"):
        engine = str(ts["engine"]).split(" · ", 1)[0]
        if engine == "Microsoft Entra Connect (on-prem)":
            engine = "Entra Connect"
        bar.append(item("Sync", f'<span class="mono">{esc(engine)}</span>'))
    if ts.get("writeback") is True:
        bar.append('<span class="sum-item tag"><span class="sum-label">Writeback</span><span class="tag-chip tag-privileged">ON</span></span>')
    if ts.get("auth_mode"):
        bar.append(item("Auth", f'<span class="tag-chip tag-divergence">{esc(ts["auth_mode"])}</span>',
                        "Authentication mode (PHS / PTA / federated), see the sync summary"))
    if "users" in ts:
        synced_note = f'<span class="muted">({ts.get("synced", "?")} synced)</span>' if "synced" in ts else ""
        bar.append(item("Users", f'{ts.get("users", 0)} {synced_note}'))
    count_labels = (("Apps / SPs", "apps", "sps"), ("Groups", "groups", None), ("Devices", "devices", None))
    for label, a_key, b_key in count_labels:
        if a_key in ts:
            value = str(ts.get(a_key, 0))
            if b_key and b_key in ts:
                value += f' / {ts.get(b_key, 0)}'
            bar.append(item(label, value))
    arc_machines = next((r for r in results if r["id"] == "azure_arc_machines"), None)
    if arc_machines and arc_machines["findings"]:
        arc_principals = next((r for r in results if r["id"] == "azure_arc_sps"), None)
        arc_note = f'{len(arc_machines["findings"])} machines, {len(arc_principals["findings"]) if arc_principals else 0} Arc principals'
        bar.append(item("Arc", f"<b>{len(arc_machines['findings'])}</b>", arc_note))
    summary_bar_html = "\n    ".join(bar)

    catalog_data = {}
    for tid in catalog_tids:
        entry = catalog_entry(tid)
        if entry:
            catalog_data[tid] = entry
    catalog_json = json.dumps(catalog_data, default=str).replace("</", "<\\/")
    extras_scripts = []
    for tid, blob in extras_blobs.items():
        if not blob:
            continue
        # only the shell-rendered azure-roles tables carry extras blobs;
        # loader-managed tables render extras on demand via cols=
        if not tid.startswith("azure-roles-"):
            continue
        blob_json = json.dumps(blob, default=str).replace("</", "<\\/")
        extras_scripts.append(
            f'<script type="application/json" id="extras-{tid}">{blob_json}</script>')
    extras_scripts_html = "\n".join(extras_scripts)

    report_css = (REPORT_CSS
                  .replace("__COLLECT_CSS__", collect_backend.styles_html())
                  .replace("__ANALYSIS_CSS__", analysis.styles_html()))
    return f"""<!doctype html>
<html lang="en">
<head>
    <script>window.REPORT_SERVE = true;</script>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra ID Surface{" - " + esc(tenant_name) if tenant_name else ""}</title>
{report_css}
</head>
<body class="sidebar-open">
{analysis.client_js()}
<aside class="sidebar" id="sidebar" aria-label="Sidebar" aria-hidden="false">
  <div class="sidebar-head">
    <h2 class="sidebar-title sidebar-brand">entra-surface</h2>
    <button type="button" class="sidebar-settings-btn" id="sidebar-settings-btn"
            aria-label="Settings" aria-haspopup="dialog" aria-expanded="false"
            aria-controls="settings-overlay" title="Settings">
      <svg width="15" height="15" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
        <path fill="currentColor" d="M19.43 12.98c.04-.32.07-.64.07-.98s-.03-.66-.07-.98l2.11-1.65c.19-.15.24-.42.12-.64l-2-3.46c-.12-.22-.39-.3-.61-.22l-2.49 1c-.52-.4-1.08-.73-1.69-.98l-.38-2.65C14.46 2.18 14.25 2 14 2h-4c-.25 0-.46.18-.49.42l-.38 2.65c-.61.25-1.17.59-1.69.98l-2.49-1c-.23-.09-.49 0-.61.22l-2 3.46c-.13.22-.07.49.12.64l2.11 1.65c-.04.32-.07.65-.07.98s.03.66.07.98l-2.11 1.65c-.19.15-.24.42-.12.64l2 3.46c.12.22.39.3.61.22l2.49-1c.52.4 1.08.73 1.69.98l.38 2.65c.03.24.24.42.49.42h4c.25 0 .46-.18.49-.42l.38-2.65c.61-.25 1.17-.59 1.69-.98l2.49 1c.23.09.49 0 .61-.22l2-3.46c.12-.22.07-.49-.12-.64l-2.11-1.65zM12 15.5c-1.93 0-3.5-1.57-3.5-3.5s1.57-3.5 3.5-3.5 3.5 1.57 3.5 3.5-1.57 3.5-3.5 3.5z"/>
      </svg>
    </button>
  </div>
  <nav class="sidebar-nav" id="sidebar-nav" aria-label="Workspace sections">
    <button type="button" class="sidebar-nav-item active" data-view="analysis" aria-current="page">Analysis</button>
    <button type="button" class="sidebar-nav-item" data-view="collect">Collect</button>
    <button type="button" class="sidebar-nav-item" data-view="tokens">Tokens</button>
  </nav>
  <div class="sidebar-principal">
    <div class="sidebar-title">Active token</div>
    <div class="sidebar-principal-body" id="sidebar-principal-body">
      <span class="sidebar-principal-empty">Loading...</span>
    </div>
  </div>
  <div class="sidebar-theme">
    <div class="theme-toggle" role="group" aria-label="Color theme">
      <button type="button" id="theme-light-btn" aria-pressed="false">Light</button>
      <button type="button" id="theme-dark-btn" aria-pressed="false">Dark</button>
    </div>
  </div>
</aside>
<button type="button" class="sidebar-toggle" id="sidebar-toggle" aria-controls="sidebar" aria-expanded="true" aria-label="Close sidebar" title="Close sidebar">
  <span class="sidebar-toggle-arrow" aria-hidden="true">&lsaquo;</span>
</button>
<div class="app-main">
<div class="wrap">
  <div class="app-view" data-view="analysis">
  <header>
    <div>
      <h1>Analysis</h1>
    </div>
  </header>

  <div class="summary-bar">
    {summary_bar_html}
  </div>

  <div id="analysis-start-wrap" class="{'' if db_path is None else 'hidden'}">
    {analysis.start_panel_html(db_path)}
  </div>

  <div class="tabs" id="category-tabs" role="tablist">
      {tabs_html}
  </div>

  <div class="controls">
    <div class="filter-row">
      <input type="search" id="filter-input" placeholder="Filter all tables by target, owner, evidence&hellip;" autocomplete="off">
      <span class="filter-spinner hidden" id="filter-spinner" role="status" aria-label="Running advanced query" title="Running advanced query&hellip;"></span>
      <button type="button" id="advanced-toggle" class="mode-btn" aria-pressed="false" title="Toggle advanced filtering: field:value, AND, OR, NOT, contains:, uniq:column">Advanced</button>
      <div class="suggest-wrap hidden" id="suggest-wrap"><ul id="suggest-list"></ul></div>
    </div>
    <div class="filter-error hidden" id="filter-error"></div>
  </div>

  {''.join(sections_html)}

  {'<div class="empty">No database loaded. Start with --db to run the analysis.</div>' if not all_findings and db_path is None else ('<div class="empty">No findings were produced. Check the check configuration.</div>' if not all_findings else '')}

  </div>
  <div class="app-view hidden" data-view="collect">{collect_backend.view_html()}</div>
  <div class="app-view hidden" data-view="tokens">{collect_backend.tokens_view_html()}</div>
</div>
</div>

<div class="settings-overlay hidden" id="settings-overlay"
     role="dialog" aria-modal="true" aria-labelledby="settings-title">
  <div class="settings-box">
    <div class="settings-head">
      <div>
        <h3 id="settings-title">Settings</h3>
      </div>
      <button type="button" class="icon-btn" id="settings-close"
              aria-label="Close settings">&times;</button>
    </div>
    <div class="settings-tabs" role="tablist" aria-label="Settings sections">
      <button type="button" class="settings-tab active" id="settings-tab-general"
              data-settings-tab="general" role="tab" aria-selected="true"
              aria-controls="settings-panel-general">General</button>
      <button type="button" class="settings-tab" id="settings-tab-global"
              data-settings-tab="global" role="tab" aria-selected="false"
              aria-controls="settings-panel-global">Global</button>
      <button type="button" class="settings-tab" id="settings-tab-collect"
              data-settings-tab="collect" role="tab" aria-selected="false"
              aria-controls="settings-panel-collect">Collect</button>
      <button type="button" class="settings-tab" id="settings-tab-tokens"
              data-settings-tab="tokens" role="tab" aria-selected="false"
              aria-controls="settings-panel-tokens">Tokens</button>
      <button type="button" class="settings-tab" id="settings-tab-proxy"
              data-settings-tab="proxy" role="tab" aria-selected="false"
              aria-controls="settings-panel-proxy">Proxy</button>
    </div>
    <div class="settings-body">
      <section class="settings-panel" id="settings-panel-general"
               role="tabpanel" aria-labelledby="settings-tab-general">
        <div class="settings-section">
          <h4>Database</h4>
          <div class="settings-value"
               title="{esc(str(db_path)) if db_path is not None else 'No database loaded'}">{esc(str(db_path)) if db_path is not None else 'No database loaded'}</div>
        </div>
        <div class="settings-section">
          <h4>Appearance</h4>
          <p class="settings-note">Use the Light / Dark toggle at the bottom of
            the sidebar.</p>
        </div>
      </section>
      <section class="settings-panel hidden" id="settings-panel-global"
               role="tabpanel" aria-labelledby="settings-tab-global">
        <div class="settings-section">
          <h4>User agent</h4>
          <p class="settings-note">Applies to all outbound requests unless the
            Collect or Tokens tab overrides it. Leave blank to use each area's
            built-in default.</p>
          <div class="settings-grid">
            <label class="settings-field wide">
              <span>Global User-Agent</span>
              <input id="settings-ua-global" type="text" autocomplete="off"
                     spellcheck="false" maxlength="512"
                     placeholder="e.g. Mozilla/5.0 ...">
            </label>
          </div>
        </div>
      </section>
      <section class="settings-panel hidden" id="settings-panel-collect"
               role="tabpanel" aria-labelledby="settings-tab-collect">
        <div class="settings-section">
          <h4>Collect user agent</h4>
          <p class="settings-note">Used for Graph, AAD Graph, and ARM collection
            traffic, including token acquisition.</p>
          <div class="settings-grid">
            <label class="settings-field wide">
              <span>Collect User-Agent</span>
              <input id="settings-ua-collect" type="text" autocomplete="off"
                     spellcheck="false" maxlength="512"
                     placeholder="Leave blank to fall back to Global">
            </label>
          </div>
        </div>
      </section>
      <section class="settings-panel hidden" id="settings-panel-tokens"
               role="tabpanel" aria-labelledby="settings-tab-tokens">
        <div class="settings-section">
          <h4>Tokens user agent</h4>
          <p class="settings-note">Used for Tokens-tab exchange/refresh and
            token-resource metadata requests. Collection token acquisition uses
            the Collect setting. Overrides Global in the Tokens area.</p>
          <div class="settings-grid">
            <label class="settings-field wide">
              <span>Tokens User-Agent</span>
              <input id="settings-ua-tokens" type="text" autocomplete="off"
                     spellcheck="false" maxlength="512"
                     placeholder="Leave blank to fall back to Global">
            </label>
          </div>
        </div>
      </section>
      <section class="settings-panel hidden" id="settings-panel-proxy"
               role="tabpanel" aria-labelledby="settings-tab-proxy">
        <div class="settings-section">
          <h4>Proxy</h4>
          <p class="settings-note">Route collector and token-refresh traffic
            through an HTTP, HTTPS, SOCKS4, or SOCKS5 proxy.</p>
          <label class="settings-check">
            <input type="checkbox" id="settings-proxy-enabled">
            <span>Use a proxy for collection and token refresh</span>
          </label>
          <div class="settings-grid">
            <label class="settings-field wide">
              <span>Proxy URL</span>
              <input id="settings-proxy-url" type="text" autocomplete="off"
                     spellcheck="false"
                     placeholder="http://127.0.0.1:8080 or socks5h://127.0.0.1:1080">
            </label>
            <label class="settings-field">
              <span>Username (optional)</span>
              <input id="settings-proxy-user" type="text" autocomplete="off"
                     spellcheck="false">
            </label>
            <label class="settings-field">
              <span>Password (optional)</span>
              <input id="settings-proxy-pass" type="password"
                     autocomplete="new-password">
            </label>
            <label class="settings-field wide">
              <span>No-proxy hosts (optional)</span>
              <input id="settings-proxy-no-proxy" type="text" autocomplete="off"
                     spellcheck="false" placeholder="localhost,127.0.0.1">
            </label>
          </div>
          <label class="settings-check">
            <input type="checkbox" id="settings-proxy-insecure">
            <span>Accept any TLS certificate through the proxy (self-signed/untrusted)</span>
          </label>
          <div class="settings-actions">
            <button type="button" class="mode-btn" id="settings-test">Test proxy</button>
          </div>
          <div class="settings-status hidden" id="settings-proxy-status"
               role="status" aria-live="polite"></div>
        </div>
      </section>
    </div>
    <div class="settings-foot">
      <div class="settings-status hidden" id="settings-status"
           role="status" aria-live="polite"></div>
      <button type="button" class="mode-btn" id="settings-save">Save</button>
      <button type="button" class="mode-btn" id="settings-done">Done</button>
    </div>
  </div>
</div>

<div class="overlay hidden" id="drilldown-overlay">
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="drilldown-title">
    <div class="modal-header">
      <div>
        <h3 id="drilldown-title"></h3>
        <p class="sub" id="drilldown-subtitle"></p>
      </div>
      <button type="button" class="icon-btn" id="drilldown-close" aria-label="Close">&times;</button>
    </div>
    <div class="modal-body">
      <div class="drawer-tabs hidden" id="drilldown-tabs"></div>
      <div class="table-scroll" id="drilldown-users-scroll">
        <table id="drilldown-table">
          <thead><tr id="drilldown-thead-row"></tr></thead>
          <tbody id="drilldown-tbody"></tbody>
        </table>
      </div>
      <div class="table-scroll hidden" id="drilldown-apps-scroll">
        <table id="drilldown-apps-table">
          <thead><tr id="drilldown-apps-thead"></tr></thead>
          <tbody id="drilldown-apps-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<script type="application/json" id="suggest-data">{suggest_json}</script>

<script type="application/json" id="role-apps-data">{role_apps_json}</script>

<script type="application/json" id="permission-apps-data">{permission_apps_json}</script>

<script type="application/json" id="table-catalog-data">{catalog_json}</script>

{extras_scripts_html}

{JS_FILTER_MODULE}
{REPORT_JS}
</body>
</html>
"""


def build_tenant_summary(graph, results=None):
    """Facts about the tenant for the top summary bar (independent of check selection)."""
    users = len(graph["user"])
    enabled = sum(1 for u in graph["user"].values() if u.get("accountEnabled"))
    synced = sum(1 for u in graph["user"].values() if u.get("dirSyncEnabled") in (1, True))

    realms = set()
    sid_prefix = None
    for u in graph["user"].values():
        dn = u.get("onPremisesDistinguishedName") or ""
        dcs = [p.strip()[3:].strip() for p in dn.split(",") if p.strip()[:3].upper() == "DC="]
        if dcs:
            realms.add(".".join(dcs))
        sid = u.get("onPremisesSecurityIdentifier") or ""
        if sid and not sid_prefix:
            dash = sid.rfind("-")
            if dash > 0:
                sid_prefix = sid[: dash + 1]

    connectors = [rec.get("displayName") or "" for rec in graph["sp"].values()
                  if (rec.get("displayName") or "").startswith("ConnectSyncProvisioning_")]
    adsync_groups = any("ADSync" in (rec.get("displayName") or "") for rec in graph["group"].values())
    host = None
    if connectors:
        parts = connectors[0].split("_")
        host = parts[1] if len(parts) > 2 else None
    if synced and (connectors or adsync_groups):
        engine = "Microsoft Entra Connect (on-prem)" + (f" · {host}" if host else "")
    elif synced:
        engine = "Likely Entra Cloud Sync"
    else:
        engine = "No sync observed"

    writeback = None  # None = unknown, True/False when sync data is present
    auth_mode = None
    sync_summary = None
    if results:
        for res in results:
            if res["id"] == "ad_sync_summary" and res.get("findings"):
                sync_summary = res["findings"][0]
                break
    # Derive from the graph even when the sync-summary check was filtered out
    # (min_severity/suppress must not blank the tenant header) (B-086).
    if sync_summary is None or sync_summary.get("writeback") is None \
            or (sync_summary.get("auth_mode") or {}).get("short") is None:
        try:
            sync_summary = check_ad_sync_summary({"graph": graph})[0]
        except Exception:
            sync_summary = sync_summary or {}
    if sync_summary:
        wb = sync_summary.get("writeback") or {}
        writeback = bool(wb.get("count"))
        auth_mode = (sync_summary.get("auth_mode") or {}).get("short") or None

    domains = []
    for d in json_list(graph["tenant"].get("verified_domains")):
        if isinstance(d, dict) and d.get("name"):
            domains.append({
                "name": d["name"],
                "default": bool(d.get("isDefault", d.get("default"))),
            })
    domains.sort(key=lambda d: (not d["default"], d["name"]))

    pim = {
        "providers": list(graph.get("pim_providers") or []),
        "governance": bool(graph.get("pim_resources") or graph.get("pim_alerts")
                           or graph.get("pim_role_assignments")
                           or graph.get("pim_role_settings")
                           or graph.get("pim_role_settings_v2")),
    }

    return {
        "tenant": graph["tenant"].get("display_name") or "Unknown",
        "tenant_id": graph["tenant"].get("object_id") or "",
        "domains": [d["name"] for d in domains],
        "realm": ", ".join(sorted(realms)) or "",
        "sid_prefix": sid_prefix or "",
        "engine": engine,
        "writeback": writeback,
        "auth_mode": auth_mode,
        "pim": pim,
        "users": users,
        "enabled": enabled,
        "synced": synced,
        "apps": len(graph["app"]),
        "sps": len(graph["sp"]),
        "groups": len(graph["group"]),
        "devices": len(graph["device"]),
    }


# ---------------------------------------------------------------------------
# Live serving: the report shell; the users table, user profiles
# and user-field drilldowns are served on demand from the in-memory results so
# the page stays small at 50k+ users. Bound to 127.0.0.1, read-only.
# ---------------------------------------------------------------------------

def _install_analysis_state(results, graph, group_roles, group_eligible_roles,
                            check_cfg, report_html, serve_tables, db_path):
    with SERVE_STATE_LOCK:
        SERVE_STATE["generation"] = SERVE_STATE.get("generation", 0) + 1
        SERVE_STATE["shell"] = report_html
        SERVE_STATE["db_path"] = str(db_path) if db_path is not None else None
        SERVE_STATE["ca_analysis"] = None
        SERVE_STATE["tables"] = serve_tables or {}
        SERVE_STATE["user_findings"] = next(
            (res["findings"] for res in results if res["id"] == "privileged_users"), [])
        SERVE_STATE["group_profiles"] = {
            f["group_id"]: f for res in results if res["id"] == "groups"
            for f in res["findings"]}
        SERVE_STATE["policy_profiles"] = {
            f["policy_id"]: f for res in results if res["id"] == "ca_exposure"
            for f in res["findings"] if f.get("policy_id")}
        SERVE_STATE["records"] = build_serve_records(results, graph)
        SERVE_STATE["graph"] = graph
        SERVE_STATE["check_cfg"] = check_cfg
        SERVE_STATE["group_roles"] = group_roles
        SERVE_STATE["group_eligible_roles"] = group_eligible_roles
        SERVE_STATE["profile_builder"] = None
        SERVE_STATE["profile_builder_generation"] = None
        SERVE_STATE["profiles_lru"] = {}
        SERVE_STATE["details_lru"] = {}
        SERVE_STATE["ca_table_ids"] = {}


def run_runtime_analysis(db_path, use_cache=True):
    """Analyze a database chosen from the UI and swap the live report shell."""
    db_path = Path(db_path)
    config_path = Path(SERVE_STATE.get("config_path") or DEFAULT_CONFIG)
    azure_config = Path(SERVE_STATE.get("azure_config_path") or DEFAULT_AZURE_CONFIG)
    if not config_path.exists():
        raise RuntimeError(f"config not found: {config_path}")
    cache_path, cache_meta_path = cache_paths(db_path)

    config_resources, check_cfg = load_config(config_path)
    azure_role_sev = load_azure_roles(azure_config)
    check_cfg["azure_roles"] = azure_role_sev
    config_fingerprint = compute_config_fingerprint(config_resources, check_cfg)
    SERVE_STATE["config_fingerprint"] = config_fingerprint

    analysis.set_message("Loading database")
    conn = open_audit_database(db_path)
    try:
        cur = conn.cursor()
        tenant_name = None
        try:
            cur.execute("SELECT displayName FROM TenantDetails LIMIT 1")
            row = cur.fetchone()
            tenant_name = row[0] if row else None
        except sqlite3.OperationalError:
            pass
        fingerprint = compute_db_fingerprint(db_path, cur, config_fingerprint)

        analysis.set_message("Building graph")
        graph = build_graph(cur)
        apply_azure_severity(graph, azure_role_sev)
    finally:
        conn.close()

    cached = load_cache(cache_path) if use_cache else None
    cache_hit = bool(use_cache and cache_fresh(cached, fingerprint))

    if cache_hit:
        analysis.set_message("Using cached analysis")
        results = cached["results"]
        group_roles = cached.get("group_roles") or {}
        group_eligible_roles = cached.get("group_eligible_roles") or {}
        tenant_summary = build_tenant_summary(graph, results)
        diff = None
        cache_meta = {"hit": True,
                      "generated_at": cached.get("generated_at") or ""}
    else:
        analysis.set_message("Computing group roles")
        group_roles = compute_group_roles(graph, check_cfg)
        group_eligible_roles = compute_group_eligible_roles(graph, check_cfg)
        sp_dir_resolver = make_sp_dir_resolver(graph, group_roles,
                                               check_cfg["directory_roles"],
                                               group_eligible_roles)

        analysis.set_message("Running checks")
        results = run_checks(graph, config_resources, check_cfg,
                             group_roles=group_roles,
                             group_eligible_roles=group_eligible_roles,
                             sp_dir_resolver=sp_dir_resolver)

        tenant_summary = build_tenant_summary(graph, results)
        diff = compute_diff(cached.get("results", []), results) if cached else None
        if use_cache:
            cache_meta = {
                "hit": False,
                "off": False,
                "fresh": cached is None,
                "generated_at": datetime.datetime.now(
                    datetime.timezone.utc).isoformat(timespec="seconds"),
                "previous_at": cached.get("generated_at") if cached else None,
            }
        else:
            cache_meta = {"hit": False, "off": True}

    analysis.set_message("Rendering report")
    serve_tables = {}
    report_html = render_report(results, tenant_name, db_path, config_path,
                                tenant_summary, graph=graph,
                                serve_tables=serve_tables,
                                group_roles=group_roles,
                                group_eligible_roles=group_eligible_roles,
                                cache_meta=cache_meta, diff=diff)
    _install_analysis_state(results, graph, group_roles, group_eligible_roles,
                            check_cfg, report_html, serve_tables, db_path)

    if use_cache and not cache_hit:
        write_analysis_cache(cache_path, cache_meta_path, db_path, fingerprint,
                             cache_meta["generated_at"], results,
                             tenant_summary, group_roles, group_eligible_roles,
                             config_fingerprint=config_fingerprint)


# ---- server-side drilldown (mirrors the DOM record model + DRILLDOWN_COLUMNS) --

# ---------------------------------------------------------------------------
# On-demand CA coverage analysis (runs on button click)
# ---------------------------------------------------------------------------

CA_ANALYSIS_STEPS = [
    ("load", "Load CA policy and directory data"),
    ("scopes", "Resolve policy scopes (users / groups / roles)"),
    ("users", "Analyze per-user coverage"),
    ("apps", "Analyze application coverage"),
    ("legacy", "Analyze legacy authentication"),
    ("exclusions", "Analyze privileged-user exclusions"),
    ("paths", "Run conditional-access path audit"),
    ("render", "Render results"),
]

def register_ca_tables(tables, kind="main"):
    """Register (or refresh) one CA view's result tables in the serve table
    pipeline so they paginate/sort/filter like the built-in tables. IDs are
    scoped per view: installing single-user results must not unregister the
    tenant-wide view's tables (and vice versa)."""
    with SERVE_STATE_LOCK:
        table_ids = SERVE_STATE.get("ca_table_ids")
        if not isinstance(table_ids, dict):
            table_ids = {}
        for tid in table_ids.pop(kind, []) or []:
            SERVE_STATE["tables"].pop(tid, None)
        ids = []
        for t in tables:
            if not t:
                continue
            tid = t["id"]
            ids.append(tid)
            SERVE_STATE["tables"][tid] = {
                "findings": t["rows"],
                "rows": make_ca_rows_fn(),
                "search": lambda f, _tid=tid: serve_search_text(_tid, f),
                "sort_keys": {str(i): field for i, field in (t.get("sort_fields") or {}).items()},
                "colspan": t.get("colspan", 4),
            }
        table_ids[kind] = ids
        SERVE_STATE["ca_table_ids"] = table_ids


def start_ca_analysis(upn=None, compare_upns=None, assume_groups=None,
                      assume_roles=None, assume_groups_b=None,
                      assume_roles_b=None, scenario=None, options=None):
    """Kick off the analysis in a background thread; returns the status dict.

    The job snapshots its database/generation/result kind. A second start while
    a job is running is rejected; completion only installs results/tables when
    the analysis generation is still current.
    """
    kind = "compare" if compare_upns else ("single" if upn else "main")
    with SERVE_STATE_LOCK:
        state = SERVE_STATE.get("ca_analysis")
        if state and state.get("status") == "running":
            running_kind = state.get("kind") or "unknown"
            raise RuntimeError(
                f"a CA analysis ({running_kind}) is already running; "
                "wait for it to finish or reload the report")
        db_path = SERVE_STATE.get("db_path")
        if not db_path:
            raise RuntimeError("no database is loaded")
        user_findings = list(SERVE_STATE.get("user_findings") or [])
        records = list(SERVE_STATE.get("records") or [])
        generation = SERVE_STATE.get("generation", 0)
        steps = [{"id": sid, "label": label, "status": "pending", "detail": ""}
                 for sid, label in CA_ANALYSIS_STEPS]
        state = {"status": "running", "steps": steps, "result": None,
                 "error": None, "kind": kind, "generation": generation,
                 "db": str(db_path)}
        SERVE_STATE["ca_analysis"] = state

    def progress(sid, detail="", running=False):
        with SERVE_STATE_LOCK:
            for step in steps:
                if step["id"] == sid:
                    step["status"] = "running" if running else "done"
                    step["detail"] = detail

    def worker():
        try:
            result = run_ca_analysis(db_path, progress,
                                     target_upn=upn,
                                     compare_upns=compare_upns,
                                     assume_groups=assume_groups,
                                     assume_roles=assume_roles,
                                     assume_groups_b=assume_groups_b,
                                     assume_roles_b=assume_roles_b,
                                     scenario=scenario,
                                     options=options,
                                     user_findings=user_findings,
                                     records=records)
            with SERVE_STATE_LOCK:
                if (SERVE_STATE.get("ca_analysis") is not state
                        or SERVE_STATE.get("generation", 0) != generation):
                    state["status"] = "stale"
                    state["error"] = ("the database/report was reloaded while this "
                                      "CA analysis was running")
                    return
                register_ca_tables(result.get("tables") or [], kind)
                state["result"] = {
                    "summary_html": result.get("summary_html", ""),
                    "sections_html": result.get("sections_html", ""),
                }
                state["status"] = "done"
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            with SERVE_STATE_LOCK:
                state["status"] = "error"
                state["error"] = str(exc)

    threading.Thread(target=worker, daemon=True).start()
    return state


def parse_http_range(header, length):
    """Parse a single-range `bytes=` header.

    Returns (start, end) inclusive, None when the header is absent/unsupported
    (server should ignore it), or False when syntactically valid but
    unsatisfiable (server should answer 416).
    """
    if not header or not isinstance(header, str):
        return None
    unit, sep, spec = header.strip().partition("=")
    if not sep or unit.strip().lower() != "bytes":
        return None
    spec = spec.strip()
    if not spec or "," in spec:  # multiple ranges are not implemented
        return None
    start_s, sep, end_s = spec.partition("-")
    if not sep:
        return None
    try:
        if start_s == "":
            suffix = int(end_s)
            if suffix <= 0:
                return False
            start = max(0, length - suffix)
            return (start, length - 1) if length else False
        start = int(start_s)
        end = int(end_s) if end_s else length - 1
    except ValueError:
        return None
    if start < 0 or end < start:
        return False
    if length == 0 or start >= length:
        return False
    end = min(end, length - 1)
    return start, end


class AuditServeHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, body_bytes, ctype, code=200, headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body_bytes)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body_bytes)

    def _send_rangeable(self, body_bytes, ctype, code=200, headers=None):
        """GET/HEAD response with single-range support (shell/document bytes)."""
        headers = dict(headers or {})
        headers.setdefault("Accept-Ranges", "bytes")
        parsed = (parse_http_range(self.headers.get("Range"), len(body_bytes))
                  if code == 200 and self.command in ("GET", "HEAD") else None)
        if parsed is False:
            self._send(b"", ctype, 416,
                       headers={**headers,
                                "Content-Range": f"bytes */{len(body_bytes)}"})
            return
        if isinstance(parsed, tuple):
            start, end = parsed
            headers["Content-Range"] = f"bytes {start}-{end}/{len(body_bytes)}"
            self._send(body_bytes[start:end + 1], ctype, 206, headers=headers)
            return
        self._send(body_bytes, ctype, code, headers=headers)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        try:
            path = parsed.path
            if path in ("/", "/index.html"):
                self._send_rangeable(SERVE_STATE["shell"].encode("utf-8"),
                                     "text/html; charset=utf-8")
            elif path == "/api/drilldown":
                data, code = serve_drilldown_response(qs)
                self._send(json.dumps(data).encode("utf-8"), "application/json; charset=utf-8", code)
            elif path.startswith("/api/table/"):
                tid = urllib.parse.unquote(path[len("/api/table/"):])
                data, code = serve_table_response(tid, qs)
                self._send(json.dumps(data).encode("utf-8"), "application/json; charset=utf-8", code)
            elif path.startswith("/api/profile/"):
                kind, _, oid = urllib.parse.unquote(path[len("/api/profile/"):]).partition("/")
                data, code = serve_profile_response(kind, oid)
                self._send(json.dumps(data, default=str).encode("utf-8"),
                           "application/json; charset=utf-8", code)
            elif path.startswith("/api/details/"):
                kind, _, oid = urllib.parse.unquote(path[len("/api/details/"):]).partition("/")
                data, code = serve_details_response(kind, oid)
                self._send(json.dumps(data, default=str).encode("utf-8"),
                           "application/json; charset=utf-8", code)
            elif path.startswith("/api/user/"):
                uid = urllib.parse.unquote(path[len("/api/user/"):])
                data, code = serve_profile_response("user", uid)
                self._send(json.dumps(data, default=str).encode("utf-8"),
                           "application/json; charset=utf-8", code)
            elif path == "/api/collect/status":
                self._send(json.dumps(collect_backend.get_status(),
                                      default=str).encode("utf-8"),
                           "application/json; charset=utf-8")
            elif path == "/api/settings":
                self._send(json.dumps(surface_settings.load_settings()).encode("utf-8"),
                           "application/json; charset=utf-8",
                           headers={"Cache-Control": "no-store"})
            elif path == "/api/tokens":
                enrich = (qs.get("enrich") or ["1"])[0].lower() not in (
                    "0", "false", "no", "off")
                self._send(json.dumps(
                    collect_backend.get_auth_status(enrich=enrich)
                ).encode("utf-8"), "application/json; charset=utf-8",
                    headers={"Cache-Control": "no-store"})
            elif path == "/api/tokens/clients":
                data = collect_backend.get_token_clients()
                self._send(json.dumps(data).encode("utf-8"),
                           "application/json; charset=utf-8",
                           headers={"Cache-Control": "no-store"})
            elif path == "/api/tokens/resources":
                token_id = (qs.get("id") or [""])[0]
                client_id = (qs.get("client_id") or [""])[0]
                try:
                    data = collect_backend.get_token_resources(
                        token_id, client_id)
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                except RuntimeError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 500)
                    return
                self._send(json.dumps(data).encode("utf-8"),
                           "application/json; charset=utf-8",
                           headers={"Cache-Control": "no-store"})
            elif path == "/api/databases":
                db_dir = collect_backend.DEFAULT_DATA_DIR
                databases = []
                try:
                    db_dir.mkdir(parents=True, exist_ok=True)
                    for db_file in db_dir.glob("*.db"):
                        if not db_file.is_file():
                            continue
                        stat = db_file.stat()
                        cached = False
                        cached_at = ""
                        try:
                            cache_file, meta_file = cache_paths(db_file)
                            cache_meta = (load_cache_sidecar(meta_file)
                                          if cache_file.is_file() else None)
                            if cache_meta and cache_meta.get("version") == CACHE_VERSION:
                                fingerprint = cache_meta.get("fingerprint") or []
                                current_config = SERVE_STATE.get("config_fingerprint") or ""
                                meta_config = cache_meta.get("config_fingerprint") or ""
                                # The list only needs a cheap freshness check; the
                                # full row-count fingerprint is recomputed when an
                                # analysis actually starts.
                                if (len(fingerprint) >= 2
                                        and fingerprint[0] == stat.st_mtime_ns
                                        and fingerprint[1] == stat.st_size
                                        and (not current_config or not meta_config
                                             or meta_config == current_config)):
                                    cached = True
                                    cached_at = cache_meta.get("generated_at") or ""
                        except (OSError, sqlite3.Error):
                            cached = False
                        databases.append({
                            "name": db_file.name,
                            "path": str(db_file.resolve()),
                            "size": stat.st_size,
                            "modified": datetime.datetime.fromtimestamp(
                                stat.st_mtime, datetime.timezone.utc
                            ).isoformat(timespec="seconds"),
                            "cached": cached,
                            "cached_at": cached_at,
                        })
                except OSError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 500)
                    return
                databases.sort(key=lambda d: d["modified"], reverse=True)
                self._send(json.dumps({
                    "directory": str(db_dir.resolve()),
                    "databases": databases,
                }).encode("utf-8"), "application/json; charset=utf-8")
            elif path == "/api/analyze/status":
                self._send(json.dumps(analysis.get_status()).encode("utf-8"),
                           "application/json; charset=utf-8")
            elif path == "/api/ca-analysis/status":
                with SERVE_STATE_LOCK:
                    state = SERVE_STATE.get("ca_analysis")
                    body = (b'{"status": "idle", "steps": []}'
                            if state is None
                            else json.dumps(state, default=str).encode("utf-8"))
                self._send(body, "application/json; charset=utf-8")
            else:
                self._send(b'{"error": "not found"}', "application/json; charset=utf-8", 404)
        except Exception as exc:  # noqa: BLE001 - surface errors for debugging
            self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                       "application/json; charset=utf-8", 500)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        try:
            if parsed.path == "/api/analyze":
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length:
                        payload = json.loads(self.rfile.read(length) or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}
                use_cache = payload.get("cache", True)
                if isinstance(use_cache, str):
                    use_cache = use_cache.strip().lower() not in (
                        "", "0", "false", "no", "off")
                try:
                    state = analysis.start(
                        payload.get("db") or "",
                        lambda path, cache=bool(use_cache):
                            run_runtime_analysis(path, cache))
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                except RuntimeError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 500)
                    return
                self._send(json.dumps(state).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            if parsed.path == "/api/tokens":
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length:
                        payload = json.loads(self.rfile.read(length) or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}
                try:
                    if payload.get("refresh_token"):
                        state = collect_backend.set_auth(
                            payload.get("refresh_token") or "",
                            payload.get("client_id") or "")
                    else:
                        state = collect_backend.set_access_token(
                            payload.get("access_token") or "")
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                except RuntimeError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 500)
                    return
                self._send(json.dumps(state).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            if parsed.path == "/api/tokens/clear":
                self._send(json.dumps(collect_backend.clear_auth()).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            if parsed.path == "/api/tokens/secrets":
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length:
                        payload = json.loads(self.rfile.read(length) or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}
                try:
                    data = collect_backend.get_token_secrets(payload.get("id") or "")
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                self._send(json.dumps(data).encode("utf-8"),
                           "application/json; charset=utf-8",
                           headers={"Cache-Control": "no-store"})
                return
            if parsed.path == "/api/tokens/redeem":
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length:
                        payload = json.loads(self.rfile.read(length) or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}
                try:
                    state = collect_backend.redeem_saved_token(
                        payload.get("id") or "",
                        payload.get("target") or "",
                        payload.get("resource") or "",
                        payload.get("client_id") or "")
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                except RuntimeError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 500)
                    return
                self._send(json.dumps(state).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            if parsed.path == "/api/tokens/update":
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length:
                        payload = json.loads(self.rfile.read(length) or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}
                if not isinstance(payload, dict):
                    payload = {}
                try:
                    state = collect_backend.update_token_metadata(
                        payload.get("id") or "",
                        payload.get("principal"),
                        payload.get("note") if "note" in payload else None)
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                self._send(json.dumps(state).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            if parsed.path in ("/api/tokens/select", "/api/tokens/delete"):
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length:
                        payload = json.loads(self.rfile.read(length) or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}
                try:
                    if parsed.path == "/api/tokens/select":
                        state = collect_backend.select_token(payload.get("id") or "")
                    else:
                        state = collect_backend.delete_token(payload.get("id") or "")
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                self._send(json.dumps(state).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            if parsed.path == "/api/settings/test":
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length:
                        payload = json.loads(
                            self.rfile.read(length) or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}
                proxy = payload.get("proxy") if isinstance(payload, dict) else {}
                try:
                    result = collect_backend.test_proxy(proxy or {})
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                except RuntimeError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 502)
                    return
                except OSError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 502)
                    return
                self._send(json.dumps(result).encode("utf-8"),
                           "application/json; charset=utf-8",
                           headers={"Cache-Control": "no-store"})
                return
            if parsed.path == "/api/settings":
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length:
                        payload = json.loads(
                            self.rfile.read(length) or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}
                try:
                    state = surface_settings.save_settings(payload)
                except (ValueError, OSError) as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                self._send(json.dumps(state).encode("utf-8"),
                           "application/json; charset=utf-8",
                           headers={"Cache-Control": "no-store"})
                return
            if parsed.path == "/api/collect/stop":
                try:
                    state = collect_backend.stop_collection()
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                except RuntimeError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 500)
                    return
                self._send(json.dumps(state).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            if parsed.path == "/api/collect":
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    raw = self.rfile.read(length) if length else b""
                    ctype = (self.headers.get("Content-Type") or "").split(
                        ";", 1)[0].strip().lower()
                    if ctype == "application/x-www-form-urlencoded":
                        payload = {k: v[0] for k, v in urllib.parse.parse_qs(
                            raw.decode("utf-8", "replace")).items()}
                    else:
                        payload = json.loads(raw or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}

                def _flag(name, default=False):
                    value = payload.get(name, default)
                    if isinstance(value, bool):
                        return value
                    return str(value).strip().lower() in (
                        "1", "true", "yes", "on")

                try:
                    state = collect_backend.start_collection(
                        refresh_token=payload.get("refresh_token") or "",
                        out=payload.get("out") or "",
                        client_id=(payload.get("client_id") or "").strip(),
                        user_agent=(payload.get("user_agent") or "").strip(),
                        backend=(payload.get("backend") or "graph").strip().lower(),
                        evade=_flag("evade"),
                        gather_all=_flag("gather_all"),
                        autotoken=_flag("autotoken", True),
                        mfa=_flag("mfa"))
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                except RuntimeError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 500)
                    return
                self._send(json.dumps(state).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            if parsed.path == "/api/ca-analysis":
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length:
                        payload = json.loads(self.rfile.read(length) or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}
                scenario = payload.get("scenario") or {}

                def _csv(key):
                    raw = payload.get(key)
                    if isinstance(raw, list):
                        return [str(x) for x in raw if str(x).strip()]
                    if isinstance(raw, str) and raw.strip():
                        return [x.strip() for x in raw.split(",") if x.strip()]
                    return []

                try:
                    max_scenarios = int(payload.get("max_scenarios") or 24)
                except (TypeError, ValueError):
                    max_scenarios = 24
                options = {
                    "population": (payload.get("population") or "privileged").strip().lower(),
                    "users": _csv("users"),
                    "synced_only": bool(payload.get("synced_only")),
                    "include_disabled": bool(payload.get("include_disabled", True)),
                    "resource": (payload.get("resource") or "").strip(),
                    "client_app": (payload.get("client_app") or "").strip(),
                    "mode": (payload.get("mode") or "fast").strip().lower(),
                    "max_scenarios": max_scenarios,
                }
                try:
                    max_total = int(payload.get("max_total_scenarios")
                                    or CA_PATH_GLOBAL_SCENARIO_BUDGET)
                except (TypeError, ValueError):
                    max_total = CA_PATH_GLOBAL_SCENARIO_BUDGET
                options["max_total_scenarios"] = max_total
                try:
                    state = start_ca_analysis(
                        upn=(payload.get("upn") or "").strip(),
                        compare_upns=_csv("compare_upns"),
                        assume_groups=_csv("assume_groups"),
                        assume_roles=_csv("assume_roles"),
                        assume_groups_b=_csv("assume_groups_b"),
                        assume_roles_b=_csv("assume_roles_b"),
                        scenario=scenario,
                        options=options)
                except RuntimeError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 409)
                    return
                self._send(json.dumps({"status": state["status"],
                                       "kind": state.get("kind")}).encode("utf-8"),
                           "application/json; charset=utf-8")
            else:
                self._send(b'{"error": "not found"}', "application/json; charset=utf-8", 404)
        except Exception as exc:  # noqa: BLE001
            self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                       "application/json; charset=utf-8", 500)


def start_serve(port, total=None, after_start=None):
    """Start the HTTP server (in a daemon thread), optionally run a callback
    (e.g. the cache write) once it is accepting connections, then idle until
    Ctrl+C. Serving first keeps the report usable while the cache is written."""
    try:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", port),
                                                 AuditServeHandler)
    except (OSError, OverflowError) as exc:
        print(f"error: cannot listen on 127.0.0.1:{port}: {exc}", file=sys.stderr)
        return 1
    count = f" ({total} findings)" if total else ""
    print(f"Serving audit report{count} on http://127.0.0.1:{port} (Ctrl+C to stop)",
          flush=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    if after_start:
        try:
            after_start()
        except Exception as exc:  # noqa: BLE001 - cache write must not kill serving
            print(f"warning: post-start task failed: {exc}", file=sys.stderr)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.shutdown()
        server.server_close()
    return 0


# ---------------------------------------------------------------------------
# Analysis cache + run-to-run diff
# ---------------------------------------------------------------------------
# The first run analyzes the tenant and stores the outcomes (findings, derived
# drawer data, group-role resolution) in ./.entra-surface.cache. Later launches reuse it
# when the database fingerprint is unchanged; when the database changed, the
# new analysis is diffed against the cached one and surfaced in the report.

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=None,
                        help="Path to the roadrecon SQLite database "
                             "(omit to serve the GUI shell with no data)")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="Path to the privileged-roles config JSON (default: privileged_roles.json)")
    parser.add_argument("--azure-config", default=str(DEFAULT_AZURE_CONFIG), help="Path to the azure-roles config JSON (default: azure_roles.json)")
    parser.add_argument("--port", type=int, default=8787,
                        help="Port to serve the report on (default: 8787)")
    parser.add_argument("--refresh", action="store_true",
                        help="Ignore the cache and re-run the full analysis")
    parser.add_argument("--no-cache", action="store_true",
                        help="Disable the analysis cache entirely: never read or write it")
    parser.add_argument("--timing", action="store_true",
                        help="Print per-phase timings and peak memory at the end of the run")
    args = parser.parse_args()

    db_path = Path(args.db) if args.db else None
    config_path = Path(args.config)
    SERVE_STATE["config_path"] = str(config_path)
    SERVE_STATE["azure_config_path"] = args.azure_config

    if db_path is None:
        print("no database: serving the empty GUI shell")
        with sqlite3.connect(":memory:") as empty_conn:
            graph = build_graph(empty_conn.cursor())
        results = []
        group_roles = {}
        group_eligible_roles = {}
        tenant_summary = build_tenant_summary(graph, results)
        check_cfg = dict(DEFAULT_CHECK_CFG)
        check_cfg["directory_roles"] = {}
        try:
            _, loaded_cfg = load_config(config_path)
            check_cfg["role_labels"] = loaded_cfg.get("role_labels") or {}
            check_cfg["directory_role_descriptions"] = (
                loaded_cfg.get("directory_role_descriptions") or {})
        except ConfigError as exc:
            print(f"warning: {exc} (using built-in defaults)", file=sys.stderr)
            check_cfg["role_labels"] = {}
            check_cfg["directory_role_descriptions"] = {}
        check_cfg["azure_roles"] = {}
        serve_tables = {}
        report_html = render_report(
            results, None, None, config_path, tenant_summary, graph=graph,
            serve_tables=serve_tables, group_roles=group_roles,
            group_eligible_roles=group_eligible_roles)
        SERVE_STATE["shell"] = report_html
        SERVE_STATE["db_path"] = None
        SERVE_STATE["ca_analysis"] = None
        SERVE_STATE["tables"] = serve_tables
        SERVE_STATE["user_findings"] = []
        SERVE_STATE["group_profiles"] = {}
        SERVE_STATE["policy_profiles"] = {}
        SERVE_STATE["records"] = []
        SERVE_STATE["graph"] = graph
        SERVE_STATE["check_cfg"] = check_cfg
        SERVE_STATE["group_roles"] = group_roles
        SERVE_STATE["group_eligible_roles"] = group_eligible_roles
        SERVE_STATE["profile_builder"] = None
        return start_serve(args.port, 0)

    if not db_path.exists():
        print(f"error: database not found: {db_path}", file=sys.stderr)
        return 1
    if not config_path.exists():
        print(f"error: config not found: {config_path}", file=sys.stderr)
        return 1

    try:
        conn = open_audit_database(db_path)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    cur = conn.cursor()

    tenant_name = None
    try:
        cur.execute("SELECT displayName FROM TenantDetails LIMIT 1")
        row = cur.fetchone()
        tenant_name = row[0] if row else None
    except sqlite3.OperationalError:
        pass

    try:
        config_resources, check_cfg = load_config(config_path)
        azure_role_sev = load_azure_roles(args.azure_config)
    except ConfigError as exc:
        conn.close()
        print(f"error: {exc}", file=sys.stderr)
        return 1
    check_cfg["azure_roles"] = azure_role_sev
    config_fingerprint = compute_config_fingerprint(config_resources, check_cfg)
    SERVE_STATE["config_fingerprint"] = config_fingerprint

    def timed(label, fn):
        t0 = time.perf_counter()
        r = fn()
        if args.timing:
            print(f"[timing] {label:<36s} {time.perf_counter() - t0:7.1f}s")
        return r

    def now_iso():
        return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

    cache_path, cache_meta_path = cache_paths(db_path)
    fingerprint = compute_db_fingerprint(db_path, cur, config_fingerprint)
    cached = None if (args.refresh or args.no_cache) else load_cache(cache_path)
    cache_hit = cache_fresh(cached, fingerprint)

    graph = timed("build_graph", lambda: build_graph(cur))
    timed("apply_azure_severity", lambda: apply_azure_severity(graph, azure_role_sev))

    if cache_hit:
        print(f"cache hit: skipping analysis (last analyzed {cached.get('generated_at')})")
        results = cached["results"]
        group_roles = cached.get("group_roles") or {}
        group_eligible_roles = cached.get("group_eligible_roles") or {}
        tenant_summary = timed("build_tenant_summary",
                               lambda: build_tenant_summary(graph, results))
        conn.close()
        diff = None
        cache_meta = {"hit": True, "generated_at": cached.get("generated_at") or ""}
    else:
        print("cache miss: running full analysis")
        # shared role resolution: computed once, reused by the checks, the
        # severity bump, the entity profiles and the report embed
        group_roles = timed("compute_group_roles",
                            lambda: compute_group_roles(graph, check_cfg))
        group_eligible_roles = timed("compute_group_eligible_roles",
                                     lambda: compute_group_eligible_roles(graph, check_cfg))
        sp_dir_resolver = make_sp_dir_resolver(graph, group_roles,
                                               check_cfg["directory_roles"],
                                               group_eligible_roles)
        results = timed("run_checks",
                        lambda: run_checks(graph, config_resources, check_cfg,
                                           group_roles=group_roles,
                                           group_eligible_roles=group_eligible_roles,
                                           sp_dir_resolver=sp_dir_resolver))

        # raw details and drawer profiles are served lazily from the database
        # and the in-memory graph (tier-2 memory saving)
        tenant_summary = timed("build_tenant_summary",
                               lambda: build_tenant_summary(graph, results))
        diff = compute_diff(cached.get("results", []), results) if cached else None
        conn.close()
        cache_meta = {
            "hit": False,
            "off": args.no_cache,
            "fresh": cached is None and not args.no_cache,
            "generated_at": now_iso(),
            "previous_at": cached.get("generated_at") if cached else None,
        }
        # the cache is written after the server starts accepting connections
        # (see start_serve(after_start=...) below)

    serve_tables = {}
    report_html = timed("render_report",
                        lambda: render_report(results, tenant_name, db_path, config_path,
                                              tenant_summary, graph=graph,
                                              serve_tables=serve_tables,
                                              group_roles=group_roles,
                                              group_eligible_roles=group_eligible_roles,
                                              cache_meta=cache_meta, diff=diff))

    total = sum(len(res["findings"]) for res in results)

    SERVE_STATE["shell"] = report_html
    SERVE_STATE["db_path"] = str(db_path)
    SERVE_STATE["ca_analysis"] = None
    SERVE_STATE["tables"] = serve_tables or {}
    SERVE_STATE["user_findings"] = next(
        (res["findings"] for res in results if res["id"] == "privileged_users"), [])
    SERVE_STATE["group_profiles"] = {
        f["group_id"]: f for res in results if res["id"] == "groups"
        for f in res["findings"]}
    SERVE_STATE["policy_profiles"] = {
        f["policy_id"]: f for res in results if res["id"] == "ca_exposure"
        for f in res["findings"] if f.get("policy_id")}
    SERVE_STATE["records"] = build_serve_records(results, graph)
    # lazy drawer inputs: the graph, role resolution and config stay resident;
    # raw details are read from the database on demand
    SERVE_STATE["graph"] = graph
    SERVE_STATE["check_cfg"] = check_cfg
    SERVE_STATE["group_roles"] = group_roles
    SERVE_STATE["group_eligible_roles"] = group_eligible_roles
    SERVE_STATE["profile_builder"] = None
    gc.collect()
    if args.timing:
        import resource
        print(f"[timing] peak RSS: {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.0f} MB")
    if args.no_cache or cache_hit:
        return start_serve(args.port, total)
    else:
        def write_cache_now():
            print(f"Writing analysis cache to {cache_path}...", flush=True)
            write_analysis_cache(cache_path, cache_meta_path, db_path,
                                 fingerprint, cache_meta["generated_at"],
                                 results, tenant_summary, group_roles,
                                 group_eligible_roles,
                                 config_fingerprint=config_fingerprint)
            try:
                size = cache_path.stat().st_size
                print(f"Analysis cache written ({size:,} bytes)", flush=True)
            except OSError:
                print("Analysis cache written", flush=True)
        return start_serve(args.port, total, after_start=write_cache_now)


if __name__ == "__main__":
    sys.exit(main())

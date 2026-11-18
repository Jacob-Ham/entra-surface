"""On-demand Conditional Access coverage, gap and path analysis."""
from __future__ import annotations

import itertools
from collections import Counter, defaultdict

from ..findings import is_privileged, severity_rank
from ..policy import _ca_state_label, _normalize_ca_policy
from ..report.html import (
    DASH_INNER, EXPAND_BUTTON_HTML, _serve_pager, drawer_for_html, esc,
)
from ..state import SERVE_STATE
from .dataset import (
    CA_CLIENT_APP_TYPES, CA_GUEST_TOKENS, CA_PATH_GLOBAL_SCENARIO_BUDGET,
    _ca_blocks, ca_app_covered, ca_app_is_office365, ca_client_matches,
    ca_location_verdict, ca_policy_blocks_legacy, ca_policy_excludes_user,
    ca_policy_includes_user, ca_user_is_guest, fmt_platforms, load_ca_dataset,
)


def run_ca_analysis(db_path, progress, target_upn=None, compare_upns=None,
                    assume_groups=None, assume_roles=None,
                    assume_groups_b=None, assume_roles_b=None,
                    scenario=None, options=None, user_findings=None,
                    records=None):
    """Conditional Access coverage analysis. `progress(step_id, detail)` marks
    each step complete as it finishes; pass running=True at phase start. When
    `target_upn` is given, the analysis is scoped to that single user.
    `compare_upns` switches to two-user policy comparison; assume_groups/roles
    apply to the first user and the _b variants to the second. `scenario` is an
    optional what-if sign-in context (platform, client app, trusted location,
    risk levels, device state, auth flow, device filter, ACR). `options`
    controls path-audit population, resource/client filters, fast/full mode, and
    the scenario caps. user_findings/records default to the live serve state;
    start_ca_analysis passes snapshots so a database reload cannot mix tenants.
    Returns {summary_html, sections_html, tables}."""
    assume_groups = assume_groups or []
    assume_roles = assume_roles or []
    assume_groups_b = assume_groups_b or []
    assume_roles_b = assume_roles_b or []
    scenario = scenario or {}
    options = options or {}
    if user_findings is None:
        user_findings = SERVE_STATE.get("user_findings", [])
    if records is None:
        records = SERVE_STATE.get("records", [])
    progress("load", running=True)
    data = load_ca_dataset(db_path)
    if target_upn:
        needle = (target_upn or "").strip().lower()
        target_uid = None
        for uid, rec in data["users"].items():
            if (rec.get("upn") or "").lower() == needle:
                target_uid = uid
                break
        if target_uid is None:
            raise ValueError(f"user '{target_upn}' not found in the collected users")
    progress("load", f"{len(data['policies'])} policy(ies), "
                     f"{len(data['users'])} user(s), {len(data['groups'])} group(s)")

    progress("scopes", running=True)

    group_memo = {}

    def _expand_group(gid, memo):
        if gid in memo:
            return memo[gid]
        out = set(data["group_member_user"].get(gid, ()))
        for child in data["group_member_group"].get(gid, ()):
            out |= _expand_group(child, memo)
        memo[gid] = out
        return out

    def _group_ancestors(gids):
        """A group set plus every parent group that contains one of them."""
        out = set(gids)
        changed = True
        while changed:
            changed = False
            for parent, children in data["group_member_group"].items():
                if parent not in out and out & set(children):
                    out.add(parent)
                    changed = True
        return out

    def _role_ids_with_templates(rids):
        out = set(rids)
        for rid in rids:
            template_id = data["role_template_by_oid"].get(rid)
            if template_id:
                out.add(template_id)
        return out

    # Role membership inherited through groups: direct role groups plus every
    # nested child group. Policies refer to DirectoryRole object IDs or role
    # template IDs, so expand into both views.
    role_group_members = defaultdict(set)
    role_template_group_members = defaultdict(set)
    for role_oid, gids in data["role_member_group"].items():
        members = set()
        for gid in gids:
            members |= _expand_group(gid, group_memo)
        role_group_members[role_oid] |= members
        template_id = data["role_template_by_oid"].get(role_oid)
        if template_id:
            role_template_group_members[template_id] |= members

    def _role_members(rid):
        return (data["role_member_user"].get(rid, set())
                | data["role_template_members"].get(rid, set())
                | role_group_members.get(rid, set())
                | role_template_group_members.get(rid, set()))

    def _user_role_ids(uid):
        """Role IDs (directory role + template) the user holds directly or
        through direct/nested group membership."""
        roles = {rid for rid, members in data["role_member_user"].items()
                 if uid in members}
        roles |= {rid for rid, members in data["role_template_members"].items()
                  if uid in members}
        for rid, gids in data["role_member_group"].items():
            if any(uid in _expand_group(gid, group_memo) for gid in gids):
                roles.add(rid)
                template_id = data["role_template_by_oid"].get(rid)
                if template_id:
                    roles.add(template_id)
        return roles

    def _is_guest(uid):
        return ca_user_is_guest(data["users"].get(uid))

    policies = []
    for p in data["policies"]:
        inner = _normalize_ca_policy(p["inner"])
        control_blocks = []
        for block in inner.get("Controls") or []:
            if not isinstance(block, dict):
                continue
            raw = block.get("Control") or block.get("GrantControls") or []
            if isinstance(raw, str):
                raw = [raw]
            names = [c for c in raw if isinstance(c, str)]
            auth_ids = block.get("AuthStrengthIds") or []
            if auth_ids:
                names.append("AuthStrength")
            if names:
                control_blocks.append({
                    "controls": names,
                    "auth_strength": bool(auth_ids),
                    "operator": block.get("Operator") or "OR",
                })
        controls = [c for b in control_blocks for c in b["controls"]]
        state = _ca_state_label(inner.get("State"))
        inc_users, inc_all, inc_guest = set(), False, False
        inc_group_list, inc_role_list = [], []
        for block in _ca_blocks(inner, "Users", "Include"):
            for uid in block.get("Users") or []:
                if uid == "All":
                    inc_all = True
                elif uid in CA_GUEST_TOKENS:
                    inc_guest = True
                else:
                    inc_users.add(uid)
            for gid in block.get("Groups") or []:
                if gid not in inc_group_list:
                    inc_group_list.append(gid)
                inc_users |= _expand_group(gid, group_memo)
            for rid in block.get("Roles") or []:
                if rid not in inc_role_list:
                    inc_role_list.append(rid)
                inc_users |= _role_members(rid)
        exc_users, exc_guest = set(), False
        exc_group_list, exc_role_list = [], []
        for block in _ca_blocks(inner, "Users", "Exclude"):
            for uid in block.get("Users") or []:
                if uid in CA_GUEST_TOKENS:
                    exc_guest = True
                elif uid != "All":
                    exc_users.add(uid)
            for gid in block.get("Groups") or []:
                if gid not in exc_group_list:
                    exc_group_list.append(gid)
                exc_users |= _expand_group(gid, group_memo)
            for rid in block.get("Roles") or []:
                if rid not in exc_role_list:
                    exc_role_list.append(rid)
                exc_users |= _role_members(rid)
        apps_inc, apps_exc, acrs_inc, acrs_exc = [], [], [], []
        for block in _ca_blocks(inner, "Applications", "Include"):
            apps_inc.extend(block.get("Applications") or [])
            acrs_inc.extend(block.get("Acrs") or block.get("UserActions") or [])
        for block in _ca_blocks(inner, "Applications", "Exclude"):
            apps_exc.extend(block.get("Applications") or [])
            acrs_exc.extend(block.get("Acrs") or block.get("UserActions") or [])
        # client types (legacy auth etc.) — modern 'ClientTypes' section,
        # with fallback to the older 'ClientApplications' shape
        client_inc, client_exc = [], []
        for block in _ca_blocks(inner, "ClientTypes", "Include"):
            client_inc.extend(block.get("ClientTypes") or [])
        for block in _ca_blocks(inner, "ClientTypes", "Exclude"):
            client_exc.extend(block.get("ClientTypes") or [])
        for block in _ca_blocks(inner, "ClientApplications", "Include"):
            client_inc.extend(block.get("IncludeClientApplications") or [])
        for block in _ca_blocks(inner, "ClientApplications", "Exclude"):
            client_exc.extend(block.get("ExcludeClientApplications") or [])
        # device platforms + device states (live under DevicePlatforms)
        platforms_inc, platforms_exc = [], []
        device_states_inc, device_states_exc = [], []
        for block in _ca_blocks(inner, "DevicePlatforms", "Include"):
            platforms_inc.extend(block.get("DevicePlatforms") or block.get("IncludeDevicePlatforms") or [])
            device_states_inc.extend(block.get("IncludeDeviceStates") or [])
        for block in _ca_blocks(inner, "DevicePlatforms", "Exclude"):
            platforms_exc.extend(block.get("DevicePlatforms") or block.get("ExcludeDevicePlatforms") or [])
            device_states_exc.extend(block.get("ExcludeDeviceStates") or [])
        # named locations + trusted locations
        locations_inc, locations_exc, trusted_locations = [], [], False
        for block in _ca_blocks(inner, "Locations", "Include"):
            locations_inc.extend(block.get("IncludeLocations") or [])
            if block.get("IncludeTrustedLocations"):
                trusted_locations = True
        for block in _ca_blocks(inner, "Locations", "Exclude"):
            locations_exc.extend(block.get("ExcludeLocations") or [])
            if block.get("ExcludeTrustedLocations"):
                trusted_locations = True
        # authentication-flow conditions
        auth_flows_inc, auth_flows_exc = [], []
        for block in _ca_blocks(inner, "AuthFlows", "Include"):
            auth_flows_inc.extend(block.get("AuthFlows") or block.get("AuthenticationFlows") or [])
        for block in _ca_blocks(inner, "AuthFlows", "Exclude"):
            auth_flows_exc.extend(block.get("AuthFlows") or block.get("AuthenticationFlows") or [])

        # device filter rules (rule text is opaque; evaluate as match/no-match)
        device_rules = []
        conds = inner.get("Conditions") or {}
        devices = conds.get("Devices") or {}
        dfilter = devices.get("Filter") or {}
        if isinstance(dfilter, dict) and dfilter.get("Rule"):
            device_rules.append(dfilter["Rule"])
        for block in _ca_blocks(inner, "Devices", "Include"):
            rule = block.get("DeviceRule") or block.get("Rule")
            if rule:
                device_rules.append(rule)

        # risk-level conditions
        risk_signin = conds.get("SignInRiskLevels") or []
        risk_user = conds.get("UserRiskLevels") or []
        auth_strength = bool(sum((b.get("AuthStrengthIds") or [] for b in inner.get("Controls") or []), []))
        policies.append({
            "id": p["id"], "name": p["name"], "state": state,
            "enabled": state == "Enabled",
            "controls": controls, "control_blocks": control_blocks,
            "mfa": any(c.lower() == "mfa" for c in controls),
            "block": any(c.lower() == "block" for c in controls),
            "compliant": any(c.lower() in ("requirecompliantdevice", "compliantdevice") for c in controls),
            "auth_strength": auth_strength,
            "inc_users": inc_users, "inc_all": inc_all, "inc_guest": inc_guest,
            "exc_users": exc_users, "exc_guest": exc_guest,
            "inc_group_list": inc_group_list, "inc_role_list": inc_role_list,
            "exc_group_list": exc_group_list, "exc_role_list": exc_role_list,
            "apps_inc": apps_inc, "apps_exc": apps_exc,
            "acrs_inc": acrs_inc, "acrs_exc": acrs_exc,
            "client_inc": client_inc, "client_exc": client_exc,
            "platforms_inc": platforms_inc, "platforms_exc": platforms_exc,
            "device_states_inc": device_states_inc, "device_states_exc": device_states_exc,
            "device_rules": device_rules,
            "locations_inc": locations_inc, "locations_exc": locations_exc,
            "trusted_locations": trusted_locations,
            "risk_signin": risk_signin, "risk_user": risk_user,
            "auth_flows_inc": auth_flows_inc, "auth_flows_exc": auth_flows_exc,
        })
    enabled = [p for p in policies if p["enabled"]]
    progress("scopes", f"{len(policies)} policy(ies), {len(enabled)} enabled")

    def would_include(p, uid):
        return ca_policy_includes_user(p, uid, data["users"])

    def _excluded(p, uid):
        return ca_policy_excludes_user(p, uid, data["users"])

    def applies_to(p, uid):
        return would_include(p, uid) and not _excluded(p, uid)

    app_name_by_id = {}
    for sp in data["sps"].values():
        app_id = (sp.get("appId") or "").lower()
        if app_id:
            app_name_by_id[app_id] = sp.get("name") or app_id

    def _path_app_axis(p, sc):
        acr = sc.get("acr")
        if acr:
            inc = [str(a).lower() for a in p.get("acrs_inc") or []]
            exc = [str(a).lower() for a in p.get("acrs_exc") or []]
            if not inc and not exc:
                return False, "not a user-action policy"
            if "all" in exc or acr.lower() in exc:
                return False, "user action excluded"
            if "all" in inc or acr.lower() in inc:
                return True, None
            return False, "user action not targeted"
        if p.get("acrs_inc") and not p.get("apps_inc"):
            return False, "user-action policy only"
        inc = [str(a).lower() for a in p.get("apps_inc") or []]
        exc = [str(a).lower() for a in p.get("apps_exc") or []]
        app_id = (sc.get("app_id") or "").lower()
        if app_id and app_id in exc:
            return False, "resource excluded"
        if "all" in exc:
            return False, "all resources excluded"
        if not inc and not exc:
            return True, None
        if "all" in inc or (app_id and app_id in inc):
            return True, None
        if "office365" in inc and app_id and ca_app_is_office365(
                app_id, app_name_by_id.get(app_id, "")):
            return True, None
        if sc.get("resource_unscoped"):
            return False, "resource not specifically targeted"
        if not app_id:
            return None, "resource not specified"
        return False, "resource not targeted"

    def _path_client_axis(p, sc):
        return ca_client_matches(p["client_inc"], p["client_exc"],
                                 sc.get("client_app"))

    def _path_platform_axis(p, sc):
        if not p["platforms_inc"] and not p["platforms_exc"]:
            return True, None
        plat = sc.get("platform")
        if not plat:
            return None, "platform not specified"
        exc = [str(x).lower() for x in p["platforms_exc"]]
        if plat.lower() in exc:
            return False, "platform excluded"
        inc = [str(x).lower() for x in p["platforms_inc"]]
        if "all" in inc or plat.lower() in inc:
            return True, None
        return False, "platform not targeted"

    def _path_device_state_axis(p, sc):
        if not p["device_states_inc"] and not p["device_states_exc"]:
            return True, None
        state = sc.get("device_state")
        if state:
            states = {str(state).lower()}
        elif (sc.get("device_compliant") is not None
              or sc.get("device_hybrid_joined") is not None):
            states = set()
            if sc.get("device_compliant"):
                states.add("compliant")
            if sc.get("device_hybrid_joined"):
                states.add("domainjoined")
            states.add("unmanaged") if not states else None
        else:
            return None, "device state not specified"
        exc = [str(x).lower() for x in p["device_states_exc"]]
        if states & set(exc):
            return False, "device state excluded"
        inc = [str(x).lower() for x in p["device_states_inc"]]
        if "all" in inc or states & set(inc):
            return True, None
        return False, "device state not targeted"

    def _path_location_axis(p, sc):
        return ca_location_verdict(p, sc, data["locations"])

    def _path_risk_axis(name, policy_list, sc_value):
        if not policy_list:
            return True, None
        if not sc_value:
            return None, f"{name} not specified"
        if any(str(r).lower() == str(sc_value).lower() for r in policy_list):
            return True, None
        return False, f"{name} not targeted"

    def _path_auth_flow_axis(p, sc):
        inc = [str(x).lower() for x in p.get("auth_flows_inc") or []]
        exc = [str(x).lower() for x in p.get("auth_flows_exc") or []]
        if not inc and not exc:
            return True, None
        flow = sc.get("auth_flow")
        if not flow:
            return None, "auth flow not specified"
        flow = str(flow).lower()
        if flow in exc:
            return False, "auth flow excluded"
        if "all" in inc or flow in inc:
            return True, None
        return False, "auth flow not targeted"

    def _path_device_filter_axis(p, sc):
        if not p.get("device_rules"):
            return True, None
        value = sc.get("device_filter")
        if value is None:
            return None, "device filter not specified"
        if value:
            return True, None
        return False, "device filter not matched"

    def condition_verdict(p, sc):
        axes = [
            _path_app_axis(p, sc), _path_client_axis(p, sc),
            _path_platform_axis(p, sc), _path_device_state_axis(p, sc),
            _path_location_axis(p, sc),
            _path_risk_axis("sign-in risk", p["risk_signin"], sc.get("signin_risk")),
            _path_risk_axis("user risk", p["risk_user"], sc.get("user_risk")),
            _path_auth_flow_axis(p, sc), _path_device_filter_axis(p, sc),
        ]
        notes = []
        for matched, note in axes:
            if matched is False:
                return "no", note
            if matched is None:
                notes.append(note)
        if notes:
            return "signal", "; ".join(notes)
        return "yes", None

    def build_scenario(payload):
        def _bool_opt(value):
            if value in (None, ""):
                return None
            return str(value).strip().lower() in ("1", "true", "yes", "match")
        return {
            "app_id": payload.get("app_id") or None,
            "acr": payload.get("acr") or None,
            "client_app": payload.get("client_app") or None,
            "platform": payload.get("platform") or None,
            "device_state": payload.get("device_state") or None,
            "signin_risk": payload.get("signin_risk") or None,
            "user_risk": payload.get("user_risk") or None,
            "auth_flow": payload.get("auth_flow") or None,
            "device_filter": _bool_opt(payload.get("device_filter")),
            "device_compliant": None,
            "device_hybrid_joined": None,
            "resource_unscoped": False,
            "require": (payload.get("require") or "").strip().lower(),
            "trusted_location": (None if payload.get("trusted_location") in (None, "")
                                 else str(payload["trusted_location"]).lower() == "true"),
            "location_id": payload.get("location_id") or payload.get("named_location") or None,
        }

    def _control_label(control):
        low = str(control).lower()
        return {"mfa": "MFA", "requirecompliantdevice": "Compliant device",
                "compliantdevice": "Compliant device", "block": "Block",
                "authstrength": "Auth strength",
                "passwordchange": "Password change",
                "domainjoineddevice": "Domain-joined device"}.get(low, str(control))

    def _policy_control_display(p):
        if p.get("block"):
            return "Block"
        parts = []
        for block in p.get("control_blocks") or []:
            names = [_control_label(c) for c in block.get("controls") or []
                     if str(c).lower() != "block"]
            if names:
                joiner = " and " if str(block.get("operator", "OR")).upper() == "AND" else " or "
                parts.append(joiner.join(names))
        return " + ".join(parts)

    def ca_gap(def_en, def_rep, excl_pols, sc, require):
        if any(p["block"] for p in def_en):
            return None
        if require == "mfa" and not any(p["mfa"] for p in def_en):
            return ("NO_MFA_ENFORCED",
                    "No definitively applying enabled policy requires MFA in this scenario.")
        if require == "compliant" and not any(p["compliant"] for p in def_en):
            return ("NO_COMPLIANT_DEVICE_ENFORCED",
                    "No definitively applying enabled policy requires a compliant device in this scenario.")
        if require == "mfa_compliant" and not (
                any(p["mfa"] for p in def_en)
                and any(p["compliant"] for p in def_en)):
            return ("NO_MFA_COMPLIANT_ENFORCED",
                    "No definitively applying enabled policy enforces both MFA and a compliant device in this scenario.")
        if excl_pols and not def_en:
            return ("EXCLUDED_BYPASS",
                    "An enabled policy would otherwise apply, but this user is excluded.")
        if not def_en and not def_rep:
            return ("NO_POLICIES_APPLY",
                    "No policy definitively applies in this scenario.")
        if not def_en:
            return ("REPORT_ONLY_BYPASS",
                    "Only report-only policies definitively apply; no enforcement.")
        if sc["trusted_location"] is True and not any(
                p["mfa"] or p["block"] or p["compliant"] for p in def_en):
            return ("TRUSTED_LOCATION_BYPASS",
                    "Definitive policies apply from the trusted location, but none enforce MFA, compliant device, or Block.")
        return None

    # Selected roster. Single-user mode analyzes the target regardless of
    # privilege; path-audit mode honors the population filters.
    population = (options.get("population") or "privileged").lower()
    include_disabled = bool(options.get("include_disabled", True))
    synced_only = bool(options.get("synced_only", False))
    requested_upns = {str(u).strip().lower()
                      for u in (options.get("users") or []) if str(u).strip()}
    sev_by_uid = {f.get("user_id"): f.get("severity", "Info")
                  for f in user_findings
                  if f.get("user_id")}
    priv_users = {}

    def _add_user(uid, rec=None, upn=None, name=None, severity=None):
        rec = rec or data["users"].get(uid) or {}
        if not include_disabled and not rec.get("enabled", True):
            return
        if synced_only and not rec.get("sync"):
            return
        priv_users[uid] = {
            "uid": uid,
            "upn": upn or rec.get("upn") or uid,
            "name": name or rec.get("name") or upn or uid,
            "severity": severity or sev_by_uid.get(uid, "Info"),
        }

    if target_upn:
        rec = data["users"].get(target_uid) or {}
        priv_users[target_uid] = {
            "uid": target_uid,
            "upn": rec.get("upn") or target_upn,
            "name": rec.get("name") or target_upn,
            "severity": sev_by_uid.get(target_uid, "Info"),
        }
    elif population == "all":
        for uid, rec in data["users"].items():
            _add_user(uid, rec)
    elif population == "list":
        for uid, rec in data["users"].items():
            if (rec.get("upn") or "").strip().lower() in requested_upns:
                _add_user(uid, rec)
    else:
        for f in user_findings:
            if is_privileged(f.get("severity", "Info")):
                uid = f.get("user_id")
                if not uid:
                    continue
                _add_user(uid, data["users"].get(uid),
                          upn=f.get("user_upn"), name=f.get("user_display"),
                          severity=f.get("severity", "Info"))

    roster_label = "User" if target_upn else {
        "all": "All users", "list": "Listed users",
    }.get(population, "Privileged users")

    progress("users", running=True)
    zero_coverage, no_mfa, no_compliant, report_only_bypass = [], [], [], []
    excluded_bypass = []
    for uid in sorted(priv_users, key=lambda u: (severity_rank(priv_users[u]["severity"]),
                                                 priv_users[u]["upn"].lower())):
        applying = [p for p in enabled if applies_to(p, uid)]
        reporting = [p for p in policies
                     if p["state"] == "Reporting" and applies_to(p, uid)]
        excluded = [p for p in enabled
                    if would_include(p, uid) and _excluded(p, uid)]
        if not applying:
            zero_coverage.append(priv_users[uid])
            if excluded:
                excluded_bypass.append({
                    **priv_users[uid],
                    "policies": ", ".join(p["name"] for p in excluded),
                })
            elif reporting:
                report_only_bypass.append({
                    **priv_users[uid],
                    "policies": ", ".join(p["name"] for p in reporting),
                })
        else:
            if not any(p["mfa"] or p["block"] for p in applying):
                no_mfa.append(priv_users[uid])
            if not any(p["compliant"] or p["block"] for p in applying):
                no_compliant.append(priv_users[uid])
    progress("users", f"{len(zero_coverage)} zero coverage, "
                      f"{len(no_mfa)} without MFA/Block, {len(no_compliant)} without compliant-device/Block, "
                      f"{len(report_only_bypass)} report-only bypass, "
                      f"{len(excluded_bypass)} excluded bypass")

    progress("apps", running=True)
    priv_sp_ids = {}
    for rec in records:
        if is_privileged(rec.get("severity", "Info")):
            sid = (rec.get("__ids") or {}).get("sp")
            if sid and sid not in priv_sp_ids:
                priv_sp_ids[sid] = rec.get("severity", "Info")
    def app_covered(p, app_id, app_name=""):
        return ca_app_covered(p["apps_inc"], p["apps_exc"], app_id, app_name)

    app_gaps = []
    for sid in sorted(priv_sp_ids):
        sp = data["sps"].get(sid) or {"name": sid, "appId": ""}
        app_id = (sp.get("appId") or "").lower()
        app_name = sp.get("name") or ""
        if app_id and not any(app_covered(p, app_id, app_name) for p in enabled):
            app_gaps.append({"sp_id": sid, "app_id": sp.get("appId") or "",
                             "name": sp.get("name") or sid,
                             "severity": priv_sp_ids[sid]})
    progress("apps", f"{len(app_gaps)} privileged app(s) without coverage")

    progress("legacy", running=True)
    legacy_blockers = [p for p in enabled if ca_policy_blocks_legacy(p)]
    legacy_gap = sorted(
        (priv_users[uid] for uid in priv_users
         if not any(applies_to(p, uid) for p in legacy_blockers)),
        key=lambda u: (severity_rank(u["severity"]), u["upn"].lower()))
    progress("legacy",
             f"{len(legacy_blockers)} legacy-auth block policy(ies), "
             f"{len(legacy_gap)} privileged user(s) outside them")

    progress("exclusions", running=True)
    excl_rows = []
    for uid in sorted(priv_users, key=lambda u: (severity_rank(priv_users[u]["severity"]),
                                                 priv_users[u]["upn"].lower())):
        exclusions = [p for p in enabled
                      if would_include(p, uid) and _excluded(p, uid)]
        if exclusions:
            excl_rows.append({
                **priv_users[uid],
                "count": len(exclusions),
                "policies": ", ".join(p["name"] for p in exclusions),
            })
    progress("exclusions", f"{len(excl_rows)} privileged user(s) with exclusions")

    # ---- bounded path audit ------------------------------------------------
    path_records = []
    path_mode = (options.get("mode") or "fast").lower()
    if path_mode not in ("fast", "full"):
        path_mode = "fast"
    raw_max = options.get("max_scenarios", 24)
    try:
        path_max = 24 if raw_max in (None, "") else max(0, min(500, int(raw_max)))
    except (TypeError, ValueError):
        path_max = 24
    raw_total = options.get("max_total_scenarios", CA_PATH_GLOBAL_SCENARIO_BUDGET)
    try:
        path_total_max = max(0, int(raw_total))
    except (TypeError, ValueError):
        path_total_max = CA_PATH_GLOBAL_SCENARIO_BUDGET
    path_active = set()
    for p in policies:
        if p["locations_inc"] or p["locations_exc"] or p["trusted_locations"]:
            path_active.add("trusted_location")
        if p["platforms_inc"] or p["platforms_exc"]:
            path_active.add("platform")
        if p["risk_signin"]:
            path_active.add("signin_risk")
        if p["risk_user"]:
            path_active.add("user_risk")
        if p["auth_flows_inc"] or p["auth_flows_exc"]:
            path_active.add("auth_flow")
        if p["device_rules"]:
            path_active.add("device_filter")
        if p["device_states_inc"] or p["device_states_exc"]:
            path_active.add("device_state")

    def _resource_label(resource_id):
        if resource_id == "__unscoped__":
            return "Apps without specific CA policies"
        name = app_name_by_id.get(str(resource_id).lower())
        return f"{name} ({resource_id})" if name else str(resource_id)

    resource_opt = str(options.get("resource") or "").strip()
    client_opt = str(options.get("client_app") or "").strip()
    path_clients = ([client_opt] if client_opt in CA_CLIENT_APP_TYPES
                    else list(CA_CLIENT_APP_TYPES))
    path_is_acr = resource_opt.lower().startswith("urn:")
    path_resources = []
    if path_is_acr:
        path_resources = [(None, resource_opt, False, resource_opt)]
    elif resource_opt and resource_opt.lower() not in ("all", ""):
        if resource_opt.lower() in ("unscoped", "__unscoped__"):
            path_resources = [(None, "Apps without specific CA policies", True, None)]
        else:
            path_resources = [(resource_opt, _resource_label(resource_opt), False, None)]
    else:
        resource_ids = set()
        for p in policies:
            for a in (p["apps_inc"] + p["apps_exc"]):
                low = str(a).lower()
                if a and low not in ("all", "none", "office365"):
                    resource_ids.add(str(a))
        for rid in sorted(resource_ids, key=lambda x: _resource_label(x).lower()):
            path_resources.append((rid, _resource_label(rid), False, None))
        path_resources.append((None, "Apps without specific CA policies", True, None))

    def _iter_path_scenarios():
        if path_mode == "full":
            platforms = (["windows", "macos", "linux", "ios", "android"]
                         if "platform" in path_active else [None])
            trusted = [False, True] if "trusted_location" in path_active else [False]
            signin = (["none", "low", "medium", "high"]
                      if "signin_risk" in path_active else [None])
            userrisk = (["low", "medium", "high"]
                        if "user_risk" in path_active else [None])
            authflow = ([None, "devicecodeflow", "authtransfer"]
                        if "auth_flow" in path_active else [None])
            devfilter = ([None, False, True]
                         if "device_filter" in path_active else [None])
        else:
            platforms = ["windows"]
            trusted = [False, True] if "trusted_location" in path_active else [False]
            signin = ["none"]
            userrisk = ["low"]
            authflow = [None]
            devfilter = [None]
        devcombos = ([(True, True), (True, False), (False, True), (False, False)]
                     if "device_state" in path_active else [(True, True)])
        for platform, trust, signin, userrisk, authflow, devfilter in itertools.product(
                platforms, trusted, signin, userrisk, authflow, devfilter):
            for compliant, hybrid in devcombos:
                yield {
                    "platform": platform,
                    "trusted_location": trust,
                    "signin_risk": signin,
                    "user_risk": userrisk,
                    "auth_flow": authflow,
                    "device_filter": devfilter,
                    "device_compliant": compliant,
                    "device_hybrid_joined": hybrid,
                }

    def _summarize_path(outcomes):
        has_gap = has_req = has_blocked = False
        gap_type, gap_policies = None, []
        req_outcome = None
        for o in outcomes:
            if o["blocked"]:
                has_blocked = True
                continue
            if not o["controls"]:
                has_gap = True
                if gap_type is None or o["gap_type"] == "NO_POLICIES_APPLY":
                    gap_type = o["gap_type"]
                    gap_policies = o["policies"]
            else:
                has_req = True
                if req_outcome is None or len(o["controls"]) < len(req_outcome["controls"]):
                    req_outcome = o
        return {
            "has_gap": has_gap, "has_req": has_req, "has_blocked": has_blocked,
            "gap_type": gap_type, "gap_policies": gap_policies,
            "req_controls": req_outcome["controls"] if req_outcome else None,
            "req_controls_display": req_outcome["controls_display"] if req_outcome else "",
            "req_policies": req_outcome["policies"] if req_outcome else [],
        }

    def _evaluate_path(uid, app_id, resource_label, unscoped, acr, client_app,
                       scenario_limit=None):
        outcomes = {}
        scenarios_evaluated = 0
        scenario_cap = path_max
        if scenario_limit is not None:
            scenario_cap = (scenario_limit if not scenario_cap
                            else min(scenario_cap, scenario_limit))
        for base_sc in _iter_path_scenarios():
            sc = dict(base_sc)
            sc.update({"app_id": app_id, "acr": acr,
                       "client_app": client_app,
                       "resource_unscoped": unscoped})
            enabled_apply, excluded_apply, reporting_apply = [], [], []
            for p in policies:
                if not would_include(p, uid):
                    continue
                verdict, _note = condition_verdict(p, sc)
                if p["enabled"]:
                    if _excluded(p, uid):
                        if verdict == "yes":
                            excluded_apply.append(p)
                    elif verdict == "yes":
                        enabled_apply.append(p)
                elif p["state"] == "Reporting":
                    if not _excluded(p, uid) and verdict == "yes":
                        reporting_apply.append(p)
            blocked = next((p for p in enabled_apply if p["block"]), None)
            if blocked:
                controls = []
                gap_type = None
                display = "Block"
                responsible = [p["name"] for p in enabled_apply if p["block"]]
            else:
                control_pols = [p for p in enabled_apply
                                if p["controls"] and not p["block"]]
                if control_pols:
                    controls = sorted({
                        _control_label(c) for p in control_pols
                        for c in p["controls"]
                        if str(c).lower() not in ("block",)
                    })
                    gap_type = None
                    display = " + ".join(filter(None, [
                        _policy_control_display(p) for p in control_pols]))
                    responsible = [p["name"] for p in control_pols]
                elif excluded_apply:
                    controls = []
                    gap_type = "EXCLUDED_BYPASS"
                    display = ""
                    responsible = [p["name"] for p in excluded_apply]
                elif reporting_apply:
                    controls = []
                    gap_type = "REPORT_ONLY_BYPASS"
                    display = ""
                    responsible = [p["name"] for p in reporting_apply]
                else:
                    controls = []
                    gap_type = "NO_POLICIES_APPLY"
                    display = ""
                    responsible = []
            key = (tuple(controls), gap_type, bool(blocked))
            o = outcomes.get(key)
            if o is None:
                o = outcomes[key] = {
                    "controls": controls, "gap_type": gap_type,
                    "blocked": bool(blocked), "policies": [],
                    "controls_display": display,
                    "scenario_count": 0,
                }
            o["scenario_count"] += 1
            for name in responsible:
                if name and name not in o["policies"]:
                    o["policies"].append(name)
            scenarios_evaluated += 1
            if scenario_cap and scenarios_evaluated >= scenario_cap:
                break
        outcome_list = list(outcomes.values())
        for o in outcome_list:
            o["policies"] = sorted(o["policies"])
        summary = _summarize_path(outcome_list)
        return {
            "outcomes": outcome_list, "scenarios_evaluated": scenarios_evaluated,
            **summary,
        }

    progress("paths", running=True)
    path_budget_used = 0
    path_budget_exhausted = False
    if not target_upn and not compare_upns and priv_users:
        for uid in sorted(priv_users, key=lambda u: (
                severity_rank(priv_users[u]["severity"]),
                priv_users[u]["upn"].lower())):
            if path_budget_exhausted:
                break
            user = priv_users[uid]
            for app_id, resource_label, unscoped, acr in path_resources:
                if path_budget_exhausted:
                    break
                for client_app in path_clients:
                    remaining = (None if not path_total_max
                                 else max(0, path_total_max - path_budget_used))
                    if remaining is not None and remaining <= 0:
                        path_budget_exhausted = True
                        break
                    result = _evaluate_path(uid, app_id, resource_label,
                                            unscoped, acr, client_app,
                                            scenario_limit=remaining)
                    path_budget_used += result["scenarios_evaluated"]
                    path_records.append({
                        "uid": uid, "user": user["name"], "upn": user["upn"],
                        "severity": user["severity"], "resource": resource_label,
                        "resource_id": app_id or "", "acr": acr or "",
                        "client_app": client_app, **result,
                    })
                    if path_total_max and path_budget_used >= path_total_max:
                        path_budget_exhausted = True
                        break
        path_records.sort(key=lambda r: (
            0 if r["has_gap"] else 1 if r["has_req"] else 2,
            r["upn"].lower(), r["resource"].lower(), r["client_app"]))
    path_gap_records = [r for r in path_records if r["has_gap"]]
    path_gap_users = len({r["uid"] for r in path_gap_records})
    path_gap_counts = Counter(r["gap_type"] for r in path_gap_records if r["gap_type"])
    path_scenarios = sum(r["scenarios_evaluated"] for r in path_records)
    progress("paths", "single-user what-if" if target_upn else
             f"{len(path_records)} path(s), {len(path_gap_records)} gap path(s), "
             f"{path_scenarios} scenario(s)"
             + (" (global scenario budget reached)" if path_budget_exhausted else ""))

    progress("render", running=True)

    def build_table(tid, title, cols, rows, sort_fields, subtitle=""):
        """cols: [(label, width), ...] for data columns (expand col implicit);
        rows: list of {'_html', '_text', 'fields'}; sort_fields: {col_idx: field}."""
        cells = ['<th class="no-sort"></th>']
        for label, _w in cols:
            cells.append(f'<th data-type="text">{esc(label)}</th>')
        colgroup = '<col style="width:44px">' + "".join(
            f'<col style="width:{width}">' for _, width in cols)
        return {
            "id": tid, "title": title, "subtitle": subtitle,
            "cols": cols, "rows": rows, "sort_fields": sort_fields,
            "colspan": len(cols) + 1,
            "section": f"""
  <section data-category="configs">
    <h2>{esc(title)}</h2>
    {subtitle}
    <div class="table-scroll">
    <table id="{esc(tid)}" class="findings" data-serve="1" data-ca-result="1">
      <colgroup>{colgroup}</colgroup>
      <thead><tr>{''.join(cells)}</tr></thead>
      <tbody></tbody>
    </table>
    </div>
    {_serve_pager()}
  </section>
""",
        }

    def user_row(r, key, extra_cell=""):
        text = f"{r['name']} {r['upn']}".lower()
        html = (f'<tr data-profile-id="{esc(r["uid"])}" data-detail-key="{key}">'
                f'<td class="expand-cell">{EXPAND_BUTTON_HTML}</td>'
                f'<td class="clickable" data-field="user" data-value="{esc(r["name"])}">{esc(r["name"])}</td>'
                f'<td class="clickable" data-field="userUpn" data-value="{esc(r["upn"])}">{esc(r["upn"])}</td>'
                f'{extra_cell}</tr>{drawer_for_html(key, 3 + (1 if extra_cell else 0))}')
        return {"_html": html, "_text": text,
                "fields": {"user": r["name"],
                           "upn": r["upn"], "userUpn": r["upn"]}}

    user_cols = [("User", "220px"), ("UPN", "260px")]
    user_sort = {"1": "user", "2": "upn"}

    def user_rows_for(entries, key_prefix, extra=None):
        out = []
        for i, r in enumerate(entries):
            extra_cell = ""
            if extra:
                extra_cell = (f'<td data-field="caExcl" data-value="{esc(str(r["count"]))}">'
                              f'<span class="perm" title="{esc(r["policies"])}">{r["count"]}</span></td>')
            out.append(user_row(r, f"{key_prefix}-{i}", extra_cell))
        return out

    app_rows = []
    for i, r in enumerate(app_gaps):
        app_rows.append({
            "_html": (f'<tr data-sp-id="{esc(r["sp_id"])}" data-app-id="{esc(r.get("app_id") or "")}" data-detail-key="ca-apps-{i}">'
                      f'<td class="expand-cell">{EXPAND_BUTTON_HTML}</td>'
                      f'<td class="clickable" data-field="app" data-value="{esc(r["name"])}">{esc(r["name"])}</td>'
                      f'</tr>{drawer_for_html("ca-apps-" + str(i), 2)}'),
            "_text": r['name'].lower(),
            "fields": {"app": r["name"]},
        })

    legacy_rows = []
    if legacy_blockers:
        legacy_rows = user_rows_for(legacy_gap, "ca-legacy")

    def conds_row(p, key):
        def fmt(items, all_label="All"):
            if not items:
                return "—"
            items = sorted(str(x) for x in items if x)
            if "All" in items:
                return all_label
            return ", ".join(items)
        controls = []
        if p["mfa"]:
            controls.append("MFA")
        if p["compliant"]:
            controls.append("Compliant device")
        if p["block"]:
            controls.append("Block")
        if p["auth_strength"]:
            controls.append("Auth strength")
        platforms = fmt_platforms(p["platforms_inc"], p["platforms_exc"]) or "—"
        device_states = fmt(p["device_states_inc"], "Any device state")
        if p["device_states_exc"]:
            device_states += f" (excl. {', '.join(sorted(p['device_states_exc']))})"
        locations = ""
        loc_bits = []
        if p["trusted_locations"]:
            loc_bits.append("Trusted locations")
        for lid in p["locations_inc"]:
            low = str(lid).lower()
            if low == "all":
                loc_bits.append("All")
            elif low == "alltrusted":
                loc_bits.append("AllTrusted")
            else:
                rec = data["locations"].get(lid)
                loc_bits.append(f"{rec['name']}{' (trusted)' if rec and rec['trusted'] else ''}"
                                if rec else lid)
        for lid in p["locations_exc"]:
            low = str(lid).lower()
            if low == "all":
                loc_bits.append("excl. All")
            elif low == "alltrusted":
                loc_bits.append("excl. AllTrusted")
            else:
                rec = data["locations"].get(lid)
                loc_bits.append(f"excl. {rec['name']}" if rec else f"excl. {lid}")
        locations = ", ".join(loc_bits) or "—"
        risks = " + ".join([", ".join(p["risk_signin"]), ", ".join(p["risk_user"])]).strip(" +")
        clients = fmt(p["client_inc"]) if p["client_inc"] else "—"
        authflows = fmt(p["auth_flows_inc"]) if p["auth_flows_inc"] else "—"
        acrs = fmt(p["acrs_inc"]) if p["acrs_inc"] else "—"
        devfilter = ("Filtered" if p["device_rules"] else "—")
        controls_display = _policy_control_display(p) or "—"
        fields = {"polname": p["name"], "polstate": p["state"],
                  "polcontrols": controls_display, "polapps": fmt(p["apps_inc"]),
                  "platforms": platforms, "devicestates": device_states,
                  "locations": locations, "risk": risks or "—", "clients": clients,
                  "authflows": authflows, "devfilter": devfilter, "acrs": acrs}
        text = " ".join(fields.values()).lower()
        cells = (
            f'<td class="clickable" data-field="polName" data-value="{esc(p["name"])}">{esc(p["name"])}</td>'
            f'<td data-field="polState" data-value="{esc(p["state"])}">{esc(p["state"])}</td>'
            f'<td data-field="polControls" data-value="{esc(controls_display)}">{esc(controls_display)}</td>'
            f'<td data-field="polApps" data-value="{esc(fmt(p["apps_inc"]))}">{esc(fmt(p["apps_inc"]))}</td>'
            f'<td>{esc(platforms)}</td><td>{esc(device_states)}</td><td>{esc(locations)}</td>'
            f'<td>{esc(risks or "—")}</td><td>{esc(clients)}</td>'
            f'<td>{esc(authflows)}</td><td>{esc(devfilter)}</td><td>{esc(acrs)}</td>')
        html = (f'<tr data-policy-id="{esc(p["id"])}" data-detail-key="{key}">'
                f'<td class="expand-cell">{EXPAND_BUTTON_HTML}</td>{cells}</tr>'
                f'{drawer_for_html(key, 13)}')
        return {"_html": html, "_text": text, "fields": fields}

    conds_rows = [conds_row(p, f"ca-conds-{i}") for i, p in enumerate(enabled)]

    tables = []
    if zero_coverage:
        tables.append(build_table("ca-zero-table", "Privileged users with no CA coverage",
                                  user_cols, user_rows_for(zero_coverage, "ca-zero"), user_sort))
    if no_mfa:
        tables.append(build_table("ca-mfa-table", "Privileged users without MFA policy coverage",
                                  user_cols, user_rows_for(no_mfa, "ca-mfa"), user_sort))
    if no_compliant:
        tables.append(build_table("ca-compliant-table", "Privileged users without compliant-device policy coverage",
                                  user_cols, user_rows_for(no_compliant, "ca-compliant"), user_sort))
    if report_only_bypass:
        ro_rows = []
        for i, r in enumerate(report_only_bypass):
            extra = (f'<td><span class="perm" title="{esc(r["policies"])}">report-only</span></td>')
            row = user_row(r, f"ca-ro-{i}", extra)
            row["fields"]["ro"] = r["policies"]
            ro_rows.append(row)
        tables.append(build_table(
            "ca-reportonly-table",
            "REPORT_ONLY_BYPASS (privileged users covered only by report-only policies)",
            [("User", "220px"), ("UPN", "240px"), ("Coverage", "110px")],
            ro_rows, {"1": "user", "2": "userUpn", "3": "ro"}))
    if excluded_bypass:
        eb_rows = []
        for i, r in enumerate(excluded_bypass):
            extra = (f'<td><span class="perm" title="{esc(r["policies"])}">excluded</span></td>')
            row = user_row(r, f"ca-eb-{i}", extra)
            row["fields"]["excluded"] = r["policies"]
            eb_rows.append(row)
        tables.append(build_table(
            "ca-excluded-table",
            "EXCLUDED_BYPASS (no other enabled policy applies)",
            [("User", "220px"), ("UPN", "240px"), ("Coverage", "110px")],
            eb_rows, {"1": "user", "2": "userUpn", "3": "excluded"}))
    if path_records:
        path_rows = []
        for i, r in enumerate(path_records):
            if r["has_gap"]:
                result_badge = '<span class="badge sev-critical">Gap</span>'
                result_text = "Gap"
            elif r["req_controls"]:
                result_badge = '<span class="badge badge-enabled">Requires</span>'
                result_text = "Requires " + r["req_controls_display"]
            elif r["has_blocked"]:
                result_badge = '<span class="badge badge-enabled">Blocked</span>'
                result_text = "Blocked"
            else:
                result_badge = '<span class="muted">&mdash;</span>'
                result_text = ""
            policies_text = ", ".join(r["gap_policies"] or r["req_policies"] or [])
            gap_text = r["gap_type"] or "—"
            fields = {
                "user": r["user"], "upn": r["upn"], "userUpn": r["upn"],
                "resource": r["resource"],
                "clientapp": r["client_app"], "result": result_text,
                "gaptype": r["gap_type"] or "", "policies": policies_text,
                "scenarios": str(r["scenarios_evaluated"]),
            }
            cells = (
                f'<td class="clickable" data-field="user" data-value="{esc(r["user"])}">{esc(r["user"])}</td>'
                f'<td data-field="userUpn" data-value="{esc(r["upn"])}">{esc(r["upn"])}</td>'
                f'<td data-field="resource" data-value="{esc(r["resource"])}">{esc(r["resource"])}</td>'
                f'<td data-field="clientapp" data-value="{esc(r["client_app"])}">{esc(r["client_app"])}</td>'
                f'<td data-field="result" data-value="{esc(result_text)}">{result_badge}</td>'
                f'<td data-field="gaptype" data-value="{esc(gap_text)}">{esc(gap_text)}</td>'
                f'<td data-field="policies" data-value="{esc(policies_text)}">{esc(policies_text or "—")}</td>'
                f'<td data-field="scenarios" data-value="{esc(str(r["scenarios_evaluated"]))}">{r["scenarios_evaluated"]}</td>'
            )
            path_rows.append({
                "_html": (f'<tr data-profile-id="{esc(r["uid"])}" data-detail-key="ca-path-{i}">'
                          f'<td class="expand-cell">{EXPAND_BUTTON_HTML}</td>{cells}</tr>'
                          f'{drawer_for_html("ca-path-" + str(i), 9)}'),
                "_text": " ".join(fields.values()).lower(),
                "fields": fields,
            })
        tables.append(build_table(
            "ca-path-table", "CA path audit",
            [("User", "180px"), ("UPN", "210px"), ("Resource", "220px"),
             ("Client app", "140px"), ("Result", "130px"), ("Gap type", "130px"),
             ("Policies", "280px"), ("Scenarios", "80px")],
            path_rows, {"1": "user", "2": "upn", "3": "resource", "4": "clientapp",
                        "5": "result", "6": "gaptype", "7": "policies", "8": "scenarios"},
            subtitle=f'<p class="sub">Mode: {esc(path_mode)} · '
                     f'active dims: {esc(", ".join(sorted(path_active)) or "none")} · '
                     f'scenarios/path: {path_max or "none"} · '
                     f'global scenario budget: {path_total_max or "none"}</p>'))
    if app_rows:
        tables.append(build_table("ca-apps-table", "Privileged apps with no CA coverage",
                                  [("Application", "240px")],
                                  app_rows, {"1": "app"}))
    if legacy_blockers:
        tables.append(build_table("ca-legacy-table",
                                  "Legacy-auth block coverage (privileged users outside)",
                                  user_cols, legacy_rows, user_sort,
                                  subtitle=f'<p class="sub">Blocking policies: '
                                           f'{esc(", ".join(p["name"] for p in legacy_blockers))}</p>'))
    if excl_rows:
        excl_table_rows = []
        for i, r in enumerate(excl_rows):
            extra = (f'<td data-field="caExcl" data-value="{esc(str(r["count"]))}">'
                     f'<span class="perm" title="{esc(r["policies"])}">{r["count"]}</span></td>')
            row = user_row(r, f"ca-excl-{i}", extra)
            row["fields"]["caexcl"] = str(r["count"])
            excl_table_rows.append(row)
        tables.append(build_table("ca-excl-table", "CA exclusions (privileged users)",
                                  [("User", "220px"), ("UPN", "260px"), ("Exclusions", "80px")],
                                  excl_table_rows, {"1": "user",
                                                    "2": "upn", "3": "caexcl"}))
    if enabled:
        tables.append(build_table("ca-conditions-table", "Enabled CA policy conditions",
                                  [("Policy", "240px"), ("State", "90px"), ("Controls", "170px"),
                                   ("Apps", "130px"), ("Platforms", "150px"), ("Device states", "130px"),
                                   ("Locations", "150px"), ("Risk", "120px"), ("Client types", "160px"),
                                   ("Auth flows", "120px"), ("Device filter", "100px"), ("ACR", "150px")],
                                  conds_rows, {"1": "polname", "2": "polstate",
                                               "3": "polcontrols", "4": "polapps",
                                               "5": "platforms", "6": "devicestates",
                                               "7": "locations", "8": "risk",
                                               "9": "clients", "10": "authflows",
                                               "11": "devfilter", "12": "acrs"}))

    sections_html = "".join(t["section"] for t in tables if t)
    if not legacy_blockers:
        sections_html += ('  <section data-category="configs"><h2>Legacy authentication</h2>'
                          '<p class="sub">No enabled policy blocks legacy authentication.</p></section>')

    # ---- shared policy condition rendering (single-user and compare) ----
    def _loc_label(lid):
        low = str(lid).lower()
        if low == "all":
            return "All"
        if low == "alltrusted":
            return "AllTrusted"
        rec = data["locations"].get(lid)
        if not rec:
            return str(lid)
        return rec["name"] + (" (trusted)" if rec["trusted"] else "")

    def signals_html(r):
        rows = []

        def axis(label, inc, exc):
            bits = []
            if inc:
                bits.append("All" if "All" in [str(x) for x in inc]
                            else ", ".join(str(x) for x in inc))
            if exc:
                bits.append("excl: " + ", ".join(str(x) for x in exc))
            if bits:
                rows.append(f"<tr><th>{esc(label)}</th><td>{esc(' \u00b7 '.join(bits))}</td></tr>")

        plat = fmt_platforms(r["platforms_inc"], r["platforms_exc"])
        if plat:
            rows.append(f"<tr><th>Platform</th><td>{esc(plat)}</td></tr>")
        axis("Client types", r["client_inc"], r["client_exc"])
        axis("Device states", r["device_states_inc"], r["device_states_exc"])
        axis("Auth flows", r["auth_flows_inc"], r["auth_flows_exc"])
        if r["device_rules"]:
            rows.append("<tr><th>Device filter</th><td>present</td></tr>")
        axis("ACR / user actions", r["acrs_inc"], r["acrs_exc"])
        loc_bits = []
        if r["trusted_locations"]:
            loc_bits.append("Trusted locations")
        for l in r["locations_inc"]:
            loc_bits.append(_loc_label(l))
        for l in r["locations_exc"]:
            loc_bits.append("excl: " + _loc_label(l))
        if loc_bits:
            rows.append(f"<tr><th>Locations</th><td>{esc(', '.join(loc_bits))}</td></tr>")
        risks = [f"sign-in: {x}" for x in r["risk_signin"]] \
            + [f"user: {x}" for x in r["risk_user"]]
        if risks:
            rows.append(f"<tr><th>Risk</th><td>{esc(', '.join(risks))}</td></tr>")
        app_bits = []
        if "All" in [str(a) for a in r["apps_inc"]]:
            app_bits.append("All")
        elif r["apps_inc"]:
            app_bits.append(", ".join(str(a) for a in r["apps_inc"]))
        if r["apps_exc"]:
            app_bits.append("excl: " + ", ".join(str(a) for a in r["apps_exc"]))
        if app_bits:
            rows.append(f"<tr><th>Applications</th><td>{esc(' \u00b7 '.join(app_bits))}</td></tr>")
        if not rows:
            return ('<p class="muted">No platform, client, device, location, risk, or app '
                    'conditions — the policy applies whenever its user scope matches.</p>')
        return '<table class="kv-table">' + "".join(rows) + "</table>"


    if target_upn:
        target = priv_users[target_uid]

        # ---- resolve assumed group/role names (or IDs) ---------------------
        def _resolve_assumed(names, table):
            ids, missing = [], []
            for raw in names:
                raw = (raw or "").strip()
                if not raw:
                    continue
                needle = raw.lower()
                hit = None
                for oid, label in table.items():
                    if oid.lower() == needle or (label or "").lower() == needle:
                        hit = oid
                        break
                if hit is None and table is data["roles"]:
                    for oid, template_id in data["role_template_by_oid"].items():
                        if (template_id or "").lower() == needle:
                            hit = oid
                            break
                if hit:
                    ids.append(hit)
                else:
                    missing.append(raw)
            return ids, missing

        assumed_gids, missing_g = _resolve_assumed(assume_groups, data["groups"])
        assumed_rids, missing_r = _resolve_assumed(assume_roles, data["roles"])
        if missing_g or missing_r:
            raise ValueError(
                ("unresolved assumed group(s): " + ", ".join(missing_g) + " · " if missing_g else "")
                + ("unresolved assumed role(s): " + ", ".join(missing_r) if missing_r else ""))

        # ---- the user's memberships, for targeting reasons -----------------
        user_roles = _user_role_ids(target_uid)
        user_groups = {gid for gid, members in data["group_member_user"].items()
                       if target_uid in members}
        referenced_gids = set()
        for p in policies:
            referenced_gids.update(p["inc_group_list"])
            referenced_gids.update(p["exc_group_list"])
        containing = _group_ancestors(user_groups | set(assumed_gids)) | {
            gid for gid in referenced_gids if target_uid in _expand_group(gid, group_memo)}
        all_groups = user_groups | set(assumed_gids)
        all_roles = user_roles | _role_ids_with_templates(assumed_rids)

        def _gname(gid):
            label = data["groups"].get(gid, gid)
            return f"{label}" + ("" if gid in all_groups else " (nested)")

        def _rname(rid):
            label = data["roles"].get(rid, rid)
            return f"{label}" + ("" if rid not in assumed_rids or rid in user_roles else " (assumed)")

        def _included_sim(p):
            if would_include(p, target_uid):
                return True
            if any(g in containing for g in p["inc_group_list"]):
                return True
            return any(r in all_roles for r in p["inc_role_list"])

        def _excluded_sim(p):
            if _excluded(p, target_uid):
                return True
            if any(g in containing for g in p["exc_group_list"]):
                return True
            return any(r in all_roles for r in p["exc_role_list"])

        def _include_reason(p):
            if p["inc_all"]:
                return "All users"
            if p["inc_guest"] and _is_guest(target_uid):
                return "guest/external users"
            matched = [g for g in p["inc_group_list"] if g in containing]
            if matched:
                return "via group: " + ", ".join(_gname(g) for g in matched[:3])
            matched_r = [r for r in p["inc_role_list"] if r in all_roles]
            if matched_r:
                return "via role: " + ", ".join(_rname(r) for r in matched_r[:3])
            if target_uid in p["inc_users"]:
                return "direct user"
            return "included"

        def _exclude_reason(p):
            if target_uid in p["exc_users"]:
                return "direct user"
            if p["exc_guest"] and _is_guest(target_uid):
                return "guest/external users"
            matched = [g for g in p["exc_group_list"] if g in containing]
            if matched:
                return "via group: " + ", ".join(_gname(g) for g in matched[:3])
            matched_r = [r for r in p["exc_role_list"] if r in all_roles]
            if matched_r:
                return "via role: " + ", ".join(_rname(r) for r in matched_r[:3])
            return "excluded"

        applying = [p for p in enabled if _included_sim(p) and not _excluded_sim(p)]
        excl_pols = [p for p in enabled if _included_sim(p) and _excluded_sim(p)]

        # ---- what-if condition evaluation ----------------------------------
        sc = build_scenario(scenario)

        def _effect(p):
            if p["block"]:
                return "Block"
            return "Grant" if p["controls"] else "Unknown"

        def whatif_eval(p):
            verdict, note = condition_verdict(p, sc)
            return {"applies": verdict, "note": note}

        whatif_rows = []
        for p in policies:
            if p["state"] == "Disabled":
                continue
            if not _included_sim(p) or _excluded_sim(p):
                continue
            verdict = whatif_eval(p)
            whatif_rows.append({**p, "verdict": verdict})

        def_en = [r for r in whatif_rows
                  if r["verdict"]["applies"] == "yes" and r["state"] == "Enabled"]
        def_rep = [r for r in whatif_rows
                   if r["verdict"]["applies"] == "yes" and r["state"] == "Reporting"]
        require = sc["require"]
        require_label = {"mfa": "MFA", "compliant": "compliant device",
                         "mfa_compliant": "MFA + compliant device"}.get(require)
        gap = ca_gap(def_en, def_rep, excl_pols, sc, require)

        # ---- render: applying table with reasons ---------------------------
        apply_rows = []
        for i, p in enumerate(applying):
            controls = []
            if p["mfa"]:
                controls.append("MFA")
            if p["compliant"]:
                controls.append("Compliant device")
            if p["block"]:
                controls.append("Block")
            if p["auth_strength"]:
                controls.append("Auth strength")
            why = _include_reason(p)
            controls_display = _policy_control_display(p) or ", ".join(controls) or "—"
            fields = {"polname": p["name"], "controls": controls_display,
                      "mfa": "Yes" if p["mfa"] else "—",
                      "compliant": "Yes" if p["compliant"] else "—",
                      "why": why}
            cells = (f'<td class="clickable" data-field="polName" data-value="{esc(p["name"])}">{esc(p["name"])}</td>'
                     f'<td>{esc(controls_display)}</td>'
                     f'<td>{esc("Yes" if p["mfa"] else "—")}</td>'
                     f'<td>{esc("Yes" if p["compliant"] else "—")}</td>'
                     f'<td class="muted">{esc(why)}</td>')
            apply_rows.append({
                "_html": (f'<tr data-policy-id="{esc(p["id"])}" data-detail-key="ca-apply-{i}">'
                          f'<td class="expand-cell">{EXPAND_BUTTON_HTML}</td>{cells}</tr>'
                          f'{drawer_for_html("ca-apply-" + str(i), 6)}'),
                "_text": " ".join(fields.values()).lower(),
                "fields": fields,
            })
        tables = [build_table("ca-apply-table", f"Policies applying to {target['upn']}",
                              [("Policy", "240px"), ("Controls", "150px"), ("MFA", "55px"),
                               ("Compliant", "80px"), ("Why", "220px")],
                              apply_rows, {"1": "polname", "2": "controls",
                                            "3": "mfa", "4": "compliant", "5": "why"})]

        # what-if table
        wi_rows = []
        for i, r in enumerate(whatif_rows):
            v = r["verdict"]
            verdict_label = {"yes": "Applies", "no": "Does not apply",
                             "signal": "Applies (signal-dependent)"}[v["applies"]]
            controls_display = _policy_control_display(r) or "—"
            fields = {"polname": r["name"], "state": r["state"],
                      "controls": controls_display, "effect": _effect(r),
                      "verdict": verdict_label, "note": v["note"] or ""}
            cells = (f'<td class="clickable" data-field="polName" data-value="{esc(r["name"])}">{esc(r["name"])}</td>'
                     f'<td>{esc(r["state"])}</td>'
                     f'<td>{esc(controls_display)}</td>'
                     f'<td>{esc(_effect(r))}</td>'
                     f'<td>{esc(verdict_label)}</td>'
                     f'<td class="muted">{esc(v["note"] or "—")}</td>')
            summary = (f'<table class="kv-table">'
                       f'<tr><th>Policy</th><td>{esc(r["name"])}</td></tr>'
                       f'<tr><th>State</th><td>{esc(r["state"])}</td></tr>'
                       f'<tr><th>Controls</th><td>{esc(controls_display)}</td></tr>'
                       f'<tr><th>Effect</th><td>{esc(_effect(r))}</td></tr>'
                       f'<tr><th>Verdict</th><td>{esc(verdict_label)}</td></tr>'
                       + (f'<tr><th>Signal note</th><td>{esc(v["note"])}</td></tr>' if v.get("note") else "")
                       + "</table>")
            drawer_body = (summary
                           + '<div class="detail-section"><h4>Dependent signals</h4>'
                           + signals_html(r) + "</div>")
            # The drawer is rendered server-side with the per-scenario summary
            # and the policy's dependent signals. Mark it prefilled so the
            # generic drawer loader does not clear it and replace it with the
            # policy profile.
            drawer = (f'<tr class="drawer" data-detail-for="ca-whatif-{i}" '
                      f'data-prefilled="1">'
                      f'<td colspan="7"><div class="drawer-body">{drawer_body}</div></td></tr>')
            wi_rows.append({
                "_html": (f'<tr data-policy-id="{esc(r["id"])}" data-detail-key="ca-whatif-{i}">'
                          f'<td class="expand-cell">{EXPAND_BUTTON_HTML}</td>{cells}</tr>'
                          f'{drawer}'),
                "_text": " ".join(fields.values()).lower(),
                "fields": fields,
            })
        wi_scenario = [x for x in [sc["require"] and f"require={require_label}",
                                   sc["platform"] and f"platform={sc['platform']}",
                                   sc["client_app"] and f"client={sc['client_app']}",
                                   sc["device_state"] and f"device={sc['device_state']}",
                                   sc["device_filter"] is not None
                                       and f"device-filter={sc['device_filter']}",
                                   sc["trusted_location"] is not None
                                       and f"trusted={sc['trusted_location']}",
                                   sc["signin_risk"] and f"signin-risk={sc['signin_risk']}",
                                   sc["user_risk"] and f"user-risk={sc['user_risk']}",
                                   sc["auth_flow"] and f"auth-flow={sc['auth_flow']}",
                                   sc["acr"] and f"acr={sc['acr']}",
                                   sc["app_id"] and f"resource={sc['app_id']}"] if x]
        gap_html = (f'<p class="sub"><b>Gap: {esc(gap[0])}</b> — {esc(gap[1])}</p>' if gap else
                    f'<p class="sub">Coverage holds: a definitive enabled policy'
                    f'{f" enforces {esc(require_label)}" if require_label else ""} in this scenario.</p>')
        tables.append(build_table(
            "ca-whatif-table", "What-if evaluation",
            [("Policy", "240px"), ("State", "90px"), ("Controls", "170px"),
             ("Effect", "70px"), ("Verdict", "150px"), ("Note", "240px")],
            wi_rows, {"1": "polname", "2": "state", "3": "controls",
                      "4": "effect", "5": "verdict", "6": "note"},
            subtitle=f'<p class="sub">Scenario: {esc(" · ".join(wi_scenario)) if wi_scenario else "unspecified (all signal-dependent axes flagged)"}</p>'
                     + gap_html))

        flags = []
        if not applying:
            flags.append("no CA policy applies")
        elif any(p["block"] for p in applying):
            flags.append("blocked by CA")
        else:
            if not any(p["mfa"] for p in applying):
                flags.append("no MFA policy")
            if not any(p["compliant"] for p in applying):
                flags.append("no compliant-device policy")
        if legacy_blockers and not any(
                _included_sim(p) and not _excluded_sim(p) for p in legacy_blockers):
            flags.append("outside legacy-auth block")
        if excl_pols:
            flags.append(f"excluded from {len(excl_pols)} policy(ies)")
        if gap:
            flags.append(f"what-if: {gap[0]}")
        elif require_label:
            flags.append(f"what-if: {require_label} enforced")
        summary_html = f"""
  <section data-category="configs">
    <h2>CA coverage analysis</h2>
    <div class="engine-card"><table class="kv-table">
      <tr><th>User</th><td>{esc(target['name'])} <span class="muted">({esc(target['upn'])})</span></td></tr>
      <tr><th>Enabled CA policies targeting user</th><td>{len(applying)}</td></tr>
      <tr><th>Block policies targeting user</th><td>{sum(1 for p in applying if p['block'])}</td></tr>
      <tr><th>MFA policies targeting user</th><td>{sum(1 for p in applying if p['mfa'])}</td></tr>
      <tr><th>Compliant-device policies targeting user</th><td>{sum(1 for p in applying if p['compliant'])}</td></tr>
      <tr><th>Exclusions</th><td>{len(excl_pols)}</td></tr>
      <tr><th>Required control</th><td>{esc(require_label or 'not specified')}</td></tr>
      <tr><th>Assessment</th><td>{esc(' · '.join(flags)) if flags else 'all coverage controls apply'}</td></tr>
    </table></div>
  </section>
"""
        if excl_pols:
            items = "".join(
                f'<li>{esc(p["name"])} <span class="muted">({esc(p["state"])} · '
                f'{esc(_exclude_reason(p))})</span></li>'
                for p in excl_pols)
            excl_html = (f'  <section data-category="configs"><h2>Policies excluding '
                         f'{esc(target["upn"])}</h2><ul class="profile-list">{items}</ul></section>')
        else:
            excl_html = ""
        sections_html = "".join(t["section"] for t in tables) + excl_html
        progress("render", f"{len(applying)} applying policy(ies), {len(excl_pols)} exclusion(s), "
                           f"{len(whatif_rows)} what-if evaluation(s)")
        return {"summary_html": summary_html, "sections_html": sections_html,
                "tables": tables}

    if compare_upns:
        if len(compare_upns) != 2:
            raise ValueError("compare mode requires exactly two user UPNs")
        sc = build_scenario(scenario)
        require = sc["require"]
        require_label = {"mfa": "MFA", "compliant": "compliant device",
                         "mfa_compliant": "MFA + compliant device"}.get(require)

        def resolve_upn(upn):
            needle = (upn or "").strip().lower()
            for uid, rec in data["users"].items():
                if (rec.get("upn") or "").strip().lower() == needle:
                    return uid, rec
            raise ValueError(f"user '{upn}' not found in the collected users")

        uid_a, rec_a = resolve_upn(compare_upns[0])
        uid_b, rec_b = resolve_upn(compare_upns[1])

        def resolve_assumed(names, table):
            ids, missing = [], []
            for raw in names:
                raw = (raw or "").strip()
                if not raw:
                    continue
                needle = raw.lower()
                hit = None
                for oid, label in table.items():
                    if oid.lower() == needle or (label or "").lower() == needle:
                        hit = oid
                        break
                if hit is None and table is data["roles"]:
                    for oid, template_id in data["role_template_by_oid"].items():
                        if (template_id or "").lower() == needle:
                            hit = oid
                            break
                if hit:
                    ids.append(hit)
                else:
                    missing.append(raw)
            return ids, missing

        def build_scope(uid, rec, assumed_groups, assumed_roles):
            assumed_gids, missing_g = resolve_assumed(assumed_groups, data["groups"])
            assumed_rids, missing_r = resolve_assumed(assumed_roles, data["roles"])
            if missing_g or missing_r:
                raise ValueError(
                    ("unresolved assumed group(s): " + ", ".join(missing_g) + " · "
                     if missing_g else "")
                    + ("unresolved assumed role(s): " + ", ".join(missing_r)
                       if missing_r else ""))
            user_roles = _user_role_ids(uid)
            user_groups = {gid for gid, members in data["group_member_user"].items()
                           if uid in members}
            referenced_gids = set()
            for p in policies:
                referenced_gids.update(p["inc_group_list"])
                referenced_gids.update(p["exc_group_list"])
            containing = _group_ancestors(user_groups | set(assumed_gids)) | {
                gid for gid in referenced_gids if uid in _expand_group(gid, group_memo)}
            all_groups = user_groups | set(assumed_gids)
            all_roles = user_roles | _role_ids_with_templates(assumed_rids)

            def included(p):
                if would_include(p, uid):
                    return True
                if any(g in containing for g in p["inc_group_list"]):
                    return True
                return any(r in all_roles for r in p["inc_role_list"])

            def excluded(p):
                if _excluded(p, uid):
                    return True
                if any(g in containing for g in p["exc_group_list"]):
                    return True
                return any(r in all_roles for r in p["exc_role_list"])

            return {"uid": uid, "upn": rec.get("upn") or uid,
                    "name": rec.get("name") or rec.get("upn") or uid,
                    "severity": sev_by_uid.get(uid, "Info"),
                    "containing": containing, "all_groups": all_groups,
                    "all_roles": all_roles, "included": included,
                    "excluded": excluded}

        scope_a = build_scope(uid_a, rec_a, assume_groups, assume_roles)
        scope_b = build_scope(uid_b, rec_b, assume_groups_b, assume_roles_b)
        status_labels = {"yes": "Applies", "no": "Does not apply",
                         "signal": "Signal-dependent",
                         "excluded": "Excluded", "not_targeted": "Not targeted"}

        def status_for(scope, p):
            if p["state"] == "Disabled":
                return "disabled", ""
            if not scope["included"](p):
                return "not_targeted", "not targeted by user scope"
            if scope["excluded"](p):
                return "excluded", "excluded by policy"
            verdict, note = condition_verdict(p, sc)
            return verdict, note or ""

        compare_rows = []
        for p in policies:
            if p["state"] == "Disabled":
                continue
            va, na = status_for(scope_a, p)
            vb, nb = status_for(scope_b, p)
            if va == "yes" and vb == "yes":
                category = "Shared"
            elif va == "yes":
                category = "Only A"
            elif vb == "yes":
                category = "Only B"
            elif va == "signal" or vb == "signal":
                category = "Signal-dependent"
            else:
                continue
            notes = []
            if na:
                notes.append("A: " + na)
            if nb:
                notes.append("B: " + nb)
            compare_rows.append({
                "p": p, "a": status_labels.get(va, va),
                "b": status_labels.get(vb, vb), "category": category,
                "notes": " · ".join(notes),
            })

        scenario_bits = []
        if require_label:
            scenario_bits.append("require=" + require_label)
        for key, label in (("platform", "platform"), ("client_app", "client"),
                           ("device_state", "device"), ("auth_flow", "auth-flow"),
                           ("signin_risk", "signin-risk"), ("user_risk", "user-risk"),
                           ("app_id", "resource"), ("acr", "acr")):
            if sc.get(key):
                scenario_bits.append(f"{label}={sc[key]}")
        if sc["device_filter"] is not None:
            scenario_bits.append(f"device-filter={sc['device_filter']}")
        if sc["trusted_location"] is not None:
            scenario_bits.append(f"trusted={sc['trusted_location']}")

        def compare_mark(status):
            if status == "Applies":
                return '<span class="badge badge-enabled" title="Applies">&#10003;</span>'
            if status == "Signal-dependent":
                return '<span class="muted" title="Signal-dependent">?</span>'
            if status == "Excluded":
                return '<span class="muted" title="Excluded">&#8212;</span>'
            if status == "Not targeted":
                return '<span class="muted" title="Not targeted">&#8212;</span>'
            return '<span class="muted" title="Does not apply">&#8212;</span>'

        compare_table_rows = []
        for i, r in enumerate(compare_rows):
            p = r["p"]
            key = f"ca-compare-{i}"
            controls_display = _policy_control_display(p) or "—"
            fields = {
                "polname": p["name"], "polstate": p["state"],
                "polcontrols": controls_display, "a": r["a"], "b": r["b"],
                "category": r["category"], "notes": r["notes"],
            }
            cells = (
                f'<td class="clickable" data-field="polName" data-value="{esc(p["name"])}">{esc(p["name"])}</td>'
                f'<td data-field="a" data-value="{esc(r["a"])}">{compare_mark(r["a"])}</td>'
                f'<td data-field="b" data-value="{esc(r["b"])}">{compare_mark(r["b"])}</td>'
                f'<td data-field="polState" data-value="{esc(p["state"])}">{esc(p["state"])}</td>'
                f'<td data-field="polControls" data-value="{esc(controls_display)}">{esc(controls_display)}</td>'
                f'<td data-field="category" data-value="{esc(r["category"])}">{esc(r["category"])}</td>'
                f'<td class="muted" data-field="notes" data-value="{esc(r["notes"])}">{esc(r["notes"] or "—")}</td>'
            )
            effect = "Block" if p["block"] else ("Grant" if p["controls"] else "Unknown")
            summary = (f'<table class="kv-table">'
                       f'<tr><th>Policy</th><td>{esc(p["name"])}</td></tr>'
                       f'<tr><th>State</th><td>{esc(p["state"])}</td></tr>'
                       f'<tr><th>Controls</th><td>{esc(controls_display)}</td></tr>'
                       f'<tr><th>Effect</th><td>{esc(effect)}</td></tr>'
                       f'<tr><th>{esc(scope_a["upn"])}</th><td>{esc(r["a"])}</td></tr>'
                       f'<tr><th>{esc(scope_b["upn"])}</th><td>{esc(r["b"])}</td></tr>'
                       + (f'<tr><th>Notes</th><td>{esc(r["notes"])}</td></tr>' if r["notes"] else "")
                       + "</table>")
            drawer_body = (summary
                           + '<div class="detail-section"><h4>Dependent signals</h4>'
                           + signals_html(p) + "</div>")
            # Server-rendered drawer with the per-user summary and the
            # policy's dependent signals; marked prefilled so the generic
            # policy profile loader leaves it alone.
            drawer = (f'<tr class="drawer" data-detail-for="{esc(key)}" '
                      f'data-prefilled="1">'
                      f'<td colspan="8"><div class="drawer-body">{drawer_body}</div></td></tr>')
            compare_table_rows.append({
                "_html": (f'<tr data-policy-id="{esc(p["id"])}" data-detail-key="{key}">'
                          f'<td class="expand-cell">{EXPAND_BUTTON_HTML}</td>{cells}</tr>'
                          f'{drawer}'),
                "_text": " ".join(fields.values()).lower(),
                "fields": fields,
            })

        table = build_table(
            "ca-compare-table", "CA user comparison",
            [("Policy", "240px"), (scope_a["upn"], "220px"),
             (scope_b["upn"], "220px"), ("State", "90px"),
             ("Controls", "170px"), ("Category", "130px"), ("Notes", "260px")],
            compare_table_rows,
            {"1": "polname", "2": "a", "3": "b", "4": "polstate",
             "5": "polcontrols", "6": "category", "7": "notes"},
            subtitle=f'<p class="sub">Scenario: '
                     f'{esc(" · ".join(scenario_bits)) if scenario_bits else "unspecified"}</p>')
        summary_html = ""
        progress("users", "comparison mode")
        progress("apps", "comparison mode")
        progress("legacy", "comparison mode")
        progress("exclusions", "comparison mode")
        progress("paths", "comparison mode")
        progress("render", f"{len(compare_rows)} policy comparison(s)")
        return {"summary_html": summary_html, "sections_html": table["section"],
                "tables": [table]}

    path_summary_rows = ""
    if path_records:
        gap_types = ", ".join(f"{k}: {v}" for k, v in sorted(path_gap_counts.items()))
        path_summary_rows = (
            f"<tr><th>Path audit population</th><td>{esc(roster_label)}</td></tr>"
            f"<tr><th>Path audit mode</th><td>{esc(path_mode)} · "
            f"active dims: {esc(', '.join(sorted(path_active)) or 'none')} · "
            f"scenarios/path: {path_max or 'none'} · "
            f"global scenario budget: {path_total_max or 'none'}"
            f"{' (reached)' if path_budget_exhausted else ''}</td></tr>"
            f"<tr><th>Paths evaluated</th><td>{len(path_records)}</td></tr>"
            f"<tr><th>Gap paths</th><td>{len(path_gap_records)} ({path_gap_users} user(s))</td></tr>"
            f"<tr><th>Path scenarios evaluated</th><td>{path_scenarios}</td></tr>"
            f"<tr><th>Gap type counts</th><td>{esc(gap_types or 'none')}</td></tr>"
        )

    summary_html = f"""
  <section data-category="configs">
    <h2>CA coverage analysis</h2>
    <div class="engine-card"><table class="kv-table">
      <tr><th>CA policies</th><td>{len(policies)} ({len(enabled)} enabled, {len(policies) - len(enabled)} report-only/disabled)</td></tr>
      {path_summary_rows}
    </table></div>
  </section>
"""
    progress("render", f"{len(zero_coverage) + len(no_mfa) + len(no_compliant) + len(report_only_bypass) + len(app_gaps) + len(legacy_gap) + len(excl_rows)} finding row(s)")
    return {"summary_html": summary_html, "sections_html": sections_html,
            "tables": tables}



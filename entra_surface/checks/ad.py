"""On-prem / Entra Connect sync checks."""
from __future__ import annotations

import json
from collections import defaultdict

from ..findings import is_privileged, make_finding, severity_rank
from ..graph import (
    app_owner_chain, compute_effective_group_membership, group_parents_index,
    json_list, json_safe_value, role_assignment_count_for_sp,
    sp_owner_details,
)
from ..policy import (
    policy_detail_inner, policy_detail_normalized, policy_state_from_record,
)
from ..roles import (
    compute_group_roles, direct_directory_roles_by_user,
    resolve_group_role_paths, role_rating_severity,
)
from ..util import parse_datetime


def check_ad_sync_users(ctx):
    """AD-synced user roster (only users carrying a targeting flag) plus realm meta.

    Flags: Privileged (dir role >= High per config, or owns privileged grants),
    Service account (svc-style UPN or resource account), No SID (synced but no
    AD SID). CA policy exclusions are carried as a per-user attribute. All
    findings are Info: targeting metadata, not scored exposures.
    """
    graph = ctx["graph"]
    role_sev = ctx["check_cfg"]["directory_roles"]
    resource_index, resource_names = ctx["resource_index"], ctx["resource_names"]

    def sev_rank_of(name):
        return severity_rank(role_sev.get(name, "Info"))

    def role_name(oid):
        rec = graph["directory_role"].get(oid)
        return rec.get("displayName") if rec else oid

    # ---- privileged user ids (>= High) ------------------------------------
    # Direct roles, plus roles inherited through direct/nested group
    # membership. AU-scoped and disabled roles never count (B-036 / B-009).
    privileged_ids = set()
    direct_user_roles = ctx.get("direct_user_roles")
    if direct_user_roles is None:
        direct_user_roles = direct_directory_roles_by_user(graph, role_sev)
    for uid, roles in direct_user_roles.items():
        if uid in graph["user"] and any(
                is_privileged(role_rating_severity(r)) for r in roles):
            privileged_ids.add(uid)
    group_roles = ctx.get("group_roles") or compute_group_roles(
        graph, ctx["check_cfg"])
    effective = (ctx.get("analysis_indexes") or {}).get("effective_membership") \
        or compute_effective_group_membership(graph)
    for gid, roles in group_roles.items():
        if not any(is_privileged(role_rating_severity(r)) for r in roles):
            continue
        for uid in effective["users_by_group"].get(gid, ()):
            if uid in graph["user"]:
                privileged_ids.add(uid)

    grants_by_sp = {}  # sp_oid -> [(permission, severity)]
    for ra in graph["role_assigns"]:
        if ra["principal_type"] != "ServicePrincipal":
            continue
        ri = resource_index.get(ra["resource_id"], {}).get(ra["app_role_id"])
        if ri:
            grants_by_sp.setdefault(ra["principal_id"], []).append(
                (ri["value"], ri["severity"]))
    priv_owner_ids = set()
    for app_oid in set(graph["app_owners"]) | set(graph.get("app_owner_sp") or {}):
        app = graph["app"].get(app_oid)
        if not app:
            continue
        if any(any(is_privileged(g[1]) for g in grants_by_sp.get(sp_oid, []))
               for sp_oid in graph["sp_by_appid"].get(app.get("appId"), [])):
            priv_owner_ids |= app_owner_chain(graph, app_oid)[1]
    for sp_oid in set(graph["sp_owners"]) | set(graph.get("sp_owner_sp") or {}):
        if any(is_privileged(g[1]) for g in grants_by_sp.get(sp_oid, [])):
            priv_owner_ids |= sp_owner_details(graph, sp_oid)[1]

    # ---- realm meta --------------------------------------------------------
    domains = set()
    sid_prefix = None
    synced_count = 0
    for uid, rec in graph["user"].items():
        if rec.get("dirSyncEnabled") not in (1, True):
            continue
        synced_count += 1
        dn = rec.get("onPremisesDistinguishedName") or ""
        dc_parts = [part.strip()[3:].strip() for part in dn.split(",") if part.strip()[:3].upper() == "DC="]
        if dc_parts:
            domains.add(".".join(dc_parts))  # DC components read left-to-right form the AD DNS realm
        sid = rec.get("onPremisesSecurityIdentifier") or ""
        if sid and not sid_prefix:
            dash = sid.rfind("-")
            if dash > 0:
                sid_prefix = sid[: dash + 1]
    dc_hosts = [rec.get("displayName") for rec in graph["device"].values()
                if rec.get("onPremisesSecurityIdentifier")]
    ctx["ad_realm"] = {
        "domain": ", ".join(sorted(domains)) or "unknown",
        "sid_prefix": sid_prefix or "",
        "synced_count": synced_count,
        "dc_hosts": sorted(d for d in dc_hosts if d),
    }

    # ---- CA policy exclusions (per-user attribute) -------------------------
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

    # ---- flagged roster -----------------------------------------------------
    def dn_parse(dn):
        cn, ou = "", []
        for part in (dn or "").split(","):
            part = part.strip()
            if part[:3].upper() == "CN=" and not cn:
                cn = part[3:].strip()
            elif part[:3].upper() == "OU=":
                ou.append(part[3:].strip())
        return cn, "/".join(ou)

    findings = []
    for uid, user in graph["user"].items():
        if user.get("dirSyncEnabled") not in (1, True):
            continue
        dn = user.get("onPremisesDistinguishedName") or ""
        sid = user.get("onPremisesSecurityIdentifier") or ""
        upn = user.get("userPrincipalName") or ""
        cn, ou = dn_parse(dn)

        tags = []
        if uid in privileged_ids or uid in priv_owner_ids:
            tags.append("Privileged")
        if not sid:
            tags.append("No SID")
        if user.get("isResourceAccount") in (1, True) or upn.lower().startswith(
                ("svc_", "svc-", "sa_", "bot_")):
            tags.append("Service account")
        if not tags:
            continue

        display = user.get("displayName") or upn or uid
        onp = parse_datetime(user.get("onPremisesPasswordChangeTimestamp"))
        pw_str = onp.strftime("%Y-%m-%d %H:%M") if onp else ""
        f = make_finding(
            check_id="ad_sync_users", category="ad", severity="Info",
            title=f"Synced user: {display}",
            evidence=(", ".join(tags) + f" · {dn or 'no DN'}" + (f" · sid {sid}" if sid else "")),
            remediation=("Hybrid note: apply MFA to synced accounts, enforce on-prem "
                         "credential hygiene, and treat synced privileged accounts as "
                         "high-value targets for overlay attacks."),
            primary_id=uid,
            object_ids={"user": {uid}},
            target={"type": "User", "name": display, "id": uid},
            status={"label": "Enabled" if user.get("accountEnabled") else "Disabled",
                    "enabled": bool(user.get("accountEnabled"))},
        )
        f["user_id"] = uid
        f["user_display"] = display
        f["user_upn"] = upn
        f["ad_cn"] = cn
        f["ad_dn"] = dn
        f["ad_ou"] = ou
        f["ad_sid"] = sid
        f["sid_rid"] = sid.rsplit("-", 1)[-1] if sid else ""
        f["pw_change"] = pw_str
        f["tags"] = tags
        f["ca_exclusions"] = sorted(ca_exclusions.get(uid, ()), key=lambda x: x["name"])
        findings.append(f)

    findings.sort(key=lambda f: (-len(f["tags"]), (f["user_display"] or "").lower()))
    return findings


def check_ad_sync_infra(ctx):
    """AD sync attack surface: ADSync groups, sync service principals, hybrid
    /legacy-auth policies, and Windows devices. All findings are Info."""
    graph = ctx["graph"]
    findings = []

    # --- ADSync groups ------------------------------------------------------
    effective = (ctx.get("analysis_indexes") or {}).get("effective_membership") \
        or compute_effective_group_membership(graph)
    for gid, rec in graph["group"].items():
        name = rec.get("displayName") or ""
        if "ADSync" not in name:
            continue
        members = sorted(graph["user"][uid].get("displayName") or uid
                         for uid in effective["users_by_group"].get(gid, set())
                         if uid in graph["user"])
        owners = sorted(graph["user"][uid].get("displayName") or uid
                        for uid in graph["group_owner_user"].get(gid, set())
                        if uid in graph["user"])
        parts = []
        parts.append("members: " + (", ".join(members) if members else "none recorded"))
        parts.append("owners: " + (", ".join(owners) if owners else "none recorded"))
        findings.append(make_finding(
            check_id="ad_sync_infra", category="ad", severity="Info",
            title=f"ADSync group: {name}",
            evidence="\n".join(parts),
            remediation=("Membership of ADSync* groups controls the sync engine "
                         "(admin/operator/password-set rights). Review members and owners."),
            primary_id=gid,
            object_ids={},
            target={"type": "Group", "name": name, "id": gid},
            status=None,
        ))

    # --- sync service principals ---------------------------------------------
    sync_prefixes = ("ConnectSyncProvisioning", "Office365DirectorySynchronizationService",
                     "Microsoft Entra AD Synchronization Service")
    sync_exact = {"Microsoft.Azure.SyncFabric"}
    for oid, rec in graph["sp"].items():
        name = rec.get("displayName") or ""
        if not (name.startswith(sync_prefixes) or name in sync_exact):
            continue
        dir_roles = [graph["directory_role"][r].get("displayName")
                     for r, sp_oid in graph["role_member_sp"] if sp_oid == oid and r in graph["directory_role"]]
        role_assign_count = role_assignment_count_for_sp(ctx, oid)
        pw = len(json_list(rec.get("passwordCredentials")))
        kc = len(json_list(rec.get("keyCredentials")))
        bits = []
        if dir_roles:
            bits.append("directory roles: " + ", ".join(sorted(d for d in dir_roles if d)))
        if role_assign_count:
            bits.append(f"{role_assign_count} app-role assignment(s)")
        if pw or kc:
            bits.append(f"{pw} password + {kc} key credential(s) present")
        if not bits:
            bits.append("no roles or credentials observed")
        findings.append(make_finding(
            check_id="ad_sync_infra", category="ad", severity="Info",
            title=f"Sync service principal: {name}",
            evidence="\n".join(bits),
            remediation=("The ADSync connector account and SyncFabric hold the keys to "
                         "the sync relationship — validate the connector credentials and "
                         "role assignments."),
            primary_id=oid,
            object_ids={"sp": {oid}},
            target={"type": "Service Principal", "name": name, "id": oid},
            status={"label": "Enabled" if rec.get("accountEnabled") else "Disabled",
                    "enabled": bool(rec.get("accountEnabled"))},
        ))
        findings[-1]["pw"] = pw
        findings[-1]["keys"] = kc
        findings[-1]["roles"] = role_assign_count

    # --- hybrid / legacy auth policies ----------------------------------------
    def legacy_auth_exposure(rec):
        """Only flag policies that actually enable legacy/on-prem auth.

        A policy named "Block legacy authentication" is a control, not an
        exposure. Type-8 On-Premise Authentication Flow policies only count
        when Desktop SSO is actually enabled (B-083).
        """
        name = rec.get("displayName") or ""
        inner = policy_detail_normalized(rec.get("policyDetail"))
        state = (str(inner.get("State") or "").strip() or "Unknown").lower()
        if state == "disabled":
            return None
        if rec.get("policyType") == 8 or "n-premise" in name.lower() \
                or "on-premise" in name.lower():
            sso = parse_desktop_sso(rec.get("policyDetail"))
            if not (sso and sso.get("enabled")):
                return None
            return f"policyType={rec.get('policyType')} · Desktop SSO enabled"
        if "legacy" in name.lower():
            controls = [str(c) for block in (inner.get("Controls") or [])
                        for c in (block.get("Control") or [])]
            if "block" in name.lower() or any(c.lower() == "block" for c in controls):
                return None
            return (f"policyType={rec.get('policyType')} · state={state} · "
                    f"controls={', '.join(controls) or 'none captured'}")
        return None

    for oid, rec in graph["policy"].items():
        name = rec.get("displayName") or ""
        detail = legacy_auth_exposure(rec)
        if not detail:
            continue
        findings.append(make_finding(
            check_id="ad_sync_infra", category="ad", severity="Info",
            title=f"Authentication policy: {name}",
            evidence=f"{detail} · policyIdentifier={rec.get('policyIdentifier') or 'n/a'}",
            remediation=("Hybrid sign-in / legacy-authentication policies widen the "
                         "on-prem attack surface; confirm they are required and enforced."),
            primary_id=oid,
            object_ids={},
            target={"type": "Policy", "name": name, "id": oid},
            status=None,
        ))

    # --- Windows devices --------------------------------------------------------
    for did, rec in graph["device"].items():
        name = rec.get("displayName") or did
        ostype = rec.get("deviceOSType") or ""
        hosts = json_list(rec.get("hostnames"))
        owner_ids = graph["device_owners"].get(did, set())
        owner_names = sorted(graph["user"][uid].get("displayName") or uid
                             for uid in owner_ids if uid in graph["user"])
        bits = []
        if ostype:
            bits.append(f"OS: {ostype}")
        if hosts:
            bits.append("hostnames: " + ", ".join(str(h) for h in hosts))
        if rec.get("onPremisesSecurityIdentifier"):
            bits.append("bound to AD/realm (domain SID present)")
        if rec.get("dirSyncEnabled") in (1, True):
            bits.append("dir-synced device")
        if owner_names:
            bits.append("owner(s): " + ", ".join(owner_names))
        else:
            bits.append("no owner recorded")
        device_label = ("Windows device" if ostype.lower().startswith("windows")
                        else f"{ostype or 'Registered'} device")
        findings.append(make_finding(
            check_id="ad_sync_infra", category="ad", severity="Info",
            title=f"{device_label}: {name}",
            evidence=" · ".join(bits),
            remediation=("Registered Windows hosts are candidates for overlay "
                         "(NTLM relay / spray) targeting; DC-bound devices include "
                         "the domain controllers."),
            primary_id=did,
            object_ids={"device": {did}, "user": set(owner_ids)},
            target={"type": "Device", "name": name, "id": did},
            status={"label": "Enabled" if rec.get("accountEnabled") else "Disabled",
                    "enabled": bool(rec.get("accountEnabled"))},
        ))

    findings.sort(key=lambda f: (f["target"]["name"] or "").lower())
    return findings


# ---- sync authentication mode (PHS / PTA / federation) markers -------------
# The EnforceCloudPasswordPolicyForPasswordSyncedUsers value only exists in
# tenants using Password Hash Sync; the PTA agent and ADFS surface as
# well-known first-party service principals. Template/name constants are
# stable across tenants (never user-controlled display text).
PASSWORD_RULE_SETTINGS_TEMPLATE_ID = "5cf42378-d67d-4f36-ba46-e8b86229381d"
PHS_ENFORCE_SETTING = "EnforceCloudPasswordPolicyForPasswordSyncedUsers"
PTA_AGENT_SP_NAMES = {"Microsoft Azure AD Connect Authentication Agent"}
FEDERATION_SP_NAMES = {"Active Directory Federation Services", "ADFS"}


def check_ad_sync_summary(ctx):
    """Assess which sync engine is in use and surface the dangerous channels.

    On-prem Entra Connect fingerprints: ADSync* system groups, the
    ConnectSyncProvisioning_<host>_<id> connector app (hostname embedded), the
    password-reset-service writeback channel, SyncFabric, the On-Premise
    Authentication Flow Policy (Desktop SSO). Cloud Sync is detectable only by
    absence of those markers, so the verdict is honest about confidence.
    """
    graph = ctx["graph"]
    findings = []

    synced = [uid for uid, rec in graph["user"].items()
              if rec.get("dirSyncEnabled") in (1, True)]
    immutable = sum(1 for uid in synced
                    if graph["user"][uid].get("immutableId"))
    sync_count = len(synced)

    adsync_groups = sorted(rec.get("displayName") for rec in graph["group"].values()
                           if "ADSync" in (rec.get("displayName") or ""))
    connectors = []
    for oid, rec in graph["sp"].items():
        name = rec.get("displayName") or ""
        if name.startswith("ConnectSyncProvisioning_"):
            parts = name.split("_")
            connectors.append({"name": name, "host": parts[1] if len(parts) > 2 else None})

    def resource_name(rid):
        rec = graph["sp"].get(rid)
        return rec.get("displayName") if rec else rid

    # writeback channel: connector's assignments on password-reset / sync resources
    writeback = {"count": 0, "resources": []}
    sync_role = None
    connector_ids = {oid for oid, rec in graph["sp"].items()
                     if (rec.get("displayName") or "").startswith("ConnectSyncProvisioning_")}
    for ra in graph["role_assigns"]:
        if ra["principal_id"] not in connector_ids:
            continue
        res = resource_name(ra["resource_id"])
        if "password reset" in (res or "").lower():
            writeback["count"] += 1
            if res not in writeback["resources"]:
                writeback["resources"].append(res)
        if "synchronization service" in (res or "").lower():
            sync_role = res

    sso = None
    for rec in graph["policy"].values():
        if rec.get("policyType") not in (8,) and "n-Premise" not in (rec.get("displayName") or ""):
            continue
        sso = parse_desktop_sso(rec.get("policyDetail"))
        if sso:
            break

    # ---- authentication mode: PHS / PTA / federation -----------------------
    # PHS is an on-prem connector setting with no direct Entra-side flag; the
    # only PHS-specific marker visible from collected data is the
    # EnforceCloudPasswordPolicyForPasswordSyncedUsers directory setting
    # (present solely in PHS tenants). Writeback alone only proves PHS or PTA.
    phs_present, phs_enforce = False, None
    for rec in graph.get("directory_settings", {}).values():
        if (rec.get("templateId") or "") != PASSWORD_RULE_SETTINGS_TEMPLATE_ID:
            continue
        for v in json_list(rec.get("values")):
            if isinstance(v, dict) and v.get("name") == PHS_ENFORCE_SETTING:
                phs_present = True
                phs_enforce = str(v.get("value") or "").lower() in ("true", "1")
    pta = any(rec.get("displayName") in PTA_AGENT_SP_NAMES
              for rec in graph["sp"].values())
    federated = any(rec.get("displayName") in FEDERATION_SP_NAMES
                    for rec in graph["sp"].values())

    sync_fabric = next((rec.get("displayName") for rec in graph["sp"].values()
                        if rec.get("displayName") == "Microsoft.Azure.SyncFabric"), None)
    o365_dir_sync = bool(next((rec for rec in graph["sp"].values()
                               if rec.get("displayName") == "Office365DirectorySynchronizationService"), None))

    onprem = bool(adsync_groups) or bool(connectors)
    if sync_count and onprem:
        verdict = "Microsoft Entra Connect (on-prem)"
    elif sync_count:
        verdict = "Likely Entra Cloud Sync"
    else:
        verdict = "Undetermined (no sync observed)"

    if phs_present:
        auth_mode = ("Password Hash Sync (PHS)"
                     + (" \u00b7 enforcing cloud password policy for synced users"
                        if phs_enforce else ""))
        auth_short = "PHS"
        auth_detail = (f"{PHS_ENFORCE_SETTING} = "
                       + ("True" if phs_enforce else "False"))
    elif pta:
        auth_mode = "Pass-through Authentication (PTA)"
        auth_short = "PTA"
        auth_detail = "PTA agent service principal present"
    elif federated:
        auth_mode = "Federated (ADFS)"
        auth_short = "Federated"
        auth_detail = "ADFS service principal present"
    elif onprem or writeback["count"]:
        auth_mode = "PHS or PTA"
        auth_short = "PHS / PTA"
        auth_detail = "(collected data does not distinguish PHS from PTA)"
    else:
        auth_mode = "Unknown"
        auth_short = ""
        auth_detail = "no sync observed"
    auth = {"mode": auth_mode, "short": auth_short, "detail": auth_detail,
            "phs_present": phs_present, "phs_enforce": phs_enforce,
            "pta": pta, "federated": federated}

    indicators = []
    indicators.append({
        "label": "Synchronized users", "present": sync_count > 0,
        "detail": f"{sync_count} dir-synced user(s), {immutable}/{sync_count} with immutableId" if sync_count else "no dirSync users",
    })
    indicators.append({
        "label": "ADSync* system groups", "present": bool(adsync_groups),
        "detail": ", ".join(adsync_groups) if adsync_groups else "none (cloud sync does not create these)",
    })
    host_txt = ""
    if connectors:
        hosts = sorted({c["host"] for c in connectors if c["host"]})
        host_txt = ", ".join(c["name"] for c in connectors) + (
            f" — connector host: {', '.join(hosts)}" if hosts else "")
    indicators.append({
        "label": "Entra Connect connector app", "present": bool(connectors),
        "detail": host_txt or "none observed",
    })
    wb_txt = (f"{writeback['count']} role assignment(s) on {', '.join(writeback['resources'])}"
              + (f" · ADSync role on {sync_role}" if sync_role else "")) if writeback["count"] else "not observed"
    indicators.append({
        "label": "Password writeback channel", "present": writeback["count"] > 0,
        "detail": wb_txt,
    })
    indicators.append({
        "label": "Authentication mode", "present": bool(auth_short),
        "detail": f"{auth_mode} \u2014 {auth_detail}",
    })
    indicators.append({
        "label": "SyncFabric sync identity", "present": bool(sync_fabric),
        "detail": sync_fabric or "not observed",
    })
    indicators.append({
        "label": "Office365 directory sync app", "present": o365_dir_sync,
        "detail": "present" if o365_dir_sync else "not observed",
    })
    if sso:
        sso_txt = (f"Desktop SSO enabled for {', '.join(sso['domains']) or 'unknown realm'}"
                   + (" · new SPNs auto-added" if sso["spns"] else ""))
        sso_txt += " (On-Premise Authentication Flow Policy, type 8)"
    else:
        sso_txt = "not observed"
    indicators.append({"label": "On-prem authentication flow (Desktop SSO)", "present": bool(sso), "detail": sso_txt})

    f = make_finding(
        check_id="ad_sync_summary", category="ad", severity="Info",
        title="Sync summary",
        evidence=verdict + " · " + " · ".join(
            f"{i['label']}: {i['detail']}" for i in indicators),
        remediation=("If the on-prem connector account is privileged in AD, the "
                     "password-writeback channel enables the classic ADSync account → "
                     "cloud-admin takeover; Desktop SSO widens the Kerberos overlay "
                     "surface. Validate the connector service account's AD-side "
                     "privileges and enforce MFA on hybrid sign-ins."),
        primary_id="sync-summary",
        object_ids={"sp": set(connector_ids)},
        target={"type": "Assessment", "name": "Sync summary", "id": "sync-summary"},
        status=None,
    )
    f["verdict"] = verdict
    f["connector_host"] = sorted({c["host"] for c in connectors if c["host"]})
    f["writeback"] = writeback
    f["auth_mode"] = auth
    f["desktop_sso"] = sso
    f["indicators"] = indicators
    f["sync_count"] = sync_count
    f["immutable_count"] = immutable
    findings.append(f)
    return findings


def parse_desktop_sso(policy_detail):
    """Decode the double-encoded policyDetail of the On-Premise Authentication Flow
    Policy: [\"{...OnPremAuthenticationFlowPolicy:{DesktopSSO:{...}}}\"]"""
    if not policy_detail:
        return None
    try:
        inner = policy_detail_inner(policy_detail)
        sso = ((inner or {}).get("OnPremAuthenticationFlowPolicy") or {}).get("DesktopSSO") or {}
        if not isinstance(sso, dict):
            return None
        enabled = str(sso.get("Enabled")).lower() in ("true", "1", "yes")
        if not enabled:
            return None  # disabled/empty policies are not "found" (B-085)
        domains = [s.get("Domain") for s in (sso.get("Secrets") or [])
                   if isinstance(s, dict) and s.get("Domain")]
        return {"enabled": True,
                "spns": bool(sso.get("AreNewSPNsAdded")),
                "domains": [d for d in domains if d]}
    except (json.JSONDecodeError, ValueError, TypeError, KeyError, IndexError):
        return None



"""Application and service-principal checks."""
from __future__ import annotations

import datetime
from collections import defaultdict

from ..findings import is_privileged, make_finding, severity_rank
from ..graph import (
    app_owner_chain, compute_effective_group_membership, is_foreign_sp,
    json_list, json_safe_value, role_assignment_count_for_sp,
    role_assignments_for_sp, sp_owner_details,
)
from ..roles import merge_role_entry, role_display_name, role_rating_severity


def build_resource_role_index(graph, config_resources):
    """
    Resolve each configured resource appId to the ServicePrincipal objectId(s)
    actually present in this tenant, and build {resourceObjectId: {appRoleId: role_info}}
    restricted to the privileged role values from the config.
    """
    index = {}  # resourceObjectId -> {appRoleId: {value, severity, reason, resourceName}}
    resource_display_names = {}
    for obj_id, rec in graph["sp"].items():
        cfg = config_resources.get(rec.get("appId"))
        if not cfg:
            continue
        resource_display_names[obj_id] = rec.get("displayName") or cfg["name"]
        role_map = {}
        for role in json_list(rec.get("appRoles")):
            value = role.get("value")
            info = cfg["roles"].get(value)
            if info:
                role_map[role["id"]] = {
                    "value": value,
                    "severity": info["severity"],
                    "reason": info["reason"],
                }
        # The SP appRoles column is frequently sparse; ApplicationRefs carries
        # the same catalog by appId. Merge it by role ID so grants resolve even
        # when the service principal row lacks its app-role list (B-011).
        for role_id, entry in (graph.get("appref_roles") or {}).get(rec.get("appId"), {}).items():
            if role_id in role_map:
                continue
            value = entry.get("value") or role_id
            info = cfg["roles"].get(value)
            if info:
                role_map[role_id] = {
                    "value": value,
                    "severity": info["severity"],
                    "reason": info["reason"],
                }
        if role_map:
            index[obj_id] = role_map
    return index, resource_display_names


def app_role_grant_severity(graph, resource_index):
    """Highest configured app-role permission severity per service principal.

    Only permissions present in `resource_index` (the Critical/High entries in
    the config) are considered. The result drives the rating of findings that
    describe a credential or a foreign principal: those checks should inherit
    the underlying grant severity instead of hardcoding Critical.
    """
    out = {}
    for ra in graph["role_assigns"]:
        if ra["principal_type"] != "ServicePrincipal":
            continue
        role_info = (resource_index.get(ra["resource_id"]) or {}).get(ra["app_role_id"])
        if not role_info:
            continue
        current = out.get(ra["principal_id"], "Info")
        if severity_rank(role_info["severity"]) < severity_rank(current):
            out[ra["principal_id"]] = role_info["severity"]
    return out


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------



def sp_display_name(rec):
    return rec.get("displayName") or rec.get("appDisplayName") or rec.get("objectId")


def check_priv_app_ownership(ctx):
    """Legacy audit, reimplemented on the entity graph. Output shape unchanged.

    Covers two kinds of privilege: privileged app-role (application permission)
    grants from the resources config, and privileged directory roles held by
    service principals (directly or through group membership)."""
    graph, resource_index, resource_names = ctx["graph"], ctx["resource_index"], ctx["resource_names"]
    include_disabled = ctx["include_disabled"]

    matches = []  # (principal_id, resource_id, role_info)
    for ra in graph["role_assigns"]:
        if ra["principal_type"] != "ServicePrincipal":
            continue
        role_info = resource_index.get(ra["resource_id"], {}).get(ra["app_role_id"])
        if role_info:
            matches.append((ra["principal_id"], ra["resource_id"], role_info))

    findings = []

    def emit_finding(sp, principal_id, severity, title_prefix, permission,
                     resource_label, reason, evidence):
        app_entries = graph["app_by_appid"].get(sp.get("appId"), [])
        owner_ids = set()
        owner_sp_ids = set()
        display_name = sp_display_name(sp)
        app_object_id = None
        if app_entries:
            app_object_id = app_entries[0]
            display_name = graph["app"][app_object_id].get("displayName") or display_name
            app_owner_sps, app_owner_users = app_owner_chain(graph, app_object_id)
            owner_sp_ids |= app_owner_sps
            owner_ids |= app_owner_users
        sp_owner_sps, sp_owner_users = sp_owner_details(graph, principal_id)
        owner_sp_ids |= sp_owner_sps
        owner_ids |= sp_owner_users

        owners = [graph["user"][u] for u in owner_ids if u in graph["user"]]
        owner_sps = [graph["sp"][s] for s in owner_sp_ids if s in graph["sp"]]
        has_owner = bool(owners or owner_sps)

        findings.append(make_finding(
            check_id="priv_app_ownership", category="apps",
            severity=severity,
            title=f"{title_prefix} with owner" if has_owner else f"{title_prefix} with no owner",
            evidence=evidence,
            remediation=("Assign an accountable owner or remove the privileged grant." if not has_owner
                         else "Verify the privilege is still required by the nominated owner."),
            primary_id=principal_id,
            object_ids={
                "sp": {principal_id},
                "app": {app_object_id} if app_object_id else set(),
                "user": {o["objectId"] for o in owners},
            },
            target={"type": "Application / SP", "name": display_name, "id": principal_id},
            status={"label": "Enabled" if sp.get("accountEnabled") else "Disabled",
                    "enabled": bool(sp.get("accountEnabled"))},
        ))
        finding = findings[-1]
        # Legacy fields consumed by the dedicated report section renderer.
        finding["principal_id"] = principal_id
        finding["sp_display_name"] = sp.get("displayName")
        finding["sp_enabled"] = bool(sp.get("accountEnabled"))
        finding["app_object_id"] = app_object_id
        finding["display_name"] = display_name
        pw = len(json_list(sp.get("passwordCredentials")))
        kc = len(json_list(sp.get("keyCredentials")))
        if app_object_id:
            app_rec = graph["app"].get(app_object_id)
            if app_rec:
                pw += len(json_list(app_rec.get("passwordCredentials")))
                kc += len(json_list(app_rec.get("keyCredentials")))
        finding["pw"] = pw
        finding["keys"] = kc
        finding["is_foreign"] = is_foreign_sp(graph, sp)
        finding["resource_name"] = resource_label
        finding["permission"] = permission
        finding["reason"] = reason
        finding["owners"] = [
            {
                "object_id": o["objectId"],
                "display_name": o.get("displayName"),
                "upn": o.get("userPrincipalName"),
                "user_type": o.get("userType") or "Member",
                "enabled": bool(o.get("accountEnabled")),
            }
            for o in owners
        ] + [
            {
                "object_id": s.get("objectId"),
                "display_name": sp_display_name(s),
                "upn": "",
                "user_type": "ServicePrincipal",
                "enabled": bool(s.get("accountEnabled")),
            }
            for s in owner_sps
        ]
        finding["owner_sps"] = sorted(
            ({"object_id": s.get("objectId"), "display_name": sp_display_name(s)}
             for s in owner_sps), key=lambda x: (x["display_name"] or "").lower())

    for principal_id, resource_id, role_info in matches:
        sp = graph["sp"].get(principal_id)
        if not sp:
            continue
        if not include_disabled and (not sp.get("accountEnabled") or sp.get("deletionTimestamp")):
            continue
        emit_finding(sp, principal_id, role_info["severity"],
                     "Privileged application permission",
                     role_info["value"],
                     resource_names.get(resource_id, resource_id),
                     role_info.get("reason", ""),
                     role_info["reason"])

    # SPs holding privileged (Critical/High) directory roles, directly or
    # through group membership — same ownership question as app-role grants.
    # PIM-eligible roles are marker-only and never create ownership findings.
    resolve_sp = ctx["sp_dir_resolver"]
    for principal_id in sorted(graph["sp"]):
        sp = graph["sp"][principal_id]
        roles = [r for r in resolve_sp(principal_id)
                 if not r.get("eligible") and is_privileged(role_rating_severity(r))]
        if not roles:
            continue
        if not include_disabled and (not sp.get("accountEnabled") or sp.get("deletionTimestamp")):
            continue
        severity = min((role_rating_severity(r) for r in roles), key=severity_rank)
        details = [role_display_name(r) + ("" if r["path"] is None
                                           else f" (via {' \u2192 '.join(r['path'])})")
                   for r in roles]
        emit_finding(sp, principal_id, severity,
                     "Privileged directory role",
                     ", ".join(r["name"] for r in roles),
                     "Directory role",
                     " \u00b7 ".join(details),
                     "Directory role: " + " \u00b7 ".join(details))

    findings.sort(key=lambda f: (severity_rank(f["severity"]), f["display_name"] or ""))
    return findings


MICROSOFT_TENANT_ID = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"

_SSO_MODE_LABELS = {
    "saml": "SAML",
    "wsfed": "WS-Fed",
    "ws-federation": "WS-Fed",
    "password": "Password",
    "linked": "Linked",
    "oidc": "OIDC",
    "openidconnect": "OIDC",
}

_SIGN_IN_AUDIENCE_LABELS = {
    "AzureADMyOrg": "Single-tenant",
    "AzureADMultipleOrgs": "Multitenant",
    "AzureADandPersonalMicrosoftAccount": "Multitenant + personal",
    "PersonalMicrosoftAccount": "Personal",
}


def _sso_parse_datetime(value):
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _sso_certificate(rec):
    """Return (end_date, days_left, thumbprint) for the preferred signing cert."""
    end = rec.get("preferredTokenSigningKeyEndDateTime")
    thumb = str(rec.get("preferredTokenSigningKeyThumbprint") or "")
    keys = [k for k in json_list(rec.get("keyCredentials")) if isinstance(k, dict)]
    if not end:
        candidates = []
        for key in keys:
            if not key.get("endDateTime"):
                continue
            usage = str(key.get("usage") or "").lower()
            if usage and "sign" not in usage:
                continue
            candidates.append(key)
        if candidates:
            matching = [k for k in candidates
                        if thumb and str(k.get("thumbprint") or "") == thumb]
            chosen = max(matching or candidates,
                         key=lambda k: str(k.get("endDateTime") or ""))
            end = chosen.get("endDateTime")
            thumb = thumb or str(chosen.get("thumbprint") or "")
    if not end:
        return "", None, thumb
    dt = _sso_parse_datetime(end)
    if dt is None:
        return str(end)[:10], None, thumb
    days = (dt - datetime.datetime.now(datetime.timezone.utc)).days
    return dt.date().isoformat(), days, thumb


def _sso_protocol(rec, app_rec, tags):
    label = _SSO_MODE_LABELS.get(
        str(rec.get("preferredSingleSignOnMode") or "").strip().lower(), "")
    if label:
        return label
    if rec.get("samlMetadataUrl") or rec.get("samlSingleSignOnSettings"):
        return "SAML"
    if json_list(rec.get("replyUrls")):
        return "OIDC"
    if app_rec and json_list(app_rec.get("replyUrls")):
        return "OIDC"
    return "Not configured"


def _sso_owner_dicts(graph, owner_ids, owner_sp_ids=()):
    out = []
    for uid in sorted(owner_ids):
        rec = graph["user"].get(uid)
        if not rec:
            continue
        out.append({
            "object_id": uid,
            "display_name": rec.get("displayName") or "",
            "upn": rec.get("userPrincipalName") or "",
            "enabled": bool(rec.get("accountEnabled")),
            "source": ("AD" if rec.get("dirSyncEnabled") in (1, True)
                       else "Cloud"),
            "ad_dn": rec.get("onPremisesDistinguishedName") or "",
            "ad_sid": rec.get("onPremisesSecurityIdentifier") or "",
            "immutable_id": rec.get("immutableId") or "",
        })
    for sid in sorted(owner_sp_ids):
        rec = graph["sp"].get(sid)
        if not rec:
            continue
        out.append({
            "object_id": sid,
            "display_name": sp_display_name(rec) or "",
            "upn": "",
            "enabled": bool(rec.get("accountEnabled")),
            "source": "ServicePrincipal",
            "ad_dn": "", "ad_sid": "", "immutable_id": "",
        })
    return out


def check_enterprise_apps(ctx):
    """SSO-focused enterprise application inventory.

    One row per user-facing application service principal (managed identities
    and social identity providers are excluded). An app is included when it has
    at least one SSO signal: an SSO mode, SAML metadata, reply URLs, user/group
    assignments, or the enterprise-app gallery marker. Microsoft first-party
    apps are included only when they have a local registration or explicit
    user/group assignments. Columns cover the SSO protocol, publisher trust,
    sign-in audience, assignment posture, effective assigned users,
    signing-certificate expiry and ownership.
    """
    graph = ctx["graph"]
    include_disabled = ctx["include_disabled"]
    tenant_id = (graph.get("tenant") or {}).get("object_id") or ""
    indexes = ctx.get("analysis_indexes") or {}
    users_by_group = ((indexes.get("effective_membership") or {})
                      .get("users_by_group") or {})
    if not users_by_group:
        users_by_group = compute_effective_group_membership(graph)["users_by_group"]

    assigns_by_resource = defaultdict(list)
    for ra in graph.get("role_assigns") or []:
        resource_id = ra.get("resource_id")
        if resource_id:
            assigns_by_resource[resource_id].append(ra)

    def principal_kind(ra):
        pid = ra.get("principal_id") or ""
        if pid in graph["user"]:
            return "User"
        if pid in graph["group"]:
            return "Group"
        if pid in graph["sp"]:
            return "ServicePrincipal"
        return ra.get("principal_type") or ""

    findings = []
    for sp_oid, rec in graph["sp"].items():
        if rec.get("servicePrincipalType") != "Application":
            continue
        enabled = bool(rec.get("accountEnabled")) and not rec.get("deletionTimestamp")
        if not include_disabled and not enabled:
            continue
        app_oids = sorted(graph["app_by_appid"].get(rec.get("appId"), []))
        app_rec = graph["app"].get(app_oids[0]) if app_oids else {}
        tags = [str(t) for t in json_list(rec.get("tags")) if t]
        owner_tenant = str(rec.get("appOwnerTenantId") or "")
        first_party = (bool(rec.get("microsoftFirstParty"))
                       or owner_tenant == MICROSOFT_TENANT_ID)
        gallery = "WindowsAzureActiveDirectoryIntegratedApp" in tags

        users, groups, sps = set(), set(), set()
        for ra in assigns_by_resource.get(sp_oid, ()):
            kind = principal_kind(ra)
            pid = ra.get("principal_id") or ""
            if not pid:
                continue
            if kind == "User":
                users.add(pid)
            elif kind == "Group":
                groups.add(pid)
            elif kind == "ServicePrincipal":
                sps.add(pid)
        effective_users = set(users)
        for gid in groups:
            effective_users |= set(users_by_group.get(gid) or ())
        has_people = bool(users or groups)

        sp_replies = json_list(rec.get("replyUrls"))
        app_replies = json_list((app_rec or {}).get("replyUrls"))
        mode = str(rec.get("preferredSingleSignOnMode") or "").strip()
        samt = bool(rec.get("samlMetadataUrl") or rec.get("samlSingleSignOnSettings"))
        sso_signal = bool(mode or samt or sp_replies or app_replies
                          or has_people or gallery)
        if first_party and not (app_oids or has_people):
            continue
        if not sso_signal:
            continue

        protocol = _sso_protocol(rec, app_rec, tags)
        audit = str((app_rec or {}).get("signInAudience") or "").strip()
        audience = _SIGN_IN_AUDIENCE_LABELS.get(audit, "")
        if not audience and app_oids and (
                not owner_tenant or (tenant_id and owner_tenant == tenant_id)):
            audience = "Single-tenant"
        if first_party:
            home_tenant = "Microsoft"
        elif owner_tenant and tenant_id and owner_tenant == tenant_id:
            home_tenant = "This tenant"
        elif owner_tenant:
            home_tenant = "External"
        else:
            home_tenant = ""

        verified_publisher = json_safe_value(rec.get("verifiedPublisher"))
        if not isinstance(verified_publisher, dict):
            verified_publisher = {}
        if not verified_publisher and app_rec:
            verified_publisher = json_safe_value(app_rec.get("verifiedPublisher"))
            if not isinstance(verified_publisher, dict):
                verified_publisher = {}
        verified = bool(verified_publisher.get("displayName")
                        or rec.get("certification")
                        or (app_rec or {}).get("certification"))
        publisher = verified_publisher.get("displayName") or ""
        is_local_app = bool(app_oids) and (
            not owner_tenant or (tenant_id and owner_tenant == tenant_id))
        if not publisher and not is_local_app:
            publisher = (rec.get("publisherName")
                         or (app_rec or {}).get("publisherName") or "")
        if not publisher and first_party:
            publisher = "Microsoft"

        cert_end, cert_days, cert_thumb = _sso_certificate(rec)
        notifications = [str(x) for x in json_list(
            rec.get("notificationEmailAddresses")) if x]
        replies = [str(x) for x in (sp_replies or app_replies) if x]

        assignment_required = bool(rec.get("appRoleAssignmentRequired"))
        if not assignment_required and not has_people:
            assigned_label = "Default access"
        elif not has_people:
            assigned_label = ""
        else:
            assigned_parts = []
            if effective_users:
                assigned_parts.append(f"{len(effective_users)} user(s)")
            if groups:
                assigned_parts.append(f"{len(groups)} group(s)")
            assigned_label = " · ".join(assigned_parts)

        owner_ids, owner_sp_ids = set(), set()
        sp_sps, sp_users = sp_owner_details(graph, sp_oid)
        owner_sp_ids |= set(sp_sps)
        owner_ids |= set(sp_users)
        for app_oid in app_oids:
            app_sps, app_users = app_owner_chain(graph, app_oid)
            owner_sp_ids |= set(app_sps)
            owner_ids |= set(app_users)
        owners = _sso_owner_dicts(graph, owner_ids, owner_sp_ids)

        bits = [protocol]
        if audience:
            bits.append(audience)
        if publisher:
            bits.append(publisher + (" (verified)" if verified else ""))
        bits.append("assignment required" if assignment_required
                    else "assignment not required")
        if has_people:
            bits.append(f"{len(effective_users)} assigned user(s), "
                        f"{len(groups)} group(s)")
        if cert_end:
            bits.append("signing cert " + cert_end
                        + (f" ({cert_days}d)" if cert_days is not None else ""))
        if replies:
            bits.append(f"{len(replies)} reply URL(s)")

        f = make_finding(
            check_id="enterprise_apps", category="apps", severity="Info",
            title=f"Enterprise app: {rec.get('displayName') or sp_oid}",
            evidence=" · ".join(bits),
            remediation=("Confirm the application is still required, review its "
                         "assignment policy, signing certificate, publisher and owner, "
                         "and remove unused assignments."),
            primary_id=sp_oid,
            object_ids={"sp": {sp_oid}, "app": set(app_oids), "user": owner_ids},
            target={"type": "Service Principal",
                    "name": rec.get("displayName") or sp_oid, "id": sp_oid},
            status={"label": "Enabled" if enabled else "Disabled",
                    "enabled": enabled},
        )
        f["display_name"] = rec.get("displayName") or sp_oid
        f["sp_id"] = sp_oid
        f["app_object_id"] = app_oids[0] if app_oids else ""
        f["app_id"] = rec.get("appId") or ""
        f["sso_mode"] = mode
        f["sso_protocol"] = protocol
        f["sso_publisher"] = publisher
        f["sso_verified"] = verified
        f["sso_audience"] = audience
        f["sso_home_tenant"] = home_tenant
        f["sso_home_tenant_id"] = owner_tenant
        f["sso_assignment_required"] = assignment_required
        f["sso_assigned_user_count"] = len(effective_users)
        f["sso_assigned_direct_users"] = len(users)
        f["sso_assigned_groups"] = len(groups)
        f["sso_assigned_sps"] = len(sps)
        f["sso_assigned_label"] = assigned_label
        f["sso_cert_end"] = cert_end
        f["sso_cert_days"] = cert_days
        f["sso_cert_thumbprint"] = cert_thumb
        f["sso_notification_emails"] = notifications
        f["sso_reply_urls"] = replies
        f["sso_gallery"] = gallery
        f["sso_first_party"] = first_party
        f["owners"] = owners
        findings.append(f)

    findings.sort(key=lambda f: ((f.get("display_name") or "").lower(),
                                 f.get("primary_id") or ""))
    return findings


def check_no_role_approval(ctx):
    graph, include_disabled = ctx["graph"], ctx["include_disabled"]
    priv_ids = ctx["priv_sp_ids"]
    findings = []
    for oid, rec in graph["sp"].items():
        if rec.get("servicePrincipalType") != "Application":
            continue
        if rec.get("microsoftFirstParty"):
            continue
        if rec.get("appRoleAssignmentRequired") != 0:
            continue
        if not include_disabled and (not rec.get("accountEnabled") or rec.get("deletionTimestamp")):
            continue
        has_priv = oid in priv_ids
        role_count = role_assignment_count_for_sp(ctx, oid)
        evidence = (
            "appRoleAssignmentRequired=false — the app does not enforce explicit role "
            "assignments; whether a default user gains access depends on the application's own "
            f"authorization logic · {role_count} app-role assignment(s)"
        )
        if has_priv:
            evidence += " · note: this service principal holds privileged app-role assignments"
        findings.append(make_finding(
            check_id="no_role_approval", category="apps",
            severity="Info",
            title=f"Role assignments not required: {sp_display_name(rec)}",
            evidence=evidence,
            remediation=("Enable appRoleAssignmentRequired on the client and explicitly assign "
                         "only the roles it needs. Until then, treat the app as a candidate to "
                         "test: obtain a token as a standard user and verify what the APIs expose."),
            primary_id=oid,
            object_ids={"sp": {oid}, "app": set(graph["app_by_appid"].get(rec.get("appId"), []))},
            target={"type": "Service Principal", "name": sp_display_name(rec), "id": oid},
            status={"label": "Enabled" if rec.get("accountEnabled") else "Disabled",
                    "enabled": bool(rec.get("accountEnabled"))},
        ))
        findings[-1]["pw"] = len(json_list(rec.get("passwordCredentials")))
        findings[-1]["keys"] = len(json_list(rec.get("keyCredentials")))
        findings[-1]["roles"] = role_count
    findings.sort(key=lambda f: (severity_rank(f["severity"]), (f["target"]["name"] or "").lower()))
    return findings


def check_public_client_privileged(ctx):
    graph = ctx["graph"]
    priv_ids = ctx["priv_sp_ids"]
    findings = []
    for oid, rec in graph["app"].items():
        if rec.get("publicClient") != 1:
            continue
        sp_oids = graph["sp_by_appid"].get(rec.get("appId"), [])
        has_priv = any(o in priv_ids for o in sp_oids)
        if not has_priv:
            continue
        role_count = sum(role_assignment_count_for_sp(ctx, o) for o in sp_oids)
        findings.append(make_finding(
            check_id="public_client_privileged", category="apps",
            severity="High",
            title=f"Public client with privileged roles: {rec.get('displayName') or oid}",
            evidence=("publicClient=true — the client cannot keep secrets, and its service "
                      "principal holds privileged app-role assignments"),
            remediation=("Treat public clients as untrusted: remove the privileged app-role "
                         "assignments, or move the privileged identity to a confidential client."),
            primary_id=oid,
            object_ids={"app": {oid}, "sp": set(sp_oids)},
            target={"type": "Application", "name": rec.get("displayName") or oid, "id": oid},
            status=None,
        ))
        findings[-1]["pw"] = len(json_list(rec.get("passwordCredentials")))
        findings[-1]["keys"] = len(json_list(rec.get("keyCredentials")))
        findings[-1]["roles"] = role_count
    findings.sort(key=lambda f: (severity_rank(f["severity"]), (f["target"]["name"] or "").lower()))
    return findings


def check_foreign_principal(ctx):
    graph, include_disabled = ctx["graph"], ctx["include_disabled"]
    priv_ids = ctx["priv_sp_ids"]
    grant_sev = app_role_grant_severity(graph, ctx["resource_index"])
    findings = []
    for oid, rec in graph["sp"].items():
        if oid not in priv_ids:
            continue
        if not is_foreign_sp(graph, rec):
            continue
        if not include_disabled and (not rec.get("accountEnabled") or rec.get("deletionTimestamp")):
            continue
        owner_tid = rec.get("appOwnerTenantId") or ""
        reasons = []
        for ra in role_assignments_for_sp(ctx, oid):
            ra_info = ctx["resource_index"].get(ra["resource_id"], {}).get(ra["app_role_id"])
            if ra_info:
                reasons.append(ra_info["reason"])
        role_count = role_assignment_count_for_sp(ctx, oid)
        findings.append(make_finding(
            check_id="foreign_principal", category="apps",
            severity=grant_sev.get(oid, "High"),
            title=f"Foreign privileged principal: {sp_display_name(rec)}",
            evidence=(f"appOwnerTenantId={owner_tid} · no local Application registration"
                      + (f"\n\nEvidence: {'; '.join(dict.fromkeys(reasons))}" if reasons else "")),
            remediation=("Review the cross-tenant trust relationship: confirm the owning "
                         "tenant is trusted and the grants are still required, then register "
                         "the app locally or revoke the assignments."),
            primary_id=oid,
            object_ids={"sp": {oid}},
            target={"type": "Service Principal", "name": sp_display_name(rec), "id": oid},
            status={"label": "Enabled" if rec.get("accountEnabled") else "Disabled",
                    "enabled": bool(rec.get("accountEnabled"))},
        ))
        findings[-1]["pw"] = len(json_list(rec.get("passwordCredentials")))
        findings[-1]["keys"] = len(json_list(rec.get("keyCredentials")))
        findings[-1]["roles"] = role_count
    findings.sort(key=lambda f: (severity_rank(f["severity"]), (f["target"]["name"] or "").lower()))
    return findings


def check_app_directory_roles(ctx):
    """One row per service principal holding directory roles — assigned directly
    or inherited through group membership (incl. nesting). Rated by the most
    critical active directory role per the 'directory_roles' config (unrated =
    Info); PIM-eligible roles are marker-only and never raise the rating."""
    graph = ctx["graph"]
    role_sev = ctx["check_cfg"]["directory_roles"]
    resolve_sp = ctx["sp_dir_resolver"]
    findings = []
    for sp_oid in sorted(graph["sp"]):
        rec = graph["sp"][sp_oid]
        roles = resolve_sp(sp_oid)
        if not roles:
            continue
        active = [r for r in roles if not r.get("eligible")]
        severity = min((role_rating_severity(r) for r in active),
                       key=severity_rank) if active else "Info"
        parts = [role_display_name(r) + (" (PIM eligible)" if r.get("eligible") else "")
                 + ("" if r["path"] is None
                    else f" (via {' \u2192 '.join(r['path'])})")
                 for r in roles]
        f = make_finding(
            check_id="app_dir_roles", category="apps",
            severity=severity,
            title=f"Application with directory roles: {sp_display_name(rec)}",
            evidence=" \u00b7 ".join(parts),
            remediation=("Review whether this application still needs its directory "
                         "roles; prefer least-privilege alternatives, an accountable "
                         "owner, and rotating credentials."),
            primary_id=sp_oid,
            object_ids={"sp": {sp_oid}},
            target={"type": "Service Principal", "name": sp_display_name(rec), "id": sp_oid},
            status={"label": "Enabled" if rec.get("accountEnabled") else "Disabled",
                    "enabled": bool(rec.get("accountEnabled"))},
        )
        f["dir_role_tags"] = roles
        f["sp_id"] = sp_oid
        findings.append(f)
    findings.sort(key=lambda f: (severity_rank(f["severity"]),
                                 (f["target"]["name"] or "").lower()))
    return findings


def check_app_inventory(ctx):
    """Exhaustive application / service-principal roster.

    One row per service principal, plus any application registration that has
    no local service principal (a registration is otherwise represented by its
    linked SP). Privileges are seeded from configured app-role grants and then
    raised by the shared directory-role pass; everything else stays Info.
    """
    graph = ctx["graph"]
    resource_index = ctx["resource_index"]
    findings = []

    grant_sev = {}
    grant_count = defaultdict(int)
    assignment_count = defaultdict(int)
    for ra in graph["role_assigns"]:
        if ra["principal_type"] != "ServicePrincipal":
            continue
        assignment_count[ra["principal_id"]] += 1
        role_info = (resource_index.get(ra["resource_id"]) or {}).get(ra["app_role_id"])
        if not role_info:
            continue
        grant_count[ra["principal_id"]] += 1
        current = grant_sev.get(ra["principal_id"], "Info")
        if severity_rank(role_info["severity"]) < severity_rank(current):
            grant_sev[ra["principal_id"]] = role_info["severity"]

    def owner_dicts(owner_ids, owner_sp_ids=()):
        out = []
        for uid in sorted(owner_ids):
            rec = graph["user"].get(uid)
            if not rec:
                continue
            out.append({
                "object_id": uid,
                "display_name": rec.get("displayName") or "",
                "upn": rec.get("userPrincipalName") or "",
                "enabled": bool(rec.get("accountEnabled")),
                "source": ("AD" if rec.get("dirSyncEnabled") in (1, True)
                           else "Cloud"),
                "ad_dn": rec.get("onPremisesDistinguishedName") or "",
                "ad_sid": rec.get("onPremisesSecurityIdentifier") or "",
                "immutable_id": rec.get("immutableId") or "",
            })
        for sid in sorted(owner_sp_ids):
            rec = graph["sp"].get(sid)
            if not rec:
                continue
            out.append({
                "object_id": sid,
                "display_name": sp_display_name(rec),
                "upn": "",
                "enabled": bool(rec.get("accountEnabled")),
                "source": "ServicePrincipal",
                "ad_dn": "", "ad_sid": "", "immutable_id": "",
            })
        return out

    def emit(name, object_type, oid, sp_oids, app_oids, app_id, sp_type,
             pw, kc, role_count, severity, status, extra=""):
        owner_ids = set()
        owner_sp_ids = set()
        for sp_oid in sp_oids:
            sp_sps, sp_users = sp_owner_details(graph, sp_oid)
            owner_sp_ids |= sp_sps
            owner_ids |= sp_users
        for app_oid in app_oids:
            app_sps, app_users = app_owner_chain(graph, app_oid)
            owner_sp_ids |= app_sps
            owner_ids |= app_users
        evidence = (f"{object_type} · {pw} password + {kc} key credential(s) · "
                    f"{role_count} app-role assignment(s)")
        if extra:
            evidence += " · " + extra
        f = make_finding(
            check_id="app_inventory", category="apps",
            severity=severity,
            title=f"{object_type}: {name}",
            evidence=evidence,
            remediation=("Confirm the application is still required, ensure it has an "
                         "accountable owner, and remove unused credentials or grants."),
            primary_id=oid,
            object_ids={"sp": set(sp_oids), "app": set(app_oids),
                        "user": owner_ids},
            target={"type": object_type, "name": name, "id": oid},
            status=status,
        )
        f["display_name"] = name
        f["inventory_type"] = object_type
        f["inventory_app_id"] = app_id
        f["inventory_sp_type"] = sp_type
        f["inventory_owners"] = owner_dicts(owner_ids, owner_sp_ids)
        f["pw"] = pw
        f["keys"] = kc
        f["roles"] = role_count
        findings.append(f)

    for oid, rec in graph["sp"].items():
        app_oids = sorted(graph["app_by_appid"].get(rec.get("appId"), []))
        name = sp_display_name(rec)
        if app_oids:
            name = (graph["app"][app_oids[0]].get("displayName") or name)
        pw = len(json_list(rec.get("passwordCredentials")))
        kc = len(json_list(rec.get("keyCredentials")))
        for app_oid in app_oids:
            app_rec = graph["app"].get(app_oid) or {}
            pw += len(json_list(app_rec.get("passwordCredentials")))
            kc += len(json_list(app_rec.get("keyCredentials")))
        enabled = bool(rec.get("accountEnabled")) and not rec.get("deletionTimestamp")
        extra = []
        if not app_oids:
            extra.append("no local application registration")
        if rec.get("deletionTimestamp"):
            extra.append("deletion pending")
        if grant_count.get(oid):
            extra.append(f"{grant_count[oid]} privileged app-role grant(s)")
        emit(name, "Service Principal", oid, [oid], app_oids,
             rec.get("appId") or "", rec.get("servicePrincipalType") or "",
             pw, kc, assignment_count.get(oid, 0),
             grant_sev.get(oid, "Info"),
             {"label": "Enabled" if enabled else "Disabled", "enabled": enabled},
             " · ".join(extra))

    for oid, rec in graph["app"].items():
        if graph["sp_by_appid"].get(rec.get("appId")):
            continue  # represented by the linked service principal row
        emit(rec.get("displayName") or oid, "Application registration", oid,
             [], [oid], rec.get("appId") or "", "",
             len(json_list(rec.get("passwordCredentials"))),
             len(json_list(rec.get("keyCredentials"))), 0, "Info", None,
             "no local service principal")

    findings.sort(key=lambda f: (severity_rank(f["severity"]),
                                 (f["target"]["name"] or "").lower(),
                                 f.get("inventory_type") or ""))
    return findings



"""Azure Arc / hybrid identity checks."""
from __future__ import annotations

from ..findings import is_privileged, make_finding, severity_rank
from ..graph import json_list, role_assignment_count_for_sp, role_assignments_for_sp


# ---------------------------------------------------------------------------
# Azure Arc detection
# ---------------------------------------------------------------------------
#
# Every signal below is a tenant-independent identifier, not display text:
#   - Azure RBAC built-in role-definition GUIDs (identical in every tenant)
#   - first-party Microsoft Arc service-principal appIds (global constants)
#   - the "AzureArcSPN" tag the Arc deployment wizard stamps on the SP it creates
#   - the Microsoft.HybridCompute managed-identity resource path of Arc servers
#
# Research references:
#   - IBM X-Force: "Identifying and abusing Azure Arc for hybrid escalation
#     and persistence" (ROADrecon hunting recipes for exactly these fields)

ARC_RBAC_ROLE_GUIDS = {
    "b64e21ea-ac4e-4cdf-9dc9-5b892992bee7": "Azure Connected Machine Onboarding",
    "cd570a14-e51a-42ad-bac8-bafd67325302": "Azure Connected Machine Resource Administrator",
    "f5819b54-e033-4d82-ac66-4fec3cbf3f4c": "Azure Connected Machine Resource Manager",
    "34e09817-6cbe-4d01-b1a2-e0eac5743d41": "Kubernetes Cluster - Azure Arc Onboarding",
    "00493d72-78f6-4148-b6c5-d3ce8e4799dd": "Azure Arc Enabled Kubernetes Cluster User Role",
    "63f0a09d-1495-4db4-a681-037d84835eb4": "Azure Arc Kubernetes Viewer",
    "5b999177-9696-4545-85c7-50de3797e5a1": "Azure Arc Kubernetes Writer",
    "8393591c-06b9-48a2-a542-1bd6b377f6a2": "Azure Arc Kubernetes Cluster Admin",
    "dffb1e0c-446f-4dde-a09f-99eb5cc68b96": "Azure Arc Kubernetes Admin",
    "06927065-6e3c-475e-b565-1dd2c3a93b60": "Azure Arc Kubernetes Reader",
    "5d3f1697-4507-4d08-bb4a-477695db5f82": "Azure Kubernetes Service Arc Contributor Role",
    "233ca253-b031-42ff-9fba-87ef12d6b55f": "Azure Kubernetes Service Arc Cluster User Role",
    "b29efa5f-7782-4dc3-9537-4d5bc70a5e9f": "Azure Kubernetes Service Arc Cluster Admin Role",
    "f6e92014-8af2-414d-9948-9b1abf559285": "Arc Gateway Manager",
    "53ad7cb7-33cc-4509-b36b-03d40643c499": "Microsoft Cloud Security Arc Machine Operator",
    "ee99642a-225b-4fe8-a771-9d9036053e87": "Arc Container Storage Contributor",
    "5d5dddae-e124-4753-972d-aae60b37deb4": "Migrate Arc Discovery Reader - Preview",
    "b748a06d-6150-4f8a-aaa9-ce3940cd96cb": "Azure Arc VMware VM Contributor",
    "ce551c02-7c42-47e0-9deb-e3b6fc3a9a83": "Azure Arc VMware Private Cloud User",
    "ddc140ed-e463-4246-9145-7c664192013f": "Azure Arc VMware Administrator role",
    "67d33e57-3129-45e6-bb0b-7cc522f762fa": "Azure Arc VMware Private Clouds Onboarding",
    "e582369a-e17b-42a5-b10c-874c387c530b": "Azure Arc ScVmm VM Contributor",
    "a92dfd61-77f9-4aec-a531-19858b406c87": "Azure Arc ScVmm Administrator role",
    "6aac74c4-6311-40d2-bbdd-7d01e7c6e3a9": "Azure Arc ScVmm Private Clouds Onboarding",
    "c0781e91-8102-4553-8951-97c6d4243cda": "Azure Arc ScVmm Private Cloud User",
}

ARC_FIRST_PARTY_APP_IDS = {
    "d00b5d58-cae5-42ad-ae0a-5a2e6f7ee6c9": "Arc Token Service",
    "aacceff9-8ec3-413c-83eb-cb131aaf55c6": "Arc Public Cloud - Servers",
    "61414a6b-7050-4d69-8e88-d6c5646bab20": "ArcGatewayApp",
    "585fc3c3-9a59-4720-8319-53cce041a605": "Azure Arc Appliance Resource Provider",
    "0000dab9-8b21-4ba2-807f-1743968cef00": "ASE-Arc-Integration",
    "1459b1f6-7a5b-4300-93a2-44b4a651759f": "Azure Container Apps Arc - Control Plane",
    "409eb69a-5e20-4e1e-a8bf-c23300057950": "Azure Container Apps Arc - Data Plane",
    "a0f92522-89de-4c5e-9a75-0044ccf66efd": "ClusterConfigToArcZone",
}

ARC_SPN_TAG = "AzureArcSPN"

ARC_HYBRIDCOMPUTE_MARK = "/providers/microsoft.hybridcompute/machines/"


def _arc_resource_parts(rec):
    """(resource_id, subscription, resource_group) for an Arc-enabled server's
    managed-identity SP record; resource id resolved from
    managedIdentityResourceId or the alternativeNames array (either carries the
    ARM resource path). Returns ("", "", "") for non-Arc identities."""
    resid = rec.get("managedIdentityResourceId") or ""
    if not resid or ARC_HYBRIDCOMPUTE_MARK not in resid.lower():
        for alt in json_list(rec.get("alternativeNames")):
            if isinstance(alt, str) and ARC_HYBRIDCOMPUTE_MARK in alt.lower():
                resid = alt
                break
    if ARC_HYBRIDCOMPUTE_MARK not in resid.lower():
        return "", "", ""
    parts = [p for p in resid.split("/") if p]
    pl = [p.lower() for p in parts]
    sub = parts[pl.index("subscriptions") + 1] if "subscriptions" in pl else ""
    rg = parts[pl.index("resourcegroups") + 1] if "resourcegroups" in pl else ""
    return resid, sub, rg


def _arc_roles_filtered(roles):
    """Dedupe + sort the Arc ARM assignments on a principal (same shape as
    the generic az_roles attach)."""
    seen, out = set(), []
    for a in roles or []:
        if (a.get("role_def_id") or "").lower() not in ARC_RBAC_ROLE_GUIDS:
            continue
        key = (a.get("role"), a.get("scope_label"), bool(a.get("eligible")))
        if key in seen:
            continue
        seen.add(key)
        out.append(a)
    out.sort(key=lambda a: (bool(a.get("eligible")), a["role"].lower()))
    return out


def _sp_password_credentials(graph, oid):
    """Combined password credentials of a service principal and its app
    registration: (count, most recent start date, latest end date,
    per-credential note lines). Defensive against both Graph 'startDateTime'
    and legacy 'startDate' key spellings, and against SPs without a local app
    registration."""
    rec = (graph.get("sp") or {}).get(oid) or {}
    creds = list(json_list(rec.get("passwordCredentials")))
    for a_oid in (graph.get("app_by_appid") or {}).get(rec.get("appId")) or []:
        a_rec = (graph.get("app") or {}).get(a_oid) or {}
        creds += list(json_list(a_rec.get("passwordCredentials")))
    starts, ends, lines = [], [], []
    for i, c in enumerate(creds):
        if not isinstance(c, dict):
            continue
        start = c.get("startDateTime") or c.get("startDate") or ""
        end = c.get("endDateTime") or c.get("endDate") or ""
        name = c.get("displayName") or c.get("customKeyIdentifier") or f"secret {i + 1}"
        if start:
            starts.append(start)
        if end:
            ends.append(end)
        lines.append(f"{name}: {start or '?'} \u2192 {end or '?'}")
    last = max(starts) if starts else ""
    expiry = max(ends) if ends else ""
    return len(creds), last, expiry, "\n".join(lines)


def check_azure_arc_machines(ctx):
    """Arc-enabled servers: ManagedIdentity service principals whose Azure
    resource path resolves to Microsoft.HybridCompute/machines (system-assigned
    identities created when a machine is onboarded to Arc)."""
    graph = ctx["graph"]
    include_disabled = ctx["include_disabled"]
    findings = []
    for oid in sorted(graph["sp"]):
        rec = graph["sp"][oid]
        if (rec.get("servicePrincipalType") or "") != "ManagedIdentity":
            continue
        resid, sub, rg = _arc_resource_parts(rec)
        if not resid:
            continue
        if not include_disabled and rec.get("deletionTimestamp"):
            continue
        name = rec.get("displayName") or (resid.rsplit("/", 1)[-1] if resid else oid)
        sub_display = (graph.get("az_sub_names") or {}).get(sub) or sub
        f = make_finding(
            check_id="azure_arc_machines", category="arc", severity="Info",
            title=f"Arc-enabled machine {name}",
            evidence=resid,
            remediation="Review whether this server still needs Azure Arc management.",
            primary_id=oid,
            object_ids={"sp": {oid}},
            target={"type": "Azure Arc machine", "name": name, "id": oid},
        )
        f["machine_name"] = name
        f["arc_sub"] = sub_display
        f["arc_rg"] = rg
        f["arc_resource_id"] = resid
        f["arc_status"] = {"label": "Enabled" if rec.get("accountEnabled") else "Disabled",
                           "enabled": bool(rec.get("accountEnabled"))}
        findings.append(f)
    findings.sort(key=lambda f: (f["machine_name"] or "").lower())
    return findings


def check_azure_arc_sps(ctx):
    """Principals (SP/user/group) holding Azure Arc ARM roles — matched by the
    built-in role-definition GUID — plus service principals carrying the
    AzureArcSPN tag (created through the Arc deployment wizard)."""
    graph = ctx["graph"]
    include_disabled = ctx["include_disabled"]
    findings = []

    def emit(kind, oid, display, enabled, tagged, arc_roles, object_ids, extra):
        f = make_finding(
            check_id="azure_arc_sps", category="arc", severity="Info",
            title=f"{kind} {display}",
            evidence=", ".join(f"{a['role']} @ {a.get('scope_label') or a.get('scope') or ''}"
                               for a in arc_roles) or ("AzureArcSPN tag" if tagged else ""),
            remediation=("Review the Arc management credentials and scope; deployment "
                         "scripts commonly embed this principal's secret."),
            primary_id=oid,
            object_ids=object_ids,
            target={"type": kind, "name": display, "id": oid},
        )
        f["arc_principal"] = display
        f["arc_principal_type"] = kind
        f["arc_tagged"] = bool(tagged)
        f["arc_roles"] = _arc_roles_filtered(arc_roles)
        f["arc_status"] = {"label": "Enabled" if enabled else "Disabled",
                           "enabled": bool(enabled)}
        f.update(extra)
        findings.append(f)

    for oid in sorted(graph["sp"]):
        rec = graph["sp"][oid]
        tagged = ARC_SPN_TAG in json_list(rec.get("tags"))
        arc_roles = _arc_roles_filtered(graph["az_sp_roles"].get(oid, []))
        if not tagged and not arc_roles:
            continue
        if not include_disabled and (not rec.get("accountEnabled") or rec.get("deletionTimestamp")):
            continue
        pw, pw_last, pw_expiry, pw_note = _sp_password_credentials(graph, oid)
        app_oids = set((graph.get("app_by_appid") or {}).get(rec.get("appId")) or [])
        emit("Service Principal", oid,
             rec.get("displayName") or rec.get("appDisplayName") or oid,
             bool(rec.get("accountEnabled")), tagged, arc_roles,
             {"sp": {oid}, "app": app_oids}, {"pw": pw, "pw_last_set": pw_last,
                                               "pw_expiry": pw_expiry,
                                               "pw_creds_note": pw_note})

    for uid in sorted(graph["az_user_roles"]):
        arc_roles = _arc_roles_filtered(graph["az_user_roles"][uid])
        if not arc_roles:
            continue
        u = graph["user"].get(uid)
        if not u:
            continue
        if not include_disabled and (not u.get("accountEnabled") or u.get("deletionTimestamp")):
            continue
        emit("User", uid, u.get("displayName") or u.get("userPrincipalName") or uid,
             bool(u.get("accountEnabled")), False, arc_roles, {"user": {uid}}, {})

    for gid in sorted(graph["az_roles"]):
        arc_roles = _arc_roles_filtered(graph["az_roles"][gid])
        if not arc_roles:
            continue
        g = graph["group"].get(gid)
        if not g:
            continue
        emit("Group", gid, g.get("displayName") or gid, True, False, arc_roles,
             {}, {"arc_group_id": gid})

    findings.sort(key=lambda f: (f["arc_principal_type"], (f["arc_principal"] or "").lower()))
    return findings


def check_azure_arc_providers(ctx):
    """First-party Microsoft Arc service principals present in the tenant
    (matched by appId) — subscription configured with the Arc resource
    providers, so Arc can be onboarded from this tenant."""
    graph = ctx["graph"]
    include_disabled = ctx["include_disabled"]
    findings = []
    for app_id in sorted(ARC_FIRST_PARTY_APP_IDS):
        for oid in sorted(graph["sp_by_appid"].get(app_id) or []):
            rec = graph["sp"].get(oid)
            if not rec:
                continue
            if not include_disabled and (not rec.get("accountEnabled") or rec.get("deletionTimestamp")):
                continue
            name = (rec.get("displayName") or rec.get("appDisplayName")
                    or ARC_FIRST_PARTY_APP_IDS[app_id])
            f = make_finding(
                check_id="azure_arc_providers", category="arc", severity="Info",
                title=f"Azure Arc provider {name}",
                evidence=f"appId {app_id}",
                remediation="",
                primary_id=oid,
                object_ids={"sp": {oid}},
                target={"type": "Azure Arc provider", "name": name, "id": oid},
            )
            f["arc_provider"] = name
            f["arc_status"] = {"label": "Enabled" if rec.get("accountEnabled") else "Disabled",
                               "enabled": bool(rec.get("accountEnabled"))}
            findings.append(f)
    findings.sort(key=lambda f: (f["arc_provider"] or "").lower())
    return findings

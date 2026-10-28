"""Endpoint -> ROADrecon-table collectors. Every section degrades gracefully:
a failing endpoint logs a warning and the run continues with everything else.
"""
from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

from .client import ArmClient, BatchPagedResult, Degraded, GraphClient
from .store import Store

API = "v1.0"
BETA = "beta"
WORKERS = 12


def parallel_map(fn: Callable, items: list, workers: int = WORKERS) -> list:
    items = list(items)
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as ex:
        return list(ex.map(fn, items))


def fetch_paged_batch(client, requests: list[dict]) -> dict[str, BatchPagedResult]:
    """Fetch independent paged endpoints, using Graph $batch when enabled."""
    if getattr(client, "batch", False):
        return client.batch_paged_many(requests)
    results: dict[str, BatchPagedResult] = {}

    def fetch(request):
        try:
            items = list(client.paged(
                request["path"], api=request.get("api", API)))
            return request["key"], items, 0, ""
        except Degraded as exc:
            return request["key"], [], exc.status, exc.body

    for key, items, status, body in parallel_map(fetch, requests):
        result = BatchPagedResult()
        result.items = items
        result.status = status
        result.body = body
        if status or body:
            result.error = f"{status} {body[:200]}"
        results[key] = result
    return results

# --------------------------------------------------------------------------
# small helpers


def jstr(v) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    return json.dumps(v, separators=(",", ":"), default=str)


class Section:
    """Tracks result of one collection section."""

    def __init__(self, name: str):
        self.name = name
        self.status = "skipped"
        self.note = ""
        self.count = 0
        self.seconds = 0.0
        self._t0 = time.time()


class Runner:
    def __init__(self, client: GraphClient, store: Store, verbose: int = 0):
        self.c = client
        self.s = store
        self.verbose = verbose
        self.sections: list[Section] = []

    def log(self, msg: str) -> None:
        print(f"[collect] {msg}", file=sys.stderr)

    def section(self, name: str) -> Section:
        sec = Section(name)
        self.sections.append(sec)
        return sec

    def finish(self, sec: Section, status: str, count: int = 0,
               note: str = "") -> None:
        sec.status = status
        sec.count = count
        sec.note = note
        sec.seconds = time.time() - sec._t0
        self.log(f"{status:10s} {sec.name} ({count}, {sec.seconds:.1f}s)"
                 + (f" - {note}" if note else ""))


def guard(sec: Section, runner: Runner, fn: Callable[[], Optional[int]],
          auto_finish: bool = True) -> Optional[int]:
    """Run fn; mark the section ok (with count) on success or degraded on failure."""
    try:
        n = fn()
    except Degraded as d:
        runner.finish(sec, "degraded", note=f"HTTP {d.status}")
        if runner.verbose:
            runner.log(f"  {sec.name}: {d}")
        return None
    except Exception as e:
        runner.finish(sec, "error", note=str(e)[:200])
        if runner.verbose:
            runner.log(f"  {sec.name}: {e}")
        return None
    if auto_finish:
        runner.finish(sec, "ok", n if isinstance(n, int) else 0)
    return n


# --------------------------------------------------------------------------
# generic directory-object row builder

def dir_row(obj: dict, obj_type: str, renames: Optional[dict] = None,
            extra: Optional[dict] = None) -> dict:
    row: dict = {}
    for k, v in obj.items():
        if k.startswith("@"):
            continue
        if isinstance(v, (dict, list)):
            continue
        row[k] = v
    row["objectId"] = obj.get("id")
    row["objectType"] = obj_type
    if renames:
        for src, dst in renames.items():
            if src in obj and obj[src] is not None:
                row[dst] = obj[src]
    # nested values go through explicit mapping (callers pass them in extra)
    if extra:
        for k, v in extra.items():
            if v is not None:
                row[k] = jstr(v)
    return row


def app_role_row(ara: dict, resource_id: Optional[str] = None,
                 display_name: Optional[str] = None) -> dict:
    """Map a Graph appRoleAssignment object to the ROADrecon table row."""
    return {
        "objectId": ara.get("id"),
        "objectType": "AppRoleAssignment",
        "id": ara.get("appRoleId"),
        "principalId": ara.get("principalId"),
        "principalType": ara.get("principalType"),
        "principalDisplayName": ara.get("principalDisplayName"),
        "resourceId": ara.get("resourceId") or resource_id,
        "resourceDisplayName": (ara.get("resourceDisplayName")
                                or display_name),
        "creationTimestamp": ara.get("createdDateTime"),
        "deletionTimestamp": ara.get("deletedDateTime"),
    }


def objtype(o: dict) -> str:
    t = (o.get("@odata.type") or "").rsplit(".", 1)[-1].lower()
    return {"user": "User", "group": "Group", "serviceprincipal": "ServicePrincipal",
            "device": "Device", "orgcontact": "OrgContact", "contact": "OrgContact",
            "organization": "Organization"}.get(t, t)


# --------------------------------------------------------------------------
# link dispatch (group members / role members / owners / AU members)

LINK_TABLES = {
    ("member", "User"): ("lnk_group_member_user", "User"),
    ("member", "Group"): ("lnk_group_member_group", "childGroup"),
    ("member", "ServicePrincipal"): ("lnk_group_member_serviceprincipal", "ServicePrincipal"),
    ("member", "Device"): ("lnk_group_member_device", "Device"),
    ("member", "OrgContact"): ("lnk_group_member_contact", "Contact"),
    ("owner", "User"): ("lnk_group_owner_user", "User"),
    ("owner", "ServicePrincipal"): ("lnk_group_owner_serviceprincipal", "ServicePrincipal"),
    ("role", "User"): ("lnk_role_member_user", "User"),
    ("role", "Group"): ("lnk_role_member_group", "Group"),
    ("role", "ServicePrincipal"): ("lnk_role_member_serviceprincipal", "ServicePrincipal"),
    ("au", "User"): ("lnk_au_member_user", "User"),
    ("au", "Group"): ("lnk_au_member_group", "Group"),
    ("au", "Device"): ("lnk_au_member_device", "Device"),
    ("appowner", "User"): ("lnk_application_owner_user", "User"),
    ("appowner", "ServicePrincipal"): ("lnk_application_owner_serviceprincipal", "ServicePrincipal"),
    ("spowner", "User"): ("lnk_serviceprincipal_owner_user", "User"),
    ("spowner", "ServicePrincipal"): ("lnk_serviceprincipal_owner_serviceprincipal", "childServicePrincipal"),
    ("devowner", "User"): ("lnk_device_owner", "User"),
}


def add_dir_links(store: Store, kind: str, parent_col: str, parent_id: str,
                  members) -> int:
    """Dispatch directory objects from a members/owners listing into lnk tables."""
    n = 0
    for m in members:
        t = objtype(m)
        if t == "Organization" or t == "Contact":
            t = "OrgContact"
        key = (kind, t)
        if key not in LINK_TABLES:
            continue
        table, col = LINK_TABLES[key]
        if m.get("id"):
            store.add_link(table, {parent_col: parent_id, col: m["id"]})
            n += 1
    return n


# --------------------------------------------------------------------------
# 1. tenant / directory objects

def collect_tenant(runner: Runner) -> None:
    sec = runner.section("TenantDetails")
    def go():
        items = list(runner.c.paged("/organization"))
        for org in items:
            row = dir_row(org, "Company", renames={
                "onPremisesSyncEnabled": "dirSyncEnabled",
                "onPremisesLastSyncDateTime": "companyLastDirSyncTime",
            }, extra={
                "privacyProfile": org.get("privacyProfile"),
                "verifiedDomains": org.get("verifiedDomains"),
                "assignedPlans": org.get("assignedPlans"),
                "provisionedPlans": org.get("provisionedPlans"),
                "provisioningErrors": org.get("provisioningErrors"),
            })
            runner.s.upsert("TenantDetails", "objectId", row)
        return len(items)
    guard(sec, runner, go)


def collect_users(runner: Runner) -> list[dict]:
    sec = runner.section("Users")
    users: list[dict] = []
    def go():
        for u in runner.c.paged("/users?$top=999", api=BETA):
            ext = (u.get("onPremisesExtensionAttributes") or {})
            crtc = u.get("cloudRealtimeCommunicationInfo") or {}
            sip = u.get("onPremisesSipInfo") or {}
            row = dir_row(u, "User", renames={
                "onPremisesSyncEnabled": "dirSyncEnabled",
                "onPremisesLastSyncDateTime": "lastDirSyncTime",
                "onPremisesImmutableId": "immutableId",
                "externalUserState": "userState",
                "externalUserStateChangeDateTime": "userStateChangedOn",
                "mobilePhone": "mobile",
                "faxNumber": "facsimileTelephoneNumber",
                "onPremisesProvisioningErrors": "provisioningErrors",
                "securityIdentifier": "cloudSecurityIdentifier",
                "onPremisesLastPasswordChangeDateTime": "onPremisesPasswordChangeTimestamp",
            }, extra={
                "assignedLicenses": u.get("assignedLicenses"),
                "assignedPlans": u.get("assignedPlans"),
                "provisionedPlans": u.get("provisionedPlans"),
                "serviceProvisioningErrors": u.get("serviceProvisioningErrors"),
                "passwordProfile": u.get("passwordProfile"),
                "otherMails": u.get("otherMails"),
                "proxyAddresses": u.get("proxyAddresses"),
                "employeeOrgData": u.get("employeeOrgData"),
                "identities": u.get("identities"),
                "infoCatalogs": u.get("infoCatalogs"),
                "inviteTicket": u.get("inviteTicket"),
                "deviceKeys": u.get("deviceKeys"),
                "cloudRealtimeCommunicationInfo": u.get("cloudRealtimeCommunicationInfo"),
                "signInNames": [
                    {"type": i.get("signInType"), "value": i.get("issuerAssignedId")}
                    for i in (u.get("identities") or [])],
                "signInNamesInfo": u.get("identities"),
            })
            if sip.get("sipAddress"):
                row["sipProxyAddress"] = sip["sipAddress"]
            if crtc.get("isSipEnabled") is not None:
                row["cloudMSRtcIsSipEnabled"] = crtc["isSipEnabled"]
            if crtc.get("sipAddress"):
                row["cloudSipProxyAddress"] = crtc["sipAddress"]
            for i in range(1, 16):
                v = ext.get(f"extensionAttribute{i}")
                if v is not None:
                    row[f"extensionAttribute{i}"] = v
            phones = u.get("businessPhones") or []
            if phones:
                row["telephoneNumber"] = phones[0]
            runner.s.upsert("Users", "objectId", row)
            users.append(u)
        return len(users)
    n = guard(sec, runner, go, auto_finish=False)
    if n is None:  # beta failed; fall back to v1.0
        def go2():
            for u in runner.c.paged("/users?$top=999"):
                runner.s.upsert("Users", "objectId", dir_row(u, "User",
                    renames={"onPremisesSyncEnabled": "dirSyncEnabled",
                             "onPremisesLastSyncDateTime": "lastDirSyncTime",
                             "onPremisesImmutableId": "immutableId"}))
                users.append(u)
            return len(users)
        n = guard(sec, runner, go2, auto_finish=False)
    if n is not None:
        runner.finish(sec, "ok", n)
    # v1.0-only field: lastPasswordChangeDateTime (absent from beta payload)
    try:
        extra_n = 0
        for u in runner.c.paged(
                "/users?$top=999&$select=id,lastPasswordChangeDateTime"):
            if u.get("lastPasswordChangeDateTime"):
                runner.s.upsert("Users", "objectId", {
                    "objectId": u.get("id"),
                    "lastPasswordChangeDateTime": u["lastPasswordChangeDateTime"],
                })
                extra_n += 1
        if extra_n:
            sec.note = (sec.note or "") + f" pw-change: {extra_n}"
    except Degraded:
        pass
    # user-principal app role assignments
    approl_n = 0
    user_ids = [u["id"] for u in users]
    requests = [{"key": uid, "path": f"/users/{uid}/appRoleAssignments",
                 "api": API} for uid in user_ids]
    for uid, result in fetch_paged_batch(runner.c, requests).items():
        if result.error:
            continue
        for ara in result.items:
            runner.s.upsert("AppRoleAssignments", "objectId",
                            app_role_row(ara))
            approl_n += 1
    if approl_n:
        sec.note = f"user appRoleAssignments: {approl_n}"
    return users


def collect_groups(runner: Runner) -> list[dict]:
    sec = runner.section("Groups")
    groups: list[dict] = []
    def go():
        for g in runner.c.paged("/groups?$top=999", api=BETA):
            row = dir_row(g, "Group", renames={
                "onPremisesSyncEnabled": "dirSyncEnabled",
                "onPremisesLastSyncDateTime": "lastDirSyncTime",
                "onPremisesProvisioningErrors": "provisioningErrors",
                "securityIdentifier": "cloudSecurityIdentifier",
            }, extra={
                "groupTypes": g.get("groupTypes"),
                "proxyAddresses": g.get("proxyAddresses"),
                "resourceBehaviorOptions": g.get("resourceBehaviorOptions"),
                "resourceProvisioningOptions": g.get("resourceProvisioningOptions"),
                "creationOptions": g.get("creationOptions") or [],
                "infoCatalogs": g.get("infoCatalogs"),
                "serviceProvisioningErrors": g.get("serviceProvisioningErrors"),
                "writebackConfiguration": g.get("writebackConfiguration"),
            })
            runner.s.upsert("Groups", "objectId", row)
            groups.append(g)
        return len(groups)
    n = guard(sec, runner, go, auto_finish=False)
    if n is None:
        return groups
    members_n = owners_n = 0
    failed = 0
    approl_n = 0
    group_ids = [g["id"] for g in groups]
    requests = []
    for gid in group_ids:
        requests.extend([
            {"key": f"{gid}|members",
             "path": f"/groups/{gid}/transitiveMembers", "api": API},
            {"key": f"{gid}|owners",
             "path": f"/groups/{gid}/owners", "api": API},
            {"key": f"{gid}|sp_members",
             "path": f"/groups/{gid}/members/microsoft.graph.servicePrincipal",
             "api": API},
            {"key": f"{gid}|aras",
             "path": f"/groups/{gid}/appRoleAssignments", "api": API},
        ])
    results = fetch_paged_batch(runner.c, requests)

    for gid in group_ids:
        members = results.get(f"{gid}|members")
        owners = results.get(f"{gid}|owners")
        sp_members = results.get(f"{gid}|sp_members")
        aras = results.get(f"{gid}|aras")
        if members is None or members.error:
            failed += 1
        else:
            members_n += add_dir_links(
                runner.s, "member", "Group", gid, members.items)
        if owners is None or owners.error:
            failed += 1
        else:
            owners_n += add_dir_links(
                runner.s, "owner", "Group", gid, owners.items)
        if sp_members is not None and not sp_members.error:
            for member in sp_members.items:
                member.setdefault(
                    "@odata.type", "#microsoft.graph.servicePrincipal")
            members_n += add_dir_links(
                runner.s, "member", "Group", gid, sp_members.items)
        if aras is not None and not aras.error:
            for ara in aras.items:
                runner.s.upsert("AppRoleAssignments", "objectId",
                                app_role_row(ara))
                approl_n += 1
    runner.finish(sec, "ok" if failed == 0 else "partial", n,
                  f"links: {members_n} members / {owners_n} owners, "
                  f"group appRoleAssignments: {approl_n}")
    return groups


def collect_applications(runner: Runner) -> list[dict]:
    sec = runner.section("Applications")
    apps: list[dict] = []
    def go():
        for a in runner.c.paged("/applications?$top=999"):
            web = a.get("web") or {}
            api = a.get("api") or {}
            row = dir_row(a, "Application", extra={
                "addIns": a.get("addIns"),
                "appRoles": a.get("appRoles"),
                "identifierUris": a.get("identifierUris"),
                "keyCredentials": a.get("keyCredentials"),
                "passwordCredentials": a.get("passwordCredentials"),
                "oauth2Permissions": api.get("oauth2PermissionScopes"),
                "optionalClaims": a.get("optionalClaims"),
                "parentalControlSettings": a.get("parentalControlSettings"),
                "requiredResourceAccess": a.get("requiredResourceAccess"),
                "replyUrls": web.get("redirectUris"),
                "knownClientApplications": api.get("knownClientApplications"),
                "informationalUrls": a.get("informationalUrls"),
                "verifiedPublisher": a.get("verifiedPublisher"),
                "certification": a.get("certification"),
                "implicitGrantSettings": web.get("implicitGrantSettings"),
                "requestedAccessTokenVersion": api.get("requestedAccessTokenVersion"),
            })
            if web.get("homepageUrl"):
                row["homepage"] = web["homepageUrl"]
            if web.get("logoutUrl"):
                row["logoutUrl"] = web["logoutUrl"]
            if api.get("preAuthorizedApplications") is not None:
                row["appData"] = jstr(api["preAuthorizedApplications"])
            # AAD Graph exposed implicit-flow booleans directly; Graph nests them
            # in web.implicitGrantSettings - derive for schema compatibility.
            igs = web.get("implicitGrantSettings") or {}
            if igs.get("enableAccessTokenIssuance") is not None:
                row["oauth2AllowImplicitFlow"] = igs["enableAccessTokenIssuance"]
            if igs.get("enableIdTokenIssuance") is not None:
                row["oauth2AllowIdTokenImplicitFlow"] = igs["enableIdTokenIssuance"]
            runner.s.upsert("Applications", "objectId", row)
            apps.append(a)
        return len(apps)
    n = guard(sec, runner, go, auto_finish=False)
    if n is None:
        return apps
    owners_n = 0
    approles_defined = 0
    ext_n = 0
    requests = []
    for app in apps:
        aid = app["id"]
        requests.extend([
            {"key": f"{aid}|owners",
             "path": f"/applications/{aid}/owners", "api": API},
            {"key": f"{aid}|ext",
             "path": f"/applications/{aid}/extensionProperties", "api": API},
        ])
    results = fetch_paged_batch(runner.c, requests)
    for app in apps:
        aid = app["id"]
        owners = results.get(f"{aid}|owners")
        ext_props = results.get(f"{aid}|ext")
        if owners is not None and not owners.error:
            owners_n += add_dir_links(
                runner.s, "appowner", "Application", aid, owners.items)
        if app.get("appRoles"):
            approles_defined += 1
        if ext_props is not None and not ext_props.error:
            for ep in ext_props.items:
                runner.s.upsert("ExtensionPropertys", "objectId", {
                    "objectId": ep.get("id"),
                    "objectType": "ExtensionProperty",
                    "appDisplayName": app.get("displayName"),
                    "name": ep.get("name"),
                    "dataType": ep.get("dataType"),
                    "isSyncedFromOnPremises": ep.get("isSyncedFromOnPremises"),
                    "targetObjects": ep.get("targetObjects"),
                })
                ext_n += 1
    runner.finish(sec, "ok", n, f"owners: {owners_n}, "
                  f"apps defining appRoles: {approles_defined}, "
                  f"extensionProperties: {ext_n}")
    return apps


def collect_serviceprincipals(runner: Runner) -> list[dict]:
    sec = runner.section("ServicePrincipals")
    merged: dict[str, dict] = {}
    sps: list[dict] = []

    def go():
        # v1.0 provides oauth2PermissionScopes; beta adds publisherName,
        # samlMetadataUrl, certification and other extras. Merge both.
        for sp in runner.c.paged("/servicePrincipals?$top=999"):
            merged[sp["id"]] = dict(sp)
        for sp in runner.c.paged("/servicePrincipals?$top=999", api=BETA):
            base = merged.get(sp["id"])
            if base is None:
                merged[sp["id"]] = dict(sp)
            else:
                for k, v in sp.items():
                    if k not in base or base[k] in (None, "", []):
                        base[k] = v
        return len(merged)
    n = guard(sec, runner, go, auto_finish=False)
    if n is None:
        return sps
    for sid, sp in merged.items():
        row = dir_row(sp, "ServicePrincipal", renames={
            "appOwnerOrganizationId": "appOwnerTenantId",
            "oauth2PermissionScopes": "oauth2Permissions",
        }, extra={
            "addIns": sp.get("addIns"),
            "alternativeNames": sp.get("alternativeNames"),
            "appRoles": sp.get("appRoles"),
            "informationalUrls": sp.get("informationalUrls"),
            "keyCredentials": sp.get("keyCredentials"),
            "passwordCredentials": sp.get("passwordCredentials"),
            "replyUrls": sp.get("replyUrls"),
            "servicePrincipalNames": sp.get("servicePrincipalNames"),
            "tags": sp.get("tags"),
            "verifiedPublisher": sp.get("verifiedPublisher"),
            "notificationEmailAddresses": sp.get("notificationEmailAddresses"),
            "samlSingleSignOnSettings": sp.get("samlSingleSignOnSettings"),
            "resourceSpecificApplicationPermissions":
                sp.get("resourceSpecificApplicationPermissions"),
            "certification": sp.get("certification"),
        })
        if row.get("publisherName") is None:
            row["publisherName"] = (sp.get("verifiedPublisher") or {}).get("displayName")
        if sp.get("informationalUrls"):
            row["informationalUrls"] = sp["informationalUrls"]
        runner.s.upsert("ServicePrincipals", "objectId", row)
        # ApplicationRefs: app metadata referenced by this SP
        ref = {
            "appId": sp.get("appId"),
            "displayName": sp.get("appDisplayName"),
            "homepage": sp.get("homepage"),
            "appRoles": sp.get("appRoles"),
            "replyUrls": sp.get("replyUrls"),
            "samlMetadataUrl": sp.get("samlMetadataUrl"),
            "logoutUrl": sp.get("logoutUrl"),
            "errorUrl": sp.get("errorUrl"),
            "publisherName": sp.get("publisherName")
                or (sp.get("verifiedPublisher") or {}).get("displayName"),
            "certification": sp.get("certification"),
            "logoUrl": (sp.get("info") or {}).get("logoUrl"),
        }
        if sp.get("verifiedPublisher"):
            ref["verifiedPublisher"] = sp["verifiedPublisher"]
        if ref.get("appId"):
            runner.s.upsert("ApplicationRefs", "appId", ref)
        sps.append(sp)
    owners_n = approl_n = 0
    sps_with_roles = 0
    requests = []
    for sp in sps:
        sid = sp["id"]
        requests.extend([
            {"key": f"{sid}|owners",
             "path": f"/servicePrincipals/{sid}/owners", "api": API},
            {"key": f"{sid}|assignments",
             "path": f"/servicePrincipals/{sid}/appRoleAssignments",
             "api": API},
            {"key": f"{sid}|assigned_to",
             "path": f"/servicePrincipals/{sid}/appRoleAssignedTo",
             "api": API},
        ])
    results = fetch_paged_batch(runner.c, requests)
    for sp in sps:
        sid = sp["id"]
        if sp.get("appRoles"):
            sps_with_roles += 1
        owners = results.get(f"{sid}|owners")
        if owners is not None and not owners.error:
            owners_n += add_dir_links(
                runner.s, "spowner", "ServicePrincipal", sid, owners.items)
        assignments = results.get(f"{sid}|assignments")
        assigned_to = results.get(f"{sid}|assigned_to")
        aras = []
        if assignments is not None and not assignments.error:
            aras.extend(assignments.items)
        if assigned_to is not None and not assigned_to.error:
            aras.extend(assigned_to.items)
        for ara in aras:
            runner.s.upsert("AppRoleAssignments", "objectId",
                            app_role_row(ara, resource_id=sid,
                                         display_name=sp.get("displayName")))
            approl_n += 1
    runner.finish(sec, "ok", n, f"owners: {owners_n}, "
                  f"appRoleAssignments: {approl_n}, "
                  f"SPs defining appRoles: {sps_with_roles}")
    return sps


def collect_devices(runner: Runner) -> None:
    sec = runner.section("Devices")
    devices = []
    def go():
        for d in runner.c.paged("/devices", api=BETA):
            row = dir_row(d, "Device", renames={
                "operatingSystem": "deviceOSType",
                "operatingSystemVersion": "deviceOSVersion",
                "trustType": "deviceTrustType",
                "approximateLastSignInDateTime": "approximateLastLogonTimestamp",
                "onPremisesLastSyncDateTime": "lastDirSyncTime",
                "onPremisesSyncEnabled": "dirSyncEnabled",
                "manufacturer": "deviceManufacturer",
                "model": "deviceModel",
                "mdmAppId": "deviceManagementAppId",
            }, extra={
                "alternativeSecurityIds": d.get("alternativeSecurityIds"),
                "devicePhysicalIds": d.get("physicalIds"),
                "systemLabels": d.get("systemLabels"),
                "keyCredentials": d.get("keyCredentials"),
                "hostnames": d.get("hostnames"),
                "deviceMetadata": d.get("deviceMetadata"),
                "extensionAttributes": d.get("extensionAttributes"),
            })
            runner.s.upsert("Devices", "objectId", row)
            devices.append(d)
        return len(devices)
    n = guard(sec, runner, go, auto_finish=False)
    if n is None:
        return
    owners_n = 0
    requests = [{"key": d["id"], "path": f"/devices/{d['id']}/registeredOwners",
                 "api": API} for d in devices]
    results = fetch_paged_batch(runner.c, requests)
    for device in devices:
        result = results.get(device["id"])
        if result is not None and not result.error:
            owners_n += add_dir_links(
                runner.s, "devowner", "Device", device["id"], result.items)
    runner.finish(sec, "ok", n, f"owners: {owners_n}")


def collect_contacts(runner: Runner) -> None:
    sec = runner.section("Contacts")
    def go():
        n = 0
        for c in runner.c.paged("/contacts?$top=999"):
            phones = c.get("businessPhones") or []
            row = dir_row(c, "Contact", renames={
                "onPremisesSyncEnabled": "dirSyncEnabled",
                "onPremisesLastSyncDateTime": "lastDirSyncTime",
            }, extra={"proxyAddresses": c.get("proxyAddresses")})
            if phones:
                row["telephoneNumber"] = phones[0]
            runner.s.upsert("Contacts", "objectId", row)
            n += 1
        return n
    guard(sec, runner, go)


def collect_directoryroles(runner: Runner) -> None:
    sec = runner.section("DirectoryRoles")
    roles = []
    def go():
        for r in runner.c.paged("/directoryRoles"):
            row = dir_row(r, "Role")
            runner.s.upsert("DirectoryRoles", "objectId", row)
            roles.append(r)
        return len(roles)
    n = guard(sec, runner, go, auto_finish=False)
    if n is None:
        return
    members_n = 0
    requests = [{"key": role["id"],
                 "path": f"/directoryRoles/{role['id']}/members", "api": API}
                for role in roles]
    results = fetch_paged_batch(runner.c, requests)
    for role in roles:
        result = results.get(role["id"])
        if result is not None and not result.error:
            members_n += add_dir_links(
                runner.s, "role", "DirectoryRole", role["id"], result.items)
    runner.finish(sec, "ok", n, f"members: {members_n}")


def collect_adminunits(runner: Runner) -> None:
    sec = runner.section("AdministrativeUnits")
    aus = []
    def go():
        for au in runner.c.paged("/directory/administrativeUnits"):
            runner.s.upsert("AdministrativeUnits", "objectId", dir_row(au, "AdministrativeUnit"))
            aus.append(au)
        return len(aus)
    n = guard(sec, runner, go, auto_finish=False)
    if n is None:
        return
    requests = [{"key": au["id"],
                 "path": f"/directory/administrativeUnits/{au['id']}/members",
                 "api": API} for au in aus]
    results = fetch_paged_batch(runner.c, requests)
    for au in aus:
        result = results.get(au["id"])
        if result is not None and not result.error:
            add_dir_links(runner.s, "au", "AdministrativeUnit",
                          au["id"], result.items)
    runner.finish(sec, "ok", n)


def collect_directorysettings(runner: Runner) -> None:
    sec = runner.section("DirectorySettings")
    def go():
        n = 0
        for s in runner.c.paged("/settings", api=BETA):
            runner.s.upsert("DirectorySettings", "id", {
                "id": s.get("id"),
                "displayName": s.get("displayName"),
                "templateId": s.get("templateId"),
                "values": s.get("values"),
            })
            n += 1
        return n
    n = guard(sec, runner, go)
    if n is None:
        def go2():
            n2 = 0
            for s in runner.c.paged("/groupSettings"):
                runner.s.upsert("DirectorySettings", "id", {
                    "id": s.get("id"), "displayName": s.get("displayName"),
                    "templateId": s.get("templateId"), "values": s.get("values")})
                n2 += 1
            return n2
        n = guard(sec, runner, go2)


def collect_authorizationpolicy(runner: Runner) -> None:
    sec = runner.section("AuthorizationPolicys")
    def go():
        n = 0
        for p in runner.c.paged("/policies/authorizationPolicy"):
            runner.s.upsert("AuthorizationPolicys", "id", {
                "id": p.get("id"),
                "allowInvitesFrom": p.get("allowInvitesFrom"),
                "allowedToSignUpEmailBasedSubscriptions":
                    p.get("allowedToSignUpEmailBasedSubscriptions"),
                "allowedToUseSSPR": p.get("allowedToUseSSPR"),
                "allowEmailVerifiedUsersToJoinOrganization":
                    p.get("allowEmailVerifiedUsersToJoinOrganization"),
                "blockMsolPowerShell": p.get("blockMsolPowerShell"),
                "defaultUserRolePermissions": p.get("defaultUserRolePermissions"),
                "displayName": p.get("displayName"),
                "description": p.get("description"),
                "enabledPreviewFeatures": p.get("enabledPreviewFeatures"),
                "guestUserRoleId": p.get("guestUserRoleId"),
                "permissionGrantPolicyIdsAssignedToDefaultUserRole":
                    p.get("permissionGrantPolicyIdsAssignedToDefaultUserRole"),
            })
            n += 1
        return n
    guard(sec, runner, go)


# --------------------------------------------------------------------------
# 2. consent

def collect_oauth2grants(runner: Runner) -> None:
    sec = runner.section("OAuth2PermissionGrants")
    def go():
        n = 0
        for g in runner.c.paged("/oauth2PermissionGrants?$top=999"):
            runner.s.upsert("OAuth2PermissionGrants", "objectId", {
                "objectId": g.get("id"),
                "clientId": g.get("clientId"),
                "consentType": g.get("consentType"),
                "expiryTime": g.get("expiryTime"),
                "principalId": g.get("principalId"),
                "resourceId": g.get("resourceId"),
                "scope": g.get("scope"),
                "startTime": g.get("startTime"),
            })
            n += 1
        return n
    guard(sec, runner, go)


# --------------------------------------------------------------------------
# 3. entra role management

def collect_roledefinitions(runner: Runner) -> None:
    sec = runner.section("RoleDefinitions")
    def go():
        n = 0
        for rd in runner.c.paged("/roleManagement/directory/roleDefinitions"):
            runner.s.upsert("RoleDefinitions", "objectId", {
                "objectId": rd.get("id"),
                "objectType": "RoleDefinition",
                "description": rd.get("description"),
                "displayName": rd.get("displayName"),
                "isBuiltIn": rd.get("isBuiltIn"),
                "isEnabled": rd.get("isEnabled"),
                "resourceScopes": rd.get("resourceScopes"),
                "rolePermissions": rd.get("rolePermissions"),
                "templateId": rd.get("templateId"),
                "version": rd.get("version"),
            })
            n += 1
        return n
    guard(sec, runner, go)


def collect_roleassignments(runner: Runner) -> None:
    sec = runner.section("RoleAssignments")
    def go():
        n = 0
        for ra in runner.c.paged("/roleManagement/directory/roleAssignments?$top=999"):
            scope = ra.get("directoryScopeId")
            if ra.get("appScopeId"):
                scope = ra["appScopeId"]
            runner.s.upsert("RoleAssignments", "id", {
                "id": ra.get("id"),
                "principalId": ra.get("principalId"),
                "roleDefinitionId": ra.get("roleDefinitionId"),
                "resourceScopes": jstr([scope]) if scope else jstr(["/"]),
            })
            # Graph's /directoryRoles/{id}/members omits service principals;
            # rebuild role-member links from the assignment (directory scope only).
            if (ra.get("directoryScopeId") == "/" and not ra.get("appScopeId")
                    and ra.get("principalId") and ra.get("roleDefinitionId")):
                role_row = runner.s.conn.execute(
                    "SELECT objectId FROM DirectoryRoles WHERE roleTemplateId=? LIMIT 1",
                    (ra["roleDefinitionId"],)).fetchone()
                if role_row:
                    pid = ra["principalId"]
                    for tbl, col, objtbl in (
                            ("lnk_role_member_user", "User", "Users"),
                            ("lnk_role_member_group", "Group", "Groups"),
                            ("lnk_role_member_serviceprincipal", "ServicePrincipal",
                             "ServicePrincipals")):
                        if runner.s.conn.execute(
                                f'SELECT 1 FROM "{objtbl}" WHERE objectId=? LIMIT 1',
                                (pid,)).fetchone():
                            runner.s.add_link(tbl, {"DirectoryRole": role_row[0],
                                                    col: pid})
                            break
            n += 1
        return n
    guard(sec, runner, go)


def collect_eligible_roles(runner: Runner) -> None:
    sec = runner.section("EligibleRoleAssignments")
    def go():
        n = 0
        for e in runner.c.paged("/roleManagement/directory/roleEligibilitySchedules"):
            runner.s.upsert("EligibleRoleAssignments", "id", {
                "id": e.get("id"),
                "principalId": e.get("principalId"),
                "roleDefinitionId": e.get("roleDefinitionId"),
                "resourceScopes": jstr([e.get("directoryScopeId", "/")]),
            })
            n += 1
        return n
    guard(sec, runner, go)


def collect_pim_directory(runner: Runner) -> None:
    """Legacy-PIM tables for aadroles rebuilt from unifiedRoleManagement schedules."""
    sec = runner.section("PIM (aadroles)")
    n_ra = n_req = 0
    try:
        for s in runner.c.paged("/roleManagement/directory/roleAssignmentSchedules"):
            runner.s.upsert("PIMgovernanceRoleAssignments", "id", {
                "id": s.get("id"), "resourceId": "aadroles",
                "roleDefinitionId": s.get("roleDefinitionId"),
                "subjectId": s.get("principalId"),
                "scopedResourceId": s.get("directoryScopeId"),
                "linkedEligibleRoleAssignmentId": s.get("eligibilityScheduleId"),
                "startDateTime": s.get("startDateTime"),
                "endDateTime": s.get("endDateTime"),
                "memberType": s.get("memberType"),
                "assignmentState": "Active",
                "status": s.get("status"),
            })
            n_ra += 1
    except Degraded as d:
        runner.finish(sec, "degraded", note=f"HTTP {d.status}")
        return
    try:
        for s in runner.c.paged("/roleManagement/directory/roleEligibilitySchedules"):
            runner.s.upsert("PIMgovernanceRoleAssignments", "id", {
                "id": s.get("id"), "resourceId": "aadroles",
                "roleDefinitionId": s.get("roleDefinitionId"),
                "subjectId": s.get("principalId"),
                "scopedResourceId": s.get("directoryScopeId"),
                "startDateTime": s.get("startDateTime"),
                "endDateTime": s.get("endDateTime"),
                "memberType": s.get("memberType"),
                "assignmentState": "Eligible",
                "status": s.get("status"),
            })
            n_ra += 1
    except Degraded:
        pass
    try:
        for rq in runner.c.paged("/roleManagement/directory/roleAssignmentScheduleRequests"):
            si = rq.get("scheduleInfo") or {}
            exp = si.get("expiration") or {}
            ti = rq.get("ticketInfo") or {}
            runner.s.upsert("PIMgovernanceRoleAssignmentRequests", "id", {
                "id": rq.get("id"), "resourceId": "aadroles",
                "roleDefinitionId": rq.get("roleDefinitionId"),
                "subjectId": rq.get("principalId"),
                "type": rq.get("type"),
                "assignmentState": rq.get("action"),
                "requestedDateTime": rq.get("createdDateTime"),
                "roleAssignmentStartDateTime": si.get("startDateTime"),
                "roleAssignmentEndDateTime": exp.get("endDateTime"),
                "reason": rq.get("justification"),
                "status": rq.get("status"),
                "schedule": si or None,
                "ticketNumber": ti.get("ticketNumber"),
                "ticketSystem": ti.get("ticketSystem"),
            })
            n_req += 1
    except Degraded:
        pass
    try:
        for rq in runner.c.paged("/roleManagement/directory/roleEligibilityScheduleRequests"):
            si = rq.get("scheduleInfo") or {}
            exp = si.get("expiration") or {}
            ti = rq.get("ticketInfo") or {}
            runner.s.upsert("PIMgovernanceRoleAssignmentRequests", "id", {
                "id": rq.get("id"), "resourceId": "aadroles",
                "roleDefinitionId": rq.get("roleDefinitionId"),
                "subjectId": rq.get("principalId"),
                "type": rq.get("type"),
                "assignmentState": rq.get("action"),
                "requestedDateTime": rq.get("createdDateTime"),
                "roleAssignmentStartDateTime": si.get("startDateTime"),
                "roleAssignmentEndDateTime": exp.get("endDateTime"),
                "reason": rq.get("justification"),
                "status": rq.get("status"),
                "schedule": si or None,
                "ticketNumber": ti.get("ticketNumber"),
                "ticketSystem": ti.get("ticketSystem"),
            })
            n_req += 1
    except Degraded:
        pass
    runner.finish(sec, "ok" if n_ra else "partial",
                  n_ra, f"requests: {n_req}")


def collect_pim_static(runner: Runner) -> None:
    sec = runner.section("PIMprivilegedAccesss")
    for pid in ("aadroles", "aadgroups", "azureResources"):
        runner.s.upsert("PIMprivilegedAccesss", "id", {"id": pid})
    runner.finish(sec, "ok", 3)


def collect_pim_groups(runner: Runner, groups: list[dict]) -> None:
    """PIM for Groups (aadgroups). Probe once: if the token has no PIM-for-groups
    permission, skip the whole section instead of hitting every group."""
    sec = runner.section("PIM (aadgroups)")
    if not groups:
        runner.finish(sec, "skipped", note="no groups")
        return
    probe_gid = groups[0]["id"]
    try:
        list(runner.c.paged(
            "/identityGovernance/privilegedAccess/group/assignmentSchedules"
            f"?$filter=groupId eq '{probe_gid}'"))
    except Degraded as d:
        if d.status == 403 or "PermissionScopeNotGranted" in d.body:
            runner.finish(sec, "degraded", note="no PIM-for-groups permission")
            return
    n_ra = n_req = 0
    perm_denied = 0
    requests = []
    for group in groups:
        gid = group["id"]
        requests.extend([
            {"key": f"{gid}|active",
             "path": ("/identityGovernance/privilegedAccess/group/"
                      f"assignmentSchedules?$filter=groupId eq '{gid}'"),
             "api": API},
            {"key": f"{gid}|eligible",
             "path": ("/identityGovernance/privilegedAccess/group/"
                      f"eligibilitySchedules?$filter=groupId eq '{gid}'"),
             "api": API},
            {"key": f"{gid}|assignment_requests",
             "path": ("/identityGovernance/privilegedAccess/group/"
                      "assignmentScheduleRequests"
                      f"?$filter=groupId eq '{gid}'"),
             "api": API},
            {"key": f"{gid}|eligibility_requests",
             "path": ("/identityGovernance/privilegedAccess/group/"
                      "eligibilityScheduleRequests"
                      f"?$filter=groupId eq '{gid}'"),
             "api": API},
        ])
    results = fetch_paged_batch(runner.c, requests)

    for group in groups:
        gid = group["id"]
        for state, suffix in (("Active", "active"), ("Eligible", "eligible")):
            result = results.get(f"{gid}|{suffix}")
            if result is None:
                continue
            if result.error:
                if (result.status == 403
                        or "PermissionScopeNotGranted" in (result.body or "")):
                    perm_denied += 1
                continue
            for schedule in result.items:
                runner.s.upsert("PIMgovernanceRoleAssignments", "id", {
                    "id": schedule.get("id"), "resourceId": gid,
                    "roleDefinitionId": schedule.get("accessId"),
                    "subjectId": schedule.get("principalId"),
                    "scopedResourceId": gid,
                    "startDateTime": schedule.get("startDateTime"),
                    "endDateTime": schedule.get("endDateTime"),
                    "memberType": schedule.get("memberType"),
                    "assignmentState": state,
                    "status": schedule.get("status"),
                })
                n_ra += 1
        for suffix in ("assignment_requests", "eligibility_requests"):
            result = results.get(f"{gid}|{suffix}")
            if result is None or result.error:
                continue
            for request in result.items:
                runner.s.upsert("PIMgovernanceRoleAssignmentRequests", "id", {
                    "id": request.get("id"), "resourceId": gid,
                    "roleDefinitionId": request.get("accessId"),
                    "subjectId": request.get("principalId"),
                    "type": request.get("type"),
                    "assignmentState": request.get("action"),
                    "requestedDateTime": request.get("createdDateTime"),
                    "reason": request.get("justification"),
                    "status": request.get("status"),
                    "schedule": request.get("scheduleInfo"),
                })
                n_req += 1
    if perm_denied >= len(groups):
        runner.finish(sec, "degraded", note="no PIM-for-groups permission")
    else:
        runner.finish(sec, "ok" if n_ra else "partial", n_ra, f"requests: {n_req}")


# --------------------------------------------------------------------------
# 4. identity governance / entitlement management

def collect_ig(runner: Runner) -> None:
    sec = runner.section("IdentityGovernance")
    try:
        cats = list(runner.c.paged("/identityGovernance/entitlementManagement/catalogs"))
    except Degraded as d:
        runner.finish(sec, "degraded", note=f"HTTP {d.status}")
        return
    n = {"catalogs": 0, "packages": 0, "policies": 0, "assignments": 0,
         "requests": 0, "resources": 0, "resourceRequests": 0, "subjects": 0,
         "rr": 0, "roles": 0, "scopes": 0, "connectedOrgs": 0}
    for c in cats:
        runner.s.upsert("IGaccessPackageCatalogs", "id", c)
        n["catalogs"] += 1
    try:
        for p in runner.c.paged("/identityGovernance/entitlementManagement/accessPackages"):
            runner.s.upsert("IGaccessPackages", "id", p)
            n["packages"] += 1
            cat_id = p.get("catalogId")
            if cat_id:
                runner.s.add_link("lnk_ig_ap", {"IGaccessPackageCatalog": cat_id,
                                                "IGaccessPackage": p["id"]})
    except Degraded:
        pass
    try:
        for p in runner.c.paged("/identityGovernance/entitlementManagement/assignmentPolicies"):
            runner.s.upsert("IGaccessPackageAssignmentPolicys", "id", p)
            n["policies"] += 1
    except Degraded:
        pass
    try:
        for a in runner.c.paged("/identityGovernance/entitlementManagement/assignments"):
            runner.s.upsert("IGaccessPackageAssignments", "id", a)
            n["assignments"] += 1
    except Degraded:
        pass
    try:
        for rq in runner.c.paged("/identityGovernance/entitlementManagement/assignmentRequests"):
            runner.s.upsert("IGaccessPackageAssignmentRequests", "id", rq)
            n["requests"] += 1
    except Degraded:
        pass
    resources = []
    try:
        for r in runner.c.paged("/identityGovernance/entitlementManagement/resources"):
            runner.s.upsert("IGaccessPackageResources", "id", r)
            n["resources"] += 1
            resources.append(r)
    except Degraded:
        pass
    requests = []
    for resource in resources:
        rid = resource["id"]
        requests.extend([
            {"key": f"{rid}|roles",
             "path": ("/identityGovernance/entitlementManagement/resources/"
                      f"{rid}/roles"),
             "api": API},
            {"key": f"{rid}|scopes",
             "path": ("/identityGovernance/entitlementManagement/resources/"
                      f"{rid}/scopes"),
             "api": API},
        ])
    results = fetch_paged_batch(runner.c, requests)
    for resource in resources:
        rid = resource["id"]
        roles = results.get(f"{rid}|roles")
        if roles is not None and not roles.error:
            for role in roles.items:
                runner.s.upsert("IGaccessPackageResourceRoles", "id", role)
                n["roles"] += 1
                runner.s.add_link("lnk_ig_ap_rr", {
                    "IGaccessPackageResource": rid,
                    "IGaccessPackageResourceRole": role["id"]})
        scopes = results.get(f"{rid}|scopes")
        if scopes is not None and not scopes.error:
            for scope in scopes.items:
                runner.s.upsert("IGaccessPackageResourceScopes", "id", scope)
                n["scopes"] += 1
    try:
        for rr in runner.c.paged("/identityGovernance/entitlementManagement/resourceRequests"):
            runner.s.upsert("IGaccessPackageResourceRequests", "id", rr)
            n["resourceRequests"] += 1
    except Degraded:
        pass
    try:
        for s in runner.c.paged("/identityGovernance/entitlementManagement/subjects"):
            row = dict(s)
            if s.get("objectId"):
                row["objectId"] = s["objectId"]
            runner.s.upsert("IGaccessPackageSubjects", "id", row)
            n["subjects"] += 1
    except Degraded:
        pass
    try:
        for _co in runner.c.paged("/identityGovernance/entitlementManagement/connectedOrganizations"):
            n["connectedOrgs"] += 1
    except Degraded:
        pass
    runner.finish(sec, "ok", sum(n.values()), note=str(n))


# --------------------------------------------------------------------------
# 5. policies

def collect_conditionalaccess(runner: Runner) -> None:
    sec = runner.section("Policys (conditionalAccess)")
    def go():
        n = 0
        for p in runner.c.paged("/identity/conditionalAccess/policies"):
            runner.s.upsert("Policys", "objectId", {
                "objectId": p.get("id"),
                "objectType": "Policy",
                "displayName": p.get("displayName"),
                "policyType": 18,
                "policyIdentifier": p.get("modifiedDateTime"),
                "policyDetail": jstr([json.dumps(p, default=str)]),
            })
            n += 1
            cond = (p.get("conditions") or {}).get("users") or {}
            inc = cond.get("includeUsers") or []
            exc = cond.get("excludeUsers") or []
            if "All" in inc:
                runner.s.add_link("lnk_policy_user_include_allusers",
                                  {"Policy": p["id"]})
            for uid in inc:
                if uid not in ("All", "None", "GuestsOrExternalUsers"):
                    runner.s.add_link("lnk_policy_user_include",
                                      {"Policy": p["id"], "User": uid})
            for uid in exc:
                if uid not in ("All", "None", "GuestsOrExternalUsers"):
                    runner.s.add_link("lnk_policy_user_exclude",
                                      {"Policy": p["id"], "User": uid})
        return n
    guard(sec, runner, go)


def collect_securitydefaults(runner: Runner) -> None:
    sec = runner.section("Policys (securityDefaults)")
    def go():
        r = runner.c.get("/policies/identitySecurityDefaultsEnforcementPolicy")
        if r.status_code != 200:
            raise Degraded(r.status_code, r.url, r.text)
        p = r.json()
        runner.s.upsert("Policys", "objectId", {
            "objectId": p.get("id"), "objectType": "Policy",
            "displayName": "Security Defaults", "policyType": 10,
            "policyDetail": jstr([json.dumps(p, default=str)]),
        })
        return 1
    guard(sec, runner, go)


def collect_authmethods(runner: Runner) -> None:
    """TAP (type 44) and FIDO2 (type 24) configurations (beta)."""
    sec = runner.section("Policys (authMethods)")
    def one(name, ptype):
        r = runner.c.get(
            "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/"
            + name, api=BETA)
        if r.status_code != 200:
            raise Degraded(r.status_code, r.url, r.text)
        p = r.json()
        runner.s.upsert("Policys", "objectId", {
            "objectId": p.get("id"), "objectType": "Policy",
            "displayName": p.get("displayName") or name, "policyType": ptype,
            "policyDetail": jstr([json.dumps(p, default=str)]),
        })
        return 1
    n = 0
    for name, ptype in (("temporaryAccessPass", 44), ("fido2", 24)):
        try:
            n += one(name, ptype)
        except Degraded:
            pass
    runner.finish(sec, "ok" if n else "degraded", n)


# --------------------------------------------------------------------------
# 6. azure resource manager (management.azure.com)

def collect_arm(arm: ArmClient, runner: Runner, subs: list[dict]) -> None:
    sec = runner.section("AZsubscriptions")
    for s in subs:
        runner.s.upsert("AZsubscriptions", "id", {
            "id": s.get("subscriptionId"),
            "subscription_id": s.get("subscriptionId"),
            "display_name": s.get("displayName"),
            "state": s.get("state"),
            "subscription_policies": s.get("subscriptionPolicies"),
            "authorization_source": s.get("authorizationSource"),
        })
    runner.finish(sec, "ok", len(subs))

    for sub in subs:
        sid = sub["subscriptionId"]
        sec = runner.section(f"AZresources ({sid[:8]})")
        try:
            r = arm.get(f"https://management.azure.com/subscriptions/{sid}/resources"
                        "?api-version=2022-09-01")
            if r.status_code != 200:
                raise Degraded(r.status_code, r.url, r.text)
            items = r.json().get("value", [])
            for res in items:
                parts = res["id"].split("/")
                rg = ""
                if "resourceGroups" in parts:
                    rg = parts[parts.index("resourceGroups") + 1]
                runner.s.upsert("AZresources", "id", {
                    "id": res.get("id"), "name": res.get("name"),
                    "type": res.get("type"),
                    "type_display_name": res.get("type"),
                    "resource_group": rg,
                    "location": res.get("location"),
                    "location_display_name": res.get("location"),
                    "subscription_id": sid,
                    "subscription_display_name": sub.get("displayName"),
                    "kind": res.get("kind"),
                    "tags": res.get("tags"),
                    "extended_location": res.get("extendedLocation"),
                })
            runner.finish(sec, "ok", len(items))
        except Degraded as d:
            runner.finish(sec, "degraded", note=f"HTTP {d.status}")

        sec = runner.section(f"AZroleDefinitions ({sid[:8]})")
        try:
            r = arm.get(f"https://management.azure.com/subscriptions/{sid}/providers/"
                        "Microsoft.Authorization/roleDefinitions?api-version=2022-04-01")
            if r.status_code != 200:
                raise Degraded(r.status_code, r.url, r.text)
            items = r.json().get("value", [])
            for rd in items:
                props = rd.get("properties") or {}
                runner.s.upsert("AZroleDefinitions", "id", {
                    "id": rd.get("id"), "name": rd.get("name"),
                    "type": rd.get("type"),
                    "role_name": props.get("roleName"),
                    "description": props.get("description"),
                    "role_type": props.get("type"),
                    "created_on": props.get("createdOn"),
                    "permissions": props.get("permissions"),
                })
            runner.finish(sec, "ok", len(items))
        except Degraded as d:
            runner.finish(sec, "degraded", note=f"HTTP {d.status}")

        sec = runner.section(f"AZroleAssignments ({sid[:8]})")
        n_ra = 0
        scopes = [f"/subscriptions/{sid}"]
        try:
            r = arm.get(f"https://management.azure.com/subscriptions/{sid}/resources"
                        "?api-version=2022-09-01")
            if r.status_code == 200:
                rgs = set()
                for res in r.json().get("value", []):
                    parts = res["id"].split("/")
                    if "resourceGroups" in parts:
                        rgs.add(parts[parts.index("resourceGroups") + 1])
                scopes += [f"/subscriptions/{sid}/resourceGroups/{rg}" for rg in rgs]
        except Degraded:
            pass
        for scope in scopes:
            try:
                r = arm.get(f"https://management.azure.com{scope}/providers/"
                            "Microsoft.Authorization/roleAssignments?api-version=2022-04-01")
                if r.status_code != 200:
                    raise Degraded(r.status_code, r.url, r.text)
                for ra in r.json().get("value", []):
                    props = ra.get("properties") or {}
                    pid = props.get("principalId")
                    ptype = props.get("principalType")
                    runner.s.upsert("AZroleAssignments", "id", {
                        "id": ra.get("id"), "name": ra.get("name"),
                        "type": ra.get("type"), "scope": props.get("scope"),
                        "role_definition_id": props.get("roleDefinitionId"),
                        "principal_id": pid, "principal_type": ptype,
                        "description": props.get("description"),
                        "condition": props.get("condition"),
                        "condition_version": props.get("conditionVersion"),
                        "created_on": props.get("createdOn"),
                        "delegated_managed_identity_resource_id":
                            props.get("delegatedManagedIdentityResourceId"),
                    })
                    n_ra += 1
                    if pid and ptype:
                        link = {"AZroleAssignment": ra["id"]}
                        if ptype == "User":
                            runner.s.add_link("lnk_az_roleassignment_user",
                                              {**link, "User": pid})
                        elif ptype == "ServicePrincipal":
                            runner.s.add_link("lnk_az_roleassignment_serviceprincipal",
                                              {**link, "ServicePrincipal": pid})
                        elif ptype == "Group":
                            runner.s.add_link("lnk_az_roleassignment_group",
                                              {**link, "Group": pid})
            except Degraded:
                pass
        runner.finish(sec, "ok" if n_ra else "degraded", n_ra)

        sec = runner.section(f"AZroleEligibilityScheduleInstances ({sid[:8]})")
        try:
            r = arm.get(f"https://management.azure.com/subscriptions/{sid}/providers/"
                        "Microsoft.Authorization/roleEligibilityScheduleInstances"
                        "?api-version=2022-04-01-preview")
            if r.status_code != 200:
                raise Degraded(r.status_code, r.url, r.text)
            items = r.json().get("value", [])
            for e in items:
                props = e.get("properties") or {}
                pid = props.get("principalId")
                ptype = props.get("principalType")
                runner.s.upsert("AZroleEligibilityScheduleInstances", "id", {
                    "id": e.get("id"), "name": e.get("name"), "type": e.get("type"),
                    "role_definition_id": props.get("roleDefinitionId"),
                    "principal_id": pid, "principal_type": ptype,
                    "scope": props.get("scope"),
                    "role_eligibility_schedule_id": props.get("roleEligibilityScheduleId"),
                    "status": props.get("status"),
                    "start_date_time": props.get("startDateTime"),
                    "end_date_time": props.get("endDateTime"),
                    "member_type": props.get("memberType"),
                    "condition": props.get("condition"),
                    "condition_version": props.get("conditionVersion"),
                    "created_on": props.get("createdOn"),
                    "expanded_properties": props,
                })
                if pid and ptype:
                    link = {"AZroleEligibilityScheduleInstance": e["id"]}
                    if ptype == "User":
                        runner.s.add_link("lnk_az_roleassignment_eligible_user",
                                          {**link, "User": pid})
                    elif ptype == "ServicePrincipal":
                        runner.s.add_link("lnk_az_roleassignment_eligible_serviceprincipal",
                                          {**link, "ServicePrincipal": pid})
                    elif ptype == "Group":
                        runner.s.add_link("lnk_az_roleassignment_eligible_group",
                                          {**link, "Group": pid})
            runner.finish(sec, "ok", len(items))
        except Degraded as d:
            runner.finish(sec, "degraded", note=f"HTTP {d.status}")

    sec = runner.section("AZmanagementGroups")
    try:
        r = arm.get("https://management.azure.com/providers/Microsoft.Management/"
                    "managementGroups?api-version=2021-04-01")
        if r.status_code != 200:
            raise Degraded(r.status_code, r.url, r.text)
        items = r.json().get("value", [])
        for mg in items:
            props = mg.get("properties") or {}
            runner.s.upsert("AZmanagementGroups", "id", {
                "id": mg.get("id"), "name": mg.get("name"), "type": mg.get("type"),
                "display_name": props.get("displayName"),
                "tenant_id": props.get("tenantId"),
                "details": props,
            })
        runner.finish(sec, "ok", len(items))
    except Degraded as d:
        runner.finish(sec, "degraded", note=f"HTTP {d.status}")


def check_arm(arm: ArmClient) -> list[dict]:
    """Quick ARM capability check: list subscriptions, skip if none/denied."""
    try:
        r = arm.get("https://management.azure.com/subscriptions?api-version=2022-12-01")
    except Exception:
        return []
    if r.status_code != 200:
        print(f"[arm] subscriptions call failed ({r.status_code}); skipping Azure tables")
        return []
    subs = r.json().get("value", [])
    if not subs:
        print("[arm] no subscriptions visible to this identity; skipping Azure tables")
    return subs


# --------------------------------------------------------------------------
# orchestration

def collect_all(client: GraphClient, arm: Optional[ArmClient],
                store: Store, verbose: int = 0) -> Runner:
    runner = Runner(client, store, verbose)
    store.clear_links()

    collect_tenant(runner)
    collect_users(runner)
    # groups first: later sections need the group list
    groups = collect_groups(runner)
    collect_applications(runner)
    collect_serviceprincipals(runner)
    collect_devices(runner)
    collect_contacts(runner)
    collect_directoryroles(runner)
    collect_adminunits(runner)
    collect_directorysettings(runner)
    collect_authorizationpolicy(runner)
    collect_oauth2grants(runner)

    collect_roledefinitions(runner)
    collect_roleassignments(runner)
    collect_eligible_roles(runner)
    # derive AAD-Graph-only role flags from unifiedRoleDefinition
    try:
        runner.s.conn.execute("""
            UPDATE DirectoryRoles SET
              isSystem = (SELECT isBuiltIn FROM RoleDefinitions rd
                          WHERE rd.objectId = DirectoryRoles.roleTemplateId),
              roleDisabled = (SELECT CASE WHEN isEnabled = 0 THEN 1 ELSE 0 END
                              FROM RoleDefinitions rd
                              WHERE rd.objectId = DirectoryRoles.roleTemplateId)
            WHERE roleTemplateId IS NOT NULL
        """)
    except sqlite3.OperationalError:
        pass
    collect_pim_static(runner)
    collect_pim_directory(runner)
    collect_pim_groups(runner, groups)

    collect_ig(runner)
    collect_conditionalaccess(runner)
    collect_securitydefaults(runner)
    collect_authmethods(runner)

    sec = runner.section("AppRoleAssignments (total)")
    runner.finish(sec, "ok", store.count("AppRoleAssignments"))

    if arm is not None:
        subs = check_arm(arm)
        if subs:
            collect_arm(arm, runner, subs)
    else:
        sec = runner.section("AZ (ARM)")
        runner.finish(sec, "skipped", note="no ARM token")

    store.commit()
    return runner

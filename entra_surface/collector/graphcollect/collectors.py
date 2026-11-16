"""Endpoint -> ROADrecon-table collectors. Every section degrades gracefully:
a failing endpoint logs a warning and the run continues with everything else.
"""
from __future__ import annotations

import json
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

from .client import ArmClient, BatchPagedResult, Degraded, GraphClient
from .store import Store

API = "v1.0"
BETA = "beta"
WORKERS = 12

# Graph returns only its default user properties unless $select is explicit.
# Every scalar/nested field consumed by collect_users()/dir_row() is listed
# here, including the hybrid, licensing, guest and extension-attribute data the
# analysis relies on.
USER_SELECT_BETA = (
    "id,accountEnabled,displayName,givenName,surname,mail,mailNickname,"
    "userPrincipalName,userType,businessPhones,mobilePhone,faxNumber,jobTitle,"
    "department,companyName,officeLocation,city,state,country,postalCode,"
    "streetAddress,preferredLanguage,usageLocation,createdDateTime,"
    "deletedDateTime,onPremisesSyncEnabled,onPremisesLastSyncDateTime,"
    "onPremisesImmutableId,onPremisesSecurityIdentifier,"
    "onPremisesDistinguishedName,onPremisesUserPrincipalName,"
    "onPremisesObjectIdentifier,onPremisesDomainName,onPremisesSamAccountName,"
    "onPremisesProvisioningErrors,onPremisesExtensionAttributes,"
    "onPremisesLastPasswordChangeDateTime,onPremisesSipInfo,"
    "lastPasswordChangeDateTime,externalUserState,"
    "externalUserStateChangeDateTime,proxyAddresses,assignedLicenses,"
    "assignedPlans,provisionedPlans,serviceProvisioningErrors,passwordProfile,"
    "passwordPolicies,otherMails,employeeOrgData,employeeId,employeeType,"
    "employeeHireDate,identities,infoCatalogs,inviteTicket,deviceKeys,"
    "cloudRealtimeCommunicationInfo,securityIdentifier,ageGroup,"
    "consentProvidedForMinor,legalAgeGroupClassification,creationType,"
    "isResourceAccount,showInAddressList,refreshTokensValidFromDateTime,"
    "preferredDataLocation"
)
# v1.0 rejects beta-only properties.  Keep the fallback selection to stable
# v1.0 fields; it still covers every field the collector/analysis needs.
USER_SELECT_V1 = (
    "id,accountEnabled,displayName,givenName,surname,mail,mailNickname,"
    "userPrincipalName,userType,businessPhones,mobilePhone,faxNumber,jobTitle,"
    "department,companyName,officeLocation,city,state,country,postalCode,"
    "streetAddress,preferredLanguage,usageLocation,createdDateTime,"
    "deletedDateTime,onPremisesSyncEnabled,onPremisesLastSyncDateTime,"
    "onPremisesImmutableId,onPremisesSecurityIdentifier,"
    "onPremisesDistinguishedName,onPremisesUserPrincipalName,"
    "onPremisesDomainName,onPremisesSamAccountName,onPremisesProvisioningErrors,"
    "onPremisesExtensionAttributes,lastPasswordChangeDateTime,"
    "externalUserState,"
    "externalUserStateChangeDateTime,proxyAddresses,assignedLicenses,"
    "assignedPlans,provisionedPlans,serviceProvisioningErrors,passwordProfile,"
    "passwordPolicies,otherMails,employeeOrgData,employeeId,employeeType,"
    "employeeHireDate,identities,securityIdentifier,ageGroup,"
    "consentProvidedForMinor,legalAgeGroupClassification,creationType,"
    "isResourceAccount,showInAddressList,preferredDataLocation"
)


def parallel_map(fn: Callable, items: list, workers: int = WORKERS) -> list:
    items = list(items)
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as ex:
        return list(ex.map(fn, items))


def fetch_paged_batch(client, requests: list[dict]) -> dict[str, BatchPagedResult]:
    """Fetch independent paged endpoints, using Graph $batch when enabled.

    A failure on a later page keeps every page already received.  Callers
    process ``result.items`` even when ``result.error`` is set and mark the
    section partial instead of discarding the relationship.
    """
    if getattr(client, "batch", False):
        return client.batch_paged_many(requests)
    results: dict[str, BatchPagedResult] = {}

    def fetch(request):
        items = []
        status = 0
        error = ""
        try:
            for item in client.paged(
                    request["path"], api=request.get("api", API)):
                items.append(item)
        except Degraded as exc:
            status = exc.status
            error = f"{exc.status} {exc.body[:200]}"
        except Exception as exc:  # malformed page / transport failure
            error = str(exc)[:200]
        return request["key"], items, status, error

    for key, items, status, body in parallel_map(fetch, requests):
        result = BatchPagedResult()
        result.items = items
        result.status = status
        result.body = body
        if status or body:
            result.error = f"{status} {body[:200]}".strip()
        results[key] = result
    return results


def arm_paged(arm, url: str, max_pages: int = 10000) -> tuple[list, str]:
    """Follow ARM ``nextLink`` pages, returning collected items and any error.

    The caller marks the section partial when items were returned before the
    paging failure, and degraded when the first page failed.
    """
    items: list = []
    error = ""
    next_url = url
    pages = 0
    while next_url:
        try:
            response = arm.get(next_url)
            if response.status_code != 200:
                raise Degraded(response.status_code, next_url, response.text)
            data = response.json()
        except Degraded as exc:
            error = f"HTTP {exc.status}"
            break
        except Exception as exc:
            error = str(exc)[:200]
            break
        if not isinstance(data, dict):
            error = "invalid ARM response"
            break
        items.extend(data.get("value") or [])
        link = data.get("nextLink") or data.get("@odata.nextLink") or ""
        if not link:
            break
        pages += 1
        if pages >= max_pages:
            error = "pagination cap reached"
            break
        next_url = str(link)
    return items, error

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
    rename_sources = set(renames or {})
    for k, v in obj.items():
        if k.startswith("@") or k in ("id", "deletedDateTime"):
            continue
        if k in rename_sources:
            continue
        if isinstance(v, (dict, list)):
            continue
        row[k] = v
    row["objectId"] = obj.get("id")
    row["objectType"] = obj_type
    # ROADrecon uses deletionTimestamp; Graph uses deletedDateTime.
    if obj.get("deletedDateTime") is not None and not obj.get("deletionTimestamp"):
        row["deletionTimestamp"] = obj["deletedDateTime"]
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
    beta_note = ""

    def store_user(u: dict) -> None:
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

    def go_beta():
        for u in runner.c.paged(
                f"/users?$top=999&$select={USER_SELECT_BETA}", api=BETA):
            store_user(u)
        return len(users)

    n = guard(sec, runner, go_beta, auto_finish=False)
    if n is None:
        # Beta is optional; v1.0 still returns the fields the analysis needs.
        users.clear()
        beta_note = "beta unavailable; used v1.0"

        def go_v1():
            for u in runner.c.paged(
                    f"/users?$top=999&$select={USER_SELECT_V1}"):
                store_user(u)
            return len(users)

        n = guard(sec, runner, go_v1, auto_finish=False)
    if n is None:
        # Last resort: a token with an unusual schema may reject one of the
        # older properties.  At least collect the Graph default fields.
        users.clear()
        beta_note = "restricted user properties; used default fields"

        def go_plain():
            for u in runner.c.paged("/users?$top=999"):
                store_user(u)
            return len(users)

        n = guard(sec, runner, go_plain, auto_finish=False)
    if n is None:
        return users

    # user-principal app role assignments
    approl_n = 0
    failed = 0
    user_ids = [u["id"] for u in users if u.get("id")]
    requests = [{"key": uid, "path": f"/users/{uid}/appRoleAssignments",
                 "api": API} for uid in user_ids]
    for uid, result in fetch_paged_batch(runner.c, requests).items():
        if result.error:
            failed += 1
        for ara in result.items:
            runner.s.upsert("AppRoleAssignments", "objectId",
                            app_role_row(ara))
            approl_n += 1
    note = f"user appRoleAssignments: {approl_n}"
    if failed:
        note += f", {failed} relationship request(s) partial"
    if beta_note:
        note = f"{beta_note}; {note}"
    runner.finish(sec, "ok" if not failed else "partial", n, note)
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
    failed = {"members": 0, "servicePrincipalMembers": 0, "deviceMembers": 0,
              "owners": 0, "appRoleAssignments": 0}
    approl_n = 0
    group_ids = [g["id"] for g in groups if g.get("id")]
    requests = []
    for gid in group_ids:
        # /members is direct containment.  Effective (transitive) membership is
        # derived in analysis from these direct edges, so hierarchy, parent and
        # "via" path display stay accurate.
        #
        # Graph's generic /members listing can omit service principals (and
        # devices); the typed casts are the reliable way to capture those
        # direct members.  Missing them drops SP group memberships, which in
        # turn hides directory roles inherited through the group.
        requests.extend([
            {"key": f"{gid}|members",
             "path": f"/groups/{gid}/members", "api": API},
            {"key": f"{gid}|sp_members",
             "path": f"/groups/{gid}/members/microsoft.graph.servicePrincipal",
             "api": API},
            {"key": f"{gid}|device_members",
             "path": f"/groups/{gid}/members/microsoft.graph.device",
             "api": API},
            {"key": f"{gid}|owners",
             "path": f"/groups/{gid}/owners", "api": API},
            {"key": f"{gid}|aras",
             "path": f"/groups/{gid}/appRoleAssignments", "api": API},
        ])
    results = fetch_paged_batch(runner.c, requests)

    for gid in group_ids:
        members = results.get(f"{gid}|members")
        sp_members = results.get(f"{gid}|sp_members")
        device_members = results.get(f"{gid}|device_members")
        owners = results.get(f"{gid}|owners")
        aras = results.get(f"{gid}|aras")
        if members is None:
            failed["members"] += 1
        else:
            if members.error:
                failed["members"] += 1
            members_n += add_dir_links(
                runner.s, "member", "Group", gid, members.items)
        if sp_members is None:
            failed["servicePrincipalMembers"] += 1
        else:
            if sp_members.error:
                failed["servicePrincipalMembers"] += 1
            for member in sp_members.items:
                member.setdefault(
                    "@odata.type", "#microsoft.graph.servicePrincipal")
            members_n += add_dir_links(
                runner.s, "member", "Group", gid, sp_members.items)
        if device_members is None:
            failed["deviceMembers"] += 1
        else:
            if device_members.error:
                failed["deviceMembers"] += 1
            for member in device_members.items:
                member.setdefault("@odata.type", "#microsoft.graph.device")
            members_n += add_dir_links(
                runner.s, "member", "Group", gid, device_members.items)
        if owners is None:
            failed["owners"] += 1
        else:
            if owners.error:
                failed["owners"] += 1
            owners_n += add_dir_links(
                runner.s, "owner", "Group", gid, owners.items)
        if aras is None:
            failed["appRoleAssignments"] += 1
        else:
            if aras.error:
                failed["appRoleAssignments"] += 1
            for ara in aras.items:
                runner.s.upsert("AppRoleAssignments", "objectId",
                                app_role_row(ara))
                approl_n += 1
    failed_n = sum(failed.values())
    note = (f"links: {members_n} members / {owners_n} owners, "
            f"group appRoleAssignments: {approl_n}")
    if failed_n:
        note += " (" + ", ".join(
            f"{kind} failures: {count}"
            for kind, count in failed.items() if count) + ")"
    runner.finish(sec, "ok" if failed_n == 0 else "partial", n, note)
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
    failures = {"owners": 0, "extensionProperties": 0}
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
        if owners is None:
            failures["owners"] += 1
        else:
            if owners.error:
                failures["owners"] += 1
            owners_n += add_dir_links(
                runner.s, "appowner", "Application", aid, owners.items)
        if app.get("appRoles"):
            approles_defined += 1
        if ext_props is None:
            failures["extensionProperties"] += 1
        else:
            if ext_props.error:
                failures["extensionProperties"] += 1
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
    failed_n = sum(failures.values())
    note = (f"owners: {owners_n}, "
            f"apps defining appRoles: {approles_defined}, "
            f"extensionProperties: {ext_n}")
    if failed_n:
        note += " (" + ", ".join(
            f"{kind} failures: {count}"
            for kind, count in failures.items() if count) + ")"
    runner.finish(sec, "ok" if failed_n == 0 else "partial", n, note)
    return apps


def collect_serviceprincipals(runner: Runner) -> list[dict]:
    sec = runner.section("ServicePrincipals")
    merged: dict[str, dict] = {}
    sps: list[dict] = []
    beta_note = ""

    def go_v1():
        for sp in runner.c.paged("/servicePrincipals?$top=999"):
            merged[sp["id"]] = dict(sp)
        return len(merged)

    n = guard(sec, runner, go_v1, auto_finish=False)

    # Beta is an optional enrichment pass.  A failure here must never discard
    # the complete v1.0 service principal list loaded above.
    try:
        for sp in runner.c.paged("/servicePrincipals?$top=999", api=BETA):
            base = merged.get(sp["id"])
            if base is None:
                merged[sp["id"]] = dict(sp)
            else:
                for k, v in sp.items():
                    if k not in base or base[k] in (None, "", []):
                        base[k] = v
    except Degraded as exc:
        beta_note = f"beta enrichment failed (HTTP {exc.status})"
        runner.log(f"  ServicePrincipals: {beta_note}")
    except Exception as exc:
        beta_note = f"beta enrichment failed ({str(exc)[:120]})"
        runner.log(f"  ServicePrincipals: {beta_note}")

    if not merged:
        if n is None:
            return sps
        runner.finish(sec, "degraded", note="no service principals returned")
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
    failures = {"owners": 0, "appRoleAssignments": 0}
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
        if owners is None:
            failures["owners"] += 1
        else:
            if owners.error:
                failures["owners"] += 1
            owners_n += add_dir_links(
                runner.s, "spowner", "ServicePrincipal", sid, owners.items)
        assignments = results.get(f"{sid}|assignments")
        assigned_to = results.get(f"{sid}|assigned_to")
        if assignments is None or assignments.error:
            failures["appRoleAssignments"] += 1
        if assigned_to is None or assigned_to.error:
            failures["appRoleAssignments"] += 1
        aras = []
        if assignments is not None:
            aras.extend(assignments.items)
        if assigned_to is not None:
            aras.extend(assigned_to.items)
        for ara in aras:
            runner.s.upsert("AppRoleAssignments", "objectId",
                            app_role_row(ara, resource_id=sid,
                                         display_name=sp.get("displayName")))
            approl_n += 1
    failed_n = sum(failures.values())
    note = (f"owners: {owners_n}, "
            f"appRoleAssignments: {approl_n}, "
            f"SPs defining appRoles: {sps_with_roles}")
    if beta_note:
        note = f"{beta_note}; {note}"
    if failed_n:
        note += " (" + ", ".join(
            f"{kind} failures: {count}"
            for kind, count in failures.items() if count) + ")"
    runner.finish(sec, "ok" if failed_n == 0 and not beta_note
                  else "partial", len(merged), note)
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
    failed = 0
    requests = [{"key": d["id"], "path": f"/devices/{d['id']}/registeredOwners",
                 "api": API} for d in devices]
    results = fetch_paged_batch(runner.c, requests)
    for device in devices:
        result = results.get(device["id"])
        if result is None:
            failed += 1
            continue
        if result.error:
            failed += 1
        owners_n += add_dir_links(
            runner.s, "devowner", "Device", device["id"], result.items)
    note = f"owners: {owners_n}"
    if failed:
        note += f", {failed} owner request(s) partial"
    runner.finish(sec, "ok" if not failed else "partial", n, note)


def collect_contacts(runner: Runner) -> None:
    sec = runner.section("Contacts")
    def go():
        n = 0
        for c in runner.c.paged("/contacts?$top=999"):
            phones = c.get("businessPhones") or []
            row = dir_row(c, "Contact", renames={
                "onPremisesSyncEnabled": "dirSyncEnabled",
                "onPremisesLastSyncDateTime": "lastDirSyncTime",
                # Same Graph -> ROADrecon mappings as collect_users (B-071).
                "mobilePhone": "mobile",
                "faxNumber": "facsimileTelephoneNumber",
                "onPremisesProvisioningErrors": "provisioningErrors",
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
    failed = 0
    requests = [{"key": role["id"],
                 "path": f"/directoryRoles/{role['id']}/members", "api": API}
                for role in roles]
    results = fetch_paged_batch(runner.c, requests)
    for role in roles:
        result = results.get(role["id"])
        if result is None:
            failed += 1
            continue
        if result.error:
            failed += 1
        members_n += add_dir_links(
            runner.s, "role", "DirectoryRole", role["id"], result.items)
    note = f"members: {members_n}"
    if failed:
        note += f", {failed} member request(s) partial"
    runner.finish(sec, "ok" if not failed else "partial", n, note)


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
    members_n = 0
    failed = 0
    for au in aus:
        result = results.get(au["id"])
        if result is None:
            failed += 1
            continue
        if result.error:
            failed += 1
        members_n += add_dir_links(runner.s, "au", "AdministrativeUnit",
                                   au["id"], result.items)
    note = f"members: {members_n}"
    if failed:
        note += f", {failed} member request(s) partial"
    runner.finish(sec, "ok" if not failed else "partial", n, note)


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


def _pim_is_permanent(schedule: dict) -> bool:
    """PIM assignment is permanent when it has no end date/expiration."""
    if schedule.get("endDateTime"):
        return False
    expiration = schedule.get("scheduleInfo") or schedule.get("expiration")
    if isinstance(expiration, dict):
        if expiration.get("endDateTime"):
            return False
        if str(expiration.get("type") or "").lower() == "noexpiration":
            return True
    return True


def _pim_resource_row(resource_id: str, display_name: str,
                      resource_type: str) -> dict:
    return {
        "id": resource_id,
        "externalId": resource_id,
        "type": resource_type,
        "displayName": display_name,
        "status": "Onboarded",
    }


def _pim_request_row(request: dict, state: str) -> dict:
    si = request.get("scheduleInfo") or {}
    exp = si.get("expiration") or {}
    ti = request.get("ticketInfo") or {}
    # ``type`` carries the Graph request action; assignmentState carries the
    # resulting assignment state (Active/Eligible).
    return {
        "id": request.get("id"),
        "resourceId": "aadroles",
        "roleDefinitionId": request.get("roleDefinitionId"),
        "subjectId": request.get("principalId"),
        "scopedResourceId": request.get("directoryScopeId"),
        "type": request.get("action"),
        "assignmentState": state,
        "requestedDateTime": request.get("createdDateTime"),
        "roleAssignmentStartDateTime": si.get("startDateTime"),
        "roleAssignmentEndDateTime": exp.get("endDateTime"),
        "reason": request.get("justification"),
        "status": request.get("status"),
        "schedule": si or None,
        "ticketNumber": ti.get("ticketNumber"),
        "ticketSystem": ti.get("ticketSystem"),
    }


def collect_pim_directory(runner: Runner) -> None:
    """Legacy-PIM tables for aadroles rebuilt from unifiedRoleManagement schedules."""
    sec = runner.section("PIM (aadroles)")
    n_ra = n_req = n_settings = n_alerts = 0
    failures = []

    try:
        for s in runner.c.paged("/roleManagement/directory/roleAssignmentSchedules"):
            runner.s.upsert("PIMgovernanceRoleAssignments", "id", {
                "id": s.get("id"), "resourceId": "aadroles",
                "roleDefinitionId": s.get("roleDefinitionId"),
                "subjectId": s.get("principalId"),
                "scopedResourceId": s.get("directoryScopeId"),
                "linkedEligibleRoleAssignmentId": s.get("eligibilityScheduleId"),
                "isPermanent": _pim_is_permanent(s),
                "startDateTime": s.get("startDateTime"),
                "endDateTime": s.get("endDateTime"),
                "memberType": s.get("memberType"),
                "assignmentState": "Active",
                "status": s.get("status"),
            })
            n_ra += 1
    except Exception as exc:
        failures.append(f"active schedules: {str(exc)[:100]}")

    try:
        for s in runner.c.paged("/roleManagement/directory/roleEligibilitySchedules"):
            runner.s.upsert("PIMgovernanceRoleAssignments", "id", {
                "id": s.get("id"), "resourceId": "aadroles",
                "roleDefinitionId": s.get("roleDefinitionId"),
                "subjectId": s.get("principalId"),
                "scopedResourceId": s.get("directoryScopeId"),
                "isPermanent": _pim_is_permanent(s),
                "startDateTime": s.get("startDateTime"),
                "endDateTime": s.get("endDateTime"),
                "memberType": s.get("memberType"),
                "assignmentState": "Eligible",
                "status": s.get("status"),
            })
            n_ra += 1
    except Exception as exc:
        failures.append(f"eligibility schedules: {str(exc)[:100]}")

    try:
        for rq in runner.c.paged("/roleManagement/directory/roleAssignmentScheduleRequests"):
            runner.s.upsert("PIMgovernanceRoleAssignmentRequests", "id",
                            _pim_request_row(rq, "Active"))
            n_req += 1
    except Exception as exc:
        failures.append(f"assignment requests: {str(exc)[:100]}")

    try:
        for rq in runner.c.paged(
                "/roleManagement/directory/roleEligibilityScheduleRequests"):
            runner.s.upsert("PIMgovernanceRoleAssignmentRequests", "id",
                            _pim_request_row(rq, "Eligible"))
            n_req += 1
    except Exception as exc:
        failures.append(f"eligibility requests: {str(exc)[:100]}")

    # Role settings (role management policies and their rules).  These APIs are
    # newer than the rest of PIM; failures mark the section partial.
    try:
        policies = list(runner.c.paged("/policies/roleManagementPolicies"))
    except Exception as exc:
        failures.append(f"role settings: {str(exc)[:100]}")
        policies = []
    for policy in policies:
        if (str(policy.get("scopeType") or "").lower() != "directoryrole"
                and str(policy.get("scopeId") or "") != "/"):
            continue
        policy_id = policy.get("id")
        if not policy_id:
            continue
        rules = []
        try:
            rules = list(runner.c.paged(
                f"/policies/roleManagementPolicies/{policy_id}/rules"))
        except Exception as exc:
            failures.append(f"role rules {policy_id}: {str(exc)[:80]}")
        role_id = policy.get("roleDefinitionId") or ""
        updated_by = policy.get("lastModifiedBy")
        runner.s.upsert("PIMgovernanceRoleSettingV2s", "id", {
            "id": policy_id,
            "resourceId": "aadroles",
            "roleDefinitionId": role_id,
            "isDefault": policy.get("isOrganizationDefault"),
            "lastUpdatedDateTime": policy.get("lastModifiedDateTime"),
            "lastUpdatedBy": jstr(updated_by) if updated_by else None,
            "lifeCycleManagement": jstr(rules) if rules else None,
        })
        grouped = {"adminEligibleSettings": [], "adminMemberSettings": [],
                   "userEligibleSettings": [], "userMemberSettings": []}
        for rule in rules:
            rule_id = str(rule.get("id") or "")
            if "AdminEligible" in rule_id or "adminEligible" in rule_id:
                grouped["adminEligibleSettings"].append(rule)
            elif "AdminMember" in rule_id or "adminMember" in rule_id:
                grouped["adminMemberSettings"].append(rule)
            elif "UserEligible" in rule_id or "userEligible" in rule_id:
                grouped["userEligibleSettings"].append(rule)
            elif "UserMember" in rule_id or "userMember" in rule_id:
                grouped["userMemberSettings"].append(rule)
        runner.s.upsert("PIMgovernanceRoleSettings", "id", {
            "id": policy_id,
            "resourceId": "aadroles",
            "roleDefinitionId": role_id,
            "isDefault": policy.get("isOrganizationDefault"),
            "lastUpdatedDateTime": policy.get("lastModifiedDateTime"),
            "lastUpdatedBy": jstr(updated_by) if updated_by else None,
            **{key: jstr(value) if value else None
               for key, value in grouped.items()},
        })
        n_settings += 1

    try:
        for alert in runner.c.paged("/identityGovernance/roleManagementAlerts/alerts"):
            definition = alert.get("alertDefinition") or {}
            runner.s.upsert("PIMgovernanceAlerts", "id", {
                "id": alert.get("id"),
                "resourceId": "aadroles",
                "alertName": definition.get("displayName"),
                "alertDescription": definition.get("description"),
                "numberOfAffectedItems": alert.get("alertIncidentCount"),
                "additionalData": jstr(alert.get("additionalData"))
                    if alert.get("additionalData") else None,
                "lastModifiedDateTime": alert.get("lastModifiedDateTime"),
                "lastScannedDateTime": alert.get("lastScannedDateTime"),
                "severityLevel": definition.get("severityLevel"),
                "alertType": definition.get("alertType"),
                "securityImpact": definition.get("securityImpact"),
                "mitigationSteps": definition.get("mitigationSteps"),
                "howToPrevent": definition.get("howToPrevent"),
                "isDisabled": definition.get("isDisabled"),
                "isActive": definition.get("isEnabled"),
                "isResolvable": definition.get("isRemediatable"),
                "isConfigurable": definition.get("isConfigurable"),
                "status": alert.get("status"),
                "settings": jstr(definition.get("settings"))
                    if definition.get("settings") else None,
            })
            n_alerts += 1
    except Exception as exc:
        failures.append(f"alerts: {str(exc)[:100]}")

    if failures:
        status = "partial" if (n_ra or n_req) else "degraded"
        note = "; ".join(failures)[:300]
    else:
        status = "ok" if n_ra else "partial"
        note = ""
    note = (f"requests: {n_req}, settings: {n_settings}, "
            f"alerts: {n_alerts}" + (f"; {note}" if note else ""))
    runner.finish(sec, status, n_ra, note)


def collect_pim_static(runner: Runner) -> None:
    sec = runner.section("PIMprivilegedAccesss")
    resources = (
        ("aadroles", "Directory roles", "aadroles"),
        ("aadgroups", "Groups", "aadgroups"),
        ("azureResources", "Azure resources", "azureResources"),
    )
    count = 0
    for pid, display_name, resource_type in resources:
        runner.s.upsert("PIMprivilegedAccesss", "id", {
            "id": pid, "displayName": display_name})
        runner.s.upsert("PIMgovernanceResources", "id",
                        _pim_resource_row(pid, display_name, resource_type))
        runner.s.add_link("lnk_pim_resource", {
            "PIMprivilegedAccess": pid, "PIMgovernanceResource": pid})
        count += 1
    # PIM role definitions mirror the directory role definitions so PIM rows
    # carry a resolvable roleDefinitionId.
    for object_id, template_id, display_name in runner.s.conn.execute(
            "SELECT objectId, templateId, displayName FROM RoleDefinitions "
            "WHERE objectId IS NOT NULL").fetchall():
        runner.s.upsert("PIMgovernanceRoleDefinitions", "id", {
            "id": object_id,
            "resourceId": "aadroles",
            "externalId": template_id,
            "templateId": template_id,
            "displayName": display_name,
            "type": "RoleDefinition",
        })
        count += 1
    # PIM for Groups has only the member/owner access IDs; give them resolvable
    # labels while keeping the aadgroups resource type.
    for access_id, display_name in (("member", "Member"), ("owner", "Owner")):
        runner.s.upsert("PIMgovernanceRoleDefinitions", "id", {
            "id": access_id,
            "resourceId": "aadgroups",
            "externalId": access_id,
            "displayName": display_name,
            "type": "GroupAccess",
        })
        count += 1
    runner.finish(sec, "ok", count)


def collect_pim_groups(runner: Runner, groups: list[dict]) -> None:
    """PIM for Groups (aadgroups). Probe once: if the token has no PIM-for-groups
    permission, skip the whole section instead of hitting every group."""
    sec = runner.section("PIM (aadgroups)")
    groups = [g for g in groups if g.get("id")]
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
    failures = 0
    requests = []
    for group in groups:
        gid = group["id"]
        runner.s.upsert("PIMgovernanceResources", "id",
                        _pim_resource_row(
                            gid, group.get("displayName") or gid, "aadgroups"))
        runner.s.add_link("lnk_pim_resource", {
            "PIMprivilegedAccess": "aadgroups", "PIMgovernanceResource": gid})
        runner.s.add_link("lnk_pim_resource_aadgroup", {
            "PIMgovernanceResource": gid, "Group": gid})
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
                failures += 1
                continue
            if result.error:
                if (result.status == 403
                        or "PermissionScopeNotGranted" in (result.body or "")):
                    perm_denied += 1
                else:
                    failures += 1
            for schedule in result.items:
                runner.s.upsert("PIMgovernanceRoleAssignments", "id", {
                    "id": schedule.get("id"), "resourceId": gid,
                    "roleDefinitionId": schedule.get("accessId"),
                    "subjectId": schedule.get("principalId"),
                    "scopedResourceId": gid,
                    "isPermanent": _pim_is_permanent(schedule),
                    "startDateTime": schedule.get("startDateTime"),
                    "endDateTime": schedule.get("endDateTime"),
                    "memberType": schedule.get("memberType"),
                    "assignmentState": state,
                    "status": schedule.get("status"),
                })
                n_ra += 1
        for state, suffix in (("Active", "assignment_requests"),
                              ("Eligible", "eligibility_requests")):
            result = results.get(f"{gid}|{suffix}")
            if result is None:
                failures += 1
                continue
            if result.error:
                if (result.status == 403
                        or "PermissionScopeNotGranted" in (result.body or "")):
                    perm_denied += 1
                else:
                    failures += 1
            for request in result.items:
                runner.s.upsert("PIMgovernanceRoleAssignmentRequests", "id", {
                    "id": request.get("id"), "resourceId": gid,
                    "roleDefinitionId": request.get("accessId"),
                    "subjectId": request.get("principalId"),
                    "type": request.get("action"),
                    "assignmentState": state,
                    "requestedDateTime": request.get("createdDateTime"),
                    "reason": request.get("justification"),
                    "status": request.get("status"),
                    "schedule": request.get("scheduleInfo"),
                })
                n_req += 1
    if perm_denied >= len(groups):
        runner.finish(sec, "degraded", note="no PIM-for-groups permission")
    else:
        status = "ok"
        if failures or perm_denied:
            status = "partial"
        runner.finish(sec, status, n_ra,
                      f"requests: {n_req}"
                      + (f", {failures + perm_denied} request(s) failed"
                         if failures or perm_denied else ""))


# --------------------------------------------------------------------------
# 4. identity governance / entitlement management

def _ig_subject(store: Store, target) -> str:
    """Upsert an access-package subject and return its Graph subject id."""
    if not isinstance(target, dict):
        return ""
    subject_id = target.get("id") or target.get("objectId")
    if not subject_id:
        return ""
    row = dict(target)
    row["id"] = subject_id
    # objectId is nullable in Graph, but the composite primary key needs a
    # stable non-null value; the subject id is the best available fallback.
    row["objectId"] = target.get("objectId") or subject_id
    store.upsert("IGaccessPackageSubjects", ("id", "objectId"), row)
    return subject_id


def collect_ig(runner: Runner) -> None:
    sec = runner.section("IdentityGovernance")
    try:
        cats = list(runner.c.paged(
            "/identityGovernance/entitlementManagement/catalogs"))
    except Exception as exc:
        runner.finish(sec, "degraded", note=str(exc)[:180])
        return
    n = {"catalogs": 0, "packages": 0, "policies": 0, "assignments": 0,
         "requests": 0, "resources": 0, "resourceRequests": 0, "subjects": 0,
         "rr": 0, "roles": 0, "scopes": 0, "connectedOrgs": 0, "roleScopes": 0}
    failures = []

    def fetch(path: str, expand: str = "") -> list:
        if expand:
            try:
                return list(runner.c.paged(f"{path}?$expand={expand}"))
            except Degraded as exc:
                if exc.status != 400:
                    raise
                # Some tenants/API versions reject a navigation expansion;
                # retry without it rather than losing the section.
        return list(runner.c.paged(path))

    for c in cats:
        runner.s.upsert("IGaccessPackageCatalogs", "id", c)
        n["catalogs"] += 1

    packages = []
    try:
        for p in runner.c.paged(
                "/identityGovernance/entitlementManagement/accessPackages"):
            runner.s.upsert("IGaccessPackages", "id", p)
            n["packages"] += 1
            packages.append(p)
            cat_id = p.get("catalogId")
            if cat_id:
                runner.s.add_link("lnk_ig_ap", {"IGaccessPackageCatalog": cat_id,
                                                "IGaccessPackage": p["id"]})
    except Exception as exc:
        failures.append(f"accessPackages: {str(exc)[:100]}")

    try:
        for p in runner.c.paged(
                "/identityGovernance/entitlementManagement/assignmentPolicies"):
            runner.s.upsert("IGaccessPackageAssignmentPolicys", "id", p)
            n["policies"] += 1
            # Specific allowed targets become in-scope links when present.
            targets = p.get("specificAllowedTargets") or []
            for target in targets:
                if not isinstance(target, dict):
                    continue
                for key, table, column in (
                        ("user", "lnk_ig_ap_assignment_policy_inscope_user",
                         "User"),
                        ("group", "lnk_ig_ap_assignment_policy_inscope_group",
                         "Group"),
                        ("servicePrincipal",
                         "lnk_ig_ap_assignment_policy_inscope_serviceprincipal",
                         "ServicePrincipal")):
                    obj = target.get(key)
                    if isinstance(obj, dict) and obj.get("id"):
                        runner.s.add_link(table, {
                            "IGaccessPackageAssignmentPolicy": p.get("id"),
                            column: obj["id"]})
    except Exception as exc:
        failures.append(f"assignmentPolicies: {str(exc)[:100]}")

    try:
        for a in fetch("/identityGovernance/entitlementManagement/assignments",
                       "target"):
            runner.s.upsert("IGaccessPackageAssignments", "id", a)
            n["assignments"] += 1
            subject_id = _ig_subject(runner.s, a.get("target"))
            if subject_id:
                runner.s.add_link("lnk_ig_ap_assignment_target", {
                    "IGaccessPackageAssignment": a.get("id"),
                    "IGaccessPackageSubject": subject_id})
                n["subjects"] += 1
    except Exception as exc:
        failures.append(f"assignments: {str(exc)[:100]}")

    try:
        for rq in fetch(
                "/identityGovernance/entitlementManagement/assignmentRequests",
                "target,requestor"):
            runner.s.upsert("IGaccessPackageAssignmentRequests", "id", rq)
            n["requests"] += 1
            package_id = (
                rq.get("accessPackage").get("id")
                if isinstance(rq.get("accessPackage"), dict) else "")
            package_id = package_id or rq.get("accessPackageId")
            if package_id:
                runner.s.add_link("lnk_ig_ap_assignment_request", {
                    "IGaccessPackage": package_id,
                    "IGaccessPackageAssignmentRequest": rq.get("id")})
            target_id = _ig_subject(runner.s, rq.get("target"))
            if target_id:
                runner.s.add_link("lnk_ig_ap_assignment_request_target", {
                    "IGaccessPackageAssignmentRequest": rq.get("id"),
                    "IGaccessPackageSubject": target_id})
            requestor_id = _ig_subject(runner.s, rq.get("requestor"))
            if requestor_id:
                runner.s.add_link("lnk_ig_ap_assignment_request_requestor", {
                    "IGaccessPackageAssignmentRequest": rq.get("id"),
                    "IGaccessPackageSubject": requestor_id})
    except Exception as exc:
        failures.append(f"assignmentRequests: {str(exc)[:100]}")

    resources = []
    try:
        if cats:
            # The documented list is per catalog and its response includes the
            # resource metadata needed by the link tables.
            cat_requests = [
                {"key": c.get("id"),
                 "path": ("/identityGovernance/entitlementManagement/"
                          f"catalogs/{c.get('id')}/resources"),
                 "api": API}
                for c in cats if c.get("id")]
            cat_results = fetch_paged_batch(runner.c, cat_requests)
            for c in cats:
                cid = c.get("id")
                if not cid:
                    continue
                result = cat_results.get(cid)
                if result is None:
                    failures.append(f"resources for catalog {cid}: missing")
                    continue
                if result.error:
                    failures.append(
                        f"resources for catalog {cid}: {result.error[:80]}")
                for r in result.items:
                    if not r.get("id"):
                        continue
                    runner.s.upsert("IGaccessPackageResources", "id", r)
                    n["resources"] += 1
                    resources.append(r)
                    runner.s.add_link("lnk_ig_cg_resource", {
                        "IGaccessPackageCatalog": cid,
                        "IGaccessPackageResource": r.get("id")})
        else:
            for r in runner.c.paged(
                    "/identityGovernance/entitlementManagement/resources"):
                runner.s.upsert("IGaccessPackageResources", "id", r)
                n["resources"] += 1
                resources.append(r)
                cat_id = r.get("catalogId")
                if cat_id:
                    runner.s.add_link("lnk_ig_cg_resource", {
                        "IGaccessPackageCatalog": cat_id,
                        "IGaccessPackageResource": r.get("id")})
    except Exception as exc:
        failures.append(f"resources: {str(exc)[:100]}")

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
    failed_resources = 0
    for resource in resources:
        rid = resource["id"]
        roles = results.get(f"{rid}|roles")
        if roles is None:
            failed_resources += 1
        else:
            if roles.error:
                failed_resources += 1
            for role in roles.items:
                if not role.get("id"):
                    continue
                runner.s.upsert("IGaccessPackageResourceRoles", "id", role)
                n["roles"] += 1
                runner.s.add_link("lnk_ig_ap_rr", {
                    "IGaccessPackageResource": rid,
                    "IGaccessPackageResourceRole": role["id"]})
        scopes = results.get(f"{rid}|scopes")
        if scopes is None:
            failed_resources += 1
        else:
            if scopes.error:
                failed_resources += 1
            for scope in scopes.items:
                if not scope.get("id"):
                    continue
                runner.s.upsert("IGaccessPackageResourceScopes", "id", scope)
                n["scopes"] += 1
    if failed_resources:
        failures.append(f"{failed_resources} resource role/scope request(s) partial")

    # Access-package resource role scopes connect a package to the role/scope
    # it grants.  Use documented navigation expansions.
    rrs_requests = [{"key": p["id"],
                     "path": ("/identityGovernance/entitlementManagement/"
                              f"accessPackages/{p['id']}/resourceRoleScopes"
                              "?$expand=role,scope"),
                     "api": API}
                    for p in packages if p.get("id")]
    rrs_results = fetch_paged_batch(runner.c, rrs_requests)
    failed_rrs = 0
    for package in packages:
        pid = package.get("id")
        if not pid:
            continue
        result = rrs_results.get(pid)
        if result is None:
            failed_rrs += 1
            continue
        if result.error:
            failed_rrs += 1
        for rrs in result.items:
            rrs_id = rrs.get("id")
            if not rrs_id:
                continue
            runner.s.upsert("IGaccessPackageResourceRoleScopes", "id", rrs)
            n["roleScopes"] += 1
            runner.s.add_link("lnk_ig_ap_rr_scope", {
                "IGaccessPackage": pid,
                "IGaccessPackageResourceRoleScope": rrs_id})
            role = rrs.get("role") or {}
            scope = rrs.get("scope") or {}
            if isinstance(role, dict) and role.get("id"):
                runner.s.upsert("IGaccessPackageResourceRoles", "id", role)
                runner.s.add_link("lnk_ig_ap_rrs_role", {
                    "IGaccessPackageResourceRoleScope": rrs_id,
                    "IGaccessPackageResourceRole": role["id"]})
            if isinstance(scope, dict) and scope.get("id"):
                runner.s.upsert("IGaccessPackageResourceScopes", "id", scope)
                runner.s.add_link("lnk_ig_ap_rrs_scope", {
                    "IGaccessPackageResourceRoleScope": rrs_id,
                    "IGaccessPackageResourceScope": scope["id"]})
    if failed_rrs:
        failures.append(f"{failed_rrs} resourceRoleScope request(s) partial")

    try:
        for rr in runner.c.paged(
                "/identityGovernance/entitlementManagement/resourceRequests"):
            runner.s.upsert("IGaccessPackageResourceRequests", "id", rr)
            n["resourceRequests"] += 1
            resource_id = (
                rr.get("resource").get("id")
                if isinstance(rr.get("resource"), dict) else "")
            resource_id = resource_id or rr.get("resourceId")
            if resource_id:
                runner.s.add_link("lnk_ig_ap_resource_request", {
                    "IGaccessPackageResource": resource_id,
                    "IGaccessPackageResourceRequest": rr.get("id")})
    except Exception as exc:
        failures.append(f"resourceRequests: {str(exc)[:100]}")

    try:
        for co in runner.c.paged(
                "/identityGovernance/entitlementManagement/connectedOrganizations"):
            runner.s.upsert("IGconnectedOrganizations", "id", co)
            n["connectedOrgs"] += 1
    except Exception as exc:
        failures.append(f"connectedOrganizations: {str(exc)[:100]}")

    total = sum(n.values())
    note = str(n)
    if failures:
        status = "partial" if total else "degraded"
        note += "; " + "; ".join(failures)[:300]
    else:
        status = "ok"
    runner.finish(sec, status, total, note)


# --------------------------------------------------------------------------
# 5. policies

def collect_conditionalaccess(runner: Runner) -> None:
    sec = runner.section("Policys (conditionalAccess)")
    def go():
        n = 0
        for p in runner.c.paged("/identity/conditionalAccess/policies"):
            if not p.get("id"):
                continue
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


def collect_namedlocations(runner: Runner) -> None:
    sec = runner.section("Policys (namedLocations)")
    def go():
        n = 0
        for loc in runner.c.paged("/identity/conditionalAccess/namedLocations"):
            if not loc.get("id"):
                continue
            # The analysis reads policyType 6 and classifies trust from the
            # upper-case Categories field used by the legacy AAD Graph shape.
            detail = dict(loc)
            detail["Categories"] = loc.get("categories") or []
            runner.s.upsert("Policys", "objectId", {
                "objectId": loc.get("id"),
                "objectType": "Policy",
                "displayName": loc.get("displayName"),
                "policyType": 6,
                "policyIdentifier": loc.get("modifiedDateTime"),
                "policyDetail": jstr([json.dumps(detail, default=str)]),
            })
            n += 1
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

    def finish_items(section, items, error, note=""):
        if error:
            status = "partial" if items else "degraded"
            note = (note + "; " if note else "") + error
        else:
            status = "ok"
        runner.finish(section, status, len(items), note)

    for sub in subs:
        sid = sub["subscriptionId"]
        resources, resources_error = arm_paged(
            arm, f"https://management.azure.com/subscriptions/{sid}/resources"
                 "?api-version=2022-09-01")
        sec = runner.section(f"AZresources ({sid[:8]})")
        for res in resources:
            parts = (res.get("id") or "").split("/")
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
        finish_items(sec, resources, resources_error)

        sec = runner.section(f"AZroleDefinitions ({sid[:8]})")
        items, error = arm_paged(
            arm, f"https://management.azure.com/subscriptions/{sid}/providers/"
                 "Microsoft.Authorization/roleDefinitions?api-version=2022-04-01")
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
        finish_items(sec, items, error)

        sec = runner.section(f"AZroleAssignments ({sid[:8]})")
        n_ra = 0
        scope_errors = []
        scopes = [f"/subscriptions/{sid}"]
        rgs = set()
        for res in resources:
            parts = (res.get("id") or "").split("/")
            if "resourceGroups" in parts:
                rgs.add(parts[parts.index("resourceGroups") + 1])
        scopes += [f"/subscriptions/{sid}/resourceGroups/{rg}" for rg in rgs]
        for scope in scopes:
            items, error = arm_paged(
                arm, f"https://management.azure.com{scope}/providers/"
                     "Microsoft.Authorization/roleAssignments?api-version=2022-04-01")
            if error:
                scope_errors.append(f"{scope}: {error}")
            for ra in items:
                if not ra.get("id"):
                    continue
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
        if scope_errors:
            status = "partial" if n_ra else "degraded"
            runner.finish(sec, status, n_ra,
                          f"{len(scope_errors)} scope(s) failed: "
                          + "; ".join(scope_errors)[:250])
        else:
            runner.finish(sec, "ok", n_ra)

        sec = runner.section(f"AZroleEligibilityScheduleInstances ({sid[:8]})")
        items, error = arm_paged(
            arm, f"https://management.azure.com/subscriptions/{sid}/providers/"
                 "Microsoft.Authorization/roleEligibilityScheduleInstances"
                 "?api-version=2022-04-01-preview")
        for e in items:
            if not e.get("id"):
                continue
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
        finish_items(sec, items, error)

    sec = runner.section("AZmanagementGroups")
    items, error = arm_paged(
        arm, "https://management.azure.com/providers/Microsoft.Management/"
             "managementGroups?api-version=2021-04-01")
    for mg in items:
        props = mg.get("properties") or {}
        runner.s.upsert("AZmanagementGroups", "id", {
            "id": mg.get("id"), "name": mg.get("name"), "type": mg.get("type"),
            "display_name": props.get("displayName"),
            "tenant_id": props.get("tenantId"),
            "details": props,
        })
    finish_items(sec, items, error)


def check_arm(arm: ArmClient) -> list[dict]:
    """Quick ARM capability check: list subscriptions, skip if none/denied."""
    try:
        subs, error = arm_paged(
            arm, "https://management.azure.com/subscriptions?api-version=2022-12-01")
    except Exception:
        return []
    if error:
        if subs:
            print(f"[arm] subscription paging failed ({error}); using the "
                  f"{len(subs)} subscription(s) already received")
            return subs
        print(f"[arm] subscriptions call failed ({error}); skipping Azure tables")
        return []
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
    # Commit the core directory phase before optional/ARM collectors; an
    # optional failure then cannot unwind the whole Graph snapshot.
    store.commit()
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
    except sqlite3.Error as exc:
        runner.log(f"  DirectoryRoles role flags not updated: {exc}")

    def optional(label: str, fn) -> None:
        try:
            fn()
        except Exception as exc:
            sec = runner.section(label)
            runner.finish(sec, "error", note=str(exc)[:200])

    optional("PIM (optional)", lambda: (
        collect_pim_static(runner),
        collect_pim_directory(runner),
        collect_pim_groups(runner, groups)))
    store.commit()

    optional("IdentityGovernance (optional)", lambda: collect_ig(runner))
    optional("Policies (optional)", lambda: (
        collect_conditionalaccess(runner),
        collect_namedlocations(runner),
        collect_securitydefaults(runner),
        collect_authmethods(runner)))
    store.commit()

    sec = runner.section("AppRoleAssignments (total)")
    runner.finish(sec, "ok", store.count("AppRoleAssignments"))

    if arm is not None:
        try:
            subs = check_arm(arm)
            if subs:
                collect_arm(arm, runner, subs)
        except Exception as exc:
            sec = runner.section("AZ (ARM)")
            runner.finish(sec, "error", note=str(exc)[:200])
    else:
        sec = runner.section("AZ (ARM)")
        runner.finish(sec, "skipped", note="no ARM token")

    store.commit()
    return runner

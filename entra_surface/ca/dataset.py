"""Conditional Access dataset loading and pure policy helpers."""
from __future__ import annotations

import json
import sqlite3
from collections import defaultdict

from ..graph import json_safe_value


CA_GUEST_TOKENS = {
    "AllGuestUsers", "AllExternalUsers", "GuestOrExternalUsers",
    "GuestsOrExternalUsers", "GuestsAndExternalUsers", "Guests",
    "Guest", "AllGuests", "ExternalUsers",
}

# ROADrecon/AAD Graph legacy client tokens, normalized to lower case. Graph's
# replaceable clientAppTypes use exchangeActiveSync/other/all instead, so both
# vocabularies are recognized wherever legacy clients are matched.
CA_LEGACY_CLIENT_TYPES = {
    "eassupported", "easunsupported", "otherlegacy", "legacysmtp", "legacypop",
    "legacyimap", "legacymapi", "legacyoffice",
}
CA_LEGACY_CLIENT_VALUES = CA_LEGACY_CLIENT_TYPES | {"exchangeactivesync", "other"}

CA_CLIENT_APP_TYPES = ["browser", "mobileAppsAndDesktopClients",
                       "exchangeActiveSync", "other"]

CA_ALL_PLATFORMS = {"android", "windows", "windows_phone", "macos", "linux", "ios"}

# The Conditional Access "Office365" target is a suite, not a single appId.
# These well-known first-party IDs are the stable core of the suite; display
# names cover the rest of Microsoft's documented suite (which changes over
# time and is tenant-populated). An explicit custom appId never matches.
CA_OFFICE365_APP_IDS = {
    "00000002-0000-0ff1-ce00-000000000000",  # Exchange Online
    "00000003-0000-0ff1-ce00-000000000000",  # SharePoint Online
    "00000004-0000-0ff1-ce00-000000000000",  # Skype for Business Online
    "00000005-0000-0ff1-ce00-000000000000",  # Yammer / Viva Engage
    "00000006-0000-0ff1-ce00-000000000000",  # Office 365 portal / Office.com
    "c5393580-f805-4401-95e8-94b7a6ef2fc2",  # Office 365 Management APIs
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264",  # Microsoft Teams
    "5e3ce6c0-2b1f-4285-8d4b-75ee78787346",  # Microsoft Teams (web)
    "2d4d3d8e-2be3-4bef-9f87-7875a61c29de",  # Microsoft Teams services
    "7df0a125-d3be-4c96-aa54-591f83ff541c",  # Power Automate
}
CA_OFFICE365_NAME_PREFIXES = (
    "office 365", "microsoft 365", "office.com", "microsoft office",
    "office online", "exchange online", "sharepoint online", "onedrive",
    "microsoft teams", "microsoft forms", "microsoft planner",
    "power automate", "microsoft flow", "microsoft powerapps", "powerapps",
    "microsoft yammer", "yammer", "viva engage", "skype for business",
    "office delve", "microsoft sway", "sway", "microsoft whiteboard",
    "microsoft loop",
)
# Hard ceiling on path scenarios across the whole request (per-path caps still
# apply); protects "all users" runs from unbounded CPU/memory use.
CA_PATH_GLOBAL_SCENARIO_BUDGET = 200000


def ca_user_is_guest(user_record):
    """Guest/external users for guest-scoped CA include/exclude evaluation."""
    rec = user_record or {}
    utype = str(rec.get("type") or "").strip().lower()
    if utype in ("guest", "external", "guestuser"):
        return True
    upn = str(rec.get("upn") or rec.get("userPrincipalName") or "").lower()
    return "#ext#" in upn


def ca_policy_includes_user(policy, uid, users):
    """Whether a policy's user include scope covers `uid`.

    Guest-only scopes must not cover member users; All users includes guests.
    """
    if policy.get("inc_all"):
        return True
    if policy.get("inc_guest") and ca_user_is_guest((users or {}).get(uid)):
        return True
    return uid in (policy.get("inc_users") or ())


def ca_policy_excludes_user(policy, uid, users):
    """Whether a policy's user exclusions cover `uid` (including guest scope)."""
    if uid in (policy.get("exc_users") or ()):
        return True
    return bool(policy.get("exc_guest")
                and ca_user_is_guest((users or {}).get(uid)))


def ca_client_matches(client_inc, client_exc, client_app):
    """Evaluate a client-app axis. Returns (True/False/None, reason)."""
    if not client_inc and not client_exc:
        return True, None
    if not client_app:
        return None, "client app not specified"
    client = str(client_app).lower()
    inc = [str(c).lower() for c in client_inc]
    exc = [str(c).lower() for c in client_exc]
    if "all" in exc or client in exc:
        return False, "client app excluded"
    if "all" in inc or client in inc:
        return True, None
    if client in ("exchangeactivesync", "other") and any(
            c in CA_LEGACY_CLIENT_TYPES for c in inc):
        return True, None
    if inc and client in ("exchangeactivesync", "other"):
        return None, "legacy client mapping uncertain"
    return False, "client app not targeted"


def ca_policy_blocks_legacy(policy):
    """True when an enabled block policy targets legacy clients."""
    if not policy.get("block"):
        return False
    inc = {str(c).lower() for c in policy.get("client_inc") or []}
    return "all" in inc or bool(inc & CA_LEGACY_CLIENT_VALUES)


def ca_app_is_office365(app_id, app_name=""):
    """Whether an application belongs to the Conditional Access Office365 suite."""
    low_id = str(app_id or "").strip().lower()
    if low_id and low_id in CA_OFFICE365_APP_IDS:
        return True
    name = str(app_name or "").strip().lower()
    if not name:
        return False
    return any(name == prefix or name.startswith(prefix + " ")
               or name.startswith(prefix + " -")
               or name.startswith(prefix + " (")
               for prefix in CA_OFFICE365_NAME_PREFIXES)


def ca_app_covered(apps_inc, apps_exc, app_id, app_name=""):
    """Whether a policy's application scope covers one appId.

    Unlike a plain `Office365 in inc` check, this restricts Office365 to the
    Microsoft 365 suite instead of treating it as "all applications".
    """
    low = str(app_id or "").strip().lower()
    inc = [str(a).lower() for a in apps_inc or [] if a]
    exc = [str(a).lower() for a in apps_exc or [] if a]
    office365 = ca_app_is_office365(low, app_name)
    if "all" in exc or (low and low in exc) or ("office365" in exc and office365):
        return False
    if "all" in inc or (low and low in inc):
        return True
    return "office365" in inc and office365


def ca_location_verdict(policy, scenario, locations):
    """Evaluate named/trusted location conditions.

    The what-if scenario only knows whether the sign-in is trusted, not which
    named location it came from. Named-location conditions therefore stay
    signal-dependent (None) unless the scenario identifies an exact location;
    a first non-matching named location must not hide a later match.
    """
    inc_l = list(policy.get("locations_inc") or [])
    exc_l = list(policy.get("locations_exc") or [])
    trust_inc = bool(policy.get("trusted_locations"))
    if not inc_l and not exc_l and not trust_inc:
        return True, None
    trusted = scenario.get("trusted_location")
    selected = scenario.get("location_id") or scenario.get("named_location")
    selected_low = str(selected).strip().lower() if selected else ""
    unknown = []

    def _same_location(loc):
        return bool(selected_low) and str(loc).strip().lower() == selected_low

    for loc in exc_l:
        low = str(loc).lower()
        if low == "all":
            return False, "all locations excluded"
        if low == "alltrusted":
            if trusted is True:
                return False, "trusted locations excluded"
            if trusted is None:
                unknown.append("trusted location not specified")
            continue
        rec = locations.get(loc)
        if selected_low:
            if _same_location(loc):
                return False, f"location '{rec['name'] if rec else loc}' excluded"
            continue
        if rec is None:
            unknown.append("named location excluded (not found)")
        else:
            unknown.append(f"location '{rec['name']}' excluded (not identified)")

    include_match = False
    include_unknown = False
    include_all = False
    if trust_inc or any(str(loc).lower() == "alltrusted" for loc in inc_l):
        if trusted is True:
            include_match = True
        elif trusted is None:
            include_unknown = True
    for loc in inc_l:
        low = str(loc).lower()
        if low == "all":
            include_all = True
            continue
        if low == "alltrusted":
            continue
        rec = locations.get(loc)
        if selected_low:
            if _same_location(loc):
                include_match = True
            continue
        include_unknown = True
        if rec is None:
            unknown.append("named location (not found)")
        else:
            unknown.append(f"location '{rec['name']}' include not identified")

    if include_all:
        include_match = True
    if include_match:
        if unknown:
            return None, "; ".join(unknown)
        return True, None
    if include_unknown:
        return None, "; ".join(unknown or ["named location include not identified"])
    if inc_l or trust_inc:
        return False, "location not targeted"
    if unknown:
        return None, "; ".join(unknown)
    return True, None


def fmt_platforms(inc, exc):
    """Human label for a policy's device-platform condition, e.g.
    'All except iOS' or 'Windows, macOS · excl: Linux'."""
    inc_l = [str(x) for x in inc if x]
    exc_l = [str(x) for x in exc if x]
    if "All" in [i.lower() for i in inc_l]:
        covered = set(CA_ALL_PLATFORMS)
    else:
        covered = {i.lower() for i in inc_l}
    excluded = {e.lower() for e in exc_l}
    if excluded and covered | excluded >= CA_ALL_PLATFORMS:
        return "All except " + ", ".join(sorted(excluded))
    parts = []
    if inc_l:
        parts.append("All" if "All" in [i.lower() for i in inc_l] else ", ".join(sorted(inc_l)))
    if exc_l:
        parts.append("excl: " + ", ".join(sorted(exc_l)))
    return " \u00b7 ".join(parts)


def _ca_policy_inner(detail):
    """Decode a CA policyDetail column that may be a dict, a JSON string, a
    one-element list holding either, or an empty/None value."""
    parsed = json_safe_value(detail)
    try:
        if isinstance(parsed, list):
            if not parsed:
                return {}
            first = parsed[0]
            inner = json.loads(first) if isinstance(first, str) else first
        elif isinstance(parsed, dict):
            inner = parsed
        elif isinstance(parsed, str):
            inner = json.loads(parsed) if parsed else {}
        else:
            inner = parsed
        return inner if isinstance(inner, dict) else {}
    except (json.JSONDecodeError, ValueError, TypeError, IndexError, KeyError):
        return {}


def _ca_blocks(inner, section, key):
    return ((inner.get("Conditions") or {}).get(section) or {}).get(key) or []


def load_ca_dataset(db_path):
    """Read-only slices of the roadrecon DB needed for the CA analysis."""
    data = {
        "policies": [], "users": {}, "sps": {}, "locations": {},
        "groups": {}, "roles": {},
        "group_member_user": defaultdict(set),
        "group_member_group": defaultdict(set),
        "role_member_user": defaultdict(set),
        "role_member_group": defaultdict(set),
        "role_template_members": defaultdict(set),
        "role_template_by_oid": {},
    }
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cur = conn.cursor()
    try:
        cur.execute("SELECT objectId, displayName, policyDetail FROM Policys WHERE policyType = 18")
        for oid, name, detail in cur.fetchall():
            data["policies"].append(
                {"id": oid, "name": name or oid, "inner": _ca_policy_inner(detail)})
        # named locations (policyType 6) with trusted classification
        cur.execute("SELECT objectId, displayName, policyDetail FROM Policys WHERE policyType = 6")
        for oid, name, detail in cur.fetchall():
            inner = _ca_policy_inner(detail)
            trusted = "trusted" in [str(c).lower()
                                    for c in (inner.get("Categories") or [])]
            data["locations"][oid] = {"name": name or oid, "trusted": trusted}
        cur.execute("SELECT objectId, displayName FROM Groups")
        for oid, disp in cur.fetchall():
            data["groups"][oid] = disp or oid
        try:
            cur.execute("SELECT objectId, displayName, roleTemplateId FROM DirectoryRoles")
            for oid, disp, template_id in cur.fetchall():
                data["roles"][oid] = disp or oid
                if template_id:
                    data["role_template_by_oid"][oid] = template_id
        except sqlite3.OperationalError:
            pass
        try:
            cur.execute("SELECT objectId, displayName FROM RoleDefinitions")
            for oid, disp in cur.fetchall():
                data["roles"].setdefault(oid, disp or oid)
        except sqlite3.OperationalError:
            pass
        cur.execute("SELECT objectId, userPrincipalName, displayName, userType, "
                    "accountEnabled, dirSyncEnabled FROM Users")
        for oid, upn, disp, utype, enabled, synced in cur.fetchall():
            data["users"][oid] = {"upn": upn or "", "name": disp or upn or oid,
                                  "type": utype or "Member",
                                  "enabled": bool(enabled),
                                  "sync": bool(synced)}
        cur.execute("SELECT objectId, displayName, appId FROM ServicePrincipals")
        for oid, disp, app_id in cur.fetchall():
            data["sps"][oid] = {"name": disp or oid, "appId": app_id or ""}
        for table, left, right, target in (
                ("lnk_group_member_user", "Group", "User", "group_member_user"),
                ("lnk_group_member_group", "Group", "childGroup", "group_member_group"),
                ("lnk_role_member_user", "DirectoryRole", "User", "role_member_user"),
                ("lnk_role_member_group", "DirectoryRole", "Group", "role_member_group")):
            try:
                cur.execute(f'SELECT "{left}", "{right}" FROM {table}')
                bucket = data[target]
                for a, b in cur.fetchall():
                    if a and b:
                        bucket[a].add(b)
            except sqlite3.OperationalError:
                pass
    finally:
        conn.close()
    # template-id view of role memberships (policies reference template IDs)
    for rid, members in data["role_member_user"].items():
        template_id = data["role_template_by_oid"].get(rid)
        if template_id:
            data["role_template_members"][template_id] |= members
    return data



"""Conditional Access policyDetail decoding and normalization.

Pure module: accepts the ROADrecon (upper-case keys) and Graph (lower-case
keys) policy shapes and returns one normalized form.
"""
from __future__ import annotations

import json

from .graph import json_safe_value


def policy_detail_inner(detail):
    """Return the decoded policy object for every collected policyDetail shape.

    ROADrecon stores a list of JSON-encoded strings (sometimes double-encoded);
    other exports store a JSON object or a plain string. Never raises for a
    valid JSON scalar/object in the wrong shape.
    """
    parsed = json_safe_value(detail)
    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, list):
        if not parsed:
            return {}
        inner = parsed[0]
    elif isinstance(parsed, str):
        inner = parsed
    else:
        return {}
    if isinstance(inner, str):
        try:
            inner = json.loads(inner)
        except (json.JSONDecodeError, ValueError, TypeError):
            return {}
    return inner if isinstance(inner, dict) else {}


def policy_detail_normalized(detail):
    return _normalize_ca_policy(policy_detail_inner(detail))


def policy_state_from_record(record):
    """CA state for a Policys row, normalized for Graph and ROADrecon shapes."""
    inner = policy_detail_normalized((record or {}).get("policyDetail"))
    return (str(inner.get("State") or "").strip() or "Unknown")



def _ca_state_label(value):
    state = str(value or "").strip()
    low = state.lower()
    if low == "enabled":
        return "Enabled"
    if low in ("enabledforreportingbutnotenforced", "reporting", "reportonly"):
        return "Reporting"
    if low == "disabled":
        return "Disabled"
    return state.title() if state else "Unknown"


def _normalize_ca_policy(inner):
    """Normalize Graph-style CA policyDetail into the roadrecon shape.

    roadrecon/AAD Graph exports use upper-case keys (State, Conditions,
    Controls); newer Graph exports use lower-case keys plus grantControls.
    The rest of the analysis consumes one shape, so normalize the latter.
    """
    if not isinstance(inner, dict):
        return {}
    if "Conditions" in inner or "Controls" in inner or "State" in inner:
        return inner

    out = {"State": _ca_state_label(inner.get("state"))}
    cond = inner.get("conditions") or inner.get("Conditions") or {}
    ncond = {}

    users = cond.get("users") or {}
    if users:
        inc, exc = [], []
        for key, field in (("includeUsers", "Users"), ("includeGroups", "Groups"),
                           ("includeRoles", "Roles")):
            vals = users.get(key) or []
            if vals:
                inc.append({field: list(vals)})
        if users.get("includeGuestsOrExternalUsers"):
            inc.append({"Users": ["GuestsOrExternalUsers"]})
        for key, field in (("excludeUsers", "Users"), ("excludeGroups", "Groups"),
                           ("excludeRoles", "Roles")):
            vals = users.get(key) or []
            if vals:
                exc.append({field: list(vals)})
        if users.get("excludeGuestsOrExternalUsers"):
            exc.append({"Users": ["GuestsOrExternalUsers"]})
        ncond["Users"] = {"Include": inc, "Exclude": exc}

    apps = cond.get("applications") or {}
    if apps:
        inc, exc = [], []
        if apps.get("includeApplications"):
            inc.append({"Applications": list(apps["includeApplications"])})
        acrs = list(apps.get("includeUserActions") or [])
        acrs += list(apps.get("includeAuthenticationContextClassReferences") or [])
        if acrs:
            inc.append({"Acrs": acrs})
        if apps.get("excludeApplications"):
            exc.append({"Applications": list(apps["excludeApplications"])})
        ncond["Applications"] = {"Include": inc, "Exclude": exc}

    client_types = cond.get("clientAppTypes") or []
    if client_types:
        ncond["ClientTypes"] = {"Include": [{"ClientTypes": list(client_types)}]}

    platforms = cond.get("platforms") or {}
    if platforms:
        inc, exc = [], []
        if platforms.get("includePlatforms"):
            inc.append({"DevicePlatforms": list(platforms["includePlatforms"])})
        if platforms.get("excludePlatforms"):
            exc.append({"DevicePlatforms": list(platforms["excludePlatforms"])})
        ncond["DevicePlatforms"] = {"Include": inc, "Exclude": exc}

    locations = cond.get("locations") or {}
    if locations:
        inc, exc = [], []
        if locations.get("includeLocations"):
            inc.append({"IncludeLocations": list(locations["includeLocations"])})
        if locations.get("excludeLocations"):
            exc.append({"ExcludeLocations": list(locations["excludeLocations"])})
        ncond["Locations"] = {"Include": inc, "Exclude": exc}

    ncond["SignInRiskLevels"] = list(cond.get("signInRiskLevels") or [])
    ncond["UserRiskLevels"] = list(cond.get("userRiskLevels") or [])

    flows = cond.get("authenticationFlows") or {}
    if flows:
        vals = (flows.get("transferMethods")
                or flows.get("includeAuthenticationFlows")
                or flows.get("includedAuthenticationFlows") or [])
        if vals:
            ncond["AuthFlows"] = {"Include": [{"AuthFlows": list(vals)}]}

    devices = cond.get("devices") or {}
    if devices:
        inc, exc = [], []
        dfilter = devices.get("deviceFilter") or devices.get("Filter") or {}
        rule = (dfilter.get("rule") if isinstance(dfilter, dict) else None) or \
               (dfilter.get("Rule") if isinstance(dfilter, dict) else None)
        if rule:
            inc.append({"DeviceRule": rule})
        if devices.get("includeDevices"):
            inc.append({"Devices": list(devices["includeDevices"])})
        if devices.get("excludeDevices"):
            exc.append({"Devices": list(devices["excludeDevices"])})
        ncond["Devices"] = {"Include": inc, "Exclude": exc}

    out["Conditions"] = ncond

    grant = inner.get("grantControls") or {}
    built = grant.get("builtInControls") or []
    names = []
    for c in built:
        low = str(c).lower()
        if low == "mfa":
            names.append("Mfa")
        elif low == "compliantdevice":
            names.append("RequireCompliantDevice")
        elif low == "block":
            names.append("Block")
        else:
            names.append(str(c))
    auth_ids = []
    auth = grant.get("authenticationStrength")
    if isinstance(auth, dict) and auth.get("id"):
        auth_ids = [auth["id"]]
    if names or auth_ids:
        out["Controls"] = [{"Control": names, "AuthStrengthIds": auth_ids,
                            "Operator": grant.get("operator") or "OR"}]
    return out



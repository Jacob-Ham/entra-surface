"""Server-side drilldown modal responses."""
from __future__ import annotations

from ..report.html import EXPAND_BUTTON_HTML, drawer_for_html, esc
from ..state import SERVE_STATE


SERVE_FIELD_LABELS = {
    "severity": "Privileges", "owner": "Owner", "ownerUpn": "Owner UPN",
    "ownerStatus": "Owner Status", "app": "Application",
    "ownerSource": "Owner Source", "ownerAdDn": "Owner AD DN",
    "ownerAdSid": "Owner SID", "ownerImmutableId": "Owner Immutable ID",
    "resource": "Resource", "permission": "Permission", "spStatus": "SP Status",
    "target": "Target", "targetType": "Target Type", "id": "Object ID",
    "status": "Target Status", "pw": "Passwords", "keys": "Keys", "roleCount": "Role assignment",
    "appId": "App ID", "spType": "SP type", "appDirRoles": "Directory roles",
    "ssoProtocol": "SSO protocol", "ssoPublisher": "Publisher",
    "ssoAudience": "Audience", "ssoAssignment": "Assignment required",
    "ssoAssigned": "Assigned users", "ssoCertExpiry": "Signing certificate",
    "ssoHomeTenant": "Home tenant", "ssoVerified": "Publisher status",
    "ssoReplyUrls": "Reply URLs", "ssoNotify": "Notification emails",
    "ssoCertThumb": "Certificate thumbprint",
    "pwLastSet": "Password last set", "pwExpiry": "Expiration date",
    "user": "User", "userUpn": "UPN",
    "roles": "Directory roles", "eligible": "Eligible roles",
    "privApps": "Privileged apps owned",
    "capGroups": "Role-capable group memberships", "grpOwned": "Groups owned",
    "hybrid": "Account Source", "caExcl": "CA exclusions", "userStatus": "Status",
    "immutableId": "Immutable ID",
    "group": "Group", "grpType": "Type", "grpRoles": "Directory roles",
    "grpMembers": "Members", "grpPriv": "Privileged members", "grpOwners": "Owners",
    "polName": "Policy", "polState": "State", "polScope": "Scope", "polApps": "Apps",
    "polControls": "Controls", "polInc": "Included users", "polExc": "Excluded users",
    "polType": "Policy type", "polCreated": "Created", "polModified": "Last modified",
    "dynGroup": "Group", "dynRule": "Membership rule", "dynAttrs": "Referenced attributes",
    "dynMods": "attribute modifiable by",
    "adUser": "User", "adUpn": "UPN", "adCn": "AD CN", "adDn": "AD DN", "adSid": "SID",
    "adPw": "On-prem pw change", "adTags": "Targeting tags", "adStatus": "Status",
    "arcMachine": "Machine", "arcSub": "Subscription", "arcRg": "Resource Group",
    "arcResourceId": "Resource ID", "arcStatus": "Status",
    "arcPrincipal": "Principal", "arcPrincipalType": "Type",
    "arcTag": "Arc marker", "arcAzRoles": "Azure roles",
    "arcProvider": "Provider service",
}

SERVE_DRILLDOWN_COLUMNS = {
    "owner":      ["app", "resource", "permission", "severity", "spStatus"],
    "ownerUpn":   ["app", "resource", "permission", "severity", "spStatus"],
    "app":        ["ownerUpn", "resource", "permission", "severity", "spStatus"],
    "resource":   ["app", "ownerUpn", "permission", "severity", "spStatus"],
    "permission": ["app", "ownerUpn", "resource", "severity", "spStatus"],
    "target":     ["targetType", "id", "roleCount", "pw", "keys", "severity", "status"],
    # identity cells normally open the profile drawer; these columns are the
    # fallback for rows without data-profile-id
    "user":       ["userUpn", "roles", "eligible", "privApps", "severity"],
    "userUpn":    ["user", "roles", "eligible", "privApps", "severity"],
    "adUser":     ["adUpn", "adCn", "adDn", "adStatus", "adTags"],
    "adUpn":      ["adUser", "adCn", "adDn", "adStatus", "adTags"],
    "roles":      ["userUpn", "privApps", "capGroups", "grpOwned", "severity"],
    "eligible":   ["userUpn", "group", "severity"],
    "group":      ["group", "grpType", "grpRoles", "grpMembers", "grpPriv", "grpOwners", "severity"],
    "grpRoles":   ["group", "grpMembers", "grpPriv", "severity"],
    "polName":    ["polState", "polScope", "polApps", "polControls", "polInc", "polExc", "severity"],
    "ssoProtocol": ["app", "ssoPublisher", "ssoAudience", "ssoAssignment", "ssoAssigned", "ssoCertExpiry", "owner", "status"],
    "ssoPublisher": ["app", "ssoProtocol", "ssoAudience", "ssoAssignment", "owner", "status"],
    "dynGroup":   ["dynRule", "dynAttrs", "dynMods"],
    "dynAttrs":   ["dynGroup", "dynRule", "dynMods"],
    "dynRule":    ["dynGroup", "dynAttrs", "dynMods"],
    "dynMods":    ["dynGroup", "dynRule", "dynAttrs"],
}

SERVE_CONTAINS_FIELDS = {"roles", "eligible", "grpRoles", "dynMods", "dynAttrs"}



def serve_drilldown_response(qs):
    field = (qs.get("field") or [""])[0]
    value = (qs.get("value") or [""])[0]
    columns = SERVE_DRILLDOWN_COLUMNS.get(field)
    if not columns:
        return {"error": f"unsupported drilldown field: {field}"}, 400
    if not value:
        # An empty value must never match rows whose target field is absent or
        # empty (it previously opened an "all tables" style modal).
        return {"error": "drilldown value is required"}, 400
    contains = field in SERVE_CONTAINS_FIELDS
    wanted = [x.strip() for x in value.split(",") if x.strip()]
    matches = []
    for rec in SERVE_STATE["records"]:
        if field not in rec:
            continue
        v = rec.get(field, "") or ""
        if not v:
            continue
        if contains:
            # A cell can display several comma-separated values (e.g. two
            # PIM-eligible roles); require every requested token to be present.
            have = [x.strip() for x in str(v).split(",")]
            hit = bool(wanted) and all(x in have for x in wanted)
        else:
            hit = v == value
        if hit:
            matches.append(rec)
    thead = ('<tr><th></th>'
             + "".join(f'<th>{esc(SERVE_FIELD_LABELS.get(c, c))}</th>' for c in columns) + "</tr>")
    rows_html = []
    for i, rec in enumerate(matches):
        key = f"dd-{i}"
        ids = rec.get("__ids") or {}
        cells = "".join(f"<td>{esc(rec.get(c, ''))}</td>" for c in columns)
        rows_html.append(f"""
        <tr data-sp-id="{esc(ids.get('sp', ''))}" data-app-id="{esc(ids.get('app', ''))}"
            data-owner-id="{esc(ids.get('owner', ''))}" data-profile-id="{esc(ids.get('owner', ''))}"
            data-group-id="{esc(rec.get('__gid', ''))}" data-policy-id="{esc(rec.get('__pid', ''))}"
            data-detail-key="{key}">
          <td class="expand-cell">{EXPAND_BUTTON_HTML}</td>
          {cells}
        </tr>{drawer_for_html(key, len(columns) + 1)}""")
    if not rows_html:
        rows_html.append(
            f'<tr><td colspan="{len(columns) + 1}" class="muted">'
            'No matching findings.</td></tr>')
    return {
        "title": f"{SERVE_FIELD_LABELS.get(field, field)}: {value}",
        "subtitle": f"{len(matches)} matching finding(s) in the collected set",
        "thead_html": thead,
        "rows_html": "".join(rows_html),
    }, 200



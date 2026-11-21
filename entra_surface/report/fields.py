"""Table field metadata and cell renderers."""
from __future__ import annotations

from ..graph import sp_owner_details
from ..roles import role_display_name
from ..util import truncate
from .html import (
    DASH_INNER, bool_badge, cap_annotate, count_cell, esc, severity_badge,
    severity_class, status_cell,
)


FIELD_META = {
    # --- SP / application ---------------------------------------------------
    "severity": {"label": "Privileges", "width": 100},
    "owner": {"label": "Owner", "width": 150, "cls": "clickable", "extra_cls": ""},
    "ownerUpn": {"label": "Owner UPN", "width": 190, "cls": "clickable", "extra_cls": ""},
    "ownerStatus": {"label": "Owner Status", "width": 100},
    "ownerSource": {"label": "Owner Source", "width": 110},
    "ownerAdDn": {"label": "Owner AD DN", "width": 200},
    "ownerAdSid": {"label": "Owner SID", "width": 100},
    "ownerImmutableId": {"label": "Owner Immutable ID", "width": 200},
    "app": {"label": "Application", "width": 210, "cls": "clickable"},
    "pw": {"label": "Passwords", "width": 70},
    "keys": {"label": "Keys", "width": 60},
    "resource": {"label": "Resource", "width": 150, "cls": "clickable"},
    "permission": {"label": "Permission", "width": 220, "cls": "clickable"},
    "spStatus": {"label": "SP Status", "width": 100},
    "appId": {"label": "App ID", "width": 170, "cls": "mono"},
    "spType": {"label": "SP type", "width": 120},
    "target": {"label": "Target", "width": 200, "cls": "clickable"},
    "targetType": {"label": "Target Type", "width": 120},
    "id": {"label": "Object ID", "width": 180, "cls": "mono"},
    "roleCount": {"label": "Role assignment", "width": 120},
    "status": {"label": "Status", "width": 110},
    "appDirRoles": {"label": "Directory roles", "width": 260},
    # --- enterprise apps (SSO) ---------------------------------------------
    "ssoProtocol": {"label": "Protocol", "width": 110, "cls": "clickable"},
    "ssoPublisher": {"label": "Publisher", "width": 180, "cls": "clickable"},
    "ssoAudience": {"label": "Audience", "width": 120},
    "ssoAssignment": {"label": "Assignment", "width": 100},
    "ssoAssigned": {"label": "Assigned users", "width": 110},
    "ssoCertExpiry": {"label": "Signing cert", "width": 140},
    "ssoHomeTenant": {"label": "Home tenant", "width": 180},
    "ssoVerified": {"label": "Publisher status", "width": 120},
    "ssoReplyUrls": {"label": "Reply URLs", "width": 90},
    "ssoNotify": {"label": "Notify emails", "width": 110},
    "ssoCertThumb": {"label": "Cert thumbprint", "width": 180, "cls": "mono"},
    # --- authentication methods --------------------------------------------
    "authMethod": {"label": "Method", "width": 230},
    "authState": {"label": "State", "width": 90},
    "authScope": {"label": "Scope", "width": 300},
    "authRegistration": {"label": "Registration", "width": 110},
    "authSettings": {"label": "Settings", "width": 380},
    "authSource": {"label": "Source", "width": 220},
    "authId": {"label": "Policy ID", "width": 180, "cls": "mono"},
    # --- certificate authentication users ----------------------------------
    "authUserType": {"label": "Type", "width": 90},
    "authCbaScope": {"label": "CBA scope", "width": 260},
    "authCbaMode": {"label": "CBA mode", "width": 110},
    "authCbaBindings": {"label": "Certificate bindings", "width": 300},
    # --- CA policy ----------------------------------------------------------
    "polName": {"label": "Policy", "width": 220, "cls": "clickable"},
    "polState": {"label": "State", "width": 90},
    "polScope": {"label": "Scope", "width": 130},
    "polApps": {"label": "Apps", "width": 160},
    "polControls": {"label": "Controls", "width": 130},
    "polInc": {"label": "Included", "width": 90},
    "polExc": {"label": "Excluded", "width": 90},
    "polType": {"label": "Policy type", "width": 110},
    "polCreated": {"label": "Created", "width": 170},
    "polModified": {"label": "Last modified", "width": 170},
    # --- CA gaps (per-user exclusions) --------------------------------------
    # --- group --------------------------------------------------------------
    "group": {"label": "Group", "width": 220, "cls": "clickable"},
    "grpType": {"label": "Type", "width": 180},
    "groupSource": {"label": "Group source", "width": 110},
    "grpRoles": {"label": "Directory roles", "width": 200},
    "grpMembers": {"label": "Members", "width": 80},
    "grpPriv": {"label": "Priv. members", "width": 110},
    "grpOwners": {"label": "Owners", "width": 90},
    "dynGroup": {"label": "Group", "width": 220, "cls": "clickable"},
    "dynRule": {"label": "Membership rule", "width": 280, "cls": "mono"},
    "dynAttrs": {"label": "Referenced attributes", "width": 220},
    "dynMods": {"label": "attribute modifiable by", "width": 340},
    # --- user ---------------------------------------------------------------
    "user": {"label": "User", "width": 170, "cls": "clickable"},
    "userUpn": {"label": "UPN", "width": 190, "cls": "clickable"},
    "roles": {"label": "Directory roles", "width": 200},
    "eligible": {"label": "Eligible", "width": 70, "cls": "clickable"},
    "privApps": {"label": "Priv apps", "width": 80},
    "capGroups": {"label": "Capable grp", "width": 90},
    "grpOwned": {"label": "Groups owned", "width": 110},
    "caExcl": {"label": "CA excl.", "width": 80},
    "hybrid": {"label": "Account Source", "width": 110},
    "userStatus": {"label": "Status", "width": 80},
    "immutableId": {"label": "Immutable ID", "width": 200},
    "adUser": {"label": "User", "width": 180, "cls": "clickable"},
    "adUpn": {"label": "UPN", "width": 200, "cls": "clickable"},
    "adCn": {"label": "AD CN", "width": 140},
    "adDn": {"label": "AD DN", "width": 200},
    "adSid": {"label": "SID", "width": 100},
    "adPw": {"label": "On-prem pw change", "width": 140},
    "adTags": {"label": "Targeting tags", "width": 150},
    "adStatus": {"label": "Status", "width": 80},
    # --- azure role assignments ---------------------------------------------
    "azApp": {"label": "Application / SP", "width": 170, "cls": "clickable"},
    "azGroup": {"label": "Group", "width": 170, "cls": "clickable"},
    "azUser": {"label": "User", "width": 170, "cls": "clickable"},
    "azRoles": {"label": "Role", "width": 210, "cls": "clickable"},
    "azSpRoles": {"label": "Role", "width": 210, "cls": "clickable"},
    "azUsrRoles": {"label": "Role", "width": 210, "cls": "clickable"},
    "azScopeType": {"label": "Scope Type", "width": 110},
    "azSub": {"label": "Subscription", "width": 230},
    "azRg": {"label": "Resource Group", "width": 120},
    "azProvider": {"label": "Provider", "width": 150},
    "azResource": {"label": "Resource", "width": 170},
    # --- azure arc ----------------------------------------------------------
    "arcMachine": {"label": "Machine", "width": 150},
    "arcSub": {"label": "Subscription", "width": 220},
    "arcRg": {"label": "Resource Group", "width": 130},
    "arcResourceId": {"label": "Resource ID", "width": 300, "cls": "mono"},
    "arcStatus": {"label": "Status", "width": 90},
    "arcPrincipal": {"label": "Principal", "width": 180},
    "arcPrincipalType": {"label": "Type", "width": 120},
    "arcTag": {"label": "Arc marker", "width": 120},
    "arcAzRoles": {"label": "Azure roles", "width": 320},
    "pwLastSet": {"label": "Password last set", "width": 130},
    "pwExpiry": {"label": "Expiration date", "width": 130},
    "arcProvider": {"label": "Provider service", "width": 210},
}


def _dash_pair():
    return DASH_INNER, ""


def _graph_of(r):
    return (r or {}).get("graph") or {}


def graph_user_record(graph, uid):
    return ((graph or {}).get("user") or {}).get(uid) if uid else None


def row_owner_dict(f, ctx=None):
    """Normalized owner (display_name/upn/enabled) for generic rows reached via
    object_ids.user; None when the row has no user handle."""
    o = f.get("object_ids") or {}
    uid = next(iter(o.get("user", ()) or ()), "")
    rec = graph_user_record((ctx or {}).get("graph"), uid)
    if not rec:
        return None
    return {"display_name": rec.get("displayName") or "",
            "upn": rec.get("userPrincipalName") or "",
            "enabled": rec.get("accountEnabled") in (1, True),
            "object_id": uid}


def sp_owner_dict(sp_id, graph):
    """First owner of a service principal (deterministic order)."""
    for uid in sorted(((graph or {}).get("sp_owners") or {}).get(sp_id) or ()):
        rec = graph_user_record(graph, uid)
        if rec:
            return {"display_name": rec.get("displayName") or "",
                    "upn": rec.get("userPrincipalName") or "",
                    "enabled": rec.get("accountEnabled") in (1, True),
                    "object_id": uid}
    return None


def sp_app_id(sp_id, app_id, graph):
    g = graph or {}
    rec = (g.get("sp") or {}).get(sp_id) if sp_id else None
    if rec is None and app_id:
        rec = (g.get("app") or {}).get(app_id)
    return (rec or {}).get("appId") or ""


def _graph_user(r, uid=None):
    g = _graph_of(r)
    uid = uid or (r or {}).get("user_id")
    return graph_user_record(g, uid)


def _owner_user_record(r):
    """Graph user record for the row's resolved owner, if any (owned/generic/
    app-dir/azure-apps rows all carry a normalized rctx owner dict)."""
    o = (r or {}).get("owner") or {}
    return graph_user_record(_graph_of(r), o.get("object_id"))


# ---- cell renderers (inner html, data_value) -------------------------------

def _cell_severity(f, r):
    return severity_badge(f["severity"]), f["severity"]


def _cell_user(f, r):
    guest = (' <span class="badge badge-guest" title="Guest / external user">Guest</span>'
             if f["user_type"] == "Guest" else "")
    return esc(f["user_display"]) + guest, f["user_display"]


def _cell_user_upn(f, r):
    return esc(f["user_upn"]), f["user_upn"]


def _cell_roles(f, r):
    def title(x):
        text = x.get("source") or ""
        if x.get("scope") and x.get("scope") != "Tenant-wide":
            text += f" \u2014 {x['scope']}"
        return text
    chips = "".join(
        f'<span class="badge {severity_class(x["severity"])} role-badge" data-role="{esc(x["name"])}" data-role-field="roles" title="{esc(title(x))}">{esc(role_display_name(x))}</span> '
        for x in f["roles"])
    return chips, ", ".join(x["name"] for x in f["roles"])


def _cell_eligible(f, r):
    elig = f.get("eligible_roles") or []
    if "group_id" in f:  # groups table flavour: dash inside the count span
        titles = "\n".join(f"{role_display_name(x)} (PIM eligible)" for x in elig)
        inner = (f'<span class="perm" title="{esc(titles or "")}">'
                 f'{len(elig) if elig else DASH_INNER}</span>')
    else:
        titles = "\n".join(f"{role_display_name(x)} ({x['source']})" for x in elig)
        inner = (f'<span class="perm" title="{esc(titles)}">{len(elig)}</span>'
                 if elig else DASH_INNER)
    return inner, ", ".join(x["name"] for x in elig)


def _cell_priv_apps(f, r):
    priv = f["priv_apps"]
    titles = []
    for app in priv:
        perms = ", ".join(g["permission"] for g in app["grants"])
        titles.append(f"{app['app_name']}: {perms}")
    return (f'<span class="perm" title="{esc(chr(10).join(titles))}">{len(priv)}</span>',
            str(len(priv)))


def _cell_cap_groups(f, r):
    cap = f["cap_member"]
    titles = "\n".join(cap_annotate(cap)) if cap else ""
    return f'<span class="perm" title="{esc(titles)}">{len(cap)}</span>', str(len(cap))


def _cell_grp_owned(f, r):
    owned = f["owned_cap"]
    titles = "\n".join(cap_annotate(owned)) if owned else ""
    return (f'<span class="perm" title="{esc(titles or "")}">{f["owned_count"]}</span>',
            str(f["owned_count"]))


def _cell_ca_excl(f, r):
    titles = "\n".join(x["name"] for x in f.get("ca_exclusions", []))
    count = len(f.get("ca_exclusions", []))
    cell = (f'<span class="tag-chip tag-divergence" title="{esc(titles)}">{count}</span>'
            if count else '<span class="muted">0</span>')
    return f'<span class="perm" title="{esc(titles)}">{cell}</span>', str(count)


def _source_badge(synced):
    badge = ('<span class="badge badge-hybrid" title="Synced from on-prem Active Directory">AD</span>'
             if synced else
             '<span class="badge badge-disabled" title="Cloud-only account">Cloud</span>')
    return badge, ("AD" if synced else "Cloud")


def _cell_hybrid(f, r):
    hyb = f.get("hybrid")
    if hyb is None:  # rows without a finding flag: resolve via the graph user
        rec = _graph_user(r)
        if rec is None:
            return _dash_pair()
        hyb = rec.get("dirSyncEnabled") in (1, True)
    return _source_badge(bool(hyb))


def group_source_value(f, r=None):
    """'AD' or 'Cloud'; falls back to the graph group when the finding predates
    the group_source flag (e.g. older analysis caches)."""
    source = f.get("group_source")
    if source:
        return str(source)
    if "group_synced" in f:
        return "AD" if f.get("group_synced") else "Cloud"
    rec = ((_graph_of(r).get("group") or {}).get(f.get("group_id") or "") or {})
    if not rec:
        return ""
    synced = (rec.get("dirSyncEnabled") in (1, True)
              or bool(rec.get("onPremisesSecurityIdentifier")))
    return "AD" if synced else "Cloud"


def _cell_group_source(f, r):
    source = group_source_value(f, r)
    if not source:
        return _dash_pair()
    synced = source == "AD"
    label = "AD" if synced else "Cloud"
    title = ("Synced from on-prem Active Directory" if synced
             else "Cloud-only group")
    cls = "badge-hybrid" if synced else "badge-disabled"
    return f'<span class="badge {cls}" title="{title}">{label}</span>', label


def _cell_user_status(f, r):
    if "user_enabled" in f:
        enabled = bool(f["user_enabled"])
    else:
        enabled = bool((_graph_user(r) or {}).get("accountEnabled"))
    return bool_badge(enabled), "Enabled" if enabled else "Disabled"


def _cell_immutable_id(f, r):
    v = (_graph_user(r) or {}).get("immutableId") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_ad_user(f, r):
    return esc(f["user_display"]), f["user_display"]


def _cell_ad_upn(f, r):
    return esc(f["user_upn"]), f["user_upn"]


def _cell_ad_cn(f, r):
    v = f.get("ad_cn") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_ad_dn(f, r):
    v = f.get("ad_dn") or ""
    if not v:
        v = (_graph_user(r) or {}).get("onPremisesDistinguishedName") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_ad_sid(f, r):
    sid = f.get("ad_sid") or ""
    if not sid:
        sid = (_graph_user(r) or {}).get("onPremisesSecurityIdentifier") or ""
    tail = f.get("sid_rid") or (sid.rsplit("-", 1)[-1] if sid else "")
    if tail:
        return f'<span class="perm" title="{esc(sid)}">{esc(tail)}</span>', sid
    return DASH_INNER, sid


def _cell_ad_pw(f, r):
    v = f.get("pw_change") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_ad_tags(f, r):
    tags = f["tags"]
    return ad_tag_chips(tags), ", ".join(tags)


def _cell_ad_status(f, r):
    enabled = bool((f.get("status") or {}).get("enabled"))
    return bool_badge(enabled), "Enabled" if enabled else "Disabled"


def _cell_owner(f, r):
    o = (r or {}).get("owner")
    if not o:
        return _dash_pair()
    v = o.get("display_name") or ""
    return esc(v), v


def _cell_owner_upn(f, r):
    o = (r or {}).get("owner")
    if not o:
        return _dash_pair()
    v = o.get("upn") or ""
    return esc(v), v


def _cell_owner_status(f, r):
    o = (r or {}).get("owner")
    if not o:
        return _dash_pair()
    enabled = bool(o.get("enabled"))
    return bool_badge(enabled), "Enabled" if enabled else "Disabled"


# User-attribute columns resolved through the row's owner (SP tables).
OWNER_USER_FIELDS = ("ownerSource", "ownerAdDn", "ownerAdSid", "ownerImmutableId")
OWNER_FIELDS = ("owner", "ownerUpn", "ownerStatus") + OWNER_USER_FIELDS


def _cell_owner_source(f, r):
    rec = _owner_user_record(r)
    if rec is None:
        return _dash_pair()
    return _source_badge(rec.get("dirSyncEnabled") in (1, True))


def _cell_owner_ad_dn(f, r):
    v = ((_owner_user_record(r) or {}).get("onPremisesDistinguishedName") or "")
    return (esc(v) if v else DASH_INNER), v


def _cell_owner_ad_sid(f, r):
    v = ((_owner_user_record(r) or {}).get("onPremisesSecurityIdentifier") or "")
    return (esc(v) if v else DASH_INNER), v


def _cell_owner_immutable_id(f, r):
    v = ((_owner_user_record(r) or {}).get("immutableId") or "")
    return (esc(v) if v else DASH_INNER), v


def _cell_app(f, r):
    tid = (r or {}).get("tid")
    if tid == "app-dir-roles-table":
        v = (f.get("target") or {}).get("name") or ""
        return esc(v), v
    v = f.get("display_name") or ""
    note = (' <span class="muted">(foreign SP, no local app registration)</span>'
            if tid == "owned-table" and f.get("is_foreign") else "")
    return esc(v) + note, v


def _cell_pw(f, r):
    v = f.get("pw")
    return count_cell(v), (str(v) if v is not None else "")


def _cell_keys(f, r):
    v = f.get("keys")
    return count_cell(v), (str(v) if v is not None else "")


def _cell_resource(f, r):
    v = f.get("resource_name") or ""
    return esc(v), v


def _cell_permission(f, r):
    return (f'<span class="perm" title="{esc(f.get("reason") or "")}">'
            f'{esc(f.get("permission") or "")}</span>', f.get("permission") or "")


def _cell_sp_status(f, r):
    enabled = bool(f.get("sp_enabled"))
    return bool_badge(enabled), "Enabled" if enabled else "Disabled"


def _cell_app_id(f, r):
    v = sp_app_id((r or {}).get("sp_id"), (r or {}).get("app_id"), _graph_of(r))
    return (esc(v) if v else DASH_INNER), v


def _cell_sp_type(f, r):
    sid = (r or {}).get("sp_id")
    rec = (_graph_of(r).get("sp") or {}).get(sid) if sid else None
    v = (rec or {}).get("servicePrincipalType") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_target(f, r):
    v = (f.get("target") or {}).get("name") or ""
    return esc(v), v


def _cell_target_type(f, r):
    v = (f.get("target") or {}).get("type") or ""
    return esc(v), v


def _cell_obj_id(f, r):
    v = (f.get("target") or {}).get("id") or ""
    return esc(v), v


def _cell_role_count(f, r):
    v = f.get("roles")
    return count_cell(v), (str(v) if v is not None else "")


def _cell_status(f, r):
    return status_cell(f.get("status")), ((f.get("status") or {}).get("label") or "")


def _cell_app_dir_roles(f, r):
    tags = f.get("dir_role_tags", [])
    chips = "".join(app_dir_role_chip(x) for x in tags)
    return (chips or DASH_INNER), ", ".join(x["name"] for x in tags)


# ---- enterprise apps (SSO) ------------------------------------------------

def _cell_sso_protocol(f, r):
    v = f.get("sso_protocol") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_sso_publisher(f, r):
    v = f.get("sso_publisher") or ""
    if not v:
        return _dash_pair()
    return esc(v), v


def _cell_sso_audience(f, r):
    v = f.get("sso_audience") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_sso_assignment(f, r):
    required = bool(f.get("sso_assignment_required"))
    return (bool_badge(required, "Required", "Not required"),
            "Required" if required else "Not required")


def _cell_sso_assigned(f, r):
    label = f.get("sso_assigned_label") or ""
    if not label:
        return _dash_pair()
    if label == "Default access":
        return '<span class="muted">Default access</span>', "Default access"
    details = []
    if not f.get("sso_assignment_required"):
        details.append("assignment not required")
    direct = f.get("sso_assigned_direct_users") or 0
    groups = f.get("sso_assigned_groups") or 0
    sps = f.get("sso_assigned_sps") or 0
    if direct:
        details.append(f"{direct} direct user(s)")
    if groups:
        details.append(f"{groups} group(s)")
    if sps:
        details.append(f"{sps} service principal(s)")
    inner = (f'<span class="perm" title="{esc(" \u00b7 ".join(details))}">'
             f'{esc(label)}</span>')
    return inner, label


def _cell_sso_cert(f, r):
    end = f.get("sso_cert_end") or ""
    days = f.get("sso_cert_days")
    if not end:
        return _dash_pair()
    if days is None:
        return esc(end), end
    if days < 0:
        return ('<span class="badge sev-critical" title="Signing certificate expired: '
                f'{esc(end)}">Expired</span>', "Expired")
    if days <= 30:
        return (f'<span class="badge sev-high" title="{esc(end)}">'
                f'{days}d</span>', end)
    return f'{esc(end)} <span class="muted">({days}d)</span>', end


def _cell_sso_home_tenant(f, r):
    v = f.get("sso_home_tenant") or ""
    if not v:
        return _dash_pair()
    tid = f.get("sso_home_tenant_id") or ""
    inner = esc(v)
    if tid:
        inner = f'<span title="{esc(tid)}">{inner}</span>'
    return inner, v


def _cell_sso_verified(f, r):
    if f.get("sso_verified"):
        return '<span class="badge badge-enabled">Verified</span>', "Verified"
    if f.get("sso_publisher"):
        return '<span class="muted">Unverified</span>', "Unverified"
    return _dash_pair()


def _cell_sso_reply_urls(f, r):
    urls = f.get("sso_reply_urls") or []
    if not urls:
        return _dash_pair()
    return (f'<span class="perm" title="{esc(chr(10).join(urls))}">'
            f'{len(urls)}</span>', str(len(urls)))


def _cell_sso_notify(f, r):
    emails = f.get("sso_notification_emails") or []
    if not emails:
        return _dash_pair()
    return (f'<span class="perm" title="{esc(chr(10).join(emails))}">'
            f'{len(emails)}</span>', str(len(emails)))


def _cell_sso_cert_thumb(f, r):
    v = f.get("sso_cert_thumbprint") or ""
    if not v:
        return _dash_pair()
    return (f'<span class="mono" title="{esc(v)}">{esc(truncate(v, 40))}</span>', v)


# ---- authentication methods ------------------------------------------------

def _cell_auth_method(f, r):
    v = f.get("auth_method_label") or ""
    if not v:
        return DASH_INNER, v
    inner = esc(v)
    if f.get("auth_managed_on_prem"):
        inner += (' <span class="tag-chip" title="Authentication data is managed '
                  'in on-premises Active Directory and synchronized to Entra ID">'
                  'Managed on-prem</span>')
    return inner, v


def _cell_auth_state(f, r):
    v = f.get("auth_state") or ""
    if v == "Enabled":
        return bool_badge(True), v
    if v == "Disabled":
        return bool_badge(False), v
    return (esc(v) if v else DASH_INNER), v


def _cell_auth_scope(f, r):
    v = f.get("auth_scope") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_auth_registration(f, r):
    v = f.get("auth_registration_label") or ""
    if v == "Required":
        return '<span class="badge badge-enabled">Required</span>', v
    if v == "Not required":
        return '<span class="muted">Not required</span>', v
    return _dash_pair()


def _cell_auth_settings(f, r):
    v = f.get("auth_settings_summary") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_auth_source(f, r):
    v = f.get("auth_source") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_auth_id(f, r):
    v = f.get("auth_source_id") or ""
    return (f'<span class="mono">{esc(v)}</span>' if v else DASH_INNER), v


# ---- certificate authentication users --------------------------------------

def _cell_auth_user_type(f, r):
    v = f.get("user_type") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_auth_cba_scope(f, r):
    v = f.get("auth_cba_scope") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_auth_cba_mode(f, r):
    v = f.get("auth_cba_mode") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_auth_cba_bindings(f, r):
    v = f.get("auth_cba_bindings") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_pol_name(f, r):
    v = f.get("policy_name") or ""
    return esc(v), v


def _cell_pol_state(f, r):
    return status_cell(f.get("status")), (f.get("state") or "")


def _cell_pol_scope(f, r):
    v = f.get("scope") or ""
    return esc(v), v


def _cell_pol_apps(f, r):
    joined = ", ".join((f.get("conditions_html") or {}).get("apps") or [])
    shown = joined or "\u2014"
    return f'<span class="perm" title="{esc(joined)}">{esc(shown)}</span>', shown


def _cell_pol_controls(f, r):
    joined = ", ".join((f.get("conditions_html") or {}).get("controls") or [])
    shown = joined or "\u2014"
    return f'<span class="perm" title="{esc(joined)}">{esc(shown)}</span>', shown


def _cell_pol_inc(f, r):
    items = f.get("included", [])
    return (f'<span class="perm" title="{esc(chr(10).join(items))}">{len(items)}</span>',
            str(len(items)))


def _cell_pol_exc(f, r):
    items = f.get("excluded", [])
    return (f'<span class="perm" title="{esc(chr(10).join(items))}">{len(items)}</span>',
            str(len(items)))


def _cell_pol_type(f, r):
    v = f.get("policy_type")
    v = "" if v is None else str(v)
    return (esc(v) if v else DASH_INNER), v


def _cell_pol_created(f, r):
    v = f.get("created") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_pol_modified(f, r):
    v = f.get("modified") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_group(f, r):
    v = f.get("group_name") or ""
    return esc(v), v


def grp_type_value(f):
    """Comma-list value for grpType, aligned with the chips shown in the cell
    (including Mail, Public, Assignable and Auto-membership flags)."""
    values = list(f.get("types") or [])
    if f.get("is_public"):
        values.append("Public")
    if f.get("assignable"):
        values.append("Assignable")
    if f.get("dynamic"):
        values.append("Auto-membership")
    if f.get("mail"):
        values.append("Mail")
    return ", ".join(values)


def _cell_grp_type(f, r):
    types = f.get("types", [])
    chips = [f'<span class="tag-chip">{esc(t)}</span>' for t in types]
    if f.get("is_public"):
        chips.append('<span class="tag-chip">Public</span>')
    if f.get("dynamic"):
        chips.append('<span class="tag-chip tag-spray">Auto-membership</span>')
    if f.get("assignable"):
        chips.append('<span class="tag-chip tag-divergence">Assignable</span>')
    if f.get("mail"):
        chips.append('<span class="tag-chip">Mail</span>')
    return ("".join(chips) or DASH_INNER), grp_type_value(f)


def _cell_grp_roles(f, r):
    chips = "".join(
        f'<span class="badge {severity_class(x["severity"])} role-badge" data-role="{esc(x["name"])}" data-role-field="grpRoles" title="{esc(role_display_name(x))}">{esc(role_display_name(x))}</span> '
        for x in f["dir_roles"])
    return (chips or DASH_INNER), ", ".join(x["name"] for x in f["dir_roles"])


def _cell_grp_members(f, r):
    if "member_count" in f:
        titles = "\n".join(
            ((m["upn"] or m["name"])
             + (" \u2014 " + ", ".join(x["name"] for x in m["roles"] if x["severity"] != "Info")
                if any(x["severity"] != "Info" for x in m["roles"]) else ""))
            for m in f["members"])
        if f["sp_members"]:
            titles += (("\n" if titles else "")
                       + f"{len(f['sp_members'])} SP member(s): "
                       + ", ".join(m["name"] for m in f["sp_members"]))
        return (f'<span class="perm" title="{esc(titles or "")}">{f["member_count"]}</span>',
                str(f["member_count"]))
    return _cell_grp_members_graph(f, r)


def _cell_grp_members_graph(f, r):
    gid = (r or {}).get("group_id")
    g = _graph_of(r)
    users = (g.get("group_member_user") or {}).get(gid) or () if gid else ()
    sps = (g.get("group_member_sp") or {}).get(gid) or () if gid else ()
    names = []
    for uid in sorted(users):
        u = graph_user_record(g, uid) or {}
        names.append(u.get("userPrincipalName") or u.get("displayName") or uid)
    for sid in sorted(sps):
        names.append(((g.get("sp") or {}).get(sid) or {}).get("displayName") or sid)
    return (f'<span class="perm" title="{esc(chr(10).join(names))}">{len(names)}</span>',
            str(len(names)))


def _cell_grp_priv(f, r):
    titles = "\n".join(
        ((m["upn"] or m["name"]) + " \u2014 " + ", ".join(x["name"] for x in m["roles"]))
        for m in f["members"] if m["privileged"])
    return (f'<span class="perm" title="{esc(titles or "")}">{f["priv_member_count"]}</span>',
            str(f["priv_member_count"]))


def _cell_grp_owners(f, r):
    if "owners" in f:
        owners = f["owners"]
        return (f'<span class="perm" title="{esc(chr(10).join(owners) or "")}">{len(owners)}</span>',
                str(len(owners)))
    return _cell_grp_owners_graph(f, r)


def _cell_grp_owners_graph(f, r):
    gid = (r or {}).get("group_id")
    g = _graph_of(r)
    owners = (g.get("group_owner_user") or {}).get(gid) or () if gid else ()
    names = []
    for uid in sorted(owners):
        u = graph_user_record(g, uid) or {}
        names.append(u.get("userPrincipalName") or u.get("displayName") or uid)
    return (f'<span class="perm" title="{esc(chr(10).join(names))}">{len(names)}</span>',
            str(len(names)))


def _cell_dyn_group(f, r):
    v = f.get("group_name") or ""
    return esc(v), v


def _cell_dyn_rule(f, r):
    rule = f.get("dyn_rule") or ""
    if rule.strip() in ("", "[]"):
        rule = ""
    if not rule:
        gid = (r or {}).get("group_id")
        rec = (_graph_of(r).get("group") or {}).get(gid) if gid else None
        rule = (rec or {}).get("membershipRule") or ""
    if rule.strip() in ("", "[]"):
        return _dash_pair()
    return (f'<span class="perm" title="{esc(rule)}">{esc(truncate(rule, 60))}</span>',
            rule)


def _cell_dyn_attrs(f, r):
    attrs = f.get("dyn_attrs", [])
    chips = "".join(
        f'<span class="tag-chip filter-tag" data-filter-field="dynAttrs" data-filter-value="{esc(a)}">{esc(a)}</span> '
        for a in attrs)
    return (chips or DASH_INNER), ", ".join(attrs)


def _cell_dyn_mods(f, r):
    mods = f.get("dyn_mods", [])
    chips = "".join(
        f'<span class="tag-chip {"tag-spray" if m == "User modifiable" else "tag-divergence" if m == "User Administrator" else "tag-privileged" if m == "Directory Writer" else ""} filter-tag" data-filter-field="dynMods" data-filter-value="{esc(m)}">{esc(m)}</span> '
        for m in mods)
    return (chips or DASH_INNER), ", ".join(mods)


def _cell_az_principal(f, r):
    v = f.get("principal") or ""
    return esc(v), v


def _cell_az_role(f, r):
    role = f.get("role") or ""
    return esc(role + (" (eligible)" if f.get("eligible") else "")), role


def _cell_az_scope_type(f, r):
    v = f.get("scope_type") or ""
    return (esc(v) if v else "\u2014"), v


def _cell_az_sub(f, r):
    v = f.get("sub") or "\u2014"
    return esc(v), v


def _cell_az_rg(f, r):
    v = f.get("scope_rg") or ""
    return (esc(v) if v else "\u2014"), v


def _cell_az_provider(f, r):
    v = f.get("scope_provider") or ""
    return (esc(v) if v else "\u2014"), v


def _cell_az_resource(f, r):
    v = f.get("scope_resource") or ""
    return (esc(v) if v else "\u2014"), v


# ---- azure arc cells --------------------------------------------------------

def _cell_arc_machine(f, r):
    v = f.get("machine_name") or ""
    return esc(v), v


def _cell_arc_sub(f, r):
    v = f.get("arc_sub") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_arc_rg(f, r):
    v = f.get("arc_rg") or ""
    return (esc(v) if v else DASH_INNER), v


def _cell_arc_resource_id(f, r):
    v = f.get("arc_resource_id") or ""
    return ((f'<span class="perm" title="{esc(v)}">{esc(truncate(v, 64))}</span>')
            if v else DASH_INNER), v


def _cell_arc_status(f, r):
    st = f.get("arc_status") or {}
    label = st.get("label") or ""
    if not label:
        return _dash_pair()
    return bool_badge(bool(st.get("enabled"))), label


def _cell_arc_principal(f, r):
    v = f.get("arc_principal") or ""
    return esc(v), v


def _cell_arc_principal_type(f, r):
    v = f.get("arc_principal_type") or ""
    return esc(v), v


def _cell_arc_tag(f, r):
    if f.get("arc_tagged"):
        return ('<span class="badge badge-info" '
                'title="Service principal created through the Azure Arc deployment wizard">'
                'AzureArcSPN</span>', "AzureArcSPN")
    return _dash_pair()


def _cell_arc_az_roles(f, r):
    roles = f.get("arc_roles") or []
    chips = "".join(
        f'<span class="badge badge-info" '
        f'title="{esc((a.get("scope_label") or a.get("scope") or ""))}">'
        f'{esc(a.get("role") or "")}{" (eligible)" if a.get("eligible") else ""}</span> '
        for a in roles)
    return chips or DASH_INNER, ", ".join(a.get("role", "") for a in roles)


def _cell_pw_last_set(f, r):
    v = f.get("pw_last_set") or ""
    if not v:
        return _dash_pair()
    note = f.get("pw_creds_note") or v
    return (f'<span class="perm" title="{esc(note)}">{esc(v[:10])}</span>', v[:10])


def _cell_pw_expiry(f, r):
    v = f.get("pw_expiry") or ""
    if not v:
        return _dash_pair()
    note = f.get("pw_creds_note") or v
    return (f'<span class="perm" title="{esc(note)}">{esc(v[:10])}</span>', v[:10])


def _cell_arc_provider(f, r):
    v = f.get("arc_provider") or ""
    return esc(v), v


FIELD_RENDERERS = {
    "severity": _cell_severity,
    "user": _cell_user,
    "userUpn": _cell_user_upn,
    "roles": _cell_roles,
    "eligible": _cell_eligible,
    "privApps": _cell_priv_apps,
    "capGroups": _cell_cap_groups,
    "grpOwned": _cell_grp_owned,
    "caExcl": _cell_ca_excl,
    "hybrid": _cell_hybrid,
    "userStatus": _cell_user_status,
    "immutableId": _cell_immutable_id,
    "owner": _cell_owner,
    "ownerUpn": _cell_owner_upn,
    "ownerStatus": _cell_owner_status,
    "ownerSource": _cell_owner_source,
    "ownerAdDn": _cell_owner_ad_dn,
    "ownerAdSid": _cell_owner_ad_sid,
    "ownerImmutableId": _cell_owner_immutable_id,
    "app": _cell_app,
    "pw": _cell_pw,
    "keys": _cell_keys,
    "resource": _cell_resource,
    "permission": _cell_permission,
    "spStatus": _cell_sp_status,
    "appId": _cell_app_id,
    "spType": _cell_sp_type,
    "target": _cell_target,
    "targetType": _cell_target_type,
    "id": _cell_obj_id,
    "roleCount": _cell_role_count,
    "status": _cell_status,
    "appDirRoles": _cell_app_dir_roles,
    "authMethod": _cell_auth_method,
    "authUserType": _cell_auth_user_type,
    "authCbaScope": _cell_auth_cba_scope,
    "authCbaMode": _cell_auth_cba_mode,
    "authCbaBindings": _cell_auth_cba_bindings,
    "authState": _cell_auth_state,
    "authScope": _cell_auth_scope,
    "authRegistration": _cell_auth_registration,
    "authSettings": _cell_auth_settings,
    "authSource": _cell_auth_source,
    "authId": _cell_auth_id,
    "ssoProtocol": _cell_sso_protocol,
    "ssoPublisher": _cell_sso_publisher,
    "ssoAudience": _cell_sso_audience,
    "ssoAssignment": _cell_sso_assignment,
    "ssoAssigned": _cell_sso_assigned,
    "ssoCertExpiry": _cell_sso_cert,
    "ssoHomeTenant": _cell_sso_home_tenant,
    "ssoVerified": _cell_sso_verified,
    "ssoReplyUrls": _cell_sso_reply_urls,
    "ssoNotify": _cell_sso_notify,
    "ssoCertThumb": _cell_sso_cert_thumb,
    "polName": _cell_pol_name,
    "polState": _cell_pol_state,
    "polScope": _cell_pol_scope,
    "polApps": _cell_pol_apps,
    "polControls": _cell_pol_controls,
    "polInc": _cell_pol_inc,
    "polExc": _cell_pol_exc,
    "polType": _cell_pol_type,
    "polCreated": _cell_pol_created,
    "polModified": _cell_pol_modified,
    "group": _cell_group,
    "grpType": _cell_grp_type,
    "groupSource": _cell_group_source,
    "grpRoles": _cell_grp_roles,
    "grpMembers": _cell_grp_members,
    "grpPriv": _cell_grp_priv,
    "grpOwners": _cell_grp_owners,
    "dynGroup": _cell_dyn_group,
    "dynRule": _cell_dyn_rule,
    "dynAttrs": _cell_dyn_attrs,
    "dynMods": _cell_dyn_mods,
    "adUser": _cell_ad_user,
    "adUpn": _cell_ad_upn,
    "adCn": _cell_ad_cn,
    "adDn": _cell_ad_dn,
    "adSid": _cell_ad_sid,
    "adPw": _cell_ad_pw,
    "adTags": _cell_ad_tags,
    "adStatus": _cell_ad_status,
    "azApp": _cell_az_principal,
    "azGroup": _cell_az_principal,
    "azUser": _cell_az_principal,
    "azRoles": _cell_az_role,
    "azSpRoles": _cell_az_role,
    "azUsrRoles": _cell_az_role,
    "azScopeType": _cell_az_scope_type,
    "azSub": _cell_az_sub,
    "azRg": _cell_az_rg,
    "azProvider": _cell_az_provider,
    "azResource": _cell_az_resource,
    "arcMachine": _cell_arc_machine,
    "arcSub": _cell_arc_sub,
    "arcRg": _cell_arc_rg,
    "arcResourceId": _cell_arc_resource_id,
    "arcStatus": _cell_arc_status,
    "arcPrincipal": _cell_arc_principal,
    "arcPrincipalType": _cell_arc_principal_type,
    "arcTag": _cell_arc_tag,
    "arcAzRoles": _cell_arc_az_roles,
    "pwLastSet": _cell_pw_last_set,
    "pwExpiry": _cell_pw_expiry,
    "arcProvider": _cell_arc_provider,
}


# ---- per-table specs -------------------------------------------------------

# User-attribute columns a row can resolve through its owner (SP tables).

def ad_tag_chips(tags):
    cls = {"Privileged": "tag-privileged"}
    return " ".join(f'<span class="tag-chip {cls.get(t, "")}">{esc(t)}</span>' for t in tags)

def app_dir_role_chip(r):
    """Chip for one directory-role entry in the app-dir-roles table; eligible
    (PIM) entries get a muted (PIM) marker and a tooltip with the path."""
    if r.get("eligible"):
        title = r["name"] + " \u2014 PIM eligible"
        if r.get("path"):
            title += " \u2014 via " + " \u2192 ".join(r["path"])
        label = f'{esc(role_display_name(r))} <span class="muted">(PIM)</span>'
    else:
        title = (r["name"] + " \u2014 via " + " \u2192 ".join(r["path"])
                 if r.get("path") else r["name"] + " \u2014 direct assignment")
        label = esc(role_display_name(r))
    if r.get("scope") and r.get("scope") != "Tenant-wide":
        title += f" \u2014 {r['scope']}"
    return (f'<span class="badge {severity_class(r["severity"])} role-badge" '
            f'data-role="{esc(r["name"])}" data-role-field="roles" '
            f'title="{esc(title)}">{label}</span> ')

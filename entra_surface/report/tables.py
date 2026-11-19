"""Table specifications, pagination metadata and row assembly."""
from __future__ import annotations

from .fields import FIELD_META, FIELD_RENDERERS
from .html import EXPAND_BUTTON_HTML, drawer_for_html, esc

SORT_TITLE = "Click to sort \u00b7 drag to reorder"


USER_OWNER_EXTRAS = [("ownerSource", "user"), ("ownerAdDn", "user"),
                     ("ownerAdSid", "user"), ("ownerImmutableId", "user")]

GENERIC_SPEC = {
    "family": "sp",
    "defaults": ["severity", "target", "targetType", "id", "pw", "keys",
                 "roleCount", "status"],
    "extras": [("owner", "user"), ("ownerUpn", "user"), ("ownerStatus", "user")]
              + USER_OWNER_EXTRAS + [("appId", "sp"), ("spType", "sp")],
}

TABLE_SPECS = {
    "owned-table": {
        "family": "sp",
        "defaults": ["severity", "owner", "ownerUpn", "ownerStatus", "app",
                     "resource", "permission", "spStatus"],
        "extras": [("pw", "sp"), ("keys", "sp"),
                   ("appId", "sp"), ("spType", "sp")] + USER_OWNER_EXTRAS,
    },
    "unowned-table": {
        "family": "sp",
        "defaults": ["severity", "app", "resource",
                     "permission", "spStatus"],
        "extras": [("pw", "sp"), ("keys", "sp"),
                   ("appId", "sp"), ("spType", "sp")],
    },
    "table-ca_exposure": {
        "family": "policy",
        "defaults": ["polName", "polState", "polScope", "polApps",
                     "polControls", "polInc", "polExc"],
        "extras": [("polType", "policy"), ("polCreated", "policy"),
                   ("polModified", "policy")],
    },
    "groups-table": {
        "family": "group",
        "defaults": ["severity", "group", "grpType", "grpRoles", "eligible",
                     "grpMembers", "grpPriv", "grpOwners"],
        "extras": [("dynRule", "group")],
    },
    "dynamic-groups-table": {
        "family": "group",
        "defaults": ["dynGroup", "dynRule", "dynAttrs", "dynMods"],
        "extras": [("grpMembers", "group"), ("grpOwners", "group")],
    },
    "privileged-users-table": {
        "family": "user",
        "defaults": ["severity", "user", "userUpn", "roles", "eligible",
                     "privApps", "capGroups", "grpOwned", "caExcl", "hybrid",
                     "userStatus"],
        "extras": [("adDn", "user"), ("adSid", "user"), ("immutableId", "user")],
    },
    "app-dir-roles-table": {
        "family": "sp",
        "defaults": ["severity", "app", "id", "appDirRoles", "status"],
        "extras": [("owner", "user"), ("ownerUpn", "user"), ("ownerStatus", "user")]
                  + USER_OWNER_EXTRAS + [("appId", "sp"), ("spType", "sp")],
    },
    "app-inventory-table": {
        "family": "sp",
        "defaults": ["severity", "app", "targetType", "appId", "spType",
                     "status", "pw", "keys", "roleCount", "appDirRoles", "owner"],
        "extras": [("ownerUpn", "user"), ("ownerStatus", "user")]
                  + USER_OWNER_EXTRAS + [("id", "sp")],
        "labels": {"targetType": "Object type",
                   "roleCount": "App role assignments",
                   "appDirRoles": "Directory roles"},
    },
    "enterprise-apps-table": {
        "family": "sp",
        "defaults": ["app", "ssoProtocol", "ssoPublisher", "ssoAudience",
                     "ssoHomeTenant", "ssoAssignment", "ssoAssigned",
                     "ssoCertExpiry", "owner", "status"],
        "extras": [("appId", "sp"), ("id", "sp"), ("spType", "sp"),
                   ("ssoVerified", "sp"), ("ssoReplyUrls", "sp"),
                   ("ssoNotify", "sp"), ("ssoCertThumb", "sp"),
                   ("ownerUpn", "user"), ("ownerStatus", "user")],
        "labels": {"ssoProtocol": "Protocol", "ssoPublisher": "Publisher",
                   "ssoAudience": "Audience", "ssoAssignment": "Assignment",
                   "ssoAssigned": "Assigned", "ssoCertExpiry": "Signing cert",
                   "ssoHomeTenant": "Home tenant", "ssoVerified": "Publisher status",
                   "ssoReplyUrls": "Reply URLs", "ssoNotify": "Notify emails",
                   "ssoCertThumb": "Cert thumbprint"},
    },
    "authentication-methods-table": {
        "family": "auth",
        "defaults": ["authMethod", "authState", "authScope",
                     "authRegistration", "authSettings"],
        "extras": [("authSource", "auth"), ("authId", "auth")],
        "labels": {"authMethod": "Method", "authState": "State",
                   "authScope": "Scope", "authRegistration": "Registration",
                   "authSettings": "Settings", "authSource": "Source",
                   "authId": "Policy ID"},
    },
    "certificate-auth-users-table": {
        "family": "user",
        "defaults": ["severity", "user", "userUpn", "authUserType",
                     "userStatus", "hybrid", "authCbaScope", "authCbaMode",
                     "authCbaBindings"],
        "extras": [("id", "user")],
        "labels": {"authUserType": "Type", "authCbaScope": "CBA scope",
                   "authCbaMode": "CBA mode",
                   "authCbaBindings": "Certificate bindings"},
    },
    "ad-sync-users-table": {
        "family": "user",
        "defaults": ["adUser", "adUpn", "adCn", "adDn", "adSid", "adPw",
                     "adTags", "caExcl", "adStatus"],
        "extras": [("immutableId", "user")],
    },
    "azure-roles-apps": {
        "family": "sp",
        "defaults": ["severity", "azApp", "azSpRoles", "azScopeType", "azSub",
                     "azRg", "azProvider", "azResource"],
        "extras": [("owner", "user"), ("ownerUpn", "user"), ("ownerStatus", "user")]
                  + USER_OWNER_EXTRAS + [("appId", "sp"), ("spType", "sp")],
    },
    "azure-roles-groups": {
        "family": "group",
        "defaults": ["severity", "azGroup", "azRoles", "azScopeType", "azSub",
                     "azRg", "azProvider", "azResource"],
        "extras": [("grpMembers", "group"), ("grpOwners", "group")],
    },
    "azure-roles-users": {
        "family": "user",
        "defaults": ["severity", "azUser", "azUsrRoles", "azScopeType", "azSub",
                     "azRg", "azProvider", "azResource"],
        "extras": [("userStatus", "user"), ("hybrid", "user"), ("adDn", "user"),
                   ("adSid", "user"), ("immutableId", "user")],
    },
    "azure-roles-ad": {
        "family": "user",
        "defaults": ["severity", "azUser", "azUsrRoles", "azScopeType", "azSub",
                     "azRg", "azProvider", "azResource"],
        "extras": [("userStatus", "user"), ("hybrid", "user"), ("adDn", "user"),
                   ("adSid", "user"), ("immutableId", "user")],
    },
    "arc-machines-table": {
        "family": "arc",
        "defaults": ["arcMachine", "arcSub", "arcRg", "arcResourceId", "arcStatus"],
        "extras": [("appId", "sp"), ("id", "sp")],
    },
    "arc-principals-table": {
        "family": "arc",
        "defaults": ["arcPrincipal", "arcPrincipalType", "arcTag", "arcAzRoles",
                     "pw", "pwLastSet", "pwExpiry", "arcStatus"],
        "extras": [("appId", "sp"), ("owner", "user"), ("ownerUpn", "user"),
                   ("ownerStatus", "user")],
    },
    "arc-providers-table": {
        "family": "arc",
        "defaults": ["arcProvider", "appId", "arcStatus"],
        "extras": [("id", "sp")],
    },
}


def table_spec(table_id):
    spec = TABLE_SPECS.get(table_id)
    if spec is not None:
        return spec
    if table_id and table_id.startswith("table-"):
        return GENERIC_SPEC
    return None


def field_label(table_id, field):
    spec = table_spec(table_id) or {}
    return (spec.get("labels") or {}).get(field) or FIELD_META[field]["label"]


def cell_cls(table_id, field, is_extra):
    meta = FIELD_META[field]
    if is_extra and "extra_cls" in meta:
        return meta["extra_cls"]
    return meta.get("cls") or ""


def allowed_fields(table_id):
    spec = table_spec(table_id)
    if spec is None:
        return None
    return list(spec["defaults"]) + [f for f, _ in spec["extras"]]


def default_fields(table_id):
    spec = table_spec(table_id)
    return list(spec["defaults"]) if spec is not None else []


def validate_table_specs():
    """Import-time guard: every catalog field must have label/width metadata and
    a renderer, otherwise a header can be emitted without a matching <td> or
    row_html can silently drop the cell (B-099/B-108)."""
    errors = []
    specs = {"table-generic": GENERIC_SPEC}
    specs.update(TABLE_SPECS)
    for table_id, spec in specs.items():
        fields = list(spec["defaults"]) + [field for field, _ in spec["extras"]]
        seen = set()
        for field in fields:
            if field in seen:
                errors.append(f"{table_id}: duplicate field {field!r}")
            seen.add(field)
            if field not in FIELD_META:
                errors.append(f"{table_id}: {field!r} missing from FIELD_META")
            if field not in FIELD_RENDERERS:
                errors.append(f"{table_id}: {field!r} missing from FIELD_RENDERERS")
    for field in FIELD_RENDERERS:
        if field not in FIELD_META:
            errors.append(f"FIELD_RENDERERS: {field!r} missing from FIELD_META")
    if errors:
        raise RuntimeError("invalid table specification:\n  " + "\n  ".join(errors))


validate_table_specs()


def parse_cols_param(raw, table_id):
    """Validate a `cols=` request parameter against the table's catalog."""
    allowed = allowed_fields(table_id)
    if allowed is None:
        return None
    fields = []
    for tok in (raw or "").split(","):
        tok = tok.strip()
        if tok and tok in allowed and tok not in fields:
            fields.append(tok)
        if len(fields) >= 40:
            break
    return fields if fields else default_fields(table_id)


def row_html(table_id, tr_attrs, key, fields, f, r, collect=None):
    """One <tr> plus its drawer row; cells follow `fields` in order. When
    `collect` is a dict, every extra column's (inner, value) pair is recorded
    under the row key so shell-rendered (azure-roles) tables can render extras on demand."""
    spec = table_spec(table_id) or GENERIC_SPEC
    extras = {e[0] for e in spec["extras"]}
    cells = [f'<td class="expand-cell">{EXPAND_BUTTON_HTML}</td>']
    blob = collect.setdefault(key, {}) if collect is not None else None
    render_list = list(fields)
    if blob is not None:
        render_list += [e[0] for e in spec["extras"] if e[0] not in fields]
    for field in render_list:
        renderer = FIELD_RENDERERS.get(field)
        if renderer is None:
            raise KeyError(f"no FIELD_RENDERERS entry for {table_id}.{field}")
        inner, value = renderer(f, r)
        if field in fields:
            cls = cell_cls(table_id, field, field in extras)
            cls_attr = f' class="{cls}"' if cls else ""
            cells.append(
                f'<td{cls_attr} data-field="{field}" data-value="{esc(value)}">{inner}</td>')
        if blob is not None and field in extras:
            # Record every extra, including empty ones: shell-rendered tables
            # must still emit a <td> for each enabled extra column (B-023).
            blob[field] = [inner, value]
    body = "\n          ".join(cells)
    return (f'\n        <tr {tr_attrs} data-detail-key="{key}">\n          {body}\n        </tr>'
            + drawer_for_html(key, len(cells)))


def table_head_html(table_id, fields=None):
    """Server-rendered <colgroup> + <thead> for one table (defaults by default)."""
    spec = table_spec(table_id)
    if spec is None:
        return ""
    fields = list(spec["defaults"] if fields is None else fields)
    cols = ['<col style="width:44px">']
    ths = ['<th class="no-sort"></th>']
    for field in fields:
        cols.append(f'<col style="width:{FIELD_META[field]["width"]}px">')
        ths.append(f'<th data-type="text" data-field="{field}" title="{SORT_TITLE}">'
                   f'{esc(field_label(table_id, field))}</th>')
    return ('<colgroup>\n        ' + '\n        '.join(cols)
            + '\n      </colgroup>\n      <thead>\n        <tr>\n          '
            + '\n          '.join(ths) + '\n        </tr>\n      </thead>')


def table_thead_row_html(table_id, fields):
    """Inner HTML of the header row (used by the serve JSON endpoint)."""
    ths = [f'<th class="no-sort"></th>']
    ths += [f'<th data-type="text" data-field="{field}" title="{SORT_TITLE}">'
            f'{esc(field_label(table_id, field))}</th>' for field in fields]
    return "\n          ".join(ths)


def table_colgroup_inner_html(fields):
    """Inner HTML of the <colgroup> (used by the serve JSON endpoint)."""
    cols = ['<col style="width:44px">']
    cols += [f'<col style="width:{FIELD_META[field]["width"]}px">' for field in fields]
    return "".join(cols)


def catalog_entry(table_id):
    spec = table_spec(table_id)
    if spec is None:
        return None
    fields = []
    for field in spec["defaults"]:
        fields.append({"id": field, "label": field_label(table_id, field),
                       "family": spec["family"], "default": True,
                       "cls": cell_cls(table_id, field, False),
                       "width": FIELD_META[field]["width"]})
    for field, family in spec["extras"]:
        fields.append({"id": field, "label": field_label(table_id, field),
                       "family": family, "default": False,
                       "cls": cell_cls(table_id, field, True),
                       "width": FIELD_META[field]["width"]})
    return {"family": spec["family"], "fields": fields}



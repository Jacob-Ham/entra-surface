#!/usr/bin/env python3
"""
Entra ID attack-surface.

Reads a roadrecon SQLite database (https://github.com/dirkjanm/ROADtools) and
runs a registry of checks that surface dangerous users, applications, service
principals, and tenant configuration. Each check emits structured findings
(check_id, category, severity, evidence, object ids); a single renderer turns
them into a sortable/filterable HTML report with drilldown and entity details.

Checks (config: privileged_roles.json -> "checks"):
  priv_app_ownership      - privileged application (app-only) permission grants
                            resolved to the human owners of the app / SP
  sp_credentials          - credential-bearing SPs / app registrations that
                            also hold role assignments
  no_role_approval        - non-Microsoft apps with appRoleAssignmentRequired
                            = false (no explicit assignment required)
  implicit_flow           - apps with the OAuth2 implicit flow enabled
  public_client_privileged - public clients holding privileged roles
  foreign_principal       - SPs owned by another tenant with privileged roles
  app_dir_roles           - applications (service principals) holding directory
                            roles, assigned directly or via group membership
                            (incl. nesting); rated by the most critical role
  privileged_users        - full user roster: one row per user; privileged users are
                            rated by directory roles (assigned and eligible), owned
                            privileged apps / role-carrying SPs, and role-capable group
                            membership or ownership. Unrated users stay Info.
                            Directory role severities come from 'directory_roles'.
  groups                  - full group roster: one row per group with the directory
                            roles it carries, role-capability, dynamic rules, owners,
                            and privileged / SP members
  ca_exposure             - Conditional Access exposure: policy states/scopes and
                            users excluded from sign-on / MFA policies (elevated
                            when the excluded user is privileged)
  ad_sync_summary         - sync summary card: engine in use (Entra Connect on-prem
                            vs likely Cloud Sync), connector host, password-writeback
                            channel, Desktop SSO status
  ad_sync_users           - AD-synced user roster (flagged users only) plus a realm
                            card: SID / DN / on-prem password change / divergence,
                            with synced-privileged, spray, service-account and
                            no-SID tags
  ad_sync_infra           - AD sync attack surface: ADSync groups, sync service
                            principals, hybrid/legacy auth policies, Windows devices
"""
import argparse
import datetime
import gc
import html
import http.server
import json
import re
import sqlite3
import sys
import time
import urllib.parse
from collections import defaultdict, Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = SCRIPT_DIR / "privileged_roles.json"
DEFAULT_AZURE_CONFIG = SCRIPT_DIR / "azure_roles.json"
SQLITE_IN_CHUNK = 500  # stay well under SQLite's default 999 bound-parameter limit

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

DEFAULT_CHECK_CFG = {
    "enabled": {},                 # {check_id: bool} - empty means all enabled
    "min_severity": "Info",        # drop findings below this
    "suppress": [],                # ["check_id:primary_id"] keys to silence
}

# Microsoft system application role: every application implicitly exposes this
# (id 00000000-0000-0000-0000-000000000000), shown as "Default" / "Default Role"
# in the portal when a principal holds an app role assignment for it.
SYSTEM_DEFAULT_ROLE_ID = "00000000-0000-0000-0000-000000000000"
SYSTEM_DEFAULT_ROLE = {"value": "Default", "description": "Default Role"}

# Short human labels for well-known catalog permissions (the DB only stores the
# long descriptions, e.g. the Microsoft Graph catalog). Override via
# privileged_roles.json -> "role_labels".
DEFAULT_ROLE_LABELS = {
    # Microsoft Graph
    "Application.ReadWrite.All": "Read and write all applications",
    "AppRoleAssignment.ReadWrite.All": "Read and write all app role assignments",
    "RoleManagement.ReadWrite.Directory": "Manage directory role assignments",
    "RoleAssignmentSchedule.ReadWrite.Directory": "Read and write the role assignment schedule (PIM)",
    "Directory.ReadWrite.All": "Read and write directory attributes.",
    "User.ReadWrite.All": "Read and write all users' full profiles",
    "Group.ReadWrite.All": "Read and write all groups except role-assignable",
    "GroupMember.ReadWrite.All": "Read and write all group memberships except role-assignable",
    "UserAuthenticationMethod.ReadWrite.All": "Read and write user authentication methods except for privileged users",
    "Domain.ReadWrite.All": "Read and write custom domains",
    "Synchronization.ReadWrite.All": "Manage directory synchronization",
    "Policy.ReadWrite.ConditionalAccess": "Edit conditional access policies",
    "PrivilegedAccess.ReadWrite.AzureAD": "Manage PIM assignments for Azure AD roles",
    "PrivilegedAccess.ReadWrite.AzureADGroup": "Manage PIM assignments for privileged groups",
    "RoleManagement.ReadWrite.All": "Manage roles for Microsoft 365 services",
    "DeviceManagementConfiguration.ReadWrite.All": "Manage Intune device configuration",
    "DeviceManagementScripts.ReadWrite.All": "Deploy scripts to Intune-managed devices",
    "DeviceManagementManagedDevices.ReadWrite.All": "Manage Intune-managed devices",
    "DeviceManagementRBAC.ReadWrite.All": "Manage Intune role-based access control",
    "Mail.Send": "Send mail",
    "Mail.ReadWrite": "Read and write mail",
    "MailboxSettings.ReadWrite": "Read and write mailbox settings",
    "Files.ReadWrite.All": "Read and write all files",
    "Sites.FullControl.All": "Full control on all site collections",
    "Sites.ReadWrite.All": "Read and write all site collections",
    "Chat.ReadWrite.All": "Read and write all chat messages",
    # Legacy AAD Graph
    "Device.ReadWrite.All": "Read and write all devices",
    # Office 365 Exchange Online
    "full_access_as_app": "Full mailbox access",
    "Exchange.ManageAsApp": "Manage Exchange as application",
    "Exchange.ManageAsAppV2": "Manage Exchange as application (V2)",
    "Exchange.AdminAPI.ManageAsApp": "Full control of Exchange Online via the admin API",
    "Mailbox.Migration": "Migrate mailboxes",
    # SharePoint Online
    "TermStore.ReadWrite.All": "Edit the managed term store",
}

CATEGORY_ORDER = ["apps", "users", "ad", "groups", "configs"]
# Which role class can fabricate membership in a dynamic group by editing the
# referenced user attribute (Entra's rule grammar: `user.<attribute>`). A group
# is tagged per category only when EVERY attribute referenced by its rule is
# modifiable by that role class.
DYN_USER_MODIFIABLE = {
    "givenName", "surname", "streetAddress", "state", "postalCode", "country",
    "telephoneNumber", "mobile", "otherMails",
}
DYN_DIRECTORY_WRITER = {
    "displayName", "city", "companyName", "country", "department",
    "facsimileTelephoneNumber", "givenName", "jobTitle", "mailNickname", "mobile",
    "physicalDeliveryOfficeName", "postalCode", "state", "streetAddress", "surname",
    "telephoneNumber", "proxyAddresses",
}
DYN_USER_ADMINISTRATOR = {
    "accountEnabled", "mail", "userPrincipalName", "userType", "usageLocation",
    "employeeId", "employeeHireDate", "passwordPolicies", "preferredLanguage",
    "sipProxyAddress", "otherMails",
}
DYN_PEOPLE_ADMINISTRATOR = {
    "displayName", "givenName", "surname", "department", "jobTitle", "mobile",
    "telephoneNumber", "physicalDeliveryOfficeName", "city", "state", "postalCode",
    "country", "streetAddress", "companyName",
}

DYNAMIC_RULE_CATEGORIES = [
    ("User modifiable", DYN_USER_MODIFIABLE),
    ("Directory Writer", DYN_DIRECTORY_WRITER),
    ("User Administrator", DYN_USER_ADMINISTRATOR),
    ("People Administrator", DYN_PEOPLE_ADMINISTRATOR),
]


def classify_dynamic_rule(rule):
    """Extract user-attribute references from an Entra membership rule and map
    them onto the role classes that could modify those attributes.

    A role class is only tagged when it can modify EVERY attribute referenced
    by the rule; attributes outside all known sets tag nothing."""
    rule = rule or ""
    attrs = set(re.findall(r"user\.([A-Za-z]+)", rule))
    # also catch bare attribute tokens (rules without the user. prefix)
    for name in set().union(*[c for _, c in DYNAMIC_RULE_CATEGORIES]):
        if re.search(rf"(?<![A-Za-z]){re.escape(name)}(?![A-Za-z])", rule):
            attrs.add(name)
    matched = sorted(attrs)
    mods = [label for label, cat in DYNAMIC_RULE_CATEGORIES
            if attrs and attrs <= cat]
    return matched, mods


CATEGORY_LABELS = {
    "apps": "Apps / Service principals",
    "users": "Users",
    "ad": "Active Directory / On-prem",
    "groups": "Groups",
    "configs": "Conditional Access Policies",
}

# ---------------------------------------------------------------------------
# SQL / JSON helpers
# ---------------------------------------------------------------------------

def chunked(seq, size):
    seq = list(seq)
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def fetch_by_ids(cur, table, id_column, columns, ids):
    """SELECT `columns` FROM `table` WHERE `id_column` IN (ids), batched. Returns list of rows."""
    ids = [i for i in set(ids) if i is not None]
    if not ids:
        return []
    col_sql = ", ".join(columns)
    rows = []
    for chunk in chunked(ids, SQLITE_IN_CHUNK):
        placeholders = ",".join("?" * len(chunk))
        cur.execute(f"SELECT {col_sql} FROM {table} WHERE {id_column} IN ({placeholders})", chunk)
        rows.extend(cur.fetchall())
    return rows


def prune_empty(value):
    """Recursively drop null/empty members so the expanded detail view only shows populated data."""
    if isinstance(value, dict):
        return {k: prune_empty(v) for k, v in value.items() if v not in (None, "", [], {})}
    if isinstance(value, list):
        return [prune_empty(v) for v in value if v not in (None, "")]
    return value


def json_safe_value(value):
    """Parse DB columns that hold JSON-encoded text (appRoles, keyCredentials, etc.) into real objects."""
    if isinstance(value, str) and value[:1] in "[{":
        try:
            return prune_empty(json.loads(value))
        except (json.JSONDecodeError, ValueError):
            return value
    return value


def json_list(value):
    parsed = json_safe_value(value)
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        return [parsed]
    return []


def parse_datetime(value):
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(str(value), fmt).replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            pass
    return None


def truncate(text, width=110):
    text = text or ""
    return text if len(text) <= width else text[: max(0, width - 1)] + "\u2026"


def severity_rank(severity):
    return SEVERITY_ORDER.get(severity, 9)


PRIVILEGED_MAX_RANK = 1  # Critical (0) and High (1)


def is_privileged(severity):
    """True when `severity` is Critical or High."""
    return severity_rank(severity) <= PRIVILEGED_MAX_RANK


# ---------------------------------------------------------------------------
# Advanced filter query language (shared semantics with the report JS — the
# JS side implements the same grammar in the filter module; both are pinned
# against the same test vectors in tests/filter_cases.json).
#
#   expr      := and ("OR" and)*
#   and       := term ("AND" term)*
#   term      := "(" expr ")" | "NOT" term | predicate
#   predicate := field:value | field:contains:value | contains:value | text
#
# Operators are case-insensitive; values can be quoted for spaces. Equality on
# comma-list fields means membership. Bare text / contains: matches substrings
# anywhere in the row.
# ---------------------------------------------------------------------------

ADV_LIST_FIELDS = {
    "roles", "eligible", "grpRoles", "dynmods", "dynattrs",
    "azroles", "azusrroles", "azsproles", "adtags", "appdirroles",
    # serve-side owned-table rows merge all owners into one map
    "owner", "ownerupn", "ownerstatus",
}


class AdvancedParseError(ValueError):
    pass


# Column-name aliases for the filter language: users write the names shown in
# the report (or the short internal names); both resolve to one or more DOM
# field names, matched with any-of semantics. Mirrored in the JS filter module.
ADV_COLUMN_ALIASES = {
    "privileges": ["severity"], "severity": ["severity"], "sev": ["severity"],
    "roles": ["roles", "grproles", "appdirroles"],
    "grproles": ["grproles"], "appdirroles": ["appdirroles"],
    "eligible": ["eligible"],
    "user": ["user"], "upn": ["userupn"], "userupn": ["userupn"],
    "privapps": ["privapps"], "capablegrp": ["capgroups"], "capgroups": ["capgroups"],
    "groupsowned": ["grpowned"], "grpowned": ["grpowned"], "caexcl": ["caexcl"],
    "accountsource": ["hybrid"], "hybrid": ["hybrid"],
    "status": ["userstatus", "status", "spstatus", "ownerstatus", "adstatus"],
    "userstatus": ["userstatus"], "spstatus": ["spstatus"],
    "ownerstatus": ["ownerstatus"], "adstatus": ["adstatus"],
    "target": ["target"], "targettype": ["targettype"],
    "objectid": ["id"], "id": ["id"],
    "passwords": ["pw"], "pw": ["pw"], "keys": ["keys"],
    "roleassignment": ["rolecount"], "rolecount": ["rolecount"],
    "group": ["group"], "type": ["grptype"], "grptype": ["grptype"],
    "members": ["grpmembers"], "grpmembers": ["grpmembers"],
    "privmembers": ["grppriv"], "grppriv": ["grppriv"],
    "owners": ["grpowners"], "grpowners": ["grpowners"],
    "policy": ["polname"], "polname": ["polname"],
    "state": ["polstate"], "polstate": ["polstate"],
    "scope": ["polscope"], "polscope": ["polscope"],
    "apps": ["polapps"], "polapps": ["polapps"],
    "controls": ["polcontrols"], "polcontrols": ["polcontrols"],
    "included": ["polinc"], "polinc": ["polinc"],
    "excluded": ["polexc"], "polexc": ["polexc"],
    "application": ["app"], "app": ["app"],
    "owner": ["owner"], "ownerupn": ["ownerupn"],
    "resource": ["resource"], "permission": ["permission"],
    "membershiprule": ["dynrule"], "dynrule": ["dynrule"],
    "referencedattributes": ["dynattrs"], "dynattrs": ["dynattrs"],
    "modifiableby": ["dynmods"], "dynmods": ["dynmods"],
    "aduser": ["aduser"], "adupn": ["adupn"],
    "adcn": ["adcn"], "addn": ["addn"],
    "sid": ["adsid"], "adsid": ["adsid"],
    "onprempwchange": ["adpw"], "adpw": ["adpw"],
    "targetingtags": ["adtags"], "adtags": ["adtags"],
    "check": ["check"], "category": ["category"],
}

# Multi-word display columns, rewritten to their canonical shortname only when
# followed by ':' (so values containing the phrase stay untouched).
ADV_DISPLAY_PHRASES = [
    ("Directory roles", "roles"), ("Priv. members", "privmembers"),
    ("Priv apps", "privapps"), ("Capable grp", "capablegrp"),
    ("Groups owned", "groupsowned"), ("CA excl.", "caexcl"),
    ("Account Source", "accountsource"), ("Target Type", "targettype"),
    ("Target Status", "status"), ("Object ID", "objectid"),
    ("Role assignment", "roleassignment"), ("SP Status", "spstatus"),
    ("Owner UPN", "ownerupn"), ("Owner Status", "ownerstatus"),
    ("Membership rule", "membershiprule"),
    ("Referenced attributes", "referencedattributes"),
    ("attribute modifiable by", "modifiableby"),
    ("AD CN", "adcn"), ("AD DN", "addn"),
    ("On-prem pw change", "onprempwchange"), ("Targeting tags", "targetingtags"),
]
ADV_PHRASE_RES = [
    (re.compile(r"\b" + re.escape(phrase) + r"(?=\s*:)", re.IGNORECASE), canonical)
    for phrase, canonical in ADV_DISPLAY_PHRASES
]


def _rewrite_column_phrases(text):
    for pattern, canonical in ADV_PHRASE_RES:
        text = pattern.sub(canonical, text)
    return text


def _normalize_field(name):
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


ADV_PHRASE_CANON = {_normalize_field(phrase): canonical
                    for phrase, canonical in ADV_DISPLAY_PHRASES}


def resolve_advanced_fields(name):
    """Map a query field (column name or internal name) to the internal DOM
    field names it matches; raises AdvancedParseError for unknown names."""
    canonical = _normalize_field(name)
    fields = ADV_COLUMN_ALIASES.get(canonical)
    if fields is None:
        phrase_canon = ADV_PHRASE_CANON.get(canonical)
        fields = ADV_COLUMN_ALIASES.get(phrase_canon) if phrase_canon else None
    if fields is None:
        raise AdvancedParseError(
            f"unknown field '{name}' (try privileges, roles, target, check, category&hellip;)")
    return fields


def tokenize_advanced(text):
    """Yield (kind, value) tokens: 'word', 'quoted', 'lparen', 'rparen'."""
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch in "()":
            yield ("lparen" if ch == "(" else "rparen", ch)
            i += 1
            continue
        if ch == '"':
            j = i + 1
            buf = []
            while j < n and text[j] != '"':
                buf.append(text[j])
                j += 1
            if j >= n:
                raise AdvancedParseError(f"unterminated quote at position {i}")
            yield ("quoted", "".join(buf))
            i = j + 1
            continue
        j = i
        while j < n and not text[j].isspace() and text[j] not in "()\"":
            j += 1
        yield ("word", text[i:j])
        i = j


def parse_advanced_query(text):
    """Parse an advanced filter expression into an AST dict, or raise
    AdvancedParseError with a human-readable message.

    AST nodes: {"op": "and"|"or", "children": [...]}, {"op": "not", "child"},
    {"op": "eq"|"contains", "fields": [dom fields], "value"}, {"op": "text", "value"}."""
    text = _rewrite_column_phrases(text or "")
    tokens = list(tokenize_advanced(text))
    if not tokens:
        return {"op": "text", "value": ""}
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def advance():
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def expect(kind):
        tok = peek()
        if tok is None or tok[0] != kind:
            raise AdvancedParseError(
                f"expected {kind} near '{tok[1] if tok else '<end>'}'")
        return advance()

    def is_operator(tok, op):
        return (tok is not None and tok[0] == "word"
                and tok[1].upper() == op)

    def is_any_operator(tok):
        return (tok is not None and tok[0] == "word"
                and tok[1].upper() in ("AND", "OR", "NOT"))

    def consume_value_words(value):
        """Append following plain words to an unquoted value so that values
        with spaces work without quotes: `roles:Global Administrator AND ...`."""
        while True:
            tok = peek()
            if tok is None or tok[0] != "word" or is_any_operator(tok):
                return value
            advance()
            value += " " + tok[1]

    def resolve_field(name):
        if name.upper() == "CONTAINS":
            return None  # bare contains: prefix handled by the caller
        return resolve_advanced_fields(name)

    def parse_or():
        children = [parse_and()]
        while is_operator(peek(), "OR"):
            advance()
            children.append(parse_and())
        return children[0] if len(children) == 1 else {"op": "or", "children": children}

    def parse_and():
        children = [parse_term()]
        while is_operator(peek(), "AND"):
            advance()
            children.append(parse_term())
        return children[0] if len(children) == 1 else {"op": "and", "children": children}

    def parse_term():
        tok = peek()
        if tok is None:
            raise AdvancedParseError("unexpected end of query")
        if tok[0] == "rparen":
            raise AdvancedParseError(f"unexpected ')' near '{tok[1]}'")
        if tok[0] == "lparen":
            advance()
            node = parse_or()
            expect("rparen")
            return node
        if is_operator(tok, "NOT"):
            advance()
            return {"op": "not", "child": parse_term()}
        if tok[0] == "quoted":
            advance()
            return {"op": "text", "value": tok[1]}
        # word: operator, field:value, contains:value, or bare text
        word = advance()[1]
        if is_operator(("word", word), "AND") or is_operator(("word", word), "OR"):
            raise AdvancedParseError(f"unexpected operator '{word}'")
        if word.upper() == "NOT":
            return {"op": "not", "child": parse_term()}
        if ":" not in word:
            return {"op": "text", "value": word}
        field, _, rest = word.partition(":")
        if not field:
            return {"op": "text", "value": word}
        if not rest:
            vt = peek()
            if vt is None or vt[0] not in ("word", "quoted"):
                raise AdvancedParseError(f"expected value after '{field}:'")
            advance()
            return {"op": "eq", "fields": resolve_field(field),
                    "value": consume_value_words(vt[1])}
        if rest.upper() == "CONTAINS":
            vt = peek()
            if vt is None or vt[0] not in ("word", "quoted"):
                raise AdvancedParseError(f"expected value after '{field}:contains:'")
            advance()
            return {"op": "contains", "fields": resolve_field(field),
                    "value": consume_value_words(vt[1])}
        if rest.upper().startswith("CONTAINS:"):
            value = consume_value_words(rest[len("contains:"):])
            return {"op": "contains", "fields": resolve_field(field), "value": value}
        if field.upper() == "CONTAINS":
            return {"op": "text", "value": rest}
        return {"op": "eq", "fields": resolve_field(field),
                "value": consume_value_words(rest)}

    node = parse_or()
    tok = peek()
    if tok is not None:
        raise AdvancedParseError(f"unexpected '{tok[1]}'")
    return node


def _glob_regex(pattern):
    """Compile a case-insensitive glob pattern ('*' wildcards) into a regex."""
    return re.compile(".*".join(re.escape(part) for part in pattern.split("*")),
                      re.IGNORECASE)


def _glob_matches(pattern, value, search=False):
    """Glob pattern match: '*' alone means 'any (non-empty) value'; otherwise
    '*' wildcards match any sequence. `search` matches anywhere in the value
    (for contains:), otherwise the whole value must match."""
    if pattern == "*":
        return bool(value)
    regex = _glob_regex(pattern)
    return regex.search(value) is not None if search else regex.fullmatch(value) is not None


def evaluate_advanced(ast, fields, full_text=""):
    """Evaluate a parsed AST against a field map {field: value string} and the
    row's full searchable text (for text/contains predicates). Field-map keys
    are matched case-insensitively (serve-side maps use CamelCase keys). Values
    support '*' wildcards: '*' alone matches any non-empty value."""
    fields_l = {str(k).lower(): v for k, v in (fields or {}).items()}
    op = ast["op"]
    if op == "text":
        return ast["value"].lower() in (full_text or "").lower()
    if op == "not":
        return not evaluate_advanced(ast["child"], fields_l, full_text)
    if op in ("and", "or"):
        results = [evaluate_advanced(c, fields_l, full_text) for c in ast["children"]]
        return all(results) if op == "and" else any(results)
    if op in ("eq", "contains"):
        needle = ast["value"].lower()
        has_glob = "*" in needle
        for field in ast["fields"]:
            value = (fields_l.get(field) or "").lower()
            if op == "contains":
                if has_glob:
                    if _glob_matches(needle, value, search=True):
                        return True
                elif needle in value:
                    return True
            elif field in ADV_LIST_FIELDS:
                if has_glob:
                    for item in value.split(","):
                        if _glob_matches(needle, item.strip().lower()):
                            return True
                elif needle in [item.strip().lower() for item in value.split(",")]:
                    return True
            else:
                if has_glob:
                    if _glob_matches(needle, value):
                        return True
                elif value == needle:
                    return True
        return False
    return False


# ---------------------------------------------------------------------------
# Entity graph
# ---------------------------------------------------------------------------

SP_GRAPH_FIELDS = [
    "objectId", "appId", "displayName", "appDisplayName", "accountEnabled",
    "deletionTimestamp", "servicePrincipalType", "appOwnerTenantId",
    "microsoftFirstParty", "appRoleAssignmentRequired", "passwordCredentials",
    "keyCredentials", "appRoles", "publicClient",
]
APP_GRAPH_FIELDS = [
    "objectId", "appId", "displayName", "publicClient", "oauth2AllowImplicitFlow",
    "oauth2AllowIdTokenImplicitFlow", "availableToOtherTenants", "publisherDomain",
    "verifiedPublisher", "passwordCredentials", "keyCredentials",
    "requiredResourceAccess", "appRoles",
]
USER_GRAPH_FIELDS = [
    "objectId", "displayName", "userPrincipalName", "userType",
    "accountEnabled", "deletionTimestamp", "dirSyncEnabled",
    "onPremisesSecurityIdentifier",
    "onPremisesDistinguishedName", "onPremisesPasswordChangeTimestamp",
    "lastPasswordChangeDateTime", "lastDirSyncTime", "isResourceAccount",
    "immutableId",
]
GROUP_GRAPH_FIELDS = [
    "objectId", "displayName", "isAssignableToRole", "membershipRule",
    "groupTypes", "visibility", "isPublic", "mailEnabled", "deletionTimestamp",
]
DEVICE_GRAPH_FIELDS = [
    "objectId", "displayName", "hostnames", "deviceOSType", "dirSyncEnabled",
    "onPremisesSecurityIdentifier", "accountEnabled",
]
POLICY_GRAPH_FIELDS = [
    "objectId", "displayName", "policyType", "policyIdentifier", "policyDetail",
]


def build_graph(cur):
    """Load every security-relevant object and adjacency list once.

    Returns a dict with:
      tenant      {object_id, display_name}
      appref_roles {appId: {role_id: {value, description}}} (ApplicationRefs catalog)
      sp          {sp_object_id: {column: value, ...}}
      app         {app_object_id: {column: value, ...}}
      user        {user_object_id: {column: value, ...}}
      app_by_appid {appId: [app_object_id, ...]}
      sp_by_appid  {appId: [service_principal_object_id, ...]}
      app_owners  {app_object_id: {user_object_id, ...}}
      sp_owners   {sp_object_id: {user_object_id, ...}}
      role_assigns [{principal_id, principal_type, resource_id, app_role_id}]
      group       {group_object_id: {column: value, ...}}
      device      {device_object_id: {column: value, ...}}
      policy      {policy_object_id: {displayName, policyType, ...}}
      directory_role {role_object_id: {displayName, ...}}
      role_definition {definition_object_id: {displayName, ...}}
      role_member_user/sp/group  [(role_object_id, principal_object_id), ...]
      group_member_user      {group_object_id: {user_object_id, ...}}
      group_member_group     {group_object_id: {child_group_object_id, ...}}
      group_owner_user       {group_object_id: {user_object_id, ...}}
      group_member_sp        {group_object_id: {service_principal_object_id, ...}}
      directory_role_assigns [{principal_id, role_definition_id, resource_scopes}]
      eligible_role_assigns  [{principal_id, role_definition_id, resource_scopes}]
      policy_user_exclude / policy_user_include  [(policy_object_id, user_object_id), ...]
      policy_include_allusers {policy_object_id, ...}
    """
    graph = {"tenant": {}, "sp": {}, "app": {}, "user": {}, "group": {}, "device": {}, "policy": {},
             "directory_role": {}, "role_definition": {}, "appref_roles": {},
             "app_by_appid": defaultdict(list), "sp_by_appid": defaultdict(list), "app_owners": defaultdict(set),
             "sp_owners": defaultdict(set), "role_assigns": [],
             "role_member_user": [], "role_member_sp": [], "role_member_group": [],
             "group_member_user": defaultdict(set), "group_member_group": defaultdict(set),
             "group_owner_user": defaultdict(set), "device_owners": defaultdict(set),
             "group_member_sp": defaultdict(set),
             "directory_role_assigns": [], "eligible_role_assigns": []}

    try:
        cur.execute("PRAGMA table_info(TenantDetails)")
        td_cols = {r[1] for r in cur.fetchall()}
        td_fields = ["objectId", "displayName"]
        if "verifiedDomains" in td_cols:
            td_fields.append("verifiedDomains")
        cur.execute(f"SELECT {', '.join(td_fields)} FROM TenantDetails LIMIT 1")
        row = cur.fetchone()
        if row:
            graph["tenant"] = {"object_id": row[0], "display_name": row[1]}
            if len(td_fields) > 2:
                graph["tenant"]["verified_domains"] = row[2]
    except sqlite3.OperationalError:
        pass

    def load_table(table, id_column, wanted):
        out = {}
        try:
            cur.execute(f"PRAGMA table_info({table})")
            available = {r[1] for r in cur.fetchall()}
            cols = [c for c in wanted if c in available]
            if id_column not in cols:
                cols = [id_column] + cols
            cur.execute(f"SELECT {', '.join(cols)} FROM {table}")
            for row in cur.fetchall():
                rec = {col: val for col, val in zip(cols, row)}
                out[row[cols.index(id_column)]] = rec
        except sqlite3.OperationalError:
            pass
        return out

    graph["sp"] = load_table("ServicePrincipals", "objectId", SP_GRAPH_FIELDS)
    graph["app"] = load_table("Applications", "objectId", APP_GRAPH_FIELDS)
    graph["user"] = load_table("Users", "objectId", USER_GRAPH_FIELDS)

    for oid, rec in graph["app"].items():
        if rec.get("appId"):
            graph["app_by_appid"][rec["appId"]].append(oid)

    for oid, rec in graph["sp"].items():
        if rec.get("appId"):
            graph["sp_by_appid"][rec["appId"]].append(oid)

    def load_owner_links(table, left_col, right_col):
        out = defaultdict(set)
        try:
            # quote identifiers: 'Group' is a SQLite reserved word
            cur.execute(f'SELECT "{left_col}", "{right_col}" FROM {table}')
            for a, b in cur.fetchall():
                if a and b:
                    out[a].add(b)
        except sqlite3.OperationalError:
            pass
        return out

    graph["app_owners"] = load_owner_links("lnk_application_owner_user", "Application", "User")
    graph["sp_owners"] = load_owner_links("lnk_serviceprincipal_owner_user", "ServicePrincipal", "User")

    graph["group"] = load_table("Groups", "objectId", GROUP_GRAPH_FIELDS)
    graph["device"] = load_table("Devices", "objectId", DEVICE_GRAPH_FIELDS)
    graph["policy"] = load_table("Policys", "objectId", POLICY_GRAPH_FIELDS)

    try:  # ApplicationRefs: app role catalogs for known applications (by appId)
        cur.execute("SELECT appId, appRoles FROM ApplicationRefs")
        for app_id, roles_json in cur.fetchall():
            if not app_id:
                continue
            index = {}
            for role in json_list(roles_json):
                if isinstance(role, dict) and role.get("id"):
                    index[role["id"]] = {
                        "value": role.get("value") or role["id"],
                        "description": role.get("description") or "",
                    }
            if index:
                graph["appref_roles"][app_id] = index
    except sqlite3.OperationalError:
        pass
    graph["directory_role"] = load_table(
        "DirectoryRoles", "objectId", ["objectId", "displayName", "isSystem", "roleDisabled"])
    graph["role_definition"] = load_table(
        "RoleDefinitions", "objectId", ["objectId", "displayName", "isBuiltIn", "isEnabled", "resourceScopes"])

    def load_member_links(table, left_col, right_col):
        out = []
        try:
            cur.execute(f'SELECT "{left_col}", "{right_col}" FROM {table}')
            out = [(a, b) for a, b in cur.fetchall() if a and b]
        except sqlite3.OperationalError:
            pass
        return out

    graph["role_member_user"] = load_member_links("lnk_role_member_user", "DirectoryRole", "User")
    graph["role_member_sp"] = load_member_links("lnk_role_member_serviceprincipal", "DirectoryRole", "ServicePrincipal")
    graph["role_member_group"] = load_member_links("lnk_role_member_group", "DirectoryRole", "Group")
    graph["group_member_user"] = load_owner_links("lnk_group_member_user", "Group", "User")
    graph["group_member_group"] = load_owner_links("lnk_group_member_group", "Group", "childGroup")
    graph["group_owner_user"] = load_owner_links("lnk_group_owner_user", "Group", "User")
    graph["group_member_sp"] = load_owner_links("lnk_group_member_serviceprincipal", "Group", "ServicePrincipal")
    graph["device_owners"] = load_owner_links("lnk_device_owner", "Device", "User")

    graph["policy_user_exclude"] = load_member_links("lnk_policy_user_exclude", "Policy", "User")
    graph["policy_user_include"] = load_member_links("lnk_policy_user_include", "Policy", "User")
    try:
        cur.execute("SELECT Policy FROM lnk_policy_user_include_allusers")
        graph["policy_include_allusers"] = {r[0] for r in cur.fetchall() if r[0]}
    except sqlite3.OperationalError:
        graph["policy_include_allusers"] = set()

    try:
        cur.execute("SELECT principalId, roleDefinitionId, resourceScopes FROM RoleAssignments")
        graph["directory_role_assigns"] = [
            {"principal_id": r[0], "role_definition_id": r[1], "resource_scopes": r[2]}
            for r in cur.fetchall()]
    except sqlite3.OperationalError:
        pass

    try:
        cur.execute("SELECT principalId, roleDefinitionId, resourceScopes FROM EligibleRoleAssignments")
        graph["eligible_role_assigns"] = [
            {"principal_id": r[0], "role_definition_id": r[1], "resource_scopes": r[2]}
            for r in cur.fetchall()]
    except sqlite3.OperationalError:
        pass

    try:
        cur.execute("SELECT id, principalId, principalType, resourceId FROM AppRoleAssignments")
        for row in cur.fetchall():
            graph["role_assigns"].append({
                "app_role_id": row[0], "principal_id": row[1],
                "principal_type": row[2] or "", "resource_id": row[3],
            })
    except sqlite3.OperationalError:
        pass

    # ---- Azure Resource Manager (ARM) role assignments per group -----------
    # Populated only when 'roadrecon azgather' has run with ARM read access;
    # empty AZ* tables => empty map, report renders unchanged.
    graph["az_roles"] = defaultdict(list)
    rd_roles, sub_names = {}, {}
    assignments, elig = {}, {}
    try:
        cur.execute("PRAGMA table_info(AZroleDefinitions)")
        if {"name", "role_name"}.issubset({r[1] for r in cur.fetchall()}):
            cur.execute("SELECT name, role_name FROM AZroleDefinitions")
            rd_roles = {guid: rname for guid, rname in cur.fetchall() if guid and rname}
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute("PRAGMA table_info(AZsubscriptions)")
        if "subscription_id" in {r[1] for r in cur.fetchall()}:
            cur.execute("SELECT subscription_id, display_name FROM AZsubscriptions")
            sub_names = {sid: disp for sid, disp in cur.fetchall() if sid and disp}
    except sqlite3.OperationalError:
        pass

    def az_role_label(role_def_id):
        guid = (role_def_id or "").rsplit("/", 1)[-1]
        return rd_roles.get(guid, guid)

    def az_scope_parse(scope):
        parts = [p for p in (scope or "").split("/") if p]
        out = {"type": "Root", "sub": "", "rg": "", "mgmt": "", "provider": "", "resource": ""}
        if not parts:
            return out
        pl = [p.lower() for p in parts]
        if pl[0] == "subscriptions" and len(parts) > 1:
            out["sub"] = parts[1]
            out["type"] = "Subscription" if len(parts) == 2 else "Scope"
        elif "managementgroups" in pl:
            i = pl.index("managementgroups")
            out["type"] = "Management group"
            if i + 1 < len(parts):
                out["mgmt"] = parts[i + 1]
        else:
            out["type"] = "Scope"
        if "resourcegroups" in pl:
            i = pl.index("resourcegroups")
            if i + 1 < len(parts):
                out["rg"] = parts[i + 1]
            out["type"] = "Resource group"
            if i + 2 < len(parts) and pl[i + 2] == "providers":
                out["type"] = "Resource"
                if i + 3 < len(parts):
                    out["provider"] = parts[i + 3]
                tail = parts[i + 4:]
                if len(tail) >= 2:
                    out["resource"] = tail[-2] + "/" + tail[-1]
        if not out["provider"]:
            for i, p in enumerate(pl):
                if p == "providers" and i + 1 < len(parts):
                    out["provider"] = parts[i + 1]
                    break
        return out

    def az_scope_type(scope):
        return az_scope_parse(scope)["type"]

    def az_scope_sub(scope):
        return az_scope_parse(scope)["sub"]

    def az_scope_label(scope):
        p = az_scope_parse(scope)
        if p["type"] == "Management group":
            return f"Management group {p['mgmt']}" if p["mgmt"] else (scope or "")
        label = sub_names.get(p["sub"]) or p["sub"] or (scope or "")
        if p["rg"]:
            label = f"{label} / {p['rg']}"
            if p["resource"]:
                label = f"{label} / {p['resource']}"
        elif not p["sub"] and not p["rg"]:
            return p["provider"] or (scope or "")
        return label

    def az_assign_entry(extra, eligible=False):
        """Build an ARM assignment record (defensive against schema drift)."""
        p = az_scope_parse(extra.get("scope"))
        entry = {
            "role": az_role_label(extra.get("role_definition_id")),
            "scope": extra.get("scope") or "",
            "scope_type": p["type"],
            "scope_sub": p["sub"],
            "scope_sub_name": sub_names.get(p["sub"], ""),
            "scope_rg": p["rg"],
            "scope_mgmt": p["mgmt"],
            "scope_provider": p["provider"],
            "scope_resource": p["resource"],
            "scope_label": az_scope_label(extra.get("scope")),
            "created_on": str(extra.get("created_on") or "")[:10],
            "condition": extra.get("condition") or "",
            "eligible": bool(eligible),
        }
        if eligible:
            entry["status"] = extra.get("status") or ""
            entry["start"] = str(extra.get("start") or "")[:10]
            entry["end"] = str(extra.get("end") or "")[:10]
        return entry

    try:
        cur.execute("PRAGMA table_info(AZroleAssignments)")
        ra_cols = {r[1] for r in cur.fetchall()}
        if {"id", "scope", "role_definition_id"}.issubset(ra_cols):
            assignments = {}
            cur.execute("SELECT id, scope, role_definition_id, created_on, condition FROM AZroleAssignments")
            for ra_id, scope, rd_id, created, cond in cur.fetchall():
                if ra_id:
                    assignments[ra_id] = {
                        "scope": scope, "role_definition_id": rd_id,
                        "created_on": created, "condition": cond,
                    }
            try:
                # 'Group' is a SQLite reserved word - quote it
                cur.execute('SELECT "Group", AZroleAssignment FROM lnk_az_roleassignment_group')
                for gid, ra_id in cur.fetchall():
                    if gid and ra_id and ra_id in assignments:
                        graph["az_roles"][gid].append(az_assign_entry(assignments[ra_id]))
            except sqlite3.OperationalError:
                pass
    except sqlite3.OperationalError:
        pass

    try:
        cur.execute("PRAGMA table_info(AZroleEligibilityScheduleInstances)")
        ec_cols = {r[1] for r in cur.fetchall()}
        if {"id", "scope", "role_definition_id"}.issubset(ec_cols):
            elig = {}
            cur.execute("SELECT id, scope, role_definition_id, status, start_date_time, end_date_time "
                        "FROM AZroleEligibilityScheduleInstances")
            for eid, scope, rd_id, status, start_dt, end_dt in cur.fetchall():
                if eid:
                    elig[eid] = {
                        "scope": scope, "role_definition_id": rd_id, "status": status,
                        "start": start_dt, "end": end_dt,
                    }
            try:
                cur.execute('SELECT "Group", AZroleEligibilityScheduleInstance '
                            "FROM lnk_az_roleassignment_eligible_group")
                for gid, eid in cur.fetchall():
                    if gid and eid and eid in elig:
                        graph["az_roles"][gid].append(
                            az_assign_entry(elig[eid], eligible=True))
            except sqlite3.OperationalError:
                pass
    except sqlite3.OperationalError:
        pass

    # Service principals with ARM role assignments (same entry shape as groups)
    graph["az_sp_roles"] = defaultdict(list)
    try:
        cur.execute("SELECT ServicePrincipal, AZroleAssignment "
                    "FROM lnk_az_roleassignment_serviceprincipal")
        for sp_id, ra_id in cur.fetchall():
            if sp_id and ra_id and ra_id in assignments:
                graph["az_sp_roles"][sp_id].append(az_assign_entry(assignments[ra_id]))
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute("SELECT ServicePrincipal, AZroleEligibilityScheduleInstance "
                    "FROM lnk_az_roleassignment_eligible_serviceprincipal")
        for sp_id, eid in cur.fetchall():
            if sp_id and eid and eid in elig:
                graph["az_sp_roles"][sp_id].append(az_assign_entry(elig[eid], eligible=True))
    except sqlite3.OperationalError:
        pass

    # Users with ARM role assignments (same entry shape)
    graph["az_user_roles"] = defaultdict(list)
    try:
        cur.execute('SELECT "User", AZroleAssignment FROM lnk_az_roleassignment_user')
        for uid, ra_id in cur.fetchall():
            if uid and ra_id and ra_id in assignments:
                graph["az_user_roles"][uid].append(az_assign_entry(assignments[ra_id]))
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('SELECT "User", AZroleEligibilityScheduleInstance '
                    "FROM lnk_az_roleassignment_eligible_user")
        for uid, eid in cur.fetchall():
            if uid and eid and eid in elig:
                graph["az_user_roles"][uid].append(az_assign_entry(elig[eid], eligible=True))
    except sqlite3.OperationalError:
        pass

    return graph


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config(config_path):
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    resources = {}
    for resource_app_id, entry in data.get("resources", {}).items():
        roles = {}
        for role in entry.get("roles", []):
            roles[role["value"]] = {
                "severity": role.get("severity", "High"),
                "reason": role.get("reason", ""),
            }
        resources[resource_app_id] = {"name": entry.get("name", resource_app_id), "roles": roles}

    check_cfg = dict(DEFAULT_CHECK_CFG)
    cfg = data.get("checks") or {}
    for key in ("enabled", "suppress"):
        if isinstance(cfg.get(key), dict if key == "enabled" else list):
            check_cfg[key] = cfg[key]
    if isinstance(cfg.get("min_severity"), str) and cfg["min_severity"] in SEVERITY_ORDER:
        check_cfg["min_severity"] = cfg["min_severity"]

    directory_roles = {}
    for name, sev in (data.get("directory_roles") or {}).items():
        if isinstance(name, str) and name.startswith("_"):
            continue  # comment keys
        if isinstance(sev, str) and sev in SEVERITY_ORDER:
            directory_roles[name] = sev
        else:
            directory_roles[name] = "Info"
    check_cfg["directory_roles"] = directory_roles

    role_labels = dict(DEFAULT_ROLE_LABELS)
    for value, label in (data.get("role_labels") or {}).items():
        if isinstance(value, str) and isinstance(label, str) and not value.startswith("_"):
            role_labels[value] = label
    check_cfg["role_labels"] = role_labels
    return resources, check_cfg


AZ_SCOPE_TYPES = {"Subscription", "Resource group", "Resource", "Management group", "Root", "Scope"}


def load_azure_roles(config_path):
    """Azure RBAC role -> severity mapping (role name, optionally 'Role@ScopeType').

    Same conventions as directory_roles: '_'-prefixed keys are comments, invalid
    severities fall back to Info. A missing file degrades to an empty mapping
    (everything renders Info) with a warning.
    """
    azure_roles = {}
    if config_path is None or not Path(config_path).exists():
        print(f"warning: azure roles config not found: {config_path} "
              "(all Azure roles will render as Info)", file=sys.stderr)
        return azure_roles
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    for key, sev in (data or {}).items():
        if not isinstance(key, str) or key.startswith("_") or not isinstance(sev, str):
            continue
        if sev not in SEVERITY_ORDER:
            azure_roles[key] = "Info"
            continue
        if "@" in key:
            role, _, scope = key.rpartition("@")
            if role and scope in AZ_SCOPE_TYPES:
                azure_roles[key] = sev
                continue
        azure_roles[key] = sev
    return azure_roles


def azure_severity_for(mapping, role, scope_type):
    """'Role@ScopeType' exact match, then plain 'Role', then Info (unrated)."""
    if scope_type:
        scoped = mapping.get(f"{role}@{scope_type}")
        if scoped:
            return scoped
    return mapping.get(role, "Info")


def apply_azure_severity(graph, mapping):
    """Stamp every collected ARM assignment with its configured severity."""
    for key in ("az_roles", "az_sp_roles", "az_user_roles"):
        for entries in graph[key].values():
            for a in entries:
                a["severity"] = azure_severity_for(mapping, a.get("role", ""), a.get("scope_type", ""))


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
        if role_map:
            index[obj_id] = role_map
    return index, resource_display_names


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def make_finding(check_id, category, severity, title, evidence, primary_id,
                 object_ids=None, remediation="", target=None, status=None):
    return {
        "check_id": check_id,
        "category": category,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "remediation": remediation,
        "primary_id": primary_id,
        "object_ids": {
            "sp": set(object_ids.get("sp", set())) if object_ids else set(),
            "app": set(object_ids.get("app", set())) if object_ids else set(),
            "user": set(object_ids.get("user", set())) if object_ids else set(),
            "device": set(object_ids.get("device", set())) if object_ids else set(),
        },
        "target": target if target else {"type": "", "name": "", "id": primary_id},
        "status": status,
    }


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
        display_name = sp_display_name(sp)
        app_object_id = None
        if app_entries:
            app_object_id = app_entries[0]
            display_name = graph["app"][app_object_id].get("displayName") or display_name
            owner_ids |= graph["app_owners"].get(app_object_id, set())
        owner_ids |= graph["sp_owners"].get(principal_id, set())

        owners = [graph["user"][u] for u in owner_ids if u in graph["user"]]

        findings.append(make_finding(
            check_id="priv_app_ownership", category="apps",
            severity=severity,
            title=f"{title_prefix} with owner" if owners else f"{title_prefix} with no owner",
            evidence=evidence,
            remediation=("Assign an accountable owner or remove the privileged grant." if not owners
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
        finding["is_foreign"] = app_object_id is None and bool(sp.get("appOwnerTenantId"))
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
        ]

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
                 if not r.get("eligible") and is_privileged(r["severity"])]
        if not roles:
            continue
        if not include_disabled and (not sp.get("accountEnabled") or sp.get("deletionTimestamp")):
            continue
        severity = min((r["severity"] for r in roles), key=severity_rank)
        details = [r["name"] + ("" if r["path"] is None
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


def check_sp_credentials(ctx):
    graph, include_disabled = ctx["graph"], ctx["include_disabled"]
    priv_ids, role_ids = ctx["priv_sp_ids"], ctx["role_sp_ids"]
    findings = []

    def emit(name, type_label, id_, sp_oids, app_oid, pw, kc, role_count):
        has_priv = any(o in priv_ids for o in sp_oids)
        has_any = any(o in role_ids for o in sp_oids)
        if not (has_priv or has_any):
            return
        sp = graph["sp"].get(sp_oids[0]) if sp_oids else None
        if not include_disabled and sp and (not sp.get("accountEnabled") or sp.get("deletionTimestamp")):
            return
        if has_priv and sp is not None and sp.get("appRoleAssignmentRequired") == 0:
            severity = "Critical"
        elif has_priv:
            severity = "High"
        else:
            severity = "Medium"
        counts = f"{pw} password + {kc} key credential(s)"
        evidence = f"{counts} · {role_count} app-role assignment(s)"
        remediation = (
            "Rotate the client credentials, restrict the grant to the minimum role set, "
            "and ensure an owner is assigned and reviews this identity regularly."
        )
        findings.append(make_finding(
            check_id="sp_credentials", category="apps",
            severity=severity,
            title=f"Credential-bearing identity with access: {name}",
            evidence=evidence,
            remediation=remediation,
            primary_id=id_,
            object_ids={"sp": set(sp_oids), "app": {app_oid} if app_oid else set()},
            target={"type": type_label, "name": name, "id": id_},
            status=({"label": "Enabled" if sp.get("accountEnabled") else "Disabled",
                     "enabled": bool(sp.get("accountEnabled"))} if sp else None),
        ))
        findings[-1]["pw"] = pw
        findings[-1]["keys"] = kc
        findings[-1]["roles"] = role_count

    flagged_sp = set()
    for oid, rec in graph["sp"].items():
        if rec.get("servicePrincipalType") != "Application":
            continue
        if rec.get("microsoftFirstParty"):
            continue
        pw = len(json_list(rec.get("passwordCredentials")))
        kc = len(json_list(rec.get("keyCredentials")))
        if not pw and not kc:
            continue
        app_oids = graph["app_by_appid"].get(rec.get("appId"), [])
        app_oid = app_oids[0] if app_oids else None
        role_count = len([ra for ra in graph["role_assigns"]
                          if ra["principal_type"] == "ServicePrincipal" and ra["principal_id"] == oid])
        emit(sp_display_name(rec) if not app_oid else graph["app"][app_oid].get("displayName"),
             "Service Principal", oid, [oid], app_oid, pw, kc, role_count)
        flagged_sp.add(oid)

    for oid, rec in graph["app"].items():
        pw = len(json_list(rec.get("passwordCredentials")))
        kc = len(json_list(rec.get("keyCredentials")))
        if not pw and not kc:
            continue
        sp_oids = graph["sp_by_appid"].get(rec.get("appId"), [])
        if sp_oids and all(o in flagged_sp for o in sp_oids):
            continue  # already reported via the service principal
        role_count = sum(len([ra for ra in graph["role_assigns"]
                              if ra["principal_type"] == "ServicePrincipal" and ra["principal_id"] == o])
                         for o in sp_oids)
        emit(rec.get("displayName") or oid, "Application registration", oid,
             sp_oids, oid, pw, kc, role_count)

    seen = set()
    unique = []
    for f in findings:
        key = (f["primary_id"], f["severity"], f["evidence"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    unique.sort(key=lambda f: (severity_rank(f["severity"]), (f["target"]["name"] or "").lower()))
    return unique


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
        role_count = len([ra for ra in graph["role_assigns"]
                          if ra["principal_type"] == "ServicePrincipal" and ra["principal_id"] == oid])
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


def check_implicit_flow(ctx):
    graph = ctx["graph"]
    priv_ids = ctx["priv_sp_ids"]
    findings = []
    for oid, rec in graph["app"].items():
        flags = []
        if rec.get("oauth2AllowImplicitFlow") == 1:
            flags.append("oauth2AllowImplicitFlow")
        if rec.get("oauth2AllowIdTokenImplicitFlow") == 1:
            flags.append("oauth2AllowIdTokenImplicitFlow")
        if not flags:
            continue
        sp_oids = graph["sp_by_appid"].get(rec.get("appId"), [])
        has_priv = any(o in priv_ids for o in sp_oids)
        role_count = sum(len([ra for ra in graph["role_assigns"]
                              if ra["principal_type"] == "ServicePrincipal" and ra["principal_id"] == o])
                         for o in sp_oids)
        findings.append(make_finding(
            check_id="implicit_flow", category="apps",
            severity="High" if has_priv else "Medium",
            title=f"Implicit flow enabled: {rec.get('displayName') or oid}",
            evidence=", ".join(flags) + (" · app holds privileged app-role assignments" if has_priv
                                         else " · no privileged app-role assignments observed"),
            remediation=("Disable the implicit flow and migrate to the authorization-code flow "
                         "with PKCE; implicit-flow tokens leak via URLs, history and referrers."),
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
        role_count = sum(len([ra for ra in graph["role_assigns"]
                              if ra["principal_type"] == "ServicePrincipal" and ra["principal_id"] == o])
                         for o in sp_oids)
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
    tenant_id = graph["tenant"].get("object_id")
    findings = []
    for oid, rec in graph["sp"].items():
        if oid not in priv_ids:
            continue
        owner_tid = rec.get("appOwnerTenantId")
        if not owner_tid:
            continue
        local_app = bool(graph["app_by_appid"].get(rec.get("appId")))
        foreign = not local_app and (tenant_id is None or str(owner_tid).lower() != str(tenant_id).lower())
        if not foreign:
            continue
        if not include_disabled and (not rec.get("accountEnabled") or rec.get("deletionTimestamp")):
            continue
        reasons = []
        for ra in graph["role_assigns"]:
            if ra["principal_type"] != "ServicePrincipal" or ra["principal_id"] != oid:
                continue
            ra_info = ctx["resource_index"].get(ra["resource_id"], {}).get(ra["app_role_id"])
            if ra_info:
                reasons.append(ra_info["reason"])
        role_count = len([ra for ra in graph["role_assigns"]
                          if ra["principal_type"] == "ServicePrincipal" and ra["principal_id"] == oid])
        findings.append(make_finding(
            check_id="foreign_principal", category="apps",
            severity="Critical",
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
        severity = min((r["severity"] for r in active), key=severity_rank) if active else "Info"
        parts = [r["name"] + (" (PIM eligible)" if r.get("eligible") else "")
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


def check_privileged_users(ctx):
    """Aggregate every privilege signal we can attribute per user into one finding.

    Signals: directory roles (lnk_role_member_user + RoleAssignments), PIM-eligible
    roles, ownership of apps/SPs that hold privileged grants (from the app-permission
    config) or directory roles, and membership/ownership of role-capable groups.
    On-prem sync is recorded as context, never rated.
    """
    graph = ctx["graph"]
    role_sev = ctx["check_cfg"]["directory_roles"]
    include_disabled = ctx["include_disabled"]
    resource_index, resource_names = ctx["resource_index"], ctx["resource_names"]

    def sev_of(name):
        return role_sev.get(name, "Info")

    def def_name(oid):
        rec = graph["role_definition"].get(oid)
        return rec.get("displayName") if rec else oid

    def sp_name(sp):
        return sp.get("displayName") or sp.get("appDisplayName") or sp.get("objectId")

    # ---- role-capable groups (shared with the groups check) ---------------
    capable = ctx["capable_groups"]
    group_roles = ctx["group_roles"]
    group_eligible_roles = ctx.get("group_eligible_roles") or {}

    # ---- privileged app grants per SP ------------------------------------
    grants_by_sp = {}  # sp_oid -> [(permission, severity, resource)]
    for ra in graph["role_assigns"]:
        if ra["principal_type"] != "ServicePrincipal":
            continue
        ri = resource_index.get(ra["resource_id"], {}).get(ra["app_role_id"])
        if ri:
            grants_by_sp.setdefault(ra["principal_id"], []).append(
                (ri["value"], ri["severity"], resource_names.get(ra["resource_id"], ra["resource_id"])))

    profiles = {}

    def ensure(uid):
        p = profiles.get(uid)
        if p is None:
            p = profiles[uid] = {
                "roles": [], "eligible_roles": [], "priv_apps": [], "dir_sp_roles": [],
                "cap_member": [], "owned_cap": [], "member_count": 0, "owned_count": 0,
                "groups": [], "hybrid": False, "enabled": True, "owned_objects": [],
            }
        return p

    def group_name(gid):
        rec = graph["group"].get(gid)
        return rec.get("displayName") if rec else gid

    # ---- CA policy exclusions (per-user attribute with drill-down data) ----
    def _policy_state(prec):
        detail = json_safe_value(prec.get("policyDetail"))
        try:
            inner = json.loads(detail[0]) if detail and isinstance(detail[0], str) else (detail[0] if detail else None)
            return ((inner or {}).get("State") or "").strip() or "Unknown"
        except (json.JSONDecodeError, ValueError, TypeError, IndexError):
            return "Unknown"

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

    # seed the roster: every user, linked or not
    for uid in graph["user"]:
        ensure(uid)

    # device ownership (user -> devices), per lnk_device_owner
    user_devices = defaultdict(list)
    for did, uids in graph["device_owners"].items():
        for uid in uids:
            user_devices[uid].append(did)

    # ---- direct directory roles ------------------------------------------
    for uid, roles in direct_directory_roles_by_user(graph, role_sev).items():
        p = ensure(uid)
        p["roles"].extend(roles)

    for ra in graph["directory_role_assigns"]:
        pid = ra["principal_id"]
        if pid in graph["sp"]:
            sp = graph["sp"][pid]
            name = def_name(ra["role_definition_id"])
            for owner in graph["sp_owners"].get(pid, set()):
                ensure(owner)["dir_sp_roles"].append(
                    {"sp_name": sp_name(sp), "role": name, "severity": sev_of(name)})

    for ea in graph["eligible_role_assigns"]:
        pid = ea["principal_id"]
        if pid in graph["user"]:
            p = ensure(pid)
            name = def_name(ea["role_definition_id"])
            p["eligible_roles"].append({"name": name, "severity": sev_of(name),
                                        "source": "PIM eligible"})

    # ---- group memberships / ownership -------------------------------------
    group_path_cache = {}

    def path_roles_for(gid):
        if gid not in group_path_cache:
            group_path_cache[gid] = resolve_group_role_paths(
                gid, group_roles, graph["group_member_group"], group_name)
        return group_path_cache[gid]

    eligible_path_cache = {}

    def eligible_paths_for(gid):
        if gid not in eligible_path_cache:
            eligible_path_cache[gid] = resolve_group_role_paths(
                gid, group_eligible_roles, graph["group_member_group"], group_name)
        return eligible_path_cache[gid]

    for gid, uids in graph["group_member_user"].items():
        rec = graph["group"].get(gid)
        if not rec:
            continue
        gname = rec.get("displayName") or gid
        inherited = path_roles_for(gid)
        inherited_eligible = eligible_paths_for(gid)
        for uid in uids:
            p = ensure(uid)
            p["member_count"] += 1
            p["groups"].append({
                "name": gname,
                "group_id": gid,
                "capable": gid in capable,
                "roles": group_roles.get(gid, []),
            })
            if gid in capable:
                p["cap_member"].append({"name": gname, "roles": group_roles.get(gid, [])})
            # directory roles inherited through this group (incl. nesting),
            # with the group path — same treatment as service principals
            for r in inherited:
                p["roles"].append({"name": r["name"], "severity": r["severity"],
                                   "source": "via " + " \u2192 ".join(r["path"])})
            # PIM-eligible roles inherited through this group (incl. nesting)
            for r in inherited_eligible:
                p["eligible_roles"].append({"name": r["name"], "severity": r["severity"],
                                            "source": "PIM eligible via "
                                                      + " \u2192 ".join(r["path"])})
    for gid, uids in graph["group_owner_user"].items():
        for uid in uids:
            p = ensure(uid)
            p["owned_count"] += 1
            if gid in capable:
                p["owned_cap"].append({"name": group_name(gid), "roles": group_roles.get(gid, [])})

    # ---- ownership of privileged objects -----------------------------------
    seen_owner_sp = set()  # (uid, sp_oid) already attributed via the app
    for app_oid, uids in graph["app_owners"].items():
        app = graph["app"].get(app_oid)
        if not app:
            continue
        sp_oids = graph["sp_by_appid"].get(app.get("appId"), [])
        app_grants = []
        for sp_oid in sp_oids:
            if sp_oid in grants_by_sp:
                app_grants += [{"permission": g[0], "severity": g[1], "resource": g[2]}
                               for g in grants_by_sp[sp_oid]]
        if not app_grants:
            continue
        for uid in uids:
            for sp_oid in sp_oids:
                seen_owner_sp.add((uid, sp_oid))
            ensure(uid)["priv_apps"].append(
                {"app_name": app.get("displayName") or app_oid, "grants": app_grants})

    for sp_oid, uids in graph["sp_owners"].items():
        if sp_oid not in grants_by_sp:
            continue
        grants = [{"permission": g[0], "severity": g[1], "resource": g[2]} for g in grants_by_sp[sp_oid]]
        sp = graph["sp"].get(sp_oid) or {}
        label = sp_name(sp) if sp else sp_oid
        for uid in uids:
            if (uid, sp_oid) in seen_owner_sp:
                continue
            seen_owner_sp.add((uid, sp_oid))
            ensure(uid)["priv_apps"].append({"app_name": label, "grants": grants})

    # ---- owned objects (full inventory, not only privileged) --------------
    def creds_of(record):
        return (len(json_list(record.get("passwordCredentials"))),
                len(json_list(record.get("keyCredentials"))))

    for app_oid, uids in graph["app_owners"].items():
        app = graph["app"].get(app_oid)
        if not app:
            continue
        sp_oids = graph["sp_by_appid"].get(app.get("appId"), [])
        grants = []
        sp_status = None
        for sp_oid in sp_oids:
            for g in grants_by_sp.get(sp_oid, []):
                grants.append({"permission": g[0], "severity": g[1], "resource": g[2]})
            sp = graph["sp"].get(sp_oid)
            if sp is not None and sp_status is None:
                sp_status = bool(sp.get("accountEnabled"))
        pw, key = creds_of(app)
        entry = {
            "type": "Application",
            "name": app.get("displayName") or app_oid,
            "object_id": app_oid,
            "app_id": app.get("appId") or "",
            "grants": grants,
            "pw": pw, "key": key,
            "status": sp_status,
        }
        for uid in uids:
            ensure(uid)["owned_objects"].append(entry)

    for sp_oid, uids in graph["sp_owners"].items():
        sp = graph["sp"].get(sp_oid)
        if not sp:
            continue
        pw, key = creds_of(sp)
        entry = {
            "type": "Service Principal",
            "name": sp.get("displayName") or sp.get("appDisplayName") or sp_oid,
            "object_id": sp_oid,
            "app_id": sp.get("appId") or "",
            "grants": [{"permission": g[0], "severity": g[1], "resource": g[2]}
                       for g in grants_by_sp.get(sp_oid, [])],
            "pw": pw, "key": key,
            "status": bool(sp.get("accountEnabled")),
        }
        for uid in uids:
            ensure(uid)["owned_objects"].append(entry)

    for gid, uids in graph["group_owner_user"].items():
        grp = graph["group"].get(gid)
        if not grp:
            continue
        entry = {
            "type": "Group",
            "name": grp.get("displayName") or gid,
            "object_id": gid,
            "app_id": "",
            "grants": [],
            "pw": 0, "key": 0,
            "status": None,
        }
        for uid in uids:
            ensure(uid)["owned_objects"].append(entry)

    # ---- hybrid / context ---------------------------------------------------
    def dedupe_roles(roles):
        merged = {}
        for r in roles:
            key = r["name"]
            src = r.get("source") or "assigned"
            if key not in merged:
                merged[key] = {"name": key, "severity": r["severity"], "source": src}
            else:
                srcs = [s.strip() for s in merged[key]["source"].split("\u00b7")]
                if src not in srcs:
                    srcs.append(src)
                merged[key]["source"] = " \u00b7 ".join(srcs)
        return sorted(merged.values(), key=lambda r: severity_rank(r["severity"]))

    for p in profiles.values():
        p["roles"] = dedupe_roles(p["roles"])
        p["eligible_roles"] = dedupe_roles(p["eligible_roles"])

    for uid, p in profiles.items():
        user = graph["user"].get(uid) or {}
        p["hybrid"] = user.get("dirSyncEnabled") in (1, True)
        p["enabled"] = bool(user.get("accountEnabled"))
        p["user_type"] = user.get("userType") or "Member"
        p["ca_exclusions"] = sorted(ca_exclusions.get(uid, ()), key=lambda x: x["name"])
        p["owned_objects"] = sorted(p.get("owned_objects", []),
                                    key=lambda o: (o["type"], (o["name"] or "").lower()))
        seen_oids = set()
        uniq = []
        for o in p["owned_objects"]:
            if o["object_id"] in seen_oids:
                continue
            seen_oids.add(o["object_id"])
            uniq.append(o)
        p["owned_objects"] = uniq
        devices = []
        for did in user_devices.get(uid, []):
            dev = graph["device"].get(did)
            if not dev:
                continue
            devices.append({
                "name": dev.get("displayName") or did,
                "object_id": did,
                "os": dev.get("deviceOSType") or "",
                "ad_bound": bool(dev.get("onPremisesSecurityIdentifier")),
                "last_logon": dev.get("approximateLastLogonTimestamp") or "",
                "enabled": bool(dev.get("accountEnabled")),
            })
        devices.sort(key=lambda d: (d["name"] or "").lower())
        p["devices"] = devices

    # ---- findings ------------------------------------------------------------
    findings = []
    for uid, p in profiles.items():
        user = graph["user"].get(uid) or {}
        if user.get("deletionTimestamp"):
            continue  # soft-deleted users are excluded; disabled users stay listed (status column)
        sevs = [r["severity"] for r in p["roles"]] + [r["severity"] for r in p["eligible_roles"]]
        sevs += [g["severity"] for app in p["priv_apps"] for g in app["grants"]]
        sevs += [s["severity"] for s in p["dir_sp_roles"]]
        if p["cap_member"]:
            sevs.append("Medium")
        if p["owned_cap"]:
            sevs.append("High")
        display = user.get("displayName") or user.get("userPrincipalName") or uid
        upn = user.get("userPrincipalName") or ""

        if not sevs:
            severity = "Info"
            parts = ["no privilege signals captured"]
        else:
            severity = min(sevs, key=severity_rank)
            parts = []
            if p["roles"]:
                parts.append(f"{len(p['roles'])} directory role(s)")
            if p["eligible_roles"]:
                parts.append(f"{len(p['eligible_roles'])} eligible role(s)")
            if p["priv_apps"]:
                parts.append(f"owns {len(p['priv_apps'])} privileged object(s)")
            if p["cap_member"]:
                parts.append(f"member of {len(p['cap_member'])} role-capable group(s)")
            if p["owned_cap"]:
                parts.append(f"owns {len(p['owned_cap'])} role-capable group(s)")

        f = make_finding(
            check_id="privileged_users", category="users",
            severity=severity,
            title=(f"Privileged user: {display}" if severity != "Info" or parts != ["no privilege signals captured"]
                   else f"User: {display}"),
            evidence=" · ".join(parts) or "privilege signal(s) present",
            remediation=(("No privilege signals observed — listed for completeness. "
                          "Nothing to remediate for this account.") if severity == "Info" and not p["roles"] and not p["priv_apps"]
                         else ("Review the user's role assignments, eligibility, and owned objects; "
                               "apply least privilege and require MFA on privileged accounts.")),
            primary_id=uid,
            object_ids={"user": {uid}},
            target={"type": "User", "name": display, "id": uid},
            status={"label": "Enabled" if p["enabled"] else "Disabled", "enabled": p["enabled"]},
        )
        f["user_id"] = uid
        f["user_display"] = display
        f["user_upn"] = upn
        f["user_type"] = p["user_type"]
        f["user_enabled"] = p["enabled"]
        f["hybrid"] = p["hybrid"]
        f["roles"] = sorted(p["roles"], key=lambda r: severity_rank(r["severity"]))
        f["eligible_roles"] = p["eligible_roles"]
        f["priv_apps"] = p["priv_apps"]
        f["dir_sp_roles"] = p["dir_sp_roles"]
        f["cap_member"] = sorted(p["cap_member"], key=lambda c: (c.get("name") or "").lower())
        f["owned_cap"] = sorted(p["owned_cap"], key=lambda c: (c.get("name") or "").lower())
        f["groups"] = sorted(p["groups"], key=lambda g: (g.get("name") or "").lower())
        f["member_count"] = p["member_count"]
        f["owned_count"] = p["owned_count"]
        f["owned_objects"] = p.get("owned_objects", [])
        f["devices"] = p.get("devices", [])
        f["ca_exclusions"] = p.get("ca_exclusions", [])
        findings.append(f)

    findings.sort(key=lambda f: (severity_rank(f["severity"]), (f["user_display"] or "").lower()))
    return findings


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
    privileged_ids = set()
    for role_oid, uid in graph["role_member_user"]:
        if sev_rank_of(role_name(role_oid)) <= 1:
            privileged_ids.add(uid)
    role_defs = graph["role_definition"]
    for ra in graph["directory_role_assigns"]:
        rd = role_defs.get(ra["role_definition_id"])
        name = rd.get("displayName") if rd else ra["role_definition_id"]
        if ra["principal_id"] in graph["user"] and sev_rank_of(name) <= 1:
            privileged_ids.add(ra["principal_id"])

    grants_by_sp = {}  # sp_oid -> [(permission, severity)]
    for ra in graph["role_assigns"]:
        if ra["principal_type"] != "ServicePrincipal":
            continue
        ri = resource_index.get(ra["resource_id"], {}).get(ra["app_role_id"])
        if ri:
            grants_by_sp.setdefault(ra["principal_id"], []).append(
                (ri["value"], ri["severity"]))
    priv_owner_ids = set()
    for app_oid, uids in graph["app_owners"].items():
        app = graph["app"].get(app_oid)
        if not app:
            continue
        for sp_oid in graph["sp_by_appid"].get(app.get("appId"), []):
            if any(is_privileged(g[1]) for g in grants_by_sp.get(sp_oid, [])):
                priv_owner_ids |= uids
    for sp_oid, uids in graph["sp_owners"].items():
        if any(is_privileged(g[1]) for g in grants_by_sp.get(sp_oid, [])):
            priv_owner_ids |= uids

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
        detail = json_safe_value(prec.get("policyDetail"))
        try:
            inner = json.loads(detail[0]) if detail and isinstance(detail[0], str) else (detail[0] if detail else None)
            return ((inner or {}).get("State") or "").strip() or "Unknown"
        except (json.JSONDecodeError, ValueError, TypeError, IndexError):
            return "Unknown"

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
    for gid, rec in graph["group"].items():
        name = rec.get("displayName") or ""
        if "ADSync" not in name:
            continue
        members = sorted(graph["user"][uid].get("displayName") or uid
                         for uid in graph["group_member_user"].get(gid, set())
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
        role_assign_count = len([ra for ra in graph["role_assigns"]
                                 if ra["principal_type"] == "ServicePrincipal" and ra["principal_id"] == oid])
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
    for oid, rec in graph["policy"].items():
        name = rec.get("displayName") or ""
        if "n-Premise" not in name and "legacy" not in name.lower():
            continue
        findings.append(make_finding(
            check_id="ad_sync_infra", category="ad", severity="Info",
            title=f"Authentication policy: {name}",
            evidence=f"policyType={rec.get('policyType')} · policyIdentifier={rec.get('policyIdentifier') or 'n/a'}",
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
        findings.append(make_finding(
            check_id="ad_sync_infra", category="ad", severity="Info",
            title=f"Windows device: {name}",
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
    indicators.append({
        "label": "Cloud-sync-specific markers", "present": False,
        "detail": ("none observed; cloud sync is inferred by absence of the on-prem "
                   "markers above, not positively confirmed"),
    })

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
        arr = json_safe_value(policy_detail)
        if not isinstance(arr, list) or not arr:
            return None
        inner = json.loads(arr[0]) if isinstance(arr[0], str) else arr[0]
        sso = ((inner or {}).get("OnPremAuthenticationFlowPolicy") or {}).get("DesktopSSO") or {}
        if not isinstance(sso, dict):
            return None
        domains = [s.get("Domain") for s in (sso.get("Secrets") or [])
                   if isinstance(s, dict) and s.get("Domain")]
        return {"enabled": bool(sso.get("Enabled")),
                "spns": bool(sso.get("AreNewSPNsAdded")),
                "domains": [d for d in domains if d]}
    except (json.JSONDecodeError, ValueError, TypeError, KeyError):
        return None


def resolve_group_role_paths(gid, group_roles, group_member_group, group_label):
    """Directory roles members of `gid` inherit through nested group membership.

    Walks up the containment chain (gid is a member of parent groups, which may
    themselves be nested in further groups) and returns one entry per role with
    the shortest group path from `gid` to the role-bearing group, e.g.
    {"name": "Global Administrator", "severity": "Critical",
     "path": ["Team A", "Team A - Admins", "Root Admins"]}.
    """
    found = {}
    seen = {gid}
    queue = [(gid, [gid])]
    while queue:
        cur, path = queue.pop(0)
        for r in group_roles.get(cur, []):
            if r["name"] not in found:
                found[r["name"]] = {
                    "name": r["name"], "severity": r["severity"],
                    "path": [group_label(g) for g in path],
                }
        for parent, children in group_member_group.items():
            if cur in children and parent not in seen:
                seen.add(parent)
                queue.append((parent, path + [parent]))
    return sorted(found.values(), key=lambda r: severity_rank(r["severity"]))


def direct_directory_roles_by_user(graph, role_sev):
    """{user_id: [{name, severity, source}]} directly-assigned directory roles
    per user (role memberships + role assignments), deduped by name with merged
    sources. Shared by the privileged-users and groups checks."""
    out = defaultdict(list)

    def _role_name(oid):
        rec = graph["directory_role"].get(oid)
        return rec.get("displayName") if rec else oid

    def _def_name(oid):
        rec = graph["role_definition"].get(oid)
        return rec.get("displayName") if rec else oid

    for role_oid, uid in graph["role_member_user"]:
        name = _role_name(role_oid)
        out[uid].append({"name": name, "severity": role_sev.get(name, "Info"),
                         "source": "role member"})
    for ra in graph["directory_role_assigns"]:
        if ra["principal_id"] in graph["user"]:
            name = _def_name(ra["role_definition_id"])
            out[ra["principal_id"]].append({"name": name,
                                            "severity": role_sev.get(name, "Info"),
                                            "source": "role assignment"})
    for uid in list(out):
        merged = {}
        for r in out[uid]:
            key = r["name"]
            if key not in merged:
                merged[key] = r
            else:
                srcs = [s.strip() for s in merged[key]["source"].split("\u00b7")]
                if r["source"] not in srcs:
                    srcs.append(r["source"])
                merged[key]["source"] = " \u00b7 ".join(srcs)
        out[uid] = sorted(merged.values(), key=lambda r: severity_rank(r["severity"]))
    return dict(out)


def direct_directory_roles_by_sp(graph, role_sev):
    """{sp_id: [{name, severity}]} directly-assigned directory roles per service
    principal (lnk_role_member_serviceprincipal + RoleAssignments), deduped by
    name. Shared by sp_directory_roles and the groups member tags."""
    out = defaultdict(list)

    def _role_name(oid):
        rec = graph["directory_role"].get(oid)
        return rec.get("displayName") if rec else oid

    def _def_name(oid):
        rec = graph["role_definition"].get(oid)
        return rec.get("displayName") if rec else oid

    for role_oid, sp_oid in graph["role_member_sp"]:
        name = _role_name(role_oid)
        out[sp_oid].append({"name": name, "severity": role_sev.get(name, "Info")})
    for ra in graph["directory_role_assigns"]:
        if ra["principal_id"] in graph["sp"]:
            name = _def_name(ra["role_definition_id"])
            out[ra["principal_id"]].append({"name": name,
                                            "severity": role_sev.get(name, "Info")})
    for sp_oid in list(out):
        seen = set()
        out[sp_oid] = [r for r in out[sp_oid]
                       if not (r["name"] in seen or seen.add(r["name"]))]
    return dict(out)


def compute_group_roles(graph, check_cfg):
    """{group_id: [{"name", "severity"}]} - directory roles carried by each group:
    direct role memberships (lnk_role_member_group) plus role assignments whose
    principal is a group (RoleAssignments). Shared by the user/groups checks and
    the SP/app profile drawer."""
    role_sev = check_cfg["directory_roles"]

    def _grole_name(oid):
        rec = graph["directory_role"].get(oid)
        return rec.get("displayName") if rec else oid

    def _gdef_name(oid):
        rec = graph["role_definition"].get(oid)
        return rec.get("displayName") if rec else oid

    def _gsev(name):
        return role_sev.get(name, "Info")

    group_roles = defaultdict(list)
    for role_oid, gid in graph["role_member_group"]:
        name = _grole_name(role_oid)
        group_roles[gid].append({"name": name, "severity": _gsev(name)})
    for ra in graph["directory_role_assigns"]:
        if ra["principal_id"] in graph["group"]:
            name = _gdef_name(ra["role_definition_id"])
            group_roles[ra["principal_id"]].append({"name": name, "severity": _gsev(name)})
    for gid in list(group_roles):
        seen = set()
        group_roles[gid] = [r for r in group_roles[gid]
                            if not (r["name"] in seen or seen.add(r["name"]))]
    return group_roles


def sp_directory_roles(graph, group_roles, sp_oid, role_sev, group_eligible_roles=None,
                       direct_sp_roles=None):
    """Directory roles held by a service principal: direct memberships and
    assignments plus roles inherited through group membership (incl. nesting).
    Each entry carries the group path to the role-bearing group (None when
    assigned directly) and an 'eligible' flag — PIM-eligible roles are marker
    data and never affect severity ratings."""
    def _def_name(oid):
        rec = graph["role_definition"].get(oid)
        return rec.get("displayName") if rec else oid

    def _group_label(gid):
        rec = graph["group"].get(gid)
        return rec.get("displayName") if rec else gid

    if direct_sp_roles is None:
        direct_sp_roles = direct_directory_roles_by_sp(graph, role_sev)
    roles = [{"name": r["name"], "severity": r["severity"], "path": None, "eligible": False}
             for r in direct_sp_roles.get(sp_oid, [])]
    seen = {r["name"] for r in roles}
    for gid, members in graph["group_member_sp"].items():
        if sp_oid not in members:
            continue
        for r in resolve_group_role_paths(gid, group_roles,
                                          graph["group_member_group"], _group_label):
            if r["name"] not in seen:
                seen.add(r["name"])
                roles.append({"name": r["name"], "severity": r["severity"],
                              "path": list(r["path"]), "eligible": False})
    # PIM-eligible directory roles (direct assignments + via groups): marker
    # only — shown with an '(eligible)' marker, never rated.
    if group_eligible_roles is not None:
        for ea in graph["eligible_role_assigns"]:
            if ea["principal_id"] == sp_oid:
                name = _def_name(ea["role_definition_id"])
                if name not in seen:
                    seen.add(name)
                    roles.append({"name": name, "severity": role_sev.get(name, "Info"),
                                  "path": None, "eligible": True})
        for gid, members in graph["group_member_sp"].items():
            if sp_oid not in members:
                continue
            for r in resolve_group_role_paths(gid, group_eligible_roles,
                                              graph["group_member_group"], _group_label):
                if r["name"] not in seen:
                    seen.add(r["name"])
                    roles.append({"name": r["name"], "severity": r["severity"],
                                  "path": list(r["path"]), "eligible": True})
    return roles


def make_sp_dir_resolver(graph, group_roles, role_sev, group_eligible_roles=None):
    """Memoized resolver of a service principal's directory roles (active +
    PIM-eligible, with group paths). Shared across the checks, the severity
    bump and the entity profiles so the group walks run once per SP per run."""
    direct_sp_roles = direct_directory_roles_by_sp(graph, role_sev)
    cache = {}

    def resolve(sp_oid):
        if sp_oid not in cache:
            cache[sp_oid] = sp_directory_roles(
                graph, group_roles, sp_oid, role_sev, group_eligible_roles,
                direct_sp_roles=direct_sp_roles)
        return cache[sp_oid]

    return resolve


def build_role_applications(graph, group_roles, group_eligible_roles=None):
    """Directory role displayName -> service principals holding that role
    (direct memberships/assignments, plus via group membership incl. nesting).
    Each entry: {"id", "name", "path", "eligible"} where path is the group
    chain to the role-bearing group (None = assigned directly) and eligible
    marks PIM-eligible assignments (marker-only). Drives the 'Applications'
    tab of the directory-role drilldown."""
    def _sp_label(sp_oid):
        rec = graph["sp"].get(sp_oid)
        return (rec.get("displayName") or rec.get("appDisplayName") or sp_oid) if rec else sp_oid

    def _group_label(gid):
        rec = graph["group"].get(gid)
        return rec.get("displayName") if rec else gid

    def _role_name(oid):
        rec = graph["directory_role"].get(oid)
        return rec.get("displayName") if rec else oid

    def _def_name(oid):
        rec = graph["role_definition"].get(oid)
        return rec.get("displayName") if rec else oid

    index = defaultdict(list)

    def add(role, sp_oid, path, eligible=False):
        for existing in index[role]:
            if existing["id"] == sp_oid and existing["path"] == path \
                    and existing.get("eligible") == eligible:
                return
        index[role].append({"id": sp_oid, "name": _sp_label(sp_oid), "path": path,
                            "eligible": eligible})

    for role_oid, sp_oid in graph["role_member_sp"]:
        add(_role_name(role_oid), sp_oid, None)
    for ra in graph["directory_role_assigns"]:
        if ra["principal_id"] in graph["sp"]:
            add(_def_name(ra["role_definition_id"]), ra["principal_id"], None)
    for gid, sp_ids in graph["group_member_sp"].items():
        for r in resolve_group_role_paths(gid, group_roles,
                                          graph["group_member_group"], _group_label):
            for sp_oid in sp_ids:
                if sp_oid in graph["sp"]:
                    add(r["name"], sp_oid, r["path"])
    if group_eligible_roles:
        for ea in graph["eligible_role_assigns"]:
            if ea["principal_id"] in graph["sp"]:
                name = _def_name(ea["role_definition_id"])
                # eligible marker only matters when the role isn't held actively
                if not any(e["id"] == ea["principal_id"] and not e.get("eligible")
                           for e in index[name]):
                    add(name, ea["principal_id"], None, eligible=True)
        for gid, sp_ids in graph["group_member_sp"].items():
            for r in resolve_group_role_paths(gid, group_eligible_roles,
                                              graph["group_member_group"], _group_label):
                for sp_oid in sp_ids:
                    if sp_oid in graph["sp"] and not any(
                            e["id"] == sp_oid and not e.get("eligible")
                            for e in index[r["name"]]):
                        add(r["name"], sp_oid, r["path"], eligible=True)
    for role in index:
        index[role].sort(key=lambda e: (e["name"] or "").lower())
    return dict(index)


def compute_group_eligible_roles(graph, check_cfg):
    """{group_id: [{"name", "severity"}]} - PIM-eligible directory roles carried
    by each group (EligibleRoleAssignments whose principal is a group). Marker
    data: eligible roles never affect severity ratings on groups/SPs."""
    role_sev = check_cfg["directory_roles"]

    def _gdef_name(oid):
        rec = graph["role_definition"].get(oid)
        return rec.get("displayName") if rec else oid

    def _gsev(name):
        return role_sev.get(name, "Info")

    out = defaultdict(list)
    for ea in graph["eligible_role_assigns"]:
        if ea["principal_id"] in graph["group"]:
            name = _gdef_name(ea["role_definition_id"])
            out[ea["principal_id"]].append({"name": name, "severity": _gsev(name)})
    for gid in list(out):
        seen = set()
        out[gid] = [r for r in out[gid] if not (r["name"] in seen or seen.add(r["name"]))]
    return out


def check_groups(ctx):
    """One row per group: directory roles carried by the group, role-capability
    (assignable / role-bearing / nested), dynamic membership rules, owners, and
    privileged / service-principal members. User members carry role tags for
    their own directory roles plus the roles the group grants them, resolved
    through nested group membership with the group path to each role."""
    graph = ctx["graph"]
    role_sev = ctx["check_cfg"]["directory_roles"]
    capable = ctx["capable_groups"]
    group_roles = ctx["group_roles"]
    group_eligible_roles = ctx.get("group_eligible_roles") or {}

    # direct directory roles per user (drives the privileged-member column)
    user_roles = direct_directory_roles_by_user(graph, role_sev)

    def user_primary(uid):
        u = graph["user"].get(uid)
        if not u:
            return uid
        return u.get("userPrincipalName") or u.get("displayName") or uid

    def user_disp(uid):
        u = graph["user"].get(uid)
        return (u.get("displayName") or u.get("userPrincipalName") or uid) if u else uid

    def group_label(gid):
        rec = graph["group"].get(gid)
        return rec.get("displayName") if rec else gid

    # Roles members inherit through nested group membership, with the group
    # path from the viewed group to each role-bearing group.
    role_path_cache = {}

    def role_paths_for(gid):
        if gid not in role_path_cache:
            role_path_cache[gid] = resolve_group_role_paths(
                gid, group_roles, graph["group_member_group"], group_label)
        return role_path_cache[gid]

    # direct directory roles per SP (memberships + role assignments)
    sp_dir_roles = direct_directory_roles_by_sp(graph, role_sev)

    # privileged app-role assignments per SP, rated by the resources config
    # (same criticality tags as the priv_app_ownership findings)
    sp_priv_grants = defaultdict(list)
    for ra in graph["role_assigns"]:
        if ra["principal_type"] != "ServicePrincipal":
            continue
        info = ctx["resource_index"].get(ra["resource_id"], {}).get(ra["app_role_id"])
        if info:
            sp_priv_grants[ra["principal_id"]].append({
                "name": info["value"],
                "severity": info["severity"],
                "resource": ctx["resource_names"].get(ra["resource_id"], ra["resource_id"]),
            })

    findings = []
    for gid, rec in graph["group"].items():
        name = rec.get("displayName") or gid
        types = [t for t in json_list(rec.get("groupTypes")) if isinstance(t, str)]
        visibility = rec.get("visibility") or ""
        is_public = rec.get("isPublic") in (1, True)
        mail = rec.get("mailEnabled") in (1, True)
        rule = (rec.get("membershipRule") or "").strip()
        dynamic = bool(rule) and rule not in ("[]",)
        if dynamic:
            dyn_attrs, dyn_mods = classify_dynamic_rule(rule)
        else:
            dyn_attrs, dyn_mods = [], []
        assignable = rec.get("isAssignableToRole") in (1, True)
        az_roles = sorted(ctx["graph"]["az_roles"].get(gid, []),
                          key=lambda a: (a.get("eligible", False), a["role"].lower()))

        dir_roles = group_roles.get(gid, [])
        eligible_roles = group_eligible_roles.get(gid, [])
        group_role_tags = role_paths_for(gid)
        parents = sorted((graph["group"][p].get("displayName") or p)
                         for p, children in graph["group_member_group"].items() if gid in children)
        children = sorted((graph["group"][c].get("displayName") or c)
                          for c in graph["group_member_group"].get(gid, []))
        sp_members = []
        for s in graph["group_member_sp"].get(gid, set()):
            if s not in graph["sp"]:
                continue
            tags = {}
            for r in sp_dir_roles.get(s, []):
                tags[r["name"]] = {"name": r["name"], "severity": r["severity"],
                                   "path": None, "kind": "dir"}
            for r in group_role_tags:
                if r["name"] not in tags:
                    tags[r["name"]] = {"name": r["name"], "severity": r["severity"],
                                       "path": list(r["path"]), "kind": "dir"}
            for g in sp_priv_grants.get(s, []):
                key = f"app:{g['name']}"
                if key not in tags:
                    tags[key] = {"name": g["name"], "severity": g["severity"],
                                 "path": None, "kind": "app", "resource": g["resource"]}
            sp_members.append({
                "id": s,
                "name": graph["sp"][s].get("displayName") or s,
                "enabled": bool(graph["sp"][s].get("accountEnabled")),
                "roles": sorted(tags.values(), key=lambda r: severity_rank(r["severity"])),
            })
        sp_members.sort(key=lambda m: (m["name"] or "").lower())
        owners = sorted(user_primary(u) for u in graph["group_owner_user"].get(gid, set())
                        if u in graph["user"])

        members = []
        for uid in graph["group_member_user"].get(gid, set()):
            if uid not in graph["user"]:
                continue
            u = graph["user"][uid]
            merged = {}
            for r in user_roles.get(uid, []):
                merged[r["name"]] = {"name": r["name"], "severity": r["severity"], "path": None}
            for r in group_role_tags:
                if r["name"] not in merged:
                    merged[r["name"]] = {
                        "name": r["name"], "severity": r["severity"], "path": list(r["path"]),
                    }
            roles = sorted(merged.values(), key=lambda r: severity_rank(r["severity"]))
            members.append({
                "name": u.get("displayName") or uid,
                "upn": u.get("userPrincipalName") or "",
                "roles": roles,
                "privileged": any(is_privileged(r["severity"]) for r in roles),
            })
        members.sort(key=lambda m: (not m["privileged"], (m["name"] or "").lower()))
        priv_members = [m for m in members if m["privileged"]]

        role_sevs = [r["severity"] for r in dir_roles]
        if role_sevs:
            severity = min(role_sevs, key=severity_rank)
        elif assignable:
            severity = "High"
        elif gid in capable:
            severity = "Medium"
        else:
            severity = "Info"

        parts = []
        if dir_roles:
            parts.append("grants " + ", ".join(sorted({r["name"] for r in dir_roles})))
        if eligible_roles:
            parts.append(f"{len(eligible_roles)} PIM-eligible role(s)")
        if assignable:
            parts.append("assignable to role")
        if dynamic:
            parts.append("auto-membership rule")
        if priv_members:
            parts.append(f"{len(priv_members)} privileged member(s)")
        if sp_members:
            parts.append(f"{len(sp_members)} SP member(s)")
        if az_roles:
            parts.append("ARM roles: " + ", ".join(sorted({a["role"] for a in az_roles})))

        f = make_finding(
            check_id="groups", category="groups",
            severity=severity,
            title=f"Group: {name}",
            evidence=" · ".join(parts) or "no privilege signals captured",
            remediation=("Review the group's membership, owners, and role assignments; "
                         "members inherit directory roles placed on the group, so restrict "
                         "both the roles and who can join."),
            primary_id=gid,
            object_ids={},
            target={"type": "Group", "name": name, "id": gid},
            status=None,
        )
        f["group_id"] = gid
        f["group_name"] = name
        f["types"] = types
        f["visibility"] = visibility
        f["is_public"] = is_public
        f["mail"] = mail
        f["rule"] = rule
        f["dynamic"] = dynamic
        f["assignable"] = assignable
        f["dir_roles"] = dir_roles
        f["eligible_roles"] = eligible_roles
        f["parents"] = parents
        f["children"] = children
        f["owners"] = owners
        f["members"] = members
        f["sp_members"] = sp_members
        f["member_count"] = len(members) + len(sp_members)
        f["user_member_count"] = len(members)
        f["priv_member_count"] = len(priv_members)
        f["dyn_rule"] = rule
        f["dyn_attrs"] = dyn_attrs
        f["dyn_mods"] = dyn_mods
        f["az_roles"] = az_roles
        findings.append(f)

    findings.sort(key=lambda f: (severity_rank(f["severity"]), (f["group_name"] or "").lower()))
    return findings


def check_ca_exposure(ctx):
    """Conditional Access exposure: per-policy posture (state, scope, exclusions)
    plus a full policy profile (included/excluded users, roles, groups,
    applications, controls, conditions) for the drawer. Per-user exclusions are
    surfaced as an attribute in the Users tab (no rating); group-targeted scope
    cannot be resolved from the captured links."""
    graph = ctx["graph"]
    role_sev = ctx["check_cfg"]["directory_roles"]

    def policy_inner(pol_id):
        rec = graph["policy"].get(pol_id)
        detail = json_safe_value(rec.get("policyDetail")) if rec else None
        try:
            inner = json.loads(detail[0]) if detail and isinstance(detail[0], str) else (detail[0] if detail else None)
            return inner if isinstance(inner, dict) else {}
        except (json.JSONDecodeError, ValueError, TypeError, IndexError):
            return {}

    def policy_state(pol_id):
        return ((policy_inner(pol_id).get("State")) or "").strip() or "Unknown"

    def label_fn(oid, table):
        rec = graph[table].get(oid)
        return rec.get("displayName") if rec else oid

    def user_label(uid):
        u = graph["user"].get(uid)
        return (u.get("userPrincipalName") or u.get("displayName") or uid) if u else uid

    def resolve_items(oids, table):
        out = []
        for oid in sorted(set(oid for oid in oids if oid)):
            name = label_fn(oid, table)
            if table == "directory_role" or table == "role_definition":
                sev = role_sev.get(name, "Info")
                out.append({"name": name, "severity": sev})
            else:
                out.append({"name": name})
        return out

    def app_label(app_id):
        for sp_oid in graph["sp_by_appid"].get(app_id, []):
            rec = graph["sp"].get(sp_oid)
            if rec and (rec.get("displayName") or rec.get("appDisplayName")):
                return rec.get("displayName") or rec.get("appDisplayName")
        return app_id

    def flatten_conditions(inner, key, field):
        items = []
        for block in ((inner.get("Conditions") or {}).get(key) or {}).get("Include") or []:
            items.extend(block.get(field) or [])
        return items

    def exclude_items(inner, field):
        items = []
        for block in ((inner.get("Conditions") or {}).get("Users") or {}).get("Exclude") or []:
            items.extend(block.get(field) or [])
        return items

    findings = []
    ca_policies = [oid for oid, rec in graph["policy"].items()
                   if rec.get("policyType") == 18]

    excludes_by_policy = defaultdict(set)
    for pol, uid in graph["policy_user_exclude"]:
        excludes_by_policy[pol].add(uid)

    # per-policy posture rows
    for pol in ca_policies:
        rec = graph["policy"][pol]
        name = rec.get("displayName") or pol
        inner = policy_inner(pol)
        state = policy_state(pol)
        is_mfa = "multifactor" in name.lower()
        if pol in graph["policy_include_allusers"]:
            scope = "all users"
        else:
            inc_ids = {uid for p, uid in graph["policy_user_include"] if p == pol}
            scope = f"{len(inc_ids)} included user(s)" if inc_ids else "no user scope captured"

        included_uids = sorted({uid for p, uid in graph["policy_user_include"] if p == pol})
        excluded_uids = sorted(excludes_by_policy.get(pol, set()))
        excluded = len(excluded_uids)
        bits = [f"state {state}", f"scope: {scope}"]
        if excluded:
            bits.append(f"{excluded} excluded user(s)")
        if is_mfa:
            bits.append("MFA policy")

        apps = ["All" if v == "All" else app_label(v)
                for v in flatten_conditions(inner, "Applications", "Applications")]
        inc_roles = resolve_items(flatten_conditions(inner, "Users", "Roles"), "role_definition")
        inc_groups = resolve_items(flatten_conditions(inner, "Users", "Groups"), "group")
        exc_groups = resolve_items(exclude_items(inner, "Groups"), "group")
        controls = [c for block in (inner.get("Controls") or [])
                    for c in block.get("Control") or [] if isinstance(c, str)]

        f = make_finding(
            check_id="ca_exposure", category="configs", severity="Info",
            title=f"Conditional Access policy: {name}",
            evidence=" · ".join(bits),
            remediation=("Confirm the policy state, scope, and exclusions; Reporting "
                         "policies do not enforce, and excluded users bypass the "
                         "policy's sign-on requirements. Per-user exclusions are "
                         "shown as an attribute in the Users tab."),
            primary_id=pol,
            object_ids={},
            target={"type": "Policy", "name": name, "id": pol},
            status={"label": state, "enabled": state == "Enabled", "raw": state},
        )
        f["policy_id"] = pol
        f["policy_name"] = name
        f["policy_type"] = rec.get("policyType")
        f["state"] = state
        f["scope"] = scope
        f["conditions_html"] = {
            "controls": controls,
            "apps": apps,
            "inc_roles": inc_roles,
            "inc_groups": inc_groups,
            "exc_groups": exc_groups,
        }
        f["included"] = [user_label(u) for u in included_uids]
        f["excluded"] = [user_label(u) for u in excluded_uids if u in graph["user"]]
        f["conditions_raw"] = json.dumps(inner, indent=2)
        f["created"] = inner.get("CreatedDateTime", "")
        f["modified"] = inner.get("ModifiedDateTime", "")
        f["template_id"] = inner.get("TemplateId", "")
        findings.append(f)

    findings.sort(key=lambda f: (severity_rank(f["severity"]),
                                 (f["target"]["name"] or "").lower()))
    return findings


CHECK_SPECS = [
    {
        "id": "priv_app_ownership",
        "category": "apps",
        "title": "Privileged application ownership",
        "description": ("Application (app-only) role assignments matched against the "
                        "privileged permission list, resolved to the human owners of the "
                        "Application / Service Principal."),
        "run": check_priv_app_ownership,
    },
    {
        "id": "sp_credentials",
        "category": "apps",
        "title": "Credential-bearing service principals and apps",
        "description": ("Non-Microsoft service principals and app registrations that store "
                        "password or key credentials while also holding app-role assignments. "
                        "Long-lived static credentials on privileged identities are a "
                        "persistence and lateral-movement target."),
        "run": check_sp_credentials,
    },
    {
        "id": "no_role_approval",
        "category": "apps",
        "title": "Apps without role-assignment requirement",
        "description": ("Service principals with appRoleAssignmentRequired=false: Azure AD does "
                        "not require explicit role assignments. Whether a default user gains "
                        "access depends on the app's own authorization logic, so treat these as "
                        "candidates to test rather than proven exposures (rated Info)."),
        "run": check_no_role_approval,
    },
    {
        "id": "implicit_flow",
        "category": "apps",
        "title": "Implicit-flow token exposure",
        "description": ("Applications with the OAuth2 implicit flow enabled expose tokens in "
                        "URLs and browser history. Rated High when the app also holds privileged roles."),
        "run": check_implicit_flow,
    },
    {
        "id": "public_client_privileged",
        "category": "apps",
        "title": "Public clients with privileged roles",
        "description": ("Public (installed or browser-based) clients whose service principal "
                        "holds privileged app-role assignments — the client cannot keep "
                        "secrets, so its identity inherits the privilege."),
        "run": check_public_client_privileged,
    },
    {
        "id": "foreign_principal",
        "category": "apps",
        "title": "Foreign principals with privileged roles",
        "description": ("Service principals owned by another tenant (appOwnerTenantId mismatch "
                        "and no local Application registration) that hold privileged application "
                        "roles — cross-tenant trust relationships to validate."),
        "run": check_foreign_principal,
    },
    {
        "id": "app_dir_roles",
        "category": "apps",
        "title": "Directory roles assigned to applications",
        "description": ("One row per service principal holding directory roles, "
                        "assigned directly or inherited through group membership "
                        "(incl. nesting). Rated by the most critical directory role."),
        "run": check_app_directory_roles,
    },
    {
        "id": "privileged_users",
        "category": "users",
        "title": "Users",
        "description": ("One row per user. Privileged users are rated by their aggregate "
                        "signal: directory roles (assigned or eligible), ownership of "
                        "apps/service principals that hold privileged grants or directory "
                        "roles, and membership or ownership of role-capable groups. Users "
                        "with no observed signals are listed at Info for completeness. "
                        "On-prem sync is context and never raises the rating. Directory "
                        "role severities come from the 'directory_roles' config block; "
                        "unrated roles stay Info."),
        "run": check_privileged_users,
    },
    {
        "id": "groups",
        "category": "groups",
        "title": "Groups",
        "description": ("One row per group: directory roles carried by the group (members "
                        "inherit them), role-capability (assignable / role-bearing / nested), "
                        "dynamic membership rules, owners, and privileged or service-principal "
                        "members."),
        "run": check_groups,
    },
    {
        "id": "ca_exposure",
        "category": "configs",
        "title": "Conditional Access policy exposure",
        "description": ("Per-policy posture (state, scope, exclusions) plus per-user "
                        "findings for users explicitly excluded from sign-on / MFA "
                        "Conditional Access policies. Elevated when the excluded user "
                        "holds privileged directory roles. Group-targeted scope cannot "
                        "be resolved from the captured links."),
        "run": check_ca_exposure,
    },
    {
        "id": "ad_sync_summary",
        "category": "ad",
        "title": "Sync summary",
        "description": "One-line picture of the sync setup: engine in use (Entra Connect on-prem vs likely Cloud Sync), connector host, password-writeback channel, Desktop SSO, and sync coverage.",
        "run": check_ad_sync_summary,
    },
    {
        "id": "ad_sync_users",
        "category": "ad",
        "title": "Interesting On-Prem Synced Users",
        "description": ("Synchronized user accounts carrying at least one targeting flag: "
                        "synced-plus-privileged, service accounts, or missing SID. CA policy "
                        "exclusions are listed per user. Targeting metadata — never scored."),
        "run": check_ad_sync_users,
    },
    {
        "id": "ad_sync_infra",
        "category": "ad",
        "title": "AD sync infrastructure",
        "description": ("ADSync groups, synchronization service principals, hybrid/legacy "
                        "authentication policies, and registered Windows devices — the "
                        "on-prem attack surface visible from the cloud side."),
        "run": check_ad_sync_infra,
    },
]

CHECK_IDS = {spec["id"] for spec in CHECK_SPECS}


def run_checks(graph, config_resources, check_cfg, args,
               group_roles=None, group_eligible_roles=None, sp_dir_resolver=None):
    """Run the selected checks and return the list of {spec, findings} results."""
    opts = {"include_disabled": args.include_disabled}
    check_config = dict(check_cfg)

    # ---- selection from CLI + config ------------------------------------
    wanted = set()
    for chunk in (args.check or []):
        for cid in chunk.split(","):
            cid = cid.strip().lower()
            for spec in CHECK_SPECS:
                if spec["id"].lower() == cid:
                    wanted.add(spec["id"])
    excluded = set()
    for chunk in (args.exclude_check or []):
        for cid in chunk.split(","):
            cid = cid.strip().lower()
            for spec in CHECK_SPECS:
                if spec["id"].lower() == cid:
                    excluded.add(spec["id"])
    selected = []
    for spec in CHECK_SPECS:
        cid = spec["id"]
        if wanted and cid not in wanted:
            continue
        if cid in excluded:
            continue
        if cid in check_config["enabled"] and not check_config["enabled"][cid]:
            continue
        selected.append(spec)

    min_rank = SEVERITY_ORDER.get(args.min_severity
                                   or check_config.get("min_severity", "Info"), 4)
    suppress = set(check_config.get("suppress", []) or [])

    # ---- shared analysis context ----------------------------------------
    resource_index, resource_names = build_resource_role_index(graph, config_resources)
    priv_sp_ids = set()
    role_sp_ids = set()
    for ra in graph["role_assigns"]:
        if ra["principal_type"] != "ServicePrincipal":
            continue
        role_sp_ids.add(ra["principal_id"])
        if ra["resource_id"] in resource_index and ra["app_role_id"] in resource_index[ra["resource_id"]]:
            priv_sp_ids.add(ra["principal_id"])

    ctx = {
        "graph": graph,
        "config_resources": config_resources,
        "check_cfg": check_config,
        "resource_index": resource_index,
        "resource_names": resource_names,
        "priv_sp_ids": priv_sp_ids,
        "role_sp_ids": role_sp_ids,
        "include_disabled": opts["include_disabled"],
    }

    # ---- role-capable groups + roles carried by groups (shared) ----------
    capable_groups = set()
    for gid, rec in graph["group"].items():
        if rec.get("isAssignableToRole") in (1, True):
            capable_groups.add(gid)
    for _, gid in graph["role_member_group"]:
        capable_groups.add(gid)
    for ra in graph["directory_role_assigns"]:
        if ra["principal_id"] in graph["group"]:
            capable_groups.add(ra["principal_id"])
    for ea in graph["eligible_role_assigns"]:
        if ea["principal_id"] in graph["group"]:
            capable_groups.add(ea["principal_id"])
    changed = True
    while changed:
        changed = False
        for parent, children in graph["group_member_group"].items():
            if parent in capable_groups:
                for child in children:
                    if child not in capable_groups:
                        capable_groups.add(child)
                        changed = True

    if group_roles is None:
        group_roles = compute_group_roles(graph, check_config)
    if group_eligible_roles is None:
        group_eligible_roles = compute_group_eligible_roles(graph, check_config)
    if sp_dir_resolver is None:
        sp_dir_resolver = make_sp_dir_resolver(
            graph, group_roles, check_config["directory_roles"], group_eligible_roles)

    ctx["capable_groups"] = capable_groups
    ctx["group_roles"] = group_roles
    ctx["group_eligible_roles"] = group_eligible_roles
    ctx["sp_dir_resolver"] = sp_dir_resolver

    results = []
    for spec in selected:
        sys.stdout.write(f"Running {spec['id']}...")
        sys.stdout.flush()
        try:
            findings = spec["run"](ctx)
            filtered = []
            for f in findings:
                if severity_rank(f["severity"]) > min_rank:
                    continue
                key = f"{f['check_id']}:{f['primary_id']}"
                if key in suppress or f["check_id"] in suppress:
                    continue
                filtered.append(f)
        except Exception:
            sys.stdout.write(" error\n")
            raise
        sys.stdout.write(f" {len(filtered)}\n")
        if filtered:
            results.append({"id": spec["id"], "category": spec["category"],
                            "title": spec["title"], "description": spec["description"],
                            "findings": filtered,
                            "meta": ctx.get("ad_realm", {})})

    # ---- ARM (Azure RBAC) roles per finding (marker only, never rated) ----
    # Attach azure role assignments to every finding whose principals carry them
    # (groups attach their own in check_groups; everything else is derived from
    # the finding's object_ids, so all tables render the same badge+tag style).
    def _az_sorted(roles):
        seen = set()
        out = []
        for a in roles:
            key = (a.get("role"), a.get("scope_label"), bool(a.get("eligible")))
            if key in seen:
                continue
            seen.add(key)
            out.append(a)
        out.sort(key=lambda a: (bool(a.get("eligible")), a["role"].lower()))
        return out

    for res in results:
        for f in res["findings"]:
            if f.get("az_roles") is not None:
                continue
            o = f.get("object_ids") or {}
            roles = []
            for sid in o.get("sp", set()):
                roles.extend(graph["az_sp_roles"].get(sid, []))
            for uid in o.get("user", set()):
                roles.extend(graph["az_user_roles"].get(uid, []))
            if roles:
                f["az_roles"] = _az_sorted(roles)

    # ---- directory roles per SP (Privileges-column severity on app findings) ----
    # Every finding whose principals include service principals is rated by the
    # SP's directory roles (direct + via group membership): the finding's
    # severity is raised to the most critical directory role it holds.
    sp_dir_tags = sp_dir_resolver

    for res in results:
        for f in res["findings"]:
            o = f.get("object_ids") or {}
            sp_ids = o.get("sp", set())
            if not sp_ids:
                continue
            merged = {}
            for sp_oid in sorted(sp_ids):
                for r in sp_dir_tags(sp_oid):
                    if r["name"] not in merged:
                        merged[r["name"]] = r
            if not merged:
                continue
            f["dir_role_tags"] = sorted(
                merged.values(), key=lambda r: severity_rank(r["severity"]))
            # eligible (PIM) roles are marker-only: rate by active roles alone
            active = [r for r in f["dir_role_tags"] if not r.get("eligible")]
            if not active:
                continue
            best_rank = min(severity_rank(r["severity"]) for r in active)
            if best_rank < severity_rank(f["severity"]):
                f["severity"] = next(
                    sev for sev, rank in SEVERITY_ORDER.items() if rank == best_rank)
    return results


# ---------------------------------------------------------------------------
# Detail-view fields (drilldown modal)
# ---------------------------------------------------------------------------

APPLICATION_DETAIL_FIELDS = [
    "displayName", "appId", "objectId", "publisherDomain", "verifiedPublisher",
    "availableToOtherTenants", "publicClient", "homepage", "replyUrls", "identifierUris",
    "requiredResourceAccess", "keyCredentials", "passwordCredentials",
    "oauth2AllowImplicitFlow", "oauth2AllowIdTokenImplicitFlow", "disabledByMicrosoftStatus",
]

SP_DETAIL_FIELDS = [
    "displayName", "appDisplayName", "appId", "objectId", "accountEnabled",
    "servicePrincipalType", "appOwnerTenantId", "microsoftFirstParty",
    "appRoleAssignmentRequired", "publisherName", "managedIdentityResourceId",
    "notificationEmailAddresses", "replyUrls", "keyCredentials", "passwordCredentials",
    "tags", "preferredSingleSignOnMode",
]

DEVICE_DETAIL_FIELDS = [
    "displayName", "objectId", "accountEnabled", "deviceOSType", "deviceOSVersion",
    "deviceModel", "deviceManufacturer", "deviceCategory", "deviceOwnership",
    "deviceTrustType", "enrollmentType", "enrollmentProfileName", "managementType",
    "isCompliant", "isManaged", "isRooted", "dirSyncEnabled",
    "onPremisesSecurityIdentifier", "hostnames", "domainName",
    "approximateLastLogonTimestamp", "lastDirSyncTime", "alternativeSecurityIds",
]

USER_DETAIL_FIELDS = [
    "displayName", "userPrincipalName", "mail", "objectId", "accountEnabled", "userType",
    "jobTitle", "department", "companyName", "createdDateTime", "dirSyncEnabled",
    "onPremisesUserPrincipalName", "onPremisesObjectIdentifier", "onPremisesSecurityIdentifier",
    "onPremisesDistinguishedName", "onPremisesPasswordChangeTimestamp", "lastDirSyncTime",
    "immutableId", "hasOnPremisesShadow", "isResourceAccount", "creationType",
    "provisioningErrors",
    "lastPasswordChangeDateTime", "refreshTokensValidFromDateTime", "isCompromised",
    "strongAuthenticationDetail", "employeeId", "employeeType", "usageLocation",
]


def fetch_full_details(cur, sp_ids, app_ids, user_ids, device_ids=None):
    """Fetch attributes for the 'expand' drawers. SPs and applications get every
    captured column (for the Raw tab); users and devices keep a curated set."""
    def fetch_all(table, id_column, ids, wanted_fields):
        ids = {i for i in ids if i}
        if not ids:
            return {}
        cur.execute(f"PRAGMA table_info({table})")
        available = {r[1] for r in cur.fetchall()}
        if wanted_fields is None:
            fields = [c for c in available if c != id_column]
        else:
            fields = [f for f in wanted_fields if f in available]
        fields = [id_column] + fields
        try:
            rows = fetch_by_ids(cur, table, id_column, fields, ids)
        except sqlite3.OperationalError:
            return {}
        id_index = fields.index(id_column)
        result = {}
        for row in rows:
            record = {}
            for col, val in zip(fields, row):
                if val is None or val == "":
                    continue
                parsed = json_safe_value(val)
                if parsed == [] or parsed == {}:
                    continue
                record[col] = parsed
            result[row[id_index]] = record
        return result

    return {
        "sp": fetch_all("ServicePrincipals", "objectId", sp_ids, None),
        "app": fetch_all("Applications", "objectId", app_ids, None),
        "user": fetch_all("Users", "objectId", user_ids, USER_DETAIL_FIELDS),
        "device": fetch_all("Devices", "objectId", device_ids or set(), DEVICE_DETAIL_FIELDS),
    }


def build_entity_profiles(graph, check_cfg, sp_ids, app_ids,
                          group_roles=None, group_eligible_roles=None,
                          sp_dir_resolver=None):
    """Relationship data for the tabbed SP/app 'more info' drawer:
    owners, directory roles, group memberships, and the two app-role views
    (roles this principal grants to others / roles granted to it)."""
    role_sev = check_cfg["directory_roles"]
    role_labels = check_cfg.get("role_labels") or {}
    if group_roles is None:
        group_roles = compute_group_roles(graph, check_cfg)
    if group_eligible_roles is None:
        group_eligible_roles = compute_group_eligible_roles(graph, check_cfg)
    if sp_dir_resolver is None:
        sp_dir_resolver = make_sp_dir_resolver(graph, group_roles, role_sev,
                                               group_eligible_roles)
    app_roles_cache = {}  # sp_oid -> {role_id: {value, description}}

    def catalog_entry(value, description):
        return {"value": value,
                "description": role_labels.get(value) or (description or "")}

    def resource_roles(sp_oid):
        if sp_oid not in app_roles_cache:
            rec = graph["sp"].get(sp_oid)
            index = {}
            for role in json_list(rec.get("appRoles") if rec else None):
                if isinstance(role, dict) and role.get("id"):
                    index[role["id"]] = catalog_entry(
                        role.get("value") or role["id"], role.get("description") or "")
            # ApplicationRefs role catalog by appId (fallback when the SP column is sparse)
            if rec and rec.get("appId"):
                for rid, entry in graph["appref_roles"].get(rec["appId"], {}).items():
                    if rid not in index:
                        index[rid] = catalog_entry(entry["value"], entry["description"])
            # Microsoft system role exposed by every application
            index.setdefault(SYSTEM_DEFAULT_ROLE_ID,
                             catalog_entry(SYSTEM_DEFAULT_ROLE["value"],
                                           SYSTEM_DEFAULT_ROLE["description"]))
            app_roles_cache[sp_oid] = index
        return app_roles_cache[sp_oid]

    def sp_label(sp_oid):
        rec = graph["sp"].get(sp_oid)
        return (rec.get("displayName") or rec.get("appDisplayName") or sp_oid) if rec else sp_oid

    def app_label(app_id):
        oids = graph["app_by_appid"].get(app_id, [])
        if not oids:
            return ""
        rec = graph["app"].get(oids[0])
        return rec.get("displayName") if rec else ""

    def principal_label(pid, ptype):
        if ptype == "User" and pid in graph["user"]:
            return graph["user"][pid].get("displayName") or pid
        return sp_label(pid)

    def dir_roles_for(sp_oid):
        return sp_dir_resolver(sp_oid)

    def groups_for(sp_oid):
        return [{"name": graph["group"][g].get("displayName") or g}
                for g, members in graph["group_member_sp"].items() if sp_oid in members]

    def owners_for(sp_oid, app_oids):
        owner_ids = set()
        for app_oid in app_oids:
            owner_ids |= graph["app_owners"].get(app_oid, set())
        owner_ids |= graph["sp_owners"].get(sp_oid, set())
        owners = []
        for uid in owner_ids:
            user = graph["user"].get(uid)
            if not user:
                continue
            owners.append({
                "name": user.get("displayName") or uid,
                "upn": user.get("userPrincipalName") or "",
                "type": user.get("userType") or "Member",
                "enabled": bool(user.get("accountEnabled")),
            })
        owners.sort(key=lambda o: (o["name"] or "").lower())
        return owners

    def role_label(sp_oid, role_id):
        role = resource_roles(sp_oid).get(role_id)
        if role:
            return role["value"]
        return role_id

    def profile_for(sp_oid):
        granted = []   # roles this SP exposes, held by other principals
        assigned = []  # roles other SPs expose, held by this SP
        for ra in graph["role_assigns"]:
            if ra["resource_id"] == sp_oid:
                role = resource_roles(sp_oid).get(ra["app_role_id"])
                granted.append({
                    "principal_name": principal_label(ra["principal_id"], ra["principal_type"]),
                    "principal_type": ra["principal_type"] or "ServicePrincipal",
                    "role": role_label(sp_oid, ra["app_role_id"]),
                    "description": role["description"] if role else "",
                })
            elif ra["principal_id"] == sp_oid and ra["principal_type"] == "ServicePrincipal":
                resource_rec = graph["sp"].get(ra["resource_id"])
                role = resource_roles(ra["resource_id"]).get(ra["app_role_id"])
                resource_app = app_label(resource_rec.get("appId")) if resource_rec else ""
                assigned.append({
                    "principal_name": sp_label(sp_oid),
                    "principal_type": "ServicePrincipal",
                    "role": role_label(ra["resource_id"], ra["app_role_id"]),
                    "application": resource_app or sp_label(ra["resource_id"]),
                    "description": role["description"] if role else "",
                })
        granted.sort(key=lambda r: (r["principal_name"] or "").lower())
        assigned.sort(key=lambda r: (r["role"] or "").lower())
        app_oids = graph["app_by_appid"].get(graph["sp"][sp_oid].get("appId"), []) if sp_oid in graph["sp"] else []
        application = (graph["app"][app_oids[0]].get("displayName") or "") if app_oids else ""
        return {
            "kind": "sp",
            "application": application,
            "app_oid": app_oids[0] if app_oids else "",
            "owners": owners_for(sp_oid, app_oids),
            "dir_roles": dir_roles_for(sp_oid),
            "groups": groups_for(sp_oid),
            "granted_roles": granted,
            "assigned_roles": assigned,
            "az_roles": sorted(graph["az_sp_roles"].get(sp_oid, []),
                               key=lambda a: (a.get("eligible", False), a["role"].lower())),
        }

    profiles = {"sp": {}, "app": {}}
    for sp_oid in sorted(sp_ids):
        if sp_oid in graph["sp"]:
            profiles["sp"][sp_oid] = profile_for(sp_oid)

    for app_oid in sorted(app_ids):
        app = graph["app"].get(app_oid)
        if not app:
            continue
        sp_oids = graph["sp_by_appid"].get(app.get("appId"), [])
        granted, assigned, dir_roles, groups = [], [], [], []
        owner_ids = set(graph["app_owners"].get(app_oid, set()))
        for sp_oid in sp_oids:
            prof = profile_for(sp_oid)
            granted += prof["granted_roles"]
            assigned += prof["assigned_roles"]
            dir_roles += prof["dir_roles"]
            groups += prof["groups"]
            owner_ids |= graph["sp_owners"].get(sp_oid, set())
        seen = set()
        dedup = []
        for item in granted + assigned:
            key = (item.get("principal_name"), item.get("role"), item.get("application"), item.get("description"))
            if key not in seen:
                seen.add(key)
                dedup.append(item)
        owner_list = []
        for uid in owner_ids:
            user = graph["user"].get(uid)
            if not user:
                continue
            owner_list.append({"name": user.get("displayName") or uid,
                               "upn": user.get("userPrincipalName") or "",
                               "type": user.get("userType") or "Member",
                               "enabled": bool(user.get("accountEnabled"))})
        owner_list.sort(key=lambda o: (o["name"] or "").lower())
        name_seen = set()
        uniq_roles, uniq_groups = [], []
        for r in dir_roles:
            if r["name"] not in name_seen:
                name_seen.add(r["name"])
                uniq_roles.append(r)
        for g in groups:
            if g["name"] not in name_seen:
                name_seen.add(g["name"])
                uniq_groups.append(g)
        az_roles = []
        for sp_oid in sp_oids:
            for a in graph["az_sp_roles"].get(sp_oid, []):
                entry = dict(a)
                sp_rec = graph["sp"].get(sp_oid)
                entry["sp_name"] = (sp_rec.get("displayName") or sp_oid) if sp_rec else sp_oid
                az_roles.append(entry)
        az_roles.sort(key=lambda a: (a.get("eligible", False), a["role"].lower()))
        sp_list = []
        for sp_oid in sp_oids:
            sp_rec = graph["sp"].get(sp_oid)
            sp_list.append({
                "object_id": sp_oid,
                "display_name": (sp_rec.get("displayName") or sp_rec.get("appDisplayName")
                                 or sp_oid) if sp_rec else sp_oid,
                "app_id": (sp_rec.get("appId") or "") if sp_rec else "",
            })
        profiles["app"][app_oid] = {
            "kind": "app",
            "application": app.get("displayName") or app_oid,
            "owners": owner_list,
            "dir_roles": uniq_roles,
            "groups": uniq_groups,
            "granted_roles": [x for x in granted],
            "assigned_roles": [x for x in assigned],
            "az_roles": az_roles,
            "sp_oids": sp_oids,
            "sp_list": sp_list,
        }
    return profiles


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

def esc(value):
    return html.escape(str(value)) if value is not None else ""


def severity_class(severity):
    return {"Critical": "sev-critical", "High": "sev-high", "Medium": "sev-medium",
            "Low": "sev-low", "Info": "sev-info"}.get(severity, "sev-info")


def severity_badge(severity):
    return f'<span class="badge {severity_class(severity)}">{esc(severity)}</span>'


def bool_badge(value, true_label="Enabled", false_label="Disabled"):
    cls = "badge-enabled" if value else "badge-disabled"
    label = true_label if value else false_label
    return f'<span class="badge {cls}">{esc(label)}</span>'


def status_cell(status):
    if not status:
        return '<span class="muted">&mdash;</span>'
    label = status.get("label", "")
    if label == "Enabled":
        return bool_badge(True)
    if label == "Disabled":
        return bool_badge(False)
    if label == "Reporting":
        return '<span class="badge badge-hybrid" title="Report-only: policy does not enforce">Reporting</span>'
    if label == "Unknown":
        return '<span class="muted">Unknown</span>'
    if isinstance(status.get("enabled"), bool):
        return bool_badge(status["enabled"])
    return f'<span class="muted">{esc(label)}</span>'


def count_cell(value):
    if value is None:
        return '<span class="muted">&mdash;</span>'
    return f'<span class="mono">{esc(str(value))}</span>'


EXPAND_BUTTON_HTML = '<button type="button" class="icon-btn expand-btn" aria-label="View full details">+</button>'


def cap_annotate(items):
    """'Group — Role (severity); …' annotations for capable-group tooltips."""
    out = []
    for c in items:
        line = c.get("name") or ""
        roles = c.get("roles") or []
        if roles:
            line += " — " + ", ".join(f"{r['name']} ({r['severity']})" for r in roles)
        out.append(line)
    return out


# Column index -> sort key for the privileged-users table (serve mode)
USER_SORT_KEYS = {
    "1": "severity", "2": "name", "3": "upn", "4": "roles", "5": "eligible",
    "6": "privapps", "7": "capgroups", "8": "grpowned", "9": "caexcl",
    "10": "hybrid", "11": "status",
}


def user_search_text(f):
    parts = [f.get("user_display") or "", f.get("user_upn") or "", f.get("severity") or ""]
    parts += [r["name"] for r in f.get("roles", [])]
    parts += [r["name"] for r in f.get("eligible_roles", [])]
    parts += [g.get("name") or "" for g in f.get("groups", [])]
    parts += [a.get("role", "") for a in f.get("az_roles", [])]
    if f.get("hybrid"):
        parts.append("AD")
    return " ".join(parts).lower()


def user_sort_value(f, key):
    if key == "severity":
        return SEVERITY_ORDER.get(f.get("severity", "Info"), 4)
    if key == "name":
        return (f.get("user_display") or "").lower()
    if key == "upn":
        return (f.get("user_upn") or "").lower()
    if key == "roles":
        return ", ".join(r["name"] for r in f.get("roles", [])).lower()
    if key == "eligible":
        return len(f.get("eligible_roles", []))
    if key == "privapps":
        return len(f.get("priv_apps", []))
    if key == "capgroups":
        return len(f.get("cap_member", []))
    if key == "grpowned":
        return f.get("owned_count", 0)
    if key == "caexcl":
        return len(f.get("ca_exclusions", []))
    if key == "hybrid":
        return "AD" if f.get("hybrid") else "Cloud"
    if key == "status":
        return 0 if f.get("user_enabled") else 1
    return 0


def user_rows_html(findings, start=0, stop=None, q="", sort_key=None, desc=False):
    """Pre-rendered <tr> html for the privileged-users table (shared by the
    static report and the --serve mode)."""
    items = findings
    if q:
        q = q.lower()
        items = [f for f in items if q in user_search_text(f)]
    if sort_key:
        items = sorted(items, key=lambda f: user_sort_value(f, sort_key), reverse=bool(desc))
    else:
        items = sorted(items, key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "Info"), 4),
                                             (f.get("user_display") or "").lower()))
    if stop is None:
        stop = len(items)
    out = []
    for f in items[start:stop]:
        key = f"row-{len(out)}"
        guest = (' <span class="badge badge-guest" title="Guest / external user">Guest</span>'
                 if f["user_type"] == "Guest" else "")
        role_chips = "".join(
            f'<span class="badge {severity_class(r["severity"])} role-badge" data-role="{esc(r["name"])}" data-role-field="roles" title="{esc(r["source"])}">{esc(r["name"])}</span> '
            for r in f["roles"])
        elig = f.get("eligible_roles") or []
        elig_titles = "\n".join(f"{r['name']} ({r['source']})" for r in elig)
        elig_cell = (f'<span class="perm" title="{esc(elig_titles)}">{len(elig)}</span>'
                     if elig else '<span class="muted">&mdash;</span>')
        priv_titles = []
        for app in f["priv_apps"]:
            perms = ", ".join(g["permission"] for g in app["grants"])
            priv_titles.append(f"{app['app_name']}: {perms}")
        cap_titles = "\n".join(cap_annotate(f["cap_member"])) if f["cap_member"] else ""
        owned_titles = "\n".join(cap_annotate(f["owned_cap"])) if f["owned_cap"] else ""
        account_source = ('<span class="badge badge-hybrid" title="Synced from on-prem Active Directory">AD</span>'
                          if f["hybrid"] else '<span class="badge badge-disabled" title="Cloud-only account">Cloud</span>')
        ca_titles = "\n".join(x["name"] for x in f.get("ca_exclusions", []))
        ca_count = len(f.get("ca_exclusions", []))
        ca_cell = (f'<span class="tag-chip tag-divergence" title="{esc(ca_titles)}">{ca_count}</span>'
                   if ca_count else '<span class="muted">0</span>')
        out.append(f"""
        <tr data-sp-id="" data-app-id="" data-owner-id="{esc(f["user_id"])}" data-profile-id="{esc(f["user_id"])}" data-detail-key="{key}">
          <td class="expand-cell">{EXPAND_BUTTON_HTML}</td>
          <td data-field="severity" data-value="{esc(f["severity"])}">{severity_badge(f["severity"])}</td>
          <td class="clickable" data-field="user" data-value="{esc(f["user_display"])}">{esc(f["user_display"])}{guest}</td>
          <td class="clickable" data-field="userUpn" data-value="{esc(f["user_upn"])}">{esc(f["user_upn"])}</td>
          <td data-field="roles" data-value="{esc(', '.join(r["name"] for r in f["roles"]))}">{role_chips}</td>
          <td class="clickable" data-field="eligible" data-value="{esc(', '.join(r['name'] for r in elig))}">{elig_cell}</td>
          <td data-field="privApps" data-value="{esc(str(len(f["priv_apps"])))}"><span class="perm" title="{esc(chr(10).join(priv_titles))}">{len(f["priv_apps"])}</span></td>
          <td data-field="capGroups" data-value="{esc(str(len(f["cap_member"])))}"><span class="perm" title="{esc(cap_titles)}">{len(f["cap_member"])}</span></td>
          <td data-field="grpOwned" data-value="{esc(str(f["owned_count"]))}"><span class="perm" title="{esc(owned_titles or '')}">{f["owned_count"]}</span></td>
          <td data-field="caExcl" data-value="{esc(str(ca_count))}"><span class="perm" title="{esc(ca_titles)}">{ca_cell}</span></td>
          <td data-field="hybrid" data-value="{esc('AD' if f['hybrid'] else 'Cloud')}">{account_source}</td>
          <td data-field="userStatus" data-value="{esc('Enabled' if f['user_enabled'] else 'Disabled')}">{bool_badge(f["user_enabled"])}</td>
        </tr>{drawer_for_html(key, 12)}""")
    return out, len(items)


def drawer_for_html(key, colspan):
    return (f'<tr class="drawer" data-detail-for="{esc(key)}">'
            f'<td colspan="{colspan}"><div class="drawer-body"></div></td></tr>')


def ad_tag_chips(tags):
    cls = {"Privileged": "tag-privileged"}
    return " ".join(f'<span class="tag-chip {cls.get(t, "")}">{esc(t)}</span>' for t in tags)


def page_rows(findings, q, sort_key, desc, start, stop, search_text, sort_value):
    """Shared q/sort/page pipeline for the serve-mode table endpoints."""
    items = findings
    if q:
        q = q.lower()
        items = [f for f in items if q in search_text(f)]
    if sort_key:
        items = sorted(items, key=lambda f: sort_value(f, sort_key), reverse=bool(desc))
    else:
        items = sorted(items, key=lambda f: (severity_rank(f.get("severity", "Info")),
                                             (str(f.get("title") or "")).lower()))
    if stop is None:
        stop = len(items)
    return items[start:stop], len(items)


# ---- legacy owned/unowned rows ---------------------------------------------

def legacy_search_text(f):
    parts = [o.get("display_name") or "" for o in f.get("owners", [])] + \
            [o.get("upn") or "" for o in f.get("owners", [])] + \
            [f.get("display_name") or "", f.get("resource_name") or "",
             f.get("permission") or "", f.get("severity") or ""]
    return " ".join(parts).lower()


def legacy_sort_value(f, key):
    owner = (f.get("owners") or [{}])[0]
    return {
        "1": severity_rank(f.get("severity", "Info")),
        "2": (owner.get("display_name") or "").lower(),
        "3": (owner.get("upn") or "").lower(),
        "4": 0 if owner.get("enabled") else 1,
        "5": (f.get("display_name") or "").lower(),
        "6": f.get("pw") or 0,
        "7": f.get("keys") or 0,
        "8": (f.get("resource_name") or "").lower(),
        "9": (f.get("permission") or "").lower(),
        "10": 0 if f.get("sp_enabled") else 1,
    }.get(key, 0)


LEGACY_SORT_KEYS = {str(i): str(i) for i in range(1, 11)}


def legacy_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None):
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                            legacy_search_text, legacy_sort_value)
    out = []
    for f in selected:
        for owner in f["owners"]:
            key = f"row-{len(out)}"
            foreign_note = (' <span class="muted">(foreign SP, no local app registration)</span>'
                            if f["is_foreign"] else "")
            out.append(f"""
        <tr data-sp-id="{esc(f["principal_id"])}" data-app-id="{esc(f["app_object_id"] or "")}" data-owner-id="{esc(owner["object_id"])}" data-detail-key="{key}">
          <td class="expand-cell">{EXPAND_BUTTON_HTML}</td>
          <td data-field="severity" data-value="{esc(f["severity"])}">{severity_badge(f["severity"])}</td>
          <td class="clickable" data-field="owner" data-value="{esc(owner["display_name"])}">{esc(owner["display_name"])}</td>
          <td class="clickable" data-field="ownerUpn" data-value="{esc(owner["upn"])}">{esc(owner["upn"])}</td>
          <td data-field="ownerStatus" data-value="{esc('Enabled' if owner['enabled'] else 'Disabled')}">{bool_badge(owner["enabled"])}</td>
          <td class="clickable" data-field="app" data-value="{esc(f["display_name"])}">{esc(f["display_name"])}{foreign_note}</td>
          <td data-field="pw" data-value="{esc(str(f.get("pw")) if f.get("pw") is not None else '')}">{count_cell(f.get("pw"))}</td>
          <td data-field="keys" data-value="{esc(str(f.get("keys")) if f.get("keys") is not None else '')}">{count_cell(f.get("keys"))}</td>
          <td class="clickable" data-field="resource" data-value="{esc(f["resource_name"])}">{esc(f["resource_name"])}</td>
          <td class="clickable" data-field="permission" data-value="{esc(f["permission"])}"><span class="perm" title="{esc(f["reason"])}">{esc(f["permission"])}</span></td>
          <td data-field="spStatus" data-value="{esc('Enabled' if f['sp_enabled'] else 'Disabled')}">{bool_badge(f["sp_enabled"])}</td>
        </tr>{drawer_for_html(key, 11)}""")
    return out, total


def unowned_search_text(f):
    return " ".join([f.get("display_name") or "", f.get("resource_name") or "",
                     f.get("permission") or "", f.get("severity") or ""]).lower()


def unowned_sort_value(f, key):
    return {
        "1": severity_rank(f.get("severity", "Info")),
        "2": (f.get("display_name") or "").lower(),
        "3": f.get("pw") or 0,
        "4": f.get("keys") or 0,
        "5": (f.get("resource_name") or "").lower(),
        "6": (f.get("permission") or "").lower(),
        "7": 0 if f.get("sp_enabled") else 1,
    }.get(key, 0)


UNOWNED_SORT_KEYS = {str(i): str(i) for i in range(1, 8)}


def legacy_unowned_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None):
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                            unowned_search_text, unowned_sort_value)
    out = []
    for f in selected:
        key = f"row-{len(out)}"
        out.append(f"""
        <tr data-sp-id="{esc(f["principal_id"])}" data-app-id="{esc(f["app_object_id"] or "")}" data-owner-id="" data-detail-key="{key}">
          <td class="expand-cell">{EXPAND_BUTTON_HTML}</td>
          <td data-field="severity" data-value="{esc(f["severity"])}">{severity_badge(f["severity"])}</td>
          <td class="clickable" data-field="app" data-value="{esc(f["display_name"])}">{esc(f["display_name"])}</td>
          <td data-field="pw" data-value="{esc(str(f.get("pw")) if f.get("pw") is not None else '')}">{count_cell(f.get("pw"))}</td>
          <td data-field="keys" data-value="{esc(str(f.get("keys")) if f.get("keys") is not None else '')}">{count_cell(f.get("keys"))}</td>
          <td class="clickable" data-field="resource" data-value="{esc(f["resource_name"])}">{esc(f["resource_name"])}</td>
          <td class="clickable" data-field="permission" data-value="{esc(f["permission"])}"><span class="perm" title="{esc(f["reason"])}">{esc(f["permission"])}</span></td>
          <td data-field="spStatus" data-value="{esc('Enabled' if f['sp_enabled'] else 'Disabled')}">{bool_badge(f["sp_enabled"])}</td>
        </tr>{drawer_for_html(key, 8)}""")
    return out, total


# ---- generic (per-check) rows ----------------------------------------------

def generic_search_text(f):
    t = f.get("target") or {}
    return " ".join([t.get("name") or "", t.get("type") or "", t.get("id") or "",
                     f.get("severity") or ""]).lower()


def generic_sort_value(f, key):
    t = f.get("target") or {}
    return {
        "1": severity_rank(f.get("severity", "Info")),
        "2": (t.get("name") or "").lower(),
        "3": (t.get("type") or "").lower(),
        "4": (t.get("id") or "").lower(),
        "5": f.get("pw") or 0,
        "6": f.get("keys") or 0,
        "7": f.get("roles") or 0,
        "8": ((f.get("status") or {}).get("label") or "").lower(),
    }.get(key, 0)


GENERIC_SORT_KEYS = {str(i): str(i) for i in range(1, 9)}


def generic_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None):
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                            generic_search_text, generic_sort_value)
    out = []
    for f in selected:
        o = f.get("object_ids") or {}
        sp_id = next(iter(o.get("sp", set())), "")
        app_id = next(iter(o.get("app", set())), "")
        owner_id = next(iter(o.get("user", set())), "")
        device_id = next(iter(o.get("device", set())), "")
        t = f.get("target") or {}
        key = f"row-{len(out)}"
        policy_id = esc(t.get("id", "")) if t.get("type") == "Policy" else ""
        out.append(f"""
        <tr data-sp-id="{esc(sp_id)}" data-app-id="{esc(app_id)}" data-owner-id="{esc(owner_id)}" data-device-id="{esc(device_id)}" data-policy-id="{policy_id}" data-check-id="{esc(f["check_id"])}" data-detail-key="{key}">
          <td class="expand-cell">{EXPAND_BUTTON_HTML}</td>
          <td data-field="severity" data-value="{esc(f["severity"])}">{severity_badge(f["severity"])}</td>
          <td class="clickable" data-field="target" data-value="{esc(t.get("name", ""))}">{esc(t.get("name", ""))}</td>
          <td data-field="targetType" data-value="{esc(t.get("type", ""))}">{esc(t.get("type", ""))}</td>
          <td class="mono" data-field="id" data-value="{esc(t.get("id", ""))}">{esc(t.get("id", ""))}</td>
          <td data-field="pw" data-value="{esc(str(f.get("pw")) if f.get("pw") is not None else '')}">{count_cell(f.get("pw"))}</td>
          <td data-field="keys" data-value="{esc(str(f.get("keys")) if f.get("keys") is not None else '')}">{count_cell(f.get("keys"))}</td>
          <td data-field="roleCount" data-value="{esc(str(f.get("roles")) if f.get("roles") is not None else '')}">{count_cell(f.get("roles"))}</td>
          <td data-field="status" data-value="{esc((f.get("status") or {}).get("label", ""))}">{status_cell(f.get("status"))}</td>
        </tr>{drawer_for_html(key, 9)}""")
    return out, total


# ---- app directory roles rows ------------------------------------------------

def app_dir_search_text(f):
    t = f.get("target") or {}
    roles = ", ".join(r["name"] for r in f.get("dir_role_tags", []))
    return " ".join([t.get("name") or "", f.get("severity") or "", roles]).lower()


def app_dir_sort_value(f, key):
    t = f.get("target") or {}
    return {
        "1": severity_rank(f.get("severity", "Info")),
        "2": (t.get("name") or "").lower(),
        "3": (t.get("id") or "").lower(),
        "4": ", ".join(r["name"] for r in f.get("dir_role_tags", [])).lower(),
        "5": 0 if (f.get("status") or {}).get("enabled") else 1,
    }.get(key, 0)


APP_DIR_SORT_KEYS = {str(i): str(i) for i in range(1, 6)}


def app_dir_role_chip(r):
    """Chip for one directory-role entry in the app-dir-roles table; eligible
    (PIM) entries get a muted (PIM) marker and a tooltip with the path."""
    if r.get("eligible"):
        title = r["name"] + " \u2014 PIM eligible"
        if r.get("path"):
            title += " \u2014 via " + " \u2192 ".join(r["path"])
        label = f'{esc(r["name"])} <span class="muted">(PIM)</span>'
    else:
        title = (r["name"] + " \u2014 via " + " \u2192 ".join(r["path"])
                 if r.get("path") else r["name"] + " \u2014 direct assignment")
        label = esc(r["name"])
    return (f'<span class="badge {severity_class(r["severity"])} role-badge" '
            f'data-role="{esc(r["name"])}" data-role-field="roles" '
            f'title="{esc(title)}">{label}</span> ')


def app_dir_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None):
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                                app_dir_search_text, app_dir_sort_value)
    out = []
    for f in selected:
        key = f"row-{len(out)}"
        tags = f.get("dir_role_tags", [])
        role_chips = "".join(app_dir_role_chip(r) for r in tags)
        out.append(f"""
        <tr data-sp-id="{esc(f.get("sp_id") or "")}" data-detail-key="{key}">
          <td class="expand-cell">{EXPAND_BUTTON_HTML}</td>
          <td data-field="severity" data-value="{esc(f["severity"])}">{severity_badge(f["severity"])}</td>
          <td class="clickable" data-field="app" data-value="{esc(f["target"]["name"])}">{esc(f["target"]["name"])}</td>
          <td class="mono" data-field="id" data-value="{esc(f["target"]["id"])}">{esc(f["target"]["id"])}</td>
          <td data-field="appDirRoles" data-value="{esc(', '.join(r['name'] for r in tags))}">{role_chips or '<span class="muted">&mdash;</span>'}</td>
          <td data-field="status" data-value="{esc((f.get("status") or {}).get("label", ""))}">{status_cell(f.get("status"))}</td>
        </tr>{drawer_for_html(key, 6)}""")
    return out, total


# ---- groups / dynamic rows ---------------------------------------------------

def group_search_text(f):
    roles = ", ".join(r["name"] for r in f.get("dir_roles", []))
    elig = ", ".join(r["name"] for r in f.get("eligible_roles", []))
    return " ".join([f.get("group_name") or "", f.get("severity") or "",
                     roles, elig, " ".join(f.get("types", []))]).lower()


def group_sort_value(f, key):
    return {
        "1": severity_rank(f.get("severity", "Info")),
        "2": (f.get("group_name") or "").lower(),
        "3": " ".join(f.get("types", [])).lower(),
        "4": ", ".join(r["name"] for r in f.get("dir_roles", [])).lower(),
        "5": len(f.get("eligible_roles", [])),
        "6": f.get("member_count", 0),
        "7": f.get("priv_member_count", 0),
        "8": len(f.get("owners", [])),
    }.get(key, 0)


GROUP_SORT_KEYS = {str(i): str(i) for i in range(1, 9)}


def group_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None):
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                            group_search_text, group_sort_value)
    out = []
    for f in selected:
        key = f"row-{len(out)}"
        type_chips = []
        for t in f["types"]:
            type_chips.append(f'<span class="tag-chip">{esc(t)}</span>')
        if f["is_public"]:
            type_chips.append('<span class="tag-chip">Public</span>')
        if f["dynamic"]:
            type_chips.append('<span class="tag-chip tag-spray">Auto-membership</span>')
        if f["assignable"]:
            type_chips.append('<span class="tag-chip tag-divergence">Assignable</span>')
        if f["mail"]:
            type_chips.append('<span class="tag-chip">Mail</span>')
        role_chips = "".join(
            f'<span class="badge {severity_class(r["severity"])} role-badge" data-role="{esc(r["name"])}" data-role-field="grpRoles" title="{esc(r["name"])}">{esc(r["name"])}</span> '
            for r in f["dir_roles"])
        member_titles = "\n".join(
            ((m["upn"] or m["name"])
             + (" — " + ", ".join(r["name"] for r in m["roles"] if r["severity"] != "Info")
                if any(r["severity"] != "Info" for r in m["roles"]) else ""))
            for m in f["members"])
        if f["sp_members"]:
            member_titles += ("\n" if member_titles else "") + f"{len(f['sp_members'])} SP member(s): " + ", ".join(m["name"] for m in f["sp_members"])
        priv_titles = "\n".join(
            ((m["upn"] or m["name"])
             + " — " + ", ".join(r["name"] for r in m["roles"]))
            for m in f["members"] if m["privileged"])
        owner_titles = "\n".join(f["owners"])
        elig = f.get("eligible_roles") or []
        elig_titles = "\n".join(f"{r['name']} (PIM eligible)" for r in elig)
        out.append(f"""
        <tr data-group-id="{esc(f["group_id"])}" data-detail-key="{key}">
          <td class="expand-cell">{EXPAND_BUTTON_HTML}</td>
          <td data-field="severity" data-value="{esc(f["severity"])}">{severity_badge(f["severity"])}</td>
          <td class="clickable" data-field="group" data-value="{esc(f["group_name"])}">{esc(f["group_name"])}</td>
          <td data-field="grpType" data-value="{esc(', '.join(f['types'] + (['Public'] if f['is_public'] else []) + (['assignable'] if f['assignable'] else []) + (['dynamic'] if f['dynamic'] else [])))}">{''.join(type_chips) or '<span class="muted">&mdash;</span>'}</td>
          <td data-field="grpRoles" data-value="{esc(', '.join(r['name'] for r in f['dir_roles']))}">{role_chips or '<span class="muted">&mdash;</span>'}</td>
          <td class="clickable" data-field="eligible" data-value="{esc(', '.join(r['name'] for r in elig))}"><span class="perm" title="{esc(elig_titles or '')}">{len(elig) if elig else '<span class="muted">&mdash;</span>'}</span></td>
          <td data-field="grpMembers" data-value="{esc(str(f['member_count']))}"><span class="perm" title="{esc(member_titles or '')}">{f['member_count']}</span></td>
          <td data-field="grpPriv" data-value="{esc(str(f['priv_member_count']))}"><span class="perm" title="{esc(priv_titles or '')}">{f['priv_member_count']}</span></td>
          <td data-field="grpOwners" data-value="{esc(str(len(f['owners'])))}"><span class="perm" title="{esc(owner_titles or '')}">{len(f['owners'])}</span></td>
        </tr>{drawer_for_html(key, 9)}""")
    return out, total


def dynamic_search_text(f):
    return " ".join([f.get("group_name") or "", f.get("dyn_rule") or "",
                     " ".join(f.get("dyn_attrs", [])),
                     " ".join(f.get("dyn_mods", []))]).lower()


def dynamic_sort_value(f, key):
    return {
        "1": (f.get("group_name") or "").lower(),
        "2": (f.get("dyn_rule") or "").lower(),
        "3": " ".join(f.get("dyn_attrs", [])).lower(),
        "4": " ".join(f.get("dyn_mods", [])).lower(),
    }.get(key, 0)


DYNAMIC_SORT_KEYS = {"1": "1", "2": "2", "3": "3", "4": "4"}


def dynamic_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None):
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                            dynamic_search_text, dynamic_sort_value)
    out = []
    for f in selected:
        key = f"row-{len(out)}"
        attr_chips = "".join(
            f'<span class="tag-chip filter-tag" data-filter-field="dynAttrs" data-filter-value="{esc(a)}">{esc(a)}</span> '
            for a in f["dyn_attrs"])
        mod_chips = "".join(
            f'<span class="tag-chip {"tag-spray" if m == "User modifiable" else "tag-divergence" if m == "User Administrator" else "tag-privileged" if m == "Directory Writer" else ""} filter-tag" data-filter-field="dynMods" data-filter-value="{esc(m)}">{esc(m)}</span> '
            for m in f["dyn_mods"])
        out.append(f"""
        <tr data-group-id="{esc(f["group_id"])}" data-detail-key="{key}">
          <td class="expand-cell">{EXPAND_BUTTON_HTML}</td>
          <td class="clickable" data-field="dynGroup" data-value="{esc(f["group_name"])}">{esc(f["group_name"])}</td>
          <td class="mono" data-field="dynRule" data-value="{esc(f["dyn_rule"])}"><span class="perm" title="{esc(f["dyn_rule"])}">{esc(truncate(f["dyn_rule"], 60))}</span></td>
          <td data-field="dynAttrs" data-value="{esc(', '.join(f['dyn_attrs']))}">{attr_chips or '<span class="muted">&mdash;</span>'}</td>
          <td data-field="dynMods" data-value="{esc(', '.join(f['dyn_mods']))}">{mod_chips or '<span class="muted">&mdash;</span>'}</td>
        </tr>{drawer_for_html(key, 5)}""")
    return out, total


# ---- AD roster rows -----------------------------------------------------------

def ad_search_text(f):
    return " ".join([f.get("user_display") or "", f.get("user_upn") or "",
                     f.get("ad_cn") or "", f.get("ad_dn") or "",
                     f.get("ad_sid") or "", " ".join(f.get("tags", [])),
                     " ".join(x.get("name") or "" for x in f.get("ca_exclusions", []))]).lower()


def ad_sort_value(f, key):
    return {
        "1": (f.get("user_display") or "").lower(),
        "2": (f.get("user_upn") or "").lower(),
        "3": (f.get("ad_cn") or "").lower(),
        "4": (f.get("ad_dn") or "").lower(),
        "5": (f.get("ad_sid") or "").lower(),
        "6": (f.get("pw_change") or "").lower(),
        "7": " ".join(f.get("tags", [])).lower(),
        "8": len(f.get("ca_exclusions", [])),
        "9": 0 if (f.get("status") or {}).get("enabled") else 1,
    }.get(key, 0)


AD_SORT_KEYS = {str(i): str(i) for i in range(1, 10)}


def ad_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None):
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                            ad_search_text, ad_sort_value)
    out = []
    for f in selected:
        key = f"row-{len(out)}"
        sid_tail = f["sid_rid"]
        sid_cell = (f'<span class="perm" title="{esc(f["ad_sid"])}">{esc(sid_tail)}</span>'
                    if sid_tail else '<span class="muted">&mdash;</span>')
        pw = esc(f["pw_change"]) if f["pw_change"] else '<span class="muted">&mdash;</span>'
        ca_titles = "\n".join(x["name"] for x in f.get("ca_exclusions", []))
        ca_count = len(f.get("ca_exclusions", []))
        ca_cell = (f'<span class="tag-chip tag-divergence" title="{esc(ca_titles)}">{ca_count}</span>'
                   if ca_count else '<span class="muted">0</span>')
        out.append(f"""
        <tr data-sp-id="" data-app-id="" data-owner-id="{esc(f["user_id"])}" data-profile-id="{esc(f["user_id"])}" data-detail-key="{key}">
          <td class="expand-cell">{EXPAND_BUTTON_HTML}</td>
          <td class="clickable" data-field="adUser" data-value="{esc(f["user_display"])}">{esc(f["user_display"])}</td>
          <td class="clickable" data-field="adUpn" data-value="{esc(f["user_upn"])}">{esc(f["user_upn"])}</td>
          <td data-field="adCn" data-value="{esc(f["ad_cn"])}">{esc(f["ad_cn"]) or '<span class="muted">&mdash;</span>'}</td>
          <td data-field="adDn" data-value="{esc(f["ad_dn"])}">{esc(f["ad_dn"]) or '<span class="muted">&mdash;</span>'}</td>
          <td data-field="adSid" data-value="{esc(f["ad_sid"])}">{sid_cell}</td>
          <td data-field="adPw" data-value="{esc(f["pw_change"])}">{pw}</td>
          <td data-field="adTags" data-value="{esc(', '.join(f["tags"]))}">{ad_tag_chips(f["tags"])}</td>
          <td data-field="caExcl" data-value="{esc(str(ca_count))}"><span class="perm" title="{esc(ca_titles)}">{ca_cell}</span></td>
          <td data-field="adStatus" data-value="{esc('Enabled' if (f.get('status') or {}).get('enabled') else 'Disabled')}">{bool_badge(bool((f.get('status') or {}).get('enabled')))}</td>
        </tr>{drawer_for_html(key, 10)}""")
    return out, total


def realm_card_html(meta):
    """Realm summary above the AD-synced users table: realm, SID prefix, synced
    count, and DC hosts — hosts are capped at 10 with a dropdown for the rest."""
    parts = []
    if meta.get("domain"):
        parts.append(f"Realm: <b>{esc(meta['domain'])}</b>")
    if meta.get("sid_prefix"):
        parts.append(f"Domain SID: <b>{esc(meta['sid_prefix'].rstrip('-'))}-x</b>")
    if meta.get("synced_count"):
        parts.append(f"{meta['synced_count']} synced user(s)")
    hosts = meta.get("dc_hosts") or []
    if hosts:
        host_html = f"<b>{esc(', '.join(hosts[:10]))}</b>"
        if len(hosts) > 10:
            host_html += (f' <details class="inline-more"><summary>+{len(hosts) - 10} more</summary>'
                          f'<span> {esc(", ".join(hosts[10:]))}</span></details>')
        parts.append("DC hosts: " + host_html)
    if not parts:
        return ""
    return '<div class="realm">' + " \u00b7 ".join(parts) + "</div>"


JS_FILTER_MODULE = """<script id="filter-module">
// Advanced filter query language — mirrors the Python grammar in
// entra-surface.py (parse_advanced_query); both are pinned against the same
// test vectors in tests/filter_cases.json.
(function() {
  var LIST_FIELDS = {roles:1, eligible:1, grproles:1, dynmods:1, dynattrs:1,
    azroles:1, azusrroles:1, azsproles:1, adtags:1, appdirroles:1,
    owner:1, ownerupn:1, ownerstatus:1};

  // column-name aliases -> DOM field names (any-match), mirrored from Python
  var COLUMN_ALIASES = {
    privileges: ['severity'], severity: ['severity'], sev: ['severity'],
    roles: ['roles', 'grproles', 'appdirroles'],
    grproles: ['grproles'], appdirroles: ['appdirroles'],
    eligible: ['eligible'],
    user: ['user'], upn: ['userupn'], userupn: ['userupn'],
    privapps: ['privapps'], capablegrp: ['capgroups'], capgroups: ['capgroups'],
    groupsowned: ['grpowned'], grpowned: ['grpowned'], caexcl: ['caexcl'],
    accountsource: ['hybrid'], hybrid: ['hybrid'],
    status: ['userstatus', 'status', 'spstatus', 'ownerstatus', 'adstatus'],
    userstatus: ['userstatus'], spstatus: ['spstatus'],
    ownerstatus: ['ownerstatus'], adstatus: ['adstatus'],
    target: ['target'], targettype: ['targettype'],
    objectid: ['id'], id: ['id'],
    passwords: ['pw'], pw: ['pw'], keys: ['keys'],
    roleassignment: ['rolecount'], rolecount: ['rolecount'],
    group: ['group'], type: ['grptype'], grptype: ['grptype'],
    members: ['grpmembers'], grpmembers: ['grpmembers'],
    privmembers: ['grppriv'], grppriv: ['grppriv'],
    owners: ['grpowners'], grpowners: ['grpowners'],
    policy: ['polname'], polname: ['polname'],
    state: ['polstate'], polstate: ['polstate'],
    scope: ['polscope'], polscope: ['polscope'],
    apps: ['polapps'], polapps: ['polapps'],
    controls: ['polcontrols'], polcontrols: ['polcontrols'],
    included: ['polinc'], polinc: ['polinc'],
    excluded: ['polexc'], polexc: ['polexc'],
    application: ['app'], app: ['app'],
    owner: ['owner'], ownerupn: ['ownerupn'],
    resource: ['resource'], permission: ['permission'],
    membershiprule: ['dynrule'], dynrule: ['dynrule'],
    referencedattributes: ['dynattrs'], dynattrs: ['dynattrs'],
    modifiableby: ['dynmods'], dynmods: ['dynmods'],
    aduser: ['aduser'], adupn: ['adupn'],
    adcn: ['adcn'], addn: ['addn'],
    sid: ['adsid'], adsid: ['adsid'],
    onprempwchange: ['adpw'], adpw: ['adpw'],
    targetingtags: ['adtags'], adtags: ['adtags'],
    check: ['check'], category: ['category']
  };

  var DISPLAY_NAMES = {
    privileges: 'Privileges', roles: 'Directory roles', eligible: 'Eligible',
    user: 'User', upn: 'UPN', privapps: 'Priv apps', capablegrp: 'Capable grp',
    groupsowned: 'Groups owned', caexcl: 'CA excl.', accountsource: 'Account Source',
    status: 'Status', target: 'Target', targettype: 'Target Type',
    objectid: 'Object ID', passwords: 'Passwords', keys: 'Keys',
    roleassignment: 'Role assignment', group: 'Group', type: 'Type',
    members: 'Members', privmembers: 'Priv. members', owners: 'Owners',
    policy: 'Policy', state: 'State', scope: 'Scope', apps: 'Apps',
    controls: 'Controls', included: 'Included', excluded: 'Excluded',
    application: 'Application', owner: 'Owner', ownerupn: 'Owner UPN',
    ownerstatus: 'Owner Status', resource: 'Resource', permission: 'Permission',
    spstatus: 'SP Status', membershiprule: 'Membership rule',
    referencedattributes: 'Referenced attributes', modifiableby: 'Modifiable by',
    aduser: 'User', adupn: 'UPN', adcn: 'AD CN', addn: 'AD DN', sid: 'SID',
    onprempwchange: 'On-prem pw change', targetingtags: 'Targeting tags',
    check: 'Check', category: 'Category'
  };

  var PHRASES = [
    ['Directory roles', 'roles'], ['Priv. members', 'privmembers'],
    ['Priv apps', 'privapps'], ['Capable grp', 'capablegrp'],
    ['Groups owned', 'groupsowned'], ['CA excl.', 'caexcl'],
    ['Account Source', 'accountsource'], ['Target Type', 'targettype'],
    ['Target Status', 'status'], ['Object ID', 'objectid'],
    ['Role assignment', 'roleassignment'], ['SP Status', 'spstatus'],
    ['Owner UPN', 'ownerupn'], ['Owner Status', 'ownerstatus'],
    ['Membership rule', 'membershiprule'],
    ['Referenced attributes', 'referencedattributes'],
    ['attribute modifiable by', 'modifiableby'],
    ['AD CN', 'adcn'], ['AD DN', 'addn'],
    ['On-prem pw change', 'onprempwchange'], ['Targeting tags', 'targetingtags']
  ];

  var BS = String.fromCharCode(92);  // backslash, avoids escape-layering with Python strings
  var REGEX_SPECIALS = '.*+?^$(){}[]|' + BS;

  function escapeRegExp(s) {
    var out = '';
    for (var i = 0; i < s.length; i++) {
      var c = s.charAt(i);
      out += REGEX_SPECIALS.indexOf(c) !== -1 ? BS + c : c;
    }
    return out;
  }

  var PHRASE_RES = PHRASES.map(function(p) {
    return [new RegExp(BS + 'b' + escapeRegExp(p[0]) + '(?=' + BS + 's*:)', 'i'), p[1]];
  });
  var DISPLAY_CANON = {};
  PHRASES.forEach(function(p) { DISPLAY_CANON[normalizeField(p[0])] = p[1]; });

  function rewritePhrases(text) {
    for (var i = 0; i < PHRASE_RES.length; i++) {
      text = text.replace(PHRASE_RES[i][0], PHRASE_RES[i][1]);
    }
    return text;
  }

  function normalizeField(name) {
    return (name || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  }

  function fieldsFor(name) {
    var canon = normalizeField(name);
    var fields = COLUMN_ALIASES[canon];
    if (!fields) {
      var mapped = DISPLAY_CANON[canon];
      if (mapped) fields = COLUMN_ALIASES[mapped];
    }
    return fields || null;
  }

  function columns() {
    var out = [];
    Object.keys(DISPLAY_NAMES).forEach(function(canon) {
      out.push({canonical: canon, display: DISPLAY_NAMES[canon],
                fields: COLUMN_ALIASES[canon] || []});
    });
    out.sort(function(a, b) { return a.display < b.display ? -1 : 1; });
    return out;
  }

  function tokenize(text) {
    var tokens = [], i = 0, n = text.length;
    while (i < n) {
      var ch = text[i];
      if (/\\s/.test(ch)) { i++; continue; }
      if (ch === '(' || ch === ')') { tokens.push({t: ch === '(' ? 'lparen' : 'rparen', v: ch}); i++; continue; }
      if (ch === '"') {
        var j = i + 1, buf = '';
        while (j < n && text[j] !== '"') { buf += text[j]; j++; }
        if (j >= n) throw new Error('unterminated quote at position ' + i);
        tokens.push({t: 'quoted', v: buf});
        i = j + 1;
        continue;
      }
      var k = i;
      while (k < n && !/\\s/.test(text[k]) && text[k] !== '(' && text[k] !== ')' && text[k] !== '"') k++;
      tokens.push({t: 'word', v: text.slice(i, k)});
      i = k;
    }
    return tokens;
  }

  function isOp(tok, op) {
    return !!tok && tok.t === 'word' && tok.v.toUpperCase() === op;
  }

  function parse(text) {
    try {
      var rewritten = rewritePhrases(text || '');
      var tokens = tokenize(rewritten), pos = 0;
      if (!tokens.length) return {ast: {op: 'text', value: ''}};
      function isAnyOperator(tok) {
        return !!tok && tok.t === 'word' &&
          (tok.v.toUpperCase() === 'AND' || tok.v.toUpperCase() === 'OR' || tok.v.toUpperCase() === 'NOT');
      }
      function consumeValueWords(value) {
        // append following plain words so unquoted values with spaces work
        while (true) {
          var tok = pos < tokens.length ? tokens[pos] : null;
          if (!tok || tok.t !== 'word' || isAnyOperator(tok)) return value;
          pos++;
          value += ' ' + tok.v;
        }
      }
      function resolveField(name) {
        if (name.toUpperCase() === 'CONTAINS') return null;
        var fields = fieldsFor(name);
        if (!fields) throw new Error("unknown field '" + name + "' (try privileges, roles, target, check, category)");
        return fields;
      }
      function peek() { return pos < tokens.length ? tokens[pos] : null; }
      function advance() { return tokens[pos++]; }
      function expect(kind) {
        var tok = peek();
        if (!tok || tok.t !== kind) {
          throw new Error('expected ' + kind + " near '" + (tok ? tok.v : '<end>') + "'");
        }
        return advance();
      }
      function parseOr() {
        var children = [parseAnd()];
        while (isOp(peek(), 'OR')) { advance(); children.push(parseAnd()); }
        return children.length === 1 ? children[0] : {op: 'or', children: children};
      }
      function parseAnd() {
        var children = [parseTerm()];
        while (isOp(peek(), 'AND')) { advance(); children.push(parseTerm()); }
        return children.length === 1 ? children[0] : {op: 'and', children: children};
      }
      function parseTerm() {
        var tok = peek();
        if (!tok) throw new Error('unexpected end of query');
        if (tok.t === 'rparen') throw new Error("unexpected ')' near '" + tok.v + "'");
        if (tok.t === 'lparen') { advance(); var node = parseOr(); expect('rparen'); return node; }
        if (isOp(tok, 'NOT')) { advance(); return {op: 'not', child: parseTerm()}; }
        if (tok.t === 'quoted') { advance(); return {op: 'text', value: tok.v}; }
        var word = advance().v;
        if (isOp({t: 'word', v: word}, 'AND') || isOp({t: 'word', v: word}, 'OR')) {
          throw new Error("unexpected operator '" + word + "'");
        }
        if (word.toUpperCase() === 'NOT') return {op: 'not', child: parseTerm()};
        if (word.indexOf(':') === -1) return {op: 'text', value: word};
        var idx = word.indexOf(':');
        var field = word.slice(0, idx), rest = word.slice(idx + 1);
        if (!field) return {op: 'text', value: word};
        if (!rest) {
          var vt = peek();
          if (!vt || (vt.t !== 'word' && vt.t !== 'quoted')) {
            throw new Error("expected value after '" + field + ":'");
          }
          advance();
          return {op: 'eq', fields: resolveField(field), value: consumeValueWords(vt.v)};
        }
        if (rest.toUpperCase() === 'CONTAINS') {
          var vt2 = peek();
          if (!vt2 || (vt2.t !== 'word' && vt2.t !== 'quoted')) {
            throw new Error("expected value after '" + field + ":contains:'");
          }
          advance();
          return {op: 'contains', fields: resolveField(field), value: consumeValueWords(vt2.v)};
        }
        if (rest.toUpperCase().indexOf('CONTAINS:') === 0) {
          return {op: 'contains', fields: resolveField(field),
                  value: consumeValueWords(rest.slice('contains:'.length))};
        }
        if (field.toUpperCase() === 'CONTAINS') return {op: 'text', value: rest};
        return {op: 'eq', fields: resolveField(field), value: consumeValueWords(rest)};
      }
      var node = parseOr();
      var extra = peek();
      if (extra) throw new Error("unexpected '" + extra.v + "'");
      return {ast: node};
    } catch (e) {
      return {error: String(e.message || e)};
    }
  }

  function globRegex(pattern) {
    var parts = pattern.split('*');
    var out = '';
    for (var i = 0; i < parts.length; i++) {
      out += escapeRegExp(parts[i]);
      if (i < parts.length - 1) out += '.*';
    }
    return new RegExp(out, 'i');
  }

  function globMatches(pattern, value, search) {
    // '*' alone means "any non-empty value"; otherwise '*' wildcards match
    // any sequence. search=true matches anywhere in the value.
    if (pattern === '*') return !!value;
    var re = globRegex(pattern);
    if (search) return re.test(value);
    var m = re.exec(value);
    return !!(m && m[0] === value);
  }

  function evaluate(ast, fields, fullText) {
    // normalize the field map to lowercase keys (DOM maps are already
    // lowercase; serve-side maps use CamelCase — handle both)
    var fl = {};
    Object.keys(fields || {}).forEach(function(k) { fl[k.toLowerCase()] = fields[k]; });
    var op = ast.op;
    if (op === 'text') {
      return (fullText || '').toLowerCase().indexOf(ast.value.toLowerCase()) !== -1;
    }
    if (op === 'not') return !evaluate(ast.child, fl, fullText);
    if (op === 'and' || op === 'or') {
      for (var i = 0; i < ast.children.length; i++) {
        var r = evaluate(ast.children[i], fl, fullText);
        if (op === 'and' && !r) return false;
        if (op === 'or' && r) return true;
      }
      return op === 'and';
    }
    if (op === 'eq' || op === 'contains') {
      var needle = ast.value.toLowerCase();
      var hasGlob = needle.indexOf('*') !== -1;
      for (var f = 0; f < ast.fields.length; f++) {
        var field = ast.fields[f];
        var value = (fl[field] || '').toLowerCase();
        if (op === 'contains') {
          if (hasGlob) {
            if (globMatches(needle, value, true)) return true;
          } else if (value.indexOf(needle) !== -1) {
            return true;
          }
        } else if (LIST_FIELDS[field]) {
          if (hasGlob) {
            var items = value.split(',');
            for (var j = 0; j < items.length; j++) {
              if (globMatches(needle, items[j].trim().toLowerCase())) return true;
            }
          } else {
            for (var j2 = 0; j2 < value.split(',').length; j2++) {
              if (value.split(',')[j2].trim().toLowerCase() === needle) return true;
            }
          }
        } else {
          if (hasGlob) {
            if (globMatches(needle, value)) return true;
          } else if (value === needle) {
            return true;
          }
        }
      }
      return false;
    }
    return false;
  }

  window.ADV_FILTER = {parse: parse, evaluate: evaluate, listFields: LIST_FIELDS,
                       fieldsFor: fieldsFor, columns: columns,
                       normalizeField: normalizeField};
})();
</script>
"""


def render_report(results, tenant_name, db_path, config_path, include_disabled, entity_details,
                  min_severity_label, entity_profiles=None, tenant_summary=None, graph=None,
                  serve_mode=False, serve_tables=None, group_roles=None,
                  group_eligible_roles=None):
    all_findings = [f for res in results for f in res["findings"]]

    category_counts = Counter(res["category"] for res in results for _ in res["findings"])

    EXPAND_BUTTON = '<button type="button" class="icon-btn expand-btn" aria-label="View full details">+</button>'

    # ---- drawer (inline dropdown) helper ---------------------------------
    def drawer_for(key, colspan):
        return (f'<tr class="drawer" data-detail-for="{esc(key)}">'
                f'<td colspan="{colspan}"><div class="drawer-body"></div></td></tr>')

    def serve_pager():
        return ('<div class="table-pager hidden">'
                '<button type="button" class="icon-btn tp-prev">&#8592; Prev</button>'
                '<span class="tp-info muted"></span>'
                '<button type="button" class="icon-btn tp-next">Next &#8594;</button>'
                '<label class="muted">Rows '
                '<select class="tp-size">'
                '<option value="25" selected>25</option><option value="50">50</option><option value="100">100</option><option value="250">250</option>'
                '<option value="500">500</option><option value="1000">1000</option>'
                '</select></label></div>')

    # ---- Azure Roles tables (one per principal section) -------------------
    def az_sub(a):
        name, sid = a.get("scope_sub_name") or "", a.get("scope_sub") or ""
        if name or sid:
            return f"{name} ({sid})" if name and sid else (name or sid)
        if a.get("scope_type") == "Management group":
            return a.get("scope_mgmt") or "—"
        return "—"

    def azure_roles_section(title, table_id, category, principal_header, rows, az_field):
        if not rows:
            return ""
        body = []
        for label, rid, kind, a in rows:
            key = f"az-{table_id}-{len(body)}"
            if kind == "sp":
                data = f'data-sp-id="{esc(rid)}"'
            elif kind == "group":
                data = f'data-group-id="{esc(rid)}"'
            else:
                data = f'data-profile-id="{esc(rid)}"'
            if kind == "sp":
                pfield = "azApp"
            elif kind == "group":
                pfield = "azGroup"
            else:
                pfield = "azUser"
            pcell = f'<td class="clickable" data-field="{pfield}" data-value="{esc(label)}">{esc(label)}</td>'
            body.append(f"""
        <tr {data} data-detail-key="{key}">
          <td class="expand-cell">{EXPAND_BUTTON}</td>
          <td data-field="severity" data-value="{esc(a.get('severity') or 'Info')}">{severity_badge(a.get('severity') or 'Info')}</td>
          {pcell}
          <td class="clickable" data-field="{az_field}" data-value="{esc(a['role'])}">{esc(a['role'] + (' (eligible)' if a.get('eligible') else ''))}</td>
          <td data-field="azScopeType" data-value="{esc(a.get('scope_type') or '')}">{esc(a.get('scope_type') or '—')}</td>
          <td data-field="azSub" data-value="{esc(az_sub(a))}">{esc(az_sub(a))}</td>
          <td data-field="azRg" data-value="{esc(a.get('scope_rg') or '')}">{esc(a.get('scope_rg') or '—')}</td>
          <td data-field="azProvider" data-value="{esc(a.get('scope_provider') or '')}">{esc(a.get('scope_provider') or '—')}</td>
          <td data-field="azResource" data-value="{esc(a.get('scope_resource') or '')}">{esc(a.get('scope_resource') or '—')}</td>
        </tr>{drawer_for(key, 9)}""")
        return f"""
  <section data-category="{esc(category)}">
    <h2>{esc(title)}</h2>
    <div class="table-scroll">
    <table id="{esc(table_id)}" class="findings">
      <colgroup>
        <col style="width:44px">
        <col style="width:90px">
        <col style="width:170px"><col style="width:210px"><col style="width:110px">
        <col style="width:230px"><col style="width:120px"><col style="width:150px"><col style="width:170px">
      </colgroup>
      <thead>
        <tr>
          <th class="no-sort"></th>
          <th data-type="text">Privileges</th>
          <th data-type="text">{esc(principal_header)}</th>
          <th data-type="text">Role</th>
          <th data-type="text">Scope Type</th>
          <th data-type="text">Subscription</th>
          <th data-type="text">Resource Group</th>
          <th data-type="text">Provider</th>
          <th data-type="text">Resource</th>
        </tr>
      </thead>
      <tbody>{''.join(body)}</tbody>
    </table>
    </div>
  </section>
"""

    def az_rows_for(mapping, kind, name_fn):
        """(label, principal_id, kind, entry) rows from an az_roles mapping."""
        rows = []
        for pid, roles in sorted(mapping.items()):
            label = name_fn(pid)
            if label is None:
                continue
            for a in sorted(roles, key=lambda x: (bool(x.get("eligible")), x["role"].lower())):
                rows.append((label, pid, kind, a))
        return rows

    # ---- legacy privileged-ownership sections ----------------------------
    def legacy_owned_section():
        priv = next((res for res in results if res["id"] == "priv_app_ownership"), None)
        if not priv:
            return ""
        owned = [f for f in priv["findings"] if f["owners"]]
        owned_rows = "" if serve_mode else "\n".join(legacy_rows_html(owned)[0])
        if serve_tables is not None:
            serve_tables["owned-table"] = {"findings": owned, "rows": legacy_rows_html,
                                           "search": legacy_search_text,
                                           "sort_keys": LEGACY_SORT_KEYS, "colspan": 11}
        owned_pager = serve_pager() if serve_mode else ""
        return f"""
  <section data-category="apps">
    <h2>{esc(priv["title"])}</h2>
    <div class="table-scroll">
    <table id="owned-table" class="findings" data-serve="1">
      <colgroup>
        <col style="width:44px">
        <col style="width:90px"><col style="width:150px"><col style="width:190px">
        <col style="width:90px"><col style="width:170px"><col style="width:60px"><col style="width:50px"><col style="width:140px"><col style="width:190px"><col style="width:90px">
      </colgroup>
      <thead>
        <tr>
          <th class="no-sort"></th>
          <th data-type="text">Privileges</th>
          <th data-type="text">Owner</th>
          <th data-type="text">Owner UPN</th>
          <th data-type="text">Owner Status</th>
          <th data-type="text">Application</th>
          <th data-type="text">Passwords</th>
          <th data-type="text">Keys</th>
          <th data-type="text">Resource</th>
          <th data-type="text">Permission</th>
          <th data-type="text">SP Status</th>
        </tr>
      </thead>
      <tbody>{owned_rows}</tbody>
    </table>
    </div>
    {owned_pager}
    {'<div class="empty">No owned applications matched the configured privileged roles.</div>' if not owned else ''}
  </section>
"""

    def legacy_unowned_section():
        priv = next((res for res in results if res["id"] == "priv_app_ownership"), None)
        if not priv:
            return ""
        unowned = [f for f in priv["findings"] if not f["owners"]]
        unowned_rows = "" if serve_mode else "\n".join(legacy_unowned_rows_html(unowned)[0])
        if serve_tables is not None:
            serve_tables["unowned-table"] = {"findings": unowned, "rows": legacy_unowned_rows_html,
                                             "search": unowned_search_text,
                                             "sort_keys": UNOWNED_SORT_KEYS, "colspan": 8}
        unowned_pager = serve_pager() if serve_mode else ""
        return f"""
  <section data-category="apps">
    <h2>Privileged applications / service principals with no recorded owner</h2>
    <div class="table-scroll">
    <table id="unowned-table" class="findings" data-serve="1">
      <colgroup>
        <col style="width:44px">
        <col style="width:110px"><col style="width:220px"><col style="width:70px"><col style="width:60px"><col style="width:160px"><col style="width:260px"><col style="width:110px">
      </colgroup>
      <thead>
        <tr>
          <th class="no-sort"></th>
          <th data-type="text">Privileges</th>
          <th data-type="text">Application</th>
          <th data-type="text">Passwords</th>
          <th data-type="text">Keys</th>
          <th data-type="text">Resource</th>
          <th data-type="text">Permission</th>
          <th data-type="text">SP Status</th>
        </tr>
      </thead>
      <tbody>{unowned_rows}</tbody>
    </table>
    </div>
    {unowned_pager}
    {'<div class="empty">No unowned privileged applications found.</div>' if not unowned else ''}
  </section>
""" + azure_roles_section(
        "Azure Roles (service principals)", "azure-roles-apps", "apps", "Application / SP",
        az_rows_for(graph["az_sp_roles"], "sp",
                    lambda oid: ((graph["sp"].get(oid) or {}).get("displayName")
                                 or (oid if oid in graph["sp"] else None))),
        "azSpRoles")

    # ---- generic findings sections ---------------------------------------
    def generic_section(res):
        tid = f"table-{res['id']}"
        rows_html = "" if serve_mode else "\n".join(generic_rows_html(res["findings"])[0])
        if serve_tables is not None:
            serve_tables[tid] = {"findings": res["findings"], "rows": generic_rows_html,
                                 "search": generic_search_text,
                                 "sort_keys": GENERIC_SORT_KEYS, "colspan": 9}
        pager = serve_pager() if serve_mode else ""
        return f"""
  <section data-category="{esc(res["category"])}">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="{esc(tid)}" class="findings" data-serve="1">
      <colgroup>
        <col style="width:44px">
        <col style="width:110px"><col style="width:200px"><col style="width:120px">
        <col style="width:170px"><col style="width:70px"><col style="width:60px"><col style="width:90px"><col style="width:110px">
      </colgroup>
      <thead>
        <tr>
          <th class="no-sort"></th>
          <th data-type="text">Privileges</th>
          <th data-type="text">Target</th>
          <th data-type="text">Target Type</th>
          <th data-type="text">Object ID</th>
          <th data-type="text">Passwords</th>
          <th data-type="text">Keys</th>
          <th data-type="text">Role assignment</th>
          <th data-type="text">Status</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    # ---- conditional-access policies section ----------------------------------
    def ca_section(res):
        rows = []
        for f in res["findings"]:
            key = f"row-{len(rows)}"
            ch = f.get("conditions_html") or {}
            inc_titles = "\n".join(f.get("included", []))
            exc_titles = "\n".join(f.get("excluded", []))
            apps = ", ".join(ch.get("apps") or []) or "—"
            controls = ", ".join(ch.get("controls") or []) or "—"
            rows.append(f"""
        <tr data-policy-id="{esc(f.get("policy_id", ""))}" data-detail-key="{key}">
          <td class="expand-cell">{EXPAND_BUTTON}</td>
          <td data-field="severity" data-value="{esc(f["severity"])}">{severity_badge(f["severity"])}</td>
          <td class="clickable" data-field="polName" data-value="{esc(f.get("policy_name", ""))}">{esc(f.get("policy_name", ""))}</td>
          <td data-field="polState" data-value="{esc(f.get("state", ""))}">{status_cell(f.get("status"))}</td>
          <td data-field="polScope" data-value="{esc(f.get("scope", ""))}">{esc(f.get("scope", ""))}</td>
          <td data-field="polApps" data-value="{esc(apps)}"><span class="perm" title="{esc(", ".join(ch.get("apps") or []))}">{esc(apps)}</span></td>
          <td data-field="polControls" data-value="{esc(controls)}"><span class="perm" title="{esc(", ".join(ch.get("controls") or []))}">{esc(controls)}</span></td>
          <td data-field="polInc" data-value="{esc(str(len(f.get('included', []))))}"><span class="perm" title="{esc(inc_titles)}">{len(f.get('included', []))}</span></td>
          <td data-field="polExc" data-value="{esc(str(len(f.get('excluded', []))))}"><span class="perm" title="{esc(exc_titles)}">{len(f.get('excluded', []))}</span></td>
        </tr>{drawer_for(key, 9)}""")
        return f"""
  <section data-category="configs">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="table-ca_exposure" class="findings">
      <colgroup>
        <col style="width:44px">
        <col style="width:90px"><col style="width:220px"><col style="width:90px"><col style="width:130px">
        <col style="width:130px"><col style="width:110px"><col style="width:90px"><col style="width:90px">
      </colgroup>
      <thead>
        <tr>
          <th class="no-sort"></th>
          <th data-type="text">Privileges</th>
          <th data-type="text">Policy</th>
          <th data-type="text">State</th>
          <th data-type="text">Scope</th>
          <th data-type="text">Apps</th>
          <th data-type="text">Controls</th>
          <th data-type="text">Included</th>
          <th data-type="text">Excluded</th>
        </tr>
      </thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    </div>
  </section>
"""

    # ---- groups section ----------------------------------------
    def groups_section(res):
        rows_html = "" if serve_mode else "\n".join(group_rows_html(res["findings"])[0])
        if serve_tables is not None:
            serve_tables["groups-table"] = {"findings": res["findings"], "rows": group_rows_html,
                                            "search": group_search_text,
                                            "sort_keys": GROUP_SORT_KEYS, "colspan": 9}
        pager = serve_pager() if serve_mode else ""
        return f"""
  <section data-category="groups">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="groups-table" class="findings" data-serve="1">
      <colgroup>
        <col style="width:44px">
        <col style="width:100px"><col style="width:220px"><col style="width:180px"><col style="width:200px">
        <col style="width:70px"><col style="width:70px"><col style="width:80px"><col style="width:110px">
      </colgroup>
      <thead>
        <tr>
          <th class="no-sort"></th>
          <th data-type="text">Privileges</th>
          <th data-type="text">Group</th>
          <th data-type="text">Type</th>
          <th data-type="text">Directory roles</th>
          <th data-type="text">Eligible</th>
          <th data-type="text">Members</th>
          <th data-type="text">Priv. members</th>
          <th data-type="text">Owners</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
""" + azure_roles_section(
        "Azure Roles (groups)", "azure-roles-groups", "groups", "Group",
        az_rows_for(graph["az_roles"], "group",
                    lambda gid: ((graph["group"].get(gid) or {}).get("displayName")
                                 or (gid if gid in graph["group"] else None))),
        "azRoles")

    def dynamic_groups_table(res):
        dyn = [f for f in res["findings"] if f.get("dyn_rule")]
        if not dyn:
            return ""
        rows_html = "" if serve_mode else "\n".join(dynamic_rows_html(dyn)[0])
        if serve_tables is not None:
            serve_tables["dynamic-groups-table"] = {"findings": dyn, "rows": dynamic_rows_html,
                                                    "search": dynamic_search_text,
                                                    "sort_keys": DYNAMIC_SORT_KEYS, "colspan": 5}
        pager = serve_pager() if serve_mode else ""
        return f"""
  <section data-category="groups">
    <h2>Dynamic membership groups ({len(dyn)})</h2>
    <div class="table-scroll">
    <table id="dynamic-groups-table" class="findings" data-serve="1">
      <colgroup>
        <col style="width:44px">
        <col style="width:220px"><col style="width:280px"><col style="width:220px"><col style="width:340px">
      </colgroup>
      <thead>
        <tr>
          <th class="no-sort"></th>
          <th data-type="text">Group</th>
          <th data-type="text">Membership rule</th>
          <th data-type="text">Referenced attributes</th>
          <th data-type="text">attribute modifiable by</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    def users_section(res):
        if serve_tables is not None:
            serve_tables["privileged-users-table"] = {
                "findings": res["findings"], "rows": user_rows_html,
                "search": user_search_text, "sort_keys": USER_SORT_KEYS, "colspan": 12}
        rows = "" if serve_mode else "".join(user_rows_html(res["findings"])[0])
        pager = serve_pager() if serve_mode else ""
        return f"""
  <section data-category="users">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="privileged-users-table" class="findings" data-serve="1">
      <colgroup>
        <col style="width:44px">
        <col style="width:90px"><col style="width:170px"><col style="width:190px"><col style="width:200px">
        <col style="width:70px"><col style="width:70px"><col style="width:70px"><col style="width:70px"><col style="width:70px"><col style="width:90px"><col style="width:80px">
      </colgroup>
      <thead>
        <tr>
          <th class="no-sort"></th>
          <th data-type="text">Privileges</th>
          <th data-type="text">User</th>
          <th data-type="text">UPN</th>
          <th data-type="text">Directory roles</th>
          <th data-type="text">Eligible</th>
          <th data-type="text">Priv apps</th>
          <th data-type="text">Capable grp</th>
          <th data-type="text">Groups owned</th>
          <th data-type="text">CA excl.</th>
          <th data-type="text">Account Source</th>
          <th data-type="text">Status</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    </div>
    {pager}
  </section>
""" + azure_roles_section(
        "Azure Roles (users)", "azure-roles-users", "users", "User",
        az_rows_for(graph["az_user_roles"], "user",
                    lambda uid: (lambda u: ((u.get("userPrincipalName")
                                             or u.get("displayName") or uid) if u else None))(
                        graph["user"].get(uid))),
        "azUsrRoles")

    # ---- app directory roles section --------------------------------------
    def app_dir_roles_section(res):
        rows_html = "" if serve_mode else "\n".join(app_dir_rows_html(res["findings"])[0])
        if serve_tables is not None:
            serve_tables["app-dir-roles-table"] = {"findings": res["findings"], "rows": app_dir_rows_html,
                                                   "search": app_dir_search_text,
                                                   "sort_keys": APP_DIR_SORT_KEYS, "colspan": 6}
        pager = serve_pager() if serve_mode else ""
        return f"""
  <section data-category="apps">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="app-dir-roles-table" class="findings" data-serve="1">
      <colgroup>
        <col style="width:44px">
        <col style="width:90px"><col style="width:200px"><col style="width:220px">
        <col style="width:260px"><col style="width:90px">
      </colgroup>
      <thead>
        <tr>
          <th class="no-sort"></th>
          <th data-type="text">Privileges</th>
          <th data-type="text">Application</th>
          <th data-type="text">Object ID</th>
          <th data-type="text">Directory roles</th>
          <th data-type="text">Status</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    # ---- ad_sync_engine assessment card --------------------------------------
    def ad_summary_card(res):
        f = res["findings"][0]
        verdict = f.get("verdict") or "Undetermined"
        hosts = f.get("connector_host") or []
        wb = f.get("writeback") or {}
        sso = f.get("desktop_sso") or {}
        indicators = {i["label"]: i for i in (f.get("indicators") or [])}

        def v(label):
            i = indicators.get(label)
            return i["detail"] if i else ""

        rows = []
        rows.append(f"<tr><th>Engine</th><td><b>{esc(verdict)}</b></td></tr>")
        if hosts:
            rows.append(f'<tr><th>Connector host</th><td class="mono">{esc(", ".join(hosts))}</td></tr>')
        if wb.get("count"):
            detail = f"Enabled \u2014 {wb['count']} role assignment(s) on {', '.join(wb['resources'])}"
            rows.append(f"<tr><th>Password writeback</th><td>{esc(detail)}</td></tr>")
        if sso.get("enabled"):
            bits = [" \u00b7 ".join(sso.get("domains") or ["unknown realm"])]
            if sso.get("spns"):
                bits.append("new SPNs auto-added")
            rows.append(f"<tr><th>Desktop SSO</th><td>{esc(bits[0])}"
                        + (f' <span class="muted">({esc(bits[1])})</span>' if len(bits) > 1 else "") + "</td></tr>")
        sync_detail = v("Synchronized users")
        if f.get("sync_count"):
            imm = f.get("immutable_count", 0)
            if imm >= f["sync_count"]:
                label = f"{f['sync_count']} users, all with immutableId"
            else:
                label = f"{f['sync_count']} users ({imm} with immutableId)"
            rows.append(f"<tr><th>Synced users</th><td>{esc(label)}</td></tr>")
        adsync = v("ADSync* system groups")
        if adsync and not adsync.startswith("none"):
            rows.append(f"<tr><th>Sync groups</th><td>{esc(adsync)}</td></tr>")
        sps = []
        conn = v("Entra Connect connector app")
        if conn and not conn.startswith("none"):
            sps.append(conn.split(" \u2014 ")[0])
        fabric = v("SyncFabric sync identity")
        if fabric and fabric != "not observed":
            sps.append(fabric)
        if v("Office365 directory sync app") == "present":
            sps.append("Office365DirectorySynchronizationService")
        if sps:
            rows.append(f'<tr><th>Sync service principals</th><td>{esc(" \u00b7 ".join(sorted(set(sps))))}</td></tr>')
        cloud = v("Cloud-sync-specific markers")
        if cloud:
            rows.append(f"<tr><th>Cloud-sync markers</th><td>{esc(cloud)}</td></tr>")

        return f"""
  <section data-category="ad">
    <h2>{esc(res["title"])} {severity_badge(f["severity"])}</h2>
    <div class="engine-card">
      <table class="kv-table">{''.join(rows)}</table>
    </div>
  </section>
"""

    # ---- ad_sync_users section (realm card + flag roster) -----------------
    def ad_users_section(res):
        realm_html = realm_card_html(res.get("meta") or {})

        rows_html = "" if serve_mode else "\n".join(ad_rows_html(res["findings"])[0])
        if serve_tables is not None:
            serve_tables["ad-sync-users-table"] = {"findings": res["findings"], "rows": ad_rows_html,
                                                   "search": ad_search_text,
                                                   "sort_keys": AD_SORT_KEYS, "colspan": 10}
        pager = serve_pager() if serve_mode else ""
        return f"""
  <section data-category="ad">
    <h2>{esc(res["title"])}</h2>
    {realm_html}
    <div class="table-scroll">
    <table id="ad-sync-users-table" class="findings" data-serve="1">
      <colgroup>
        <col style="width:44px">
        <col style="width:180px"><col style="width:200px"><col style="width:140px"><col style="width:200px">
        <col style="width:100px"><col style="width:120px"><col style="width:150px"><col style="width:90px"><col style="width:80px">
      </colgroup>
      <thead>
        <tr>
          <th class="no-sort"></th>
          <th data-type="text">User</th>
          <th data-type="text">UPN</th>
          <th data-type="text">AD CN</th>
          <th data-type="text">AD DN</th>
          <th data-type="text">SID</th>
          <th data-type="text">On-prem pw change</th>
          <th data-type="text">Targeting tags</th>
          <th data-type="text">CA excl.</th>
          <th data-type="text">Status</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
""" + azure_roles_section(
        "Azure Roles (synced users)", "azure-roles-ad", "ad", "User",
        az_rows_for(
            {uid: roles for uid, roles in graph["az_user_roles"].items()
             if (graph["user"].get(uid) or {}).get("dirSyncEnabled") in (1, True)},
            "user",
            lambda uid: (lambda u: ((u.get("userPrincipalName")
                                     or u.get("displayName") or uid) if u else None))(
                graph["user"].get(uid))),
        "azUsrRoles")

    sections_html = []
    user_profile_data = {}
    group_profile_data = {}
    policy_profile_data = {}
    for res in results:
        if res["id"] == "priv_app_ownership":
            owned_html = legacy_owned_section()
            if owned_html:
                sections_html.append(owned_html)
            # 'Directory roles assigned to applications' renders as the
            # second table, right after the ownership table
            app_dir = next((r for r in results if r["id"] == "app_dir_roles"), None)
            if app_dir:
                sections_html.append(app_dir_roles_section(app_dir))
            unowned_html = legacy_unowned_section()
            if unowned_html:
                sections_html.append(unowned_html)
        elif res["id"] == "app_dir_roles":
            pass  # already rendered after the first table above
        elif res["id"] == "privileged_users":
            sections_html.append(users_section(res))
            if not serve_mode:
                user_profile_data = {f["user_id"]: f for f in res["findings"]}
        elif res["id"] == "app_dir_roles":
            sections_html.append(app_dir_roles_section(res))
        elif res["id"] == "groups":
            sections_html.append(groups_section(res))
            dyn_html = dynamic_groups_table(res)
            if dyn_html:
                sections_html.append(dyn_html)
            if not serve_mode:
                group_profile_data = {f["group_id"]: f for f in res["findings"]}
        elif res["id"] == "ca_exposure":
            sections_html.append(ca_section(res))
            if not serve_mode:
                policy_profile_data = {f["policy_id"]: f for f in res["findings"] if f.get("policy_id")}
        elif res["id"] == "ad_sync_summary":
            sections_html.append(ad_summary_card(res))
        elif res["id"] == "ad_sync_users":
            sections_html.append(ad_users_section(res))
        else:
            sections_html.append(generic_section(res))
    user_profile_json = json.dumps(user_profile_data, default=str).replace("</", "<\\/")
    group_profile_json = json.dumps(group_profile_data, default=str).replace("</", "<\\/")
    policy_profile_json = json.dumps(policy_profile_data, default=str).replace("</", "<\\/")
    # directory role -> service principals holding it (drilldown 'Applications' tab);
    # small index, embedded in serve mode too
    role_apps_json = json.dumps(
        build_role_applications(graph, group_roles, group_eligible_roles),
        default=str).replace("</", "<\\/")
    # distinct values per field for advanced-filter autocomplete (capped)
    SUGGEST_VALUE_FIELDS = {
        "severity", "category", "check", "roles", "eligible", "grproles",
        "dynmods", "dynattrs", "adtags", "targettype", "status", "hybrid",
        "userstatus", "spstatus", "ownerstatus", "adstatus", "polstate",
        "resource", "permission",
    }
    suggest_data = {}

    def _suggest_add(field, value):
        value = (value or "").strip()
        if not value:
            return
        bucket = suggest_data.setdefault(field, [])
        if value not in bucket and len(bucket) < 30:
            bucket.append(value)

    for res in results:
        for f in res["findings"]:
            for k, v in serve_field_map(_serve_table_id(res["id"]), f).items():
                if k.lower() in SUGGEST_VALUE_FIELDS:
                    for item in v.split(","):
                        _suggest_add(k.lower(), item)
            if res["id"] == "groups" and f.get("dyn_rule"):
                for k, v in serve_field_map("dynamic-groups-table", f).items():
                    if k.lower() in SUGGEST_VALUE_FIELDS:
                        for item in v.split(","):
                            _suggest_add(k.lower(), item)
    for sev in SEVERITY_ORDER:
        _suggest_add("severity", sev)
    for spec in CHECK_SPECS:
        _suggest_add("check", spec["id"])
    suggest_json = json.dumps(suggest_data, default=str).replace("</", "<\\/")

    # ---- tabs ------------------------------------------------------------
    tabs_html = ['<button type="button" class="tab-btn active" data-category="all">All</button>']
    for cat in CATEGORY_ORDER:
        count = category_counts.get(cat, 0)
        if count:
            tabs_html.append(
                f'<button type="button" class="tab-btn" data-category="{cat}">'
                f'{esc(CATEGORY_LABELS.get(cat, cat))} <span class="tab-count">{count}</span></button>')
    tabs_html = "\n      ".join(tabs_html)

    # ---- tenant summary bar (lean inline facts) ---------------------------
    ts = tenant_summary or {}
    bar = []
    def item(label, value_html, title=""):
        t = f' title="{esc(title)}"' if title else ""
        return f'<span class="sum-item"{t}><span class="sum-label">{esc(label)}</span>{value_html}</span>'

    bar.append(item("Tenant", f"<b>{esc(ts.get('tenant') or 'Unknown')}</b>"))
    if ts.get("tenant_id"):
        tid = ts["tenant_id"]
        bar.append(item("Tenant ID", f'<span class="mono">{esc(tid)}</span>'))
    if ts.get("domains"):
        dlist = ts["domains"]
        default = dlist[0]
        if len(dlist) > 1:
            dom_html = f'<span class="mono">{esc(default)}</span> <span class="muted">(+{len(dlist) - 1})</span>'
        else:
            dom_html = f'<span class="mono">{esc(default)}</span>'
        bar.append(item("Domains", dom_html, ", ".join(dlist)))
    if ts.get("realm"):
        sid_title = ts.get("sid_prefix", "").rstrip("-") + "-x" if ts.get("sid_prefix") else ""
        bar.append(item("Realm", f'<span class="mono">{esc(ts["realm"])}</span>', sid_title))
    if ts.get("engine"):
        bar.append(item("Sync", f'<span class="mono">{esc(ts["engine"])}</span>'))
    if ts.get("writeback") is True:
        bar.append('<span class="sum-item tag"><span class="sum-label">Writeback</span><span class="tag-chip tag-privileged">ON</span></span>')
    if "users" in ts:
        synced_note = f'<span class="muted">({ts.get("synced", "?")} synced)</span>' if "synced" in ts else ""
        bar.append(item("Users", f'{ts.get("users", 0)} {synced_note}'))
    count_labels = (("Apps / SPs", "apps", "sps"), ("Groups", "groups", None), ("Devices", "devices", None))
    for label, a_key, b_key in count_labels:
        if a_key in ts:
            value = str(ts.get(a_key, 0))
            if b_key and b_key in ts:
                value += f' / {ts.get(b_key, 0)}'
            bar.append(item(label, value))
    summary_bar_html = "\n    ".join(bar)

    entity_details_json = json.dumps(entity_details, default=str).replace("</", "<\\/")
    entity_profiles_json = json.dumps(entity_profiles or {"sp": {}, "app": {}}, default=str).replace("</", "<\\/")

    return f"""<!doctype html>
<html lang="en">
<head>
    <script>window.REPORT_SERVE = {str(serve_mode).lower()};</script>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra ID Surface{" - " + esc(tenant_name) if tenant_name else ""}</title>
<style>
  :root {{
    color-scheme: light;
    --surface-1:      #fcfcfb;
    --page-plane:     #f9f9f7;
    --text-primary:   #0b0b0b;
    --text-secondary: #46453f;
    --text-muted:     #6b6961;
    --gridline:       #e1e0d9;
    --border:         rgba(11,11,11,0.10);
    --status-critical:#a23731;
    --status-serious: #b95c26;
    --status-medium:  #8a7a1f;
    --status-low:     #4a659e;
    --status-good:    #22703f;
    --row-hover:      #e8e6df;
    --accent:         #2f63a8;
  }}
  @media (prefers-color-scheme: dark) {{
    :root:where(:not([data-theme="light"])) {{
      color-scheme: dark;
      --surface-1:      #232321;
      --page-plane:     #181816;
      --text-primary:   #ffffff;
      --text-secondary: #d2d1c6;
      --text-muted:     #9d9b91;
      --gridline:       #3a3a36;
      --border:         rgba(255,255,255,0.13);
      --status-critical:#b3443f;
      --status-serious: #cf7a54;
      --status-medium:  #ab9536;
      --status-low:     #617fbb;
      --status-good:    #2e8b57;
      --row-hover:      #2d2d2a;
      --accent:         #7fa7e0;
    }}
  }}
  :root[data-theme="dark"] {{
    color-scheme: dark;
    --surface-1:      #232321;
    --page-plane:     #181816;
    --text-primary:   #ffffff;
    --text-secondary: #d2d1c6;
    --text-muted:     #9d9b91;
    --gridline:       #3a3a36;
    --border:         rgba(255,255,255,0.13);
    --status-critical:#b3443f;
    --status-serious: #cf7a54;
    --status-medium:  #ab9536;
    --status-low:     #617fbb;
    --status-good:    #2e8b57;
    --row-hover:      #2d2d2a;
    --accent:         #7fa7e0;
  }}
  * {{ box-sizing: border-box; }}
  html {{ background: var(--page-plane); }}
  body {{
    margin: 0;
    background: var(--page-plane);
    color: var(--text-primary);
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  }}
  .wrap {{ max-width: 1400px; margin: 0 auto; padding: 36px 28px 72px; }}
  header {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }}
  header h1 {{ font-size: 22px; margin: 0 0 4px; }}
  header p {{ margin: 0; color: var(--text-secondary); font-size: 13px; }}
  .theme-toggle {{
    display: flex; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; flex: none;
  }}
  .theme-toggle button {{
    background: var(--surface-1); color: var(--text-secondary); border: none;
    padding: 7px 14px; font-size: 13px; font-family: inherit; cursor: pointer;
  }}
  .theme-toggle button + button {{ border-left: 1px solid var(--border); }}
  .theme-toggle button:hover {{ color: var(--text-primary); }}
  .theme-toggle button[aria-pressed="true"] {{ background: var(--row-hover); color: var(--text-primary); font-weight: 600; }}
  .summary-bar {{
    display: flex; flex-wrap: wrap; gap: 6px 20px; align-items: baseline;
    margin: 14px 0 6px; font-size: 12px; color: var(--text-secondary);
  }}
  .summary-bar .sum-item {{ white-space: nowrap; }}
  .summary-bar .sum-label {{
    color: var(--text-muted); font-size: 10px; text-transform: uppercase;
    letter-spacing: 0.02em; margin-right: 5px;
  }}
  .summary-bar .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px; color: var(--text-primary); }}
  .tabs {{ display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin: 20px 0 6px; }}
  .tab-btn {{
    background: var(--surface-1); color: var(--text-secondary);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 7px 14px; font-size: 13px; font-family: inherit; cursor: pointer;
  }}
  .tab-btn.active {{ background: color-mix(in srgb, var(--accent) 12%, transparent); color: var(--accent); font-weight: 600; border-color: color-mix(in srgb, var(--accent) 35%, transparent); }}
  .tab-btn .tab-count {{ color: var(--text-muted); font-size: 11px; margin-left: 5px; }}
  .controls {{
    display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
    margin: 10px 0 12px;
  }}
  .controls .filter-row {{
    display: flex; flex: 1; gap: 8px; align-items: center; position: relative; min-width: 260px;
  }}
  .controls input, .controls select {{
    background: var(--surface-1);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 7px 10px;
    font-size: 13px;
  }}
  .controls input[type="search"] {{ flex: 1; min-width: 220px; }}
  .mode-btn {{
    background: var(--surface-1); color: var(--text-secondary);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 7px 12px; font-size: 13px; cursor: pointer; white-space: nowrap;
  }}
  .mode-btn:hover {{ color: var(--text-primary); }}
  .mode-btn[aria-pressed="true"] {{
    background: color-mix(in srgb, var(--accent) 12%, transparent); color: var(--accent);
    border-color: color-mix(in srgb, var(--accent) 35%, transparent); font-weight: 600;
  }}
  .suggest-wrap {{
    position: absolute; top: calc(100% + 4px); left: 0; width: 100%; z-index: 40;
    background: var(--surface-1); border: 1px solid var(--border); border-radius: 8px;
    box-shadow: 0 10px 28px rgba(0,0,0,0.16); overflow: hidden;
  }}
  .suggest-wrap ul {{ list-style: none; margin: 0; padding: 4px 0; max-height: 240px; overflow-y: auto; }}
  .suggest-wrap li {{
    padding: 6px 12px; font-size: 13px; cursor: pointer;
  }}
  .suggest-wrap li.active {{ background: var(--row-hover); color: var(--accent); }}
  .suggest-wrap li .sugg-hint {{ color: var(--text-muted); font-size: 11px; margin-left: 8px; }}
  .filter-error {{
    width: 100%; color: var(--status-critical); font-size: 12px; margin-top: 4px;
  }}
  th.col-drag-source {{ opacity: 0.45; }}
  body.col-dragging {{ cursor: grabbing; user-select: none; }}
  body.col-dragging th {{ cursor: grabbing; }}
  th.col-drop-target {{ outline: 2px dashed var(--accent); outline-offset: -3px; }}
  section {{ margin-top: 32px; }}
  section[data-category] {{ margin-top: 26px; }}
  section.hidden {{ display: none; }}
  .hidden {{ display: none; }}
  section h2 {{ font-size: 15px; font-weight: 600; margin: 0 0 4px; }}
  section .sub {{ color: var(--text-secondary); font-size: 12px; margin: 0 0 10px; }}
  .table-scroll {{
    overflow-x: auto;
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: 8px;
  }}
  .pager {{ margin: 10px 0; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }}
  .pager button:disabled {{ opacity: 0.4; cursor: default; }}
  .pager select {{ background: var(--surface-1); color: var(--text-primary); border: 1px solid var(--border); border-radius: 6px; padding: 3px 6px; }}
  table {{ border-collapse: collapse; font-size: 13px; table-layout: fixed; }}
  table.findings {{ width: 100%; }}
  thead th {{
    position: relative;
    text-align: left; padding: 11px 16px 11px 14px; color: var(--text-muted);
    font-weight: 500; font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.02em;
    border-bottom: 1px solid var(--gridline); cursor: pointer; user-select: none;
    overflow-wrap: anywhere;
  }}
  thead th:hover {{ color: var(--text-primary); }}
  thead th.sorted::after {{ content: " \\2195"; }}
  .col-resizer {{
    position: absolute; top: 0; right: 0; width: 8px; height: 100%; cursor: col-resize; z-index: 1;
  }}
  .col-resizer:hover, .col-resizer.resizing {{ background: var(--border); }}
  tbody td {{ padding: 11px 14px; border-bottom: 1px solid var(--gridline); vertical-align: top; overflow-wrap: anywhere; }}
  tbody tr:hover {{ background: var(--row-hover); }}
  tbody tr.hidden {{ display: none; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px; color: var(--text-secondary); overflow-wrap: anywhere; }}
  .muted {{ color: var(--text-muted); font-size: 12px; }}
  .badge {{
    display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 600;
    border: 1px solid transparent;
  }}
  .sev-critical {{ color: var(--status-critical); background: color-mix(in srgb, var(--status-critical) 16%, transparent); }}
  .sev-high {{ color: var(--status-serious); background: color-mix(in srgb, var(--status-serious) 16%, transparent); }}
  .sev-medium {{ color: var(--status-medium); background: color-mix(in srgb, var(--status-medium) 16%, transparent); }}
  .sev-low {{ color: var(--status-low); background: color-mix(in srgb, var(--status-low) 14%, transparent); }}
  .sev-info {{ color: var(--text-muted); border-color: var(--border); background: transparent; }}
  .role-badge {{ cursor: pointer; }}
  .filter-tag {{ cursor: pointer; }}
  .filter-tag:hover {{ background: var(--row-hover); color: var(--text-primary); }}
  .role-badge:hover {{ background: var(--row-hover); color: var(--text-primary); }}
  .badge-enabled {{ color: var(--status-good); border-color: color-mix(in srgb, var(--status-good) 45%, transparent); }}
  .badge-disabled {{ color: var(--text-muted); border-color: var(--border); }}
  .badge-guest {{ color: var(--status-serious); border-color: color-mix(in srgb, var(--status-serious) 45%, transparent); }}
  .badge-hybrid {{ color: var(--text-muted); border-color: var(--border); }}
  .tag-chip {{
    display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600;
    border: 1px solid var(--border); color: var(--text-secondary);
  }}
  .tag-privileged {{ color: var(--status-serious); border-color: color-mix(in srgb, var(--status-serious) 45%, transparent); }}
  .tag-spray {{ color: var(--status-medium); border-color: color-mix(in srgb, var(--status-medium) 45%, transparent); }}
  .tag-divergence {{ color: var(--status-low); border-color: color-mix(in srgb, var(--status-low) 45%, transparent); }}
  .realm {{ margin: 8px 0 10px; color: var(--text-secondary); font-size: 12px; }}
  .realm b {{ color: var(--text-primary); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px; }}
  details.inline-more {{ display: inline; }}
  details.inline-more summary {{ display: inline; cursor: pointer; color: var(--accent); }}
  details.inline-more > span {{ display: inline; }}
  .engine-card {{
    border: 1px solid var(--border); border-radius: 10px; padding: 14px 18px;
    background: var(--surface-1); margin: 4px 0 6px;
  }}
  .engine-card .kv-table {{ width: 100%; }}
  .perm {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; border-bottom: 1px dotted var(--text-muted); cursor: default; overflow-wrap: anywhere; }}
  .az-count {{ display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; border: 1px solid var(--border); color: var(--text-primary); background: var(--surface-1); margin-right: 4px; vertical-align: 1px; }}
  td.clickable {{ cursor: pointer; }}
  td.clickable:hover {{ text-decoration: none; color: var(--text-primary); background: var(--row-hover); }}
  thead th.no-sort {{ cursor: default; }}
  thead th.no-sort:hover {{ color: var(--text-secondary); }}
  td.expand-cell {{ text-align: center; }}
  .expand-btn {{
    width: 24px; height: 24px; padding: 0; font-size: 14px; font-weight: 600;
    display: inline-flex; align-items: center; justify-content: center;
  }}
  .empty {{ padding: 24px; text-align: center; color: var(--text-muted); }}
  .overlay {{
    position: fixed; inset: 0; background: rgba(0,0,0,0.45);
    display: flex; align-items: center; justify-content: center; padding: 24px; z-index: 100;
  }}
  .overlay.hidden {{ display: none; }}
  .modal {{
    background: var(--surface-1); border: 1px solid var(--border); border-radius: 12px;
    width: 1100px; max-width: 95vw; height: 82vh; max-height: 95vh; min-width: 420px; min-height: 280px;
    display: flex; flex-direction: column;
    box-shadow: 0 20px 60px rgba(0,0,0,0.25);
    resize: both; overflow: auto;
  }}
  .modal-header {{
    display: flex; align-items: center; justify-content: space-between; gap: 12px;
    padding: 14px 18px; border-bottom: 1px solid var(--gridline); flex: none;
  }}
  .modal-header h3 {{ margin: 0; font-size: 15px; }}
  .modal-header .sub {{ color: var(--text-secondary); font-size: 12px; margin: 2px 0 0; }}
  .modal-body {{ padding: 14px 18px 18px; overflow: auto; }}
  .icon-btn {{
    background: none; border: 1px solid var(--border); color: var(--text-secondary);
    font-size: 16px; line-height: 1; cursor: pointer; padding: 5px 10px; border-radius: 6px; flex: none;
  }}
  .icon-btn:hover {{ background: var(--row-hover); color: var(--text-primary); }}
  #drilldown-table {{ table-layout: auto; width: 100%; }}
  #drilldown-table, #drilldown-apps-table {{ table-layout: auto; width: 100%; }}
  #drilldown-table th, #drilldown-table td {{ padding: 8px 12px; border-bottom: 1px solid var(--gridline); text-align: left; font-size: 13px; }}
  #drilldown-apps-table th, #drilldown-apps-table td {{ padding: 8px 12px; border-bottom: 1px solid var(--gridline); text-align: left; font-size: 13px; }}
  #drilldown-table th {{ color: var(--text-muted); font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.02em; white-space: nowrap; }}
  .detail-section {{ margin-bottom: 22px; }}
  .detail-section:last-child {{ margin-bottom: 0; }}
  .detail-section h4 {{ margin: 0 0 8px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.02em; color: var(--text-muted); }}
  .kv-table {{ width: 100%; border-collapse: collapse; }}
  .kv-table tr {{ border-bottom: 1px solid var(--gridline); }}
  .kv-table tr:last-child {{ border-bottom: none; }}
  .kv-table th {{
    text-align: left; vertical-align: top; width: 240px; padding: 6px 12px 6px 0;
    font-size: 12px; font-weight: 600; color: var(--text-secondary); white-space: nowrap;
  }}
  .kv-table td {{ padding: 6px 0; font-size: 12.5px; overflow-wrap: anywhere; vertical-align: top; }}
  .kv-table pre {{
    margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px;
    white-space: pre-wrap; overflow-wrap: anywhere; background: var(--page-plane);
    border: 1px solid var(--border); border-radius: 6px; padding: 8px; max-height: 240px; overflow: auto;
  }}
  .profile-list {{ margin: 0 0 10px; padding: 0 0 0 18px; font-size: 12.5px; }}
  .profile-list li {{ margin: 3px 0; overflow-wrap: anywhere; }}
  .profile-list ul {{ list-style: circle; padding-left: 14px; }}
  .drawer-tabs-wrap {{ margin: 0; }}
  .drawer-tabs {{ display: flex; flex-wrap: wrap; gap: 4px; margin: 0 0 12px; }}
  .drawer-tab {{
    background: none; border: 1px solid var(--border); border-radius: 6px;
    padding: 6px 12px; font-size: 12px; color: var(--text-secondary);
    font-family: inherit; cursor: pointer;
  }}
  .drawer-tab.active {{ background: color-mix(in srgb, var(--accent) 12%, transparent); color: var(--accent); font-weight: 600; border-color: color-mix(in srgb, var(--accent) 35%, transparent); }}
  .dtab-pane {{ display: none; }}
  .dtab-pane.active {{ display: block; }}
  .minor-table {{ width: 100%; border-collapse: collapse; font-size: 12px; margin: 4px 0 10px; }}
  .minor-table th {{
    text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--gridline);
    color: var(--text-muted); font-size: 10.5px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.02em;
  }}
  .minor-table td {{ padding: 6px 10px; border-bottom: 1px solid var(--gridline); overflow-wrap: anywhere; vertical-align: top; }}
  .dtab-sp-link, .app-link {{
    background: none; border: none; padding: 0; margin: 0;
    color: var(--accent); text-decoration: underline; cursor: pointer;
    font-family: inherit; font-size: 12px; text-align: left;
  }}
  .drawer-back-row {{ margin: 0 0 6px; }}
  tr.drawer {{ display: none; }}
  tr.drawer.open {{ display: table-row; }}
  tr.drawer td {{ padding: 8px 12px 12px; background: var(--page-plane); }}
  .drawer-body {{
    border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px;
    background: var(--surface-1);
  }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>Entra ID Attack Surface</h1>
    </div>
    <div class="theme-toggle" role="group" aria-label="Color theme">
      <button type="button" id="theme-light-btn" aria-pressed="false">Light</button>
      <button type="button" id="theme-dark-btn" aria-pressed="false">Dark</button>
    </div>
  </header>

  <div class="summary-bar">
    {summary_bar_html}
  </div>

  <div class="tabs" id="category-tabs" role="tablist">
      {tabs_html}
  </div>

  <div class="controls">
    <div class="filter-row">
      <input type="search" id="filter-input" placeholder="Filter all tables by target, owner, evidence&hellip;" autocomplete="off">
      <button type="button" id="advanced-toggle" class="mode-btn" aria-pressed="false" title="Toggle advanced filtering: field:value, AND, OR, NOT, contains:">Advanced</button>
      <div class="suggest-wrap hidden" id="suggest-wrap"><ul id="suggest-list"></ul></div>
    </div>
    <div class="filter-error hidden" id="filter-error"></div>
  </div>

  {''.join(sections_html)}

  {'<div class="empty">No findings meet the configured severity threshold. Try lowering --min-severity or enabling more checks.</div>' if not all_findings else ''}

</div>

<div class="overlay hidden" id="drilldown-overlay">
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="drilldown-title">
    <div class="modal-header">
      <div>
        <h3 id="drilldown-title"></h3>
        <p class="sub" id="drilldown-subtitle"></p>
      </div>
      <button type="button" class="icon-btn" id="drilldown-close" aria-label="Close">&times;</button>
    </div>
    <div class="modal-body">
      <div class="drawer-tabs hidden" id="drilldown-tabs"></div>
      <div class="table-scroll" id="drilldown-users-scroll">
        <table id="drilldown-table">
          <thead><tr id="drilldown-thead-row"></tr></thead>
          <tbody id="drilldown-tbody"></tbody>
        </table>
      </div>
      <div class="table-scroll hidden" id="drilldown-apps-scroll">
        <table id="drilldown-apps-table">
          <thead><tr id="drilldown-apps-thead"></tr></thead>
          <tbody id="drilldown-apps-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<script type="application/json" id="entity-details-data">{entity_details_json}</script>

<script type="application/json" id="user-profile-data">{user_profile_json}</script>

<script type="application/json" id="entity-profile-data">{entity_profiles_json}</script>

<script type="application/json" id="group-profile-data">{group_profile_json}</script>

<script type="application/json" id="suggest-data">{suggest_json}</script>

<script type="application/json" id="role-apps-data">{role_apps_json}</script>

<script type="application/json" id="policy-profile-data">{policy_profile_json}</script>

{JS_FILTER_MODULE}
<script>
(function() {{
  var root = document.documentElement;
  var lightBtn = document.getElementById('theme-light-btn');
  var darkBtn = document.getElementById('theme-dark-btn');

  function currentTheme() {{
    var attr = root.getAttribute('data-theme');
    if (attr === 'light' || attr === 'dark') return attr;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }}
  function updateThemeButtons() {{
    var active = currentTheme();
    lightBtn.setAttribute('aria-pressed', String(active === 'light'));
    darkBtn.setAttribute('aria-pressed', String(active === 'dark'));
  }}
  function setTheme(theme) {{
    root.setAttribute('data-theme', theme);
    try {{ localStorage.setItem('entra-audit-theme', theme); }} catch (e) {{}}
    updateThemeButtons();
  }}
  try {{
    var stored = localStorage.getItem('entra-audit-theme');
    if (stored === 'light' || stored === 'dark') root.setAttribute('data-theme', stored);
  }} catch (e) {{}}
  lightBtn.addEventListener('click', function() {{ setTheme('light'); }});
  darkBtn.addEventListener('click', function() {{ setTheme('dark'); }});
  updateThemeButtons();
}})();

(function() {{
  var tabsEl = document.getElementById('category-tabs');
  if (tabsEl) {{
    var btns = Array.prototype.slice.call(tabsEl.querySelectorAll('button[data-category]'));
    var sections = Array.prototype.slice.call(document.querySelectorAll('section[data-category]'));
    function apply(category) {{
      sections.forEach(function(s) {{
        s.classList.toggle('hidden', category !== 'all' && s.getAttribute('data-category') !== category);
      }});
      btns.forEach(function(b) {{
        b.classList.toggle('active', b.getAttribute('data-category') === category);
      }});
    }}
    btns.forEach(function(b) {{ b.addEventListener('click', function() {{ apply(b.getAttribute('data-category')); }}); }});
  }}
}})();

(function() {{
  function allTables() {{
    return Array.prototype.slice.call(document.querySelectorAll('table.findings'));
  }}
  var FIELD_LABELS = {{
    severity: 'Privileges', owner: 'Owner', ownerUpn: 'Owner UPN',
    ownerStatus: 'Owner Status', app: 'Application',
    resource: 'Resource', permission: 'Permission', spStatus: 'SP Status',
    target: 'Target', targetType: 'Target Type', id: 'Object ID', status: 'Target Status',
    pw: 'Passwords', keys: 'Keys', roleCount: 'Role assignment',
    userUpn: 'UPN', roles: 'Directory roles', eligible: 'Eligible roles',
    privApps: 'Privileged apps owned',
    capGroups: 'Role-capable group memberships', grpOwned: 'Groups owned',
    group: 'Group', grpType: 'Type', grpRoles: 'Directory roles',
    grpMembers: 'Members', grpPriv: 'Privileged members', grpOwners: 'Owners',
    polName: 'Policy', polState: 'State', polScope: 'Scope', polApps: 'Apps',
    polControls: 'Controls', polInc: 'Included users', polExc: 'Excluded users',
    dynGroup: 'Group', dynRule: 'Membership rule', dynAttrs: 'Referenced attributes',
    dynMods: 'attribute modifiable by',
    azRoles: 'Azure roles',
    azUsrRoles: 'Azure roles',
    azSpRoles: 'Azure roles',
    azApp: 'Application / SP', azUser: 'User', azGroup: 'Group',
    azScopeType: 'Scope Type', azSub: 'Subscription', azRg: 'Resource Group',
    azProvider: 'Provider', azResource: 'Resource'
  }};
  var DRILLDOWN_COLUMNS = {{
    owner:      ['app', 'resource', 'permission', 'severity', 'spStatus'],
    ownerUpn:   ['app', 'resource', 'permission', 'severity', 'spStatus'],
    app:        ['ownerUpn', 'resource', 'permission', 'severity', 'spStatus'],
    resource:   ['app', 'ownerUpn', 'permission', 'severity', 'spStatus'],
    permission: ['app', 'ownerUpn', 'resource', 'severity', 'spStatus'],
    target:     ['targetType', 'id', 'roleCount', 'pw', 'keys', 'severity', 'status'],
    roles:      ['userUpn', 'privApps', 'capGroups', 'grpOwned', 'severity'],
    eligible:   ['userUpn', 'group', 'severity'],
    group:      ['group', 'grpType', 'grpRoles', 'grpMembers', 'grpPriv', 'grpOwners', 'severity'],
    grpRoles:   ['group', 'grpMembers', 'grpPriv', 'severity'],
    polName:    ['polState', 'polScope', 'polApps', 'polControls', 'polInc', 'polExc', 'severity'],
    dynGroup:   ['dynRule', 'dynAttrs', 'dynMods'],
    dynAttrs:   ['dynGroup', 'dynRule', 'dynMods'],
    dynRule:    ['dynGroup', 'dynAttrs', 'dynMods'],
    dynMods:    ['dynGroup', 'dynRule', 'dynAttrs'],
    azRoles:    ['azGroup', 'azRoles', 'severity', 'azScopeType', 'azSub', 'azRg', 'azProvider', 'azResource'],
    azUsrRoles: ['azUser', 'azUsrRoles', 'severity', 'azScopeType', 'azSub', 'azRg', 'azProvider', 'azResource'],
    azSpRoles:  ['azApp', 'azSpRoles', 'severity', 'azScopeType', 'azSub', 'azRg', 'azProvider', 'azResource'],
    azGroup:    ['azGroup', 'azRoles', 'severity', 'azScopeType', 'azSub', 'azRg', 'azProvider', 'azResource'],
    azUser:     ['azUser', 'azUsrRoles', 'severity', 'azScopeType', 'azSub', 'azRg', 'azProvider', 'azResource'],
    azApp:      ['azApp', 'azSpRoles', 'severity', 'azScopeType', 'azSub', 'azRg', 'azProvider', 'azResource']
  }};

  function collectRecords() {{
    var records = [];
    allTables().forEach(function(table) {{
      Array.prototype.forEach.call(table.tBodies[0].rows, function(row) {{
        var rec = {{}};
        Array.prototype.forEach.call(row.cells, function(td) {{
          var field = td.getAttribute('data-field');
          if (field) rec[field] = td.getAttribute('data-value') || '';
        }});
        rec.__ids = {{
          sp: row.getAttribute('data-sp-id') || '',
          app: row.getAttribute('data-app-id') || '',
          owner: row.getAttribute('data-owner-id') || ''
        }};
        rec.__gid = row.getAttribute('data-group-id') || '';
        rec.__pid = row.getAttribute('data-policy-id') || '';
        rec.__check = row.getAttribute('data-check-id') || '';
        records.push(rec);
      }});
    }});
    return records;
  }}
  var allRecords = collectRecords();

  var overlay = document.getElementById('drilldown-overlay');
  var titleEl = document.getElementById('drilldown-title');
  var subtitleEl = document.getElementById('drilldown-subtitle');
  var theadRow = document.getElementById('drilldown-thead-row');
  var tbody = document.getElementById('drilldown-tbody');
  var tabsWrap = document.getElementById('drilldown-tabs');
  var usersScroll = document.getElementById('drilldown-users-scroll');
  var appsScroll = document.getElementById('drilldown-apps-scroll');
  var appsThead = document.getElementById('drilldown-apps-thead');
  var appsTbody = document.getElementById('drilldown-apps-tbody');

  var ROLE_APPS = {{}};
  try {{ ROLE_APPS = JSON.parse(document.getElementById('role-apps-data').textContent); }} catch (e) {{}}

  function closeDrilldown() {{
    overlay.classList.add('hidden');
    tabsWrap.classList.add('hidden');
    usersScroll.classList.remove('hidden');
    appsScroll.classList.add('hidden');
  }}

  var CONTAINS_FIELDS = {{ roles: true, eligible: true, grpRoles: true, dynMods: true, dynAttrs: true, azRoles: true, azUsrRoles: true, azSpRoles: true }};
  var SERVE_DRILLDOWN_FIELDS = {{
    owner: 1, ownerUpn: 1, ownerStatus: 1, app: 1, resource: 1, permission: 1,
    spStatus: 1, target: 1, targetType: 1, id: 1, roleCount: 1, pw: 1, keys: 1,
    status: 1, user: 1, userUpn: 1, roles: 1, eligible: 1, privApps: 1, capGroups: 1,
    grpOwned: 1, hybrid: 1, userStatus: 1, caExcl: 1, group: 1, grpType: 1,
    grpRoles: 1, grpMembers: 1, grpPriv: 1, grpOwners: 1, severity: 1,
    polName: 1, polState: 1, polScope: 1, polApps: 1, polControls: 1,
    polInc: 1, polExc: 1, dynGroup: 1, dynRule: 1, dynAttrs: 1, dynMods: 1,
    adUser: 1, adUpn: 1, adCn: 1, adDn: 1, adSid: 1, adPw: 1, adTags: 1, adStatus: 1
  }};

  function isRoleDrilldown(field) {{ return field === 'roles'; }}

  function openDrilldown(field, value) {{
    if (isRoleDrilldown(field)) {{ openRoleDrilldown(field, value); return; }}
    tabsWrap.classList.add('hidden');
    usersScroll.classList.remove('hidden');
    appsScroll.classList.add('hidden');
    if (window.REPORT_SERVE && SERVE_DRILLDOWN_FIELDS[field]) {{
      fetch('/api/drilldown?field=' + encodeURIComponent(field) + '&value=' + encodeURIComponent(value))
        .then(function(r) {{ return r.json(); }})
        .then(function(d) {{
          if (!d || d.rows_html == null) {{ fillUsersLocal(field, value); return; }}
          titleEl.textContent = d.title;
          subtitleEl.textContent = d.subtitle;
          theadRow.innerHTML = d.thead_html;
          tbody.innerHTML = d.rows_html;
          overlay.classList.remove('hidden');
        }})
        .catch(function() {{ fillUsersLocal(field, value); overlay.classList.remove('hidden'); }});
      return;
    }}
    titleEl.textContent = (FIELD_LABELS[field] || field) + ': ' + value;
    fillUsersLocal(field, value);
    overlay.classList.remove('hidden');
  }}

  function fillUsersLocal(field, value) {{
    var matches = allRecords.filter(function(r) {{
      var v = r[field] || '';
      if (CONTAINS_FIELDS[field]) {{
        return v.split(',').map(function(x) {{ return x.trim(); }}).indexOf(value) >= 0;
      }}
      return v === value;
    }});
    var columns = DRILLDOWN_COLUMNS[field] || Object.keys(FIELD_LABELS).filter(function(f) {{ return f !== field; }});

    subtitleEl.textContent = matches.length + (matches.length === 1 ? ' matching finding in the collected set' : ' matching findings in the collected set');

    theadRow.innerHTML = '';
    theadRow.appendChild(document.createElement('th'));
    columns.forEach(function(f) {{
      var th = document.createElement('th');
      th.textContent = FIELD_LABELS[f] || f;
      theadRow.appendChild(th);
    }});

    tbody.innerHTML = '';
    matches.forEach(function(r, rIdx) {{
      var tr = document.createElement('tr');
      tr.setAttribute('data-sp-id', r.__ids.sp);
      tr.setAttribute('data-app-id', r.__ids.app);
      tr.setAttribute('data-owner-id', r.__ids.owner);
      tr.setAttribute('data-group-id', r.__gid || '');
      tr.setAttribute('data-policy-id', r.__pid || '');
      tr.setAttribute('data-detail-key', 'dd-' + matches.length + '-' + rIdx);

      var expandTd = document.createElement('td');
      expandTd.className = 'expand-cell';
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'icon-btn expand-btn';
      btn.setAttribute('aria-label', 'View full details');
      btn.textContent = '+';
      expandTd.appendChild(btn);
      tr.appendChild(expandTd);

      columns.forEach(function(f) {{
        var td = document.createElement('td');
        var val = r[f];
        if (!val) val = (f === 'owner') ? '(no owner)' : '\\u2014';
        td.textContent = val;
        tr.appendChild(td);
      }});
      tbody.appendChild(tr);
      var tdr = document.createElement('tr');
      tdr.className = 'drawer';
      tdr.setAttribute('data-detail-for', tr.getAttribute('data-detail-key'));
      var tdc = document.createElement('td');
      tdc.colSpan = columns.length + 1;
      var tdb = document.createElement('div');
      tdb.className = 'drawer-body';
      tdc.appendChild(tdb);
      tdr.appendChild(tdc);
      tbody.appendChild(tdr);
    }});
  }}

  function fillAppsPane(role) {{
    var entries = ROLE_APPS[role] || [];
    appsTbody.innerHTML = '';
    appsThead.innerHTML = '';
    appsThead.appendChild(document.createElement('th'));
    ['Application', 'ObjectId', 'Assignment'].forEach(function(label) {{
      var th = document.createElement('th');
      th.textContent = label;
      appsThead.appendChild(th);
    }});
    if (!entries.length) {{
      var tr = document.createElement('tr');
      var td = document.createElement('td');
      td.colSpan = 4;
      td.className = 'muted';
      td.textContent = 'No service principals hold this directory role.';
      tr.appendChild(td);
      appsTbody.appendChild(tr);
      return;
    }}
    entries.forEach(function(a, i) {{
      var key = 'ra-' + i;
      var tr = document.createElement('tr');
      tr.setAttribute('data-sp-id', a.id);
      tr.setAttribute('data-detail-key', key);
      var expandTd = document.createElement('td');
      expandTd.className = 'expand-cell';
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'icon-btn expand-btn';
      btn.setAttribute('aria-label', 'View full details');
      btn.textContent = '+';
      expandTd.appendChild(btn);
      tr.appendChild(expandTd);
      var nameTd = document.createElement('td');
      nameTd.textContent = a.name;
      tr.appendChild(nameTd);
      var idTd = document.createElement('td');
      idTd.className = 'mono';
      idTd.textContent = a.id;
      tr.appendChild(idTd);
      var assignTd = document.createElement('td');
      assignTd.textContent = (a.eligible ? '(eligible) ' : '') + (a.path ? ('via ' + a.path.join(' \u2192 ')) : 'Direct');
      tr.appendChild(assignTd);
      appsTbody.appendChild(tr);
      var tdr = document.createElement('tr');
      tdr.className = 'drawer';
      tdr.setAttribute('data-detail-for', key);
      var tdc = document.createElement('td');
      tdc.colSpan = 4;
      var tdb = document.createElement('div');
      tdb.className = 'drawer-body';
      tdc.appendChild(tdb);
      tdr.appendChild(tdc);
      appsTbody.appendChild(tdr);
    }});
  }}

  function openRoleDrilldown(field, value) {{
    titleEl.textContent = (FIELD_LABELS[field] || field) + ': ' + value;
    tabsWrap.innerHTML = '';
    var mkTab = function(id, label, active) {{
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'drawer-tab' + (active ? ' active' : '');
      b.setAttribute('data-dtab', id);
      b.textContent = label;
      return b;
    }};
    var entries = ROLE_APPS[value] || [];
    tabsWrap.appendChild(mkTab('users', 'Users', true));
    tabsWrap.appendChild(mkTab('apps', 'Applications (' + entries.length + ')', false));
    tabsWrap.classList.remove('hidden');
    usersScroll.classList.remove('hidden');
    appsScroll.classList.add('hidden');
    fillAppsPane(value);
    if (window.REPORT_SERVE && SERVE_DRILLDOWN_FIELDS[field]) {{
      fetch('/api/drilldown?field=' + encodeURIComponent(field) + '&value=' + encodeURIComponent(value))
        .then(function(r) {{ return r.json(); }})
        .then(function(d) {{
          if (!d || d.rows_html == null) {{ fillUsersLocal(field, value); return; }}
          subtitleEl.textContent = d.subtitle;
          theadRow.innerHTML = d.thead_html;
          tbody.innerHTML = d.rows_html;
        }})
        .catch(function() {{ fillUsersLocal(field, value); }});
    }} else {{
      fillUsersLocal(field, value);
    }}
    overlay.classList.remove('hidden');
  }}

  tabsWrap.addEventListener('click', function(e) {{
    var b = e.target.closest('.drawer-tab');
    if (!b) return;
    var id = b.getAttribute('data-dtab');
    Array.prototype.forEach.call(tabsWrap.querySelectorAll('.drawer-tab'), function(x) {{
      x.classList.toggle('active', x === b);
    }});
    usersScroll.classList.toggle('hidden', id !== 'users');
    appsScroll.classList.toggle('hidden', id !== 'apps');
  }});

  document.addEventListener('click', function(e) {{
    var badge = e.target.closest('.role-badge');
    if (!badge) return;
    e.stopPropagation();
    openDrilldown(badge.getAttribute('data-role-field') || 'roles', badge.getAttribute('data-role') || '');
  }});
  document.addEventListener('click', function(e) {{
    var tag = e.target.closest('.filter-tag');
    if (!tag) return;
    e.stopPropagation();
    openDrilldown(tag.getAttribute('data-filter-field') || '', tag.getAttribute('data-filter-value') || '');
  }});

  document.getElementById('drilldown-close').addEventListener('click', closeDrilldown);
  overlay.addEventListener('click', function(e) {{ if (e.target === overlay) closeDrilldown(); }});
  document.addEventListener('keydown', function(e) {{ if (e.key === 'Escape') closeDrilldown(); }});

  allTables().forEach(function(table) {{
    table.tBodies[0].addEventListener('click', function(e) {{
      var cell = e.target.closest('td.clickable');
      if (!cell || !table.contains(cell)) return;
      var field = cell.getAttribute('data-field');
      var value = cell.getAttribute('data-value');
      if (!field || !value) return;
      openDrilldown(field, value);
    }});
  }});
}})();

(function() {{
  var MEMBER_CAP = 500;
  var DETAILS = {{ sp: {{}}, app: {{}}, user: {{}}, device: {{}} }};
  try {{ DETAILS = JSON.parse(document.getElementById('entity-details-data').textContent); }} catch (e) {{}}
  var PROFILES = {{}};
  try {{ PROFILES = JSON.parse(document.getElementById('user-profile-data').textContent); }} catch (e) {{}}
  var PROFILES2 = {{ sp: {{}}, app: {{}} }};
  try {{ PROFILES2 = JSON.parse(document.getElementById('entity-profile-data').textContent); }} catch (e) {{}}
  var GROUPS = {{}};
  try {{ GROUPS = JSON.parse(document.getElementById('group-profile-data').textContent); }} catch (e) {{}}
  var POLICIES = {{}};
  try {{ POLICIES = JSON.parse(document.getElementById('policy-profile-data').textContent); }} catch (e) {{}}

  function pEsc(s) {{
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }}
  function pSev(sev) {{
    var cls = {{ Critical: 'sev-critical', High: 'sev-high', Medium: 'sev-medium', Low: 'sev-low' }}[sev] || 'sev-info';
    return '<span class="badge ' + cls + '">' + pEsc(sev) + '</span>';
  }}
  function pSection(label, html) {{
    return '<div class="detail-section"><h4>' + pEsc(label) + '</h4>' + html + '</div>';
  }}
  function pList(items, render) {{
    if (!items || !items.length) return '<p class="muted">None.</p>';
    return '<ul class="profile-list">' + items.map(render).join('') + '</ul>';
  }}

  function minorTable(cols, rows) {{
    // cols: [[header, rowField], ...]
    if (!rows || !rows.length) return '';
    var head = '<tr>' + cols.map(function(c) {{ return '<th>' + pEsc(c[0]) + '</th>'; }}).join('') + '</tr>';
    var body = rows.map(function(r) {{
      return '<tr>' + cols.map(function(c) {{
        return '<td>' + pEsc(r[c[1]] || '') + '</td>';
      }}).join('') + '</tr>';
    }}).join('');
    return '<table class="minor-table"><thead>' + head + '</thead><tbody>' + body + '</tbody></table>';
  }}

  function azTableHtml(list, withSp) {{
    if (!list || !list.length) return '<p class="muted">No Azure (ARM) role assignments captured for this principal.</p>';
    var rows = list.map(function(a) {{
      var sub = (a.scope_sub_name || '') + (a.scope_sub ? ((a.scope_sub_name ? ' (' : '') + a.scope_sub + (a.scope_sub_name ? ')' : '')) : '');
      if (!sub) sub = a.scope_type === 'Management group' ? (a.scope_mgmt || '—') : '—';
      var rg = a.scope_type === 'Management group' ? (a.scope_mgmt || '—') : (a.scope_rg || '—');
      return {{
        role: pSev(a.severity || 'Info') + ' ' + pEsc(a.role + (a.eligible ? ' (eligible)' : '')),
        sp: pEsc(a.sp_name || '—'),
        stype: pEsc(a.scope_type || '—'),
        sub: pEsc(sub),
        rg: pEsc(rg),
        prov: pEsc(a.scope_provider || '—'),
        res: pEsc(a.scope_resource || '—')
      }};
    }});
    var cols = [['Role', 'role']];
    if (withSp) cols.push(['Service Principal', 'sp']);
    cols.push(['Scope Type', 'stype'], ['Subscription', 'sub'], ['Resource Group', 'rg'],
              ['Provider', 'prov'], ['Resource', 'res']);
    var head = '<tr>' + cols.map(function(c) {{ return '<th>' + pEsc(c[0]) + '</th>'; }}).join('') + '</tr>';
    var body = rows.map(function(r) {{
      return '<tr>' + cols.map(function(c) {{ return '<td>' + (r[c[1]] || '') + '</td>'; }}).join('') + '</tr>';
    }}).join('');
    return '<table class="minor-table"><thead>' + head + '</thead><tbody>' + body + '</tbody></table>';
  }}

  function rawValueHtml(v) {{
    if (v !== null && typeof v === 'object') return '<pre>' + pEsc(JSON.stringify(v, null, 2)) + '</pre>';
    return pEsc(String(v == null ? '' : v));
  }}

  function renderKVHtml(record) {{
    if (!record) return '';
    var rows = Object.keys(record).sort().map(function(k) {{
      return '<tr><th>' + pEsc(k) + '</th><td>' + rawValueHtml(record[k]) + '</td></tr>';
    }}).join('');
    return '<table class="kv-table">' + rows + '</table>';
  }}

  function renderSpAppTabs(prof, rec, container) {{
    var isSp = (prof.kind || 'sp') === 'sp';
    var kvRows = [];
    if (rec) {{
      kvRows.push(['Display name', rec.displayName || '']);
      if (rec.objectId) kvRows.push(['ObjectId', rec.objectId]);
      if (rec.appId) kvRows.push(['AppId', rec.appId]);
      var pub = isSp ? (rec.publisherName || '') : (rec.publisherDomain || '');
      if (pub) kvRows.push(['Publisher', pub]);
      if (isSp) {{
        kvRows.push(['Status', rec.accountEnabled === false ? 'Disabled' : 'Enabled']);
        if (prof.application) {{
          var appVal = prof.app_oid
              ? '<button type="button" class="app-link" data-app-oid="' + pEsc(prof.app_oid) + '">' + pEsc(prof.application) + '</button>'
              : pEsc(prof.application);
          kvRows.push(['Application', prof.application, appVal]);
        }}
        kvRows.push(['Assignment required', rec.appRoleAssignmentRequired ? 'Yes' : 'No']);
      }} else {{
        kvRows.push(['Public client', rec.publicClient === 1 ? 'Yes' : 'No']);
      }}
      var urls = rec.replyUrls;
      if (urls) {{
        if (!Array.isArray(urls)) urls = [urls];
        kvRows.push(['Reply URLs', urls.join(', ')]);
      }}
    }} else {{
      kvRows.push(['Display name', prof.application || '']);
    }}
    var kv = '<table class="kv-table">' + kvRows.map(function(r) {{
      var val = r.length > 2 ? r[2] : pEsc(r[1]);
      return '<tr><th>' + pEsc(r[0]) + '</th><td>' + val + '</td></tr>';
    }}).join('') + '</table>';

    var ownersHtml = (prof.owners && prof.owners.length)
        ? '<ul class="profile-list">' + prof.owners.map(function(o) {{
            return '<li><span class="mono">' + pEsc(o.upn || o.name) + '</span>'
                + ' <span class="muted">(' + pEsc(o.type) + ')</span></li>';
          }}).join('') + '</ul>'
        : '<p class="muted">No owners recorded.</p>';
    var dirRolesHtml = (prof.dir_roles && prof.dir_roles.length)
        ? '<p>' + prof.dir_roles.map(function(r) {{
            var tag = pSev(r.severity) + ' ' + pEsc(r.name);
            if (r.eligible) tag += ' <span class="muted">(eligible)</span>';
            if (r.path) tag += ' <span class="muted">via ' + pEsc(r.path.join(' \u2192 ')) + '</span>';
            return tag;
          }}).join(' &nbsp;&middot;&nbsp; ') + '</p>'
        : '<p class="muted">No directory roles assigned.</p>';
    var groupsHtml = (prof.groups && prof.groups.length)
        ? '<p>' + prof.groups.map(function(g) {{ return pEsc(g.name); }}).join(', ') + '</p>'
        : '<p class="muted">Not a member of any captured group.</p>';

    var azHtml = '';
    var overview = kv
        + pSection('Owners (' + (prof.owners ? prof.owners.length : 0) + ')', ownersHtml)
        + pSection('Assigned roles (' + (prof.dir_roles ? prof.dir_roles.length : 0) + ')', dirRolesHtml)
        + pSection('Assigned groups (' + (prof.groups ? prof.groups.length : 0) + ')', groupsHtml);

    var rawPane = rec ? renderKVHtml(rec) : '<p class="muted">Not available in the collected data.</p>';

    var isAppMode = (prof.kind || 'sp') !== 'sp';
    var panes;
    if (isAppMode) {{
      var spList = prof.sp_list || [];
      var spListHtml;
      if (!spList.length) {{
        spListHtml = '<p class="muted">No service principal captured for this application.</p>';
      }} else {{
        spListHtml = '<table class="minor-table"><thead><tr><th>Service Principal</th><th>ObjectId</th><th>AppId</th></tr></thead><tbody>'
          + spList.map(function(spr) {{
              return '<tr><td><button type="button" class="dtab-sp-link" data-sp-id="' + pEsc(spr.object_id) + '">' + pEsc(spr.display_name || spr.object_id) + '</button></td>'
                + '<td class="mono">' + pEsc(spr.object_id) + '</td>'
                + '<td class="mono">' + pEsc(spr.app_id || '') + '</td></tr>';
            }}).join('') + '</tbody></table>'
          + '<p class="muted">Click a service principal to open its full detail view.</p>';
      }}
      panes = [
        ['overview', 'Overview', overview],
        ['azure', 'Azure roles (' + (prof.az_roles ? prof.az_roles.length : 0) + ')', azTableHtml(prof.az_roles || [], true)],
        ['sps', 'Service Principal' + (spList.length ? ' (' + spList.length + ')' : ''), spListHtml],
        ['raw', 'Raw', rawPane]
      ];
    }} else {{
      var gTitle = 'Roles granted to others (' + prof.granted_roles.length + ')';
      var aTitle = 'App roles assigned to this principal (' + prof.assigned_roles.length + ')';
      var gPane = minorTable([['Principal Name', 'principal_name'], ['Principal Type', 'principal_type'], ['Role', 'role'], ['Description', 'description']], prof.granted_roles)
          || '<p class="muted">No roles granted by this principal.</p>';
      var aPane = minorTable([['Principal Name', 'principal_name'], ['Principal Type', 'principal_type'], ['Role', 'role'], ['Application', 'application'], ['Description', 'description']], prof.assigned_roles)
          || '<p class="muted">No app-role assignments to this principal. Directory roles (incl. those inherited via group membership) are listed under Overview &rarr; Assigned roles.</p>';
      panes = [
        ['overview', 'Overview', overview],
        ['azure', 'Azure roles (' + (prof.az_roles ? prof.az_roles.length : 0) + ')', azTableHtml(prof.az_roles || [], false)],
        ['granted', gTitle, gPane],
        ['assigned', aTitle, aPane],
        ['raw', 'Raw', rawPane]
      ];
    }}
    var tabsHtml = '<div class="drawer-tabs">' + panes.map(function(pt) {{
      return '<button type="button" class="drawer-tab' + (pt[0] === 'overview' ? ' active' : '') + '" data-dtab="' + pt[0] + '">' + pEsc(pt[1]) + '</button>';
    }}).join('') + '</div>';
    var panesHtml = panes.map(function(pt) {{
      return '<div class="dtab-pane' + (pt[0] === 'overview' ? ' active' : '') + '" data-dtab="' + pt[0] + '">' + pt[2] + '</div>';
    }}).join('');

    var wrap = document.createElement('div');
    wrap.className = 'drawer-tabs-wrap';
    wrap.innerHTML = tabsHtml + panesHtml;
    container.appendChild(wrap);
    Array.prototype.forEach.call(wrap.querySelectorAll('.drawer-tab'), function(b) {{
      b.addEventListener('click', function() {{
        var tab = b.getAttribute('data-dtab');
        Array.prototype.forEach.call(wrap.querySelectorAll('.drawer-tab'), function(x) {{
          x.classList.toggle('active', x.getAttribute('data-dtab') === tab);
        }});
        Array.prototype.forEach.call(wrap.querySelectorAll('.dtab-pane'), function(x) {{
          x.classList.toggle('active', x.getAttribute('data-dtab') === tab);
        }});
      }});
    }});
    Array.prototype.forEach.call(wrap.querySelectorAll('.dtab-sp-link'), function(b) {{
      b.addEventListener('click', function() {{
        var spOid = b.getAttribute('data-sp-id');
        var spProf = PROFILES2.sp[spOid];
        if (!spProf && !window.REPORT_SERVE) return;
        container.innerHTML = '';
        var backRow = document.createElement('div');
        backRow.className = 'drawer-back-row';
        backRow.innerHTML = '<button type="button" class="drawer-tab drawer-back">&larr; Back to ' + pEsc(prof.application || 'application') + '</button>';
        container.appendChild(backRow);
        Array.prototype.forEach.call(backRow.querySelectorAll('.drawer-back'), function(x) {{
          x.addEventListener('click', function() {{
            container.innerHTML = '';
            renderSpAppTabs(prof, rec, container);
          }});
        }});
        if (spProf) {{
          renderSpAppTabs(spProf, DETAILS.sp[spOid] || null, container);
        }} else {{
          fetchSpApp(spOid, 'sp', container);
        }}
      }});
    }});
  }}

  function attachDrawerTabs(wrap) {{
    Array.prototype.forEach.call(wrap.querySelectorAll('.drawer-tab'), function(b) {{
      b.addEventListener('click', function() {{
        var tab = b.getAttribute('data-dtab');
        Array.prototype.forEach.call(wrap.querySelectorAll('.drawer-tab'), function(x) {{
          x.classList.toggle('active', x.getAttribute('data-dtab') === tab);
        }});
        Array.prototype.forEach.call(wrap.querySelectorAll('.dtab-pane'), function(x) {{
          x.classList.toggle('active', x.getAttribute('data-dtab') === tab);
        }});
      }});
    }});
  }}

  function renderPolicyTabs(pol, container) {{
    var kv = [['Name', pol.policy_name || ''],
              ['ObjectId', pol.policy_id || ''],
              ['State', pol.state || '?'],
              ['Scope', pol.scope || '?'],
              ['Controls', (pol.conditions_html.controls || []).join(', ') || '—'],
              ['Applications', (pol.conditions_html.apps || []).join(', ') || '—'],
              ['Template', pol.template_id || '—'],
              ['Created', pol.created || '—'],
              ['Modified', pol.modified || '—']];
    var kvHtml = '<table class="kv-table">' + kv.map(function(r) {{
      return '<tr><th>' + pEsc(r[0]) + '</th><td>' + pEsc(r[1]) + '</td></tr>';
    }}).join('') + '</table>';
    var rolesHtml = (pol.conditions_html.inc_roles && pol.conditions_html.inc_roles.length)
        ? '<p>' + pol.conditions_html.inc_roles.map(function(r) {{ return pSev(r.severity) + ' ' + pEsc(r.name); }}).join(' &nbsp;&middot;&nbsp; ') + '</p>'
        : '<p class="muted">None captured.</p>';
    var groupsHtml = 'Included groups: ' + ((pol.conditions_html.inc_groups || []).map(function(g) {{ return pEsc(g.name); }}).join(', ') || 'none')
        + '<br>Excluded groups: ' + ((pol.conditions_html.exc_groups || []).map(function(g) {{ return pEsc(g.name); }}).join(', ') || 'none');
    var conditionsHtml = '<pre>' + pEsc(pol.conditions_raw || '{{}}') + '</pre>';
    var overview = kvHtml
        + pSection('Included roles (' + ((pol.conditions_html.inc_roles || []).length) + ')', rolesHtml)
        + pSection('Groups', '<p class="muted">' + groupsHtml + '</p>')
        + pSection('Conditions (raw)', conditionsHtml);
    var incHtml = (pol.included && pol.included.length)
        ? '<ul class="profile-list">' + pol.included.map(function(u) {{ return '<li>' + pEsc(u) + '</li>'; }}).join('') + '</ul>'
        : '<p class="muted">No included users captured.</p>';
    var excHtml = (pol.excluded && pol.excluded.length)
        ? '<ul class="profile-list">' + pol.excluded.map(function(u) {{ return '<li>' + pEsc(u) + '</li>'; }}).join('') + '</ul>'
        : '<p class="muted">No excluded users captured.</p>';
    var panes = [
      ['overview', 'Overview', overview],
      ['included', 'Included users (' + (pol.included ? pol.included.length : 0) + ')', incHtml],
      ['excluded', 'Excluded users (' + (pol.excluded ? pol.excluded.length : 0) + ')', excHtml]
    ];
    var tabsHtml = '<div class="drawer-tabs">' + panes.map(function(pt) {{
      return '<button type="button" class="drawer-tab' + (pt[0] === 'overview' ? ' active' : '') + '" data-dtab="' + pt[0] + '">' + pEsc(pt[1]) + '</button>';
    }}).join('') + '</div>';
    var panesHtml = panes.map(function(pt) {{
      return '<div class="dtab-pane' + (pt[0] === 'overview' ? ' active' : '') + '" data-dtab="' + pt[0] + '">' + pt[2] + '</div>';
    }}).join('');
    var wrap = document.createElement('div');
    wrap.className = 'drawer-tabs-wrap';
    wrap.innerHTML = tabsHtml + panesHtml;
    container.appendChild(wrap);
    attachDrawerTabs(wrap);
  }}

  function renderGroupTabs(g, container) {{
    var kvRows = [
      ['Name', g.group_name || ''],
      ['ObjectId', g.group_id || ''],
      ['Types', (g.types || []).join(', ')],
      ['Visibility', g.visibility || '—'],
      ['Public', g.is_public ? 'Yes' : 'No'],
      ['Mail-enabled', g.mail ? 'Yes' : 'No'],
      ['Auto-membership rule', g.dynamic ? (g.rule || 'yes') : 'No'],
      ['Assignable to role', g.assignable ? 'Yes' : 'No']
    ];
    var kv = '<table class="kv-table">' + kvRows.map(function(r) {{
      return '<tr><th>' + pEsc(r[0]) + '</th><td>' + pEsc(r[1]) + '</td></tr>';
    }}).join('') + '</table>';
    var dirRolesHtml = (g.dir_roles && g.dir_roles.length)
        ? '<p>' + g.dir_roles.map(function(r) {{ return pSev(r.severity) + ' ' + pEsc(r.name); }}).join(' &nbsp;&middot;&nbsp; ') + '</p>'
        : '<p class="muted">No directory roles assigned to this group.</p>';
    var eligRolesHtml = (g.eligible_roles && g.eligible_roles.length)
        ? '<p>' + g.eligible_roles.map(function(r) {{ return pSev(r.severity) + ' ' + pEsc(r.name) + ' <span class="muted">(PIM eligible)</span>'; }}).join(' &nbsp;&middot;&nbsp; ') + '</p>'
        : '';
    var ownersHtml = (g.owners && g.owners.length)
        ? '<p>' + g.owners.map(function(o) {{ return pEsc(o); }}).join(', ') + '</p>'
        : '<p class="muted">No owners recorded.</p>';
    var membershipHtml = '<p class="muted">' + (g.user_member_count || 0) + ' user member(s)';
    if (g.sp_members && g.sp_members.length) membershipHtml += ' · ' + g.sp_members.length + ' app member(s): ' + pEsc(g.sp_members.map(function(m) {{ return m.name; }}).join(', '));
    if (g.parents && g.parents.length) membershipHtml += ' · member of: ' + pEsc(g.parents.join(', '));
    if (g.children && g.children.length) membershipHtml += ' · contains groups: ' + pEsc(g.children.join(', '));
    membershipHtml += '</p>';
    var dynHtml = '';
    if (g.dyn_rule) {{
      var dynAttrs = (g.dyn_attrs || []).map(function(a) {{ return '<span class="tag-chip">' + pEsc(a) + '</span>'; }}).join(' ');
      var dynMods = (g.dyn_mods || []).map(function(m) {{
        var cls = m === 'User modifiable' ? 'tag-spray'
                : m === 'User Administrator' ? 'tag-divergence'
                : m === 'Directory Writer' ? 'tag-privileged' : '';
        return '<span class="tag-chip ' + cls + '">' + pEsc(m) + '</span>';
      }}).join(' ');
      dynHtml = pSection('Dynamic membership',
          '<p class="mono">' + pEsc(g.dyn_rule) + '</p>'
          + '<p>Referenced attributes: ' + (dynAttrs || '<span class="muted">none</span>') + '</p>'
          + '<p>Membership modifiable by: ' + (dynMods || '<span class="muted">none</span>') + '</p>');
    }}
    var azHtml = '';
    var overview = kv
        + dynHtml
        + pSection('Directory roles (' + ((g.dir_roles || []).length) + ')', dirRolesHtml)
        + (eligRolesHtml ? pSection('Eligible (PIM) roles (' + g.eligible_roles.length + ')', eligRolesHtml) : '')
        + pSection('Owners (' + ((g.owners || []).length) + ')', ownersHtml)
        + pSection('Membership', membershipHtml);
    var allMembers = g.members || [];
    var capped = allMembers.length > MEMBER_CAP;
    var shownMembers = capped ? allMembers.slice(0, MEMBER_CAP) : allMembers;
    var memberRows = shownMembers.map(function(m) {{
      var roleHtml = (m.roles || []).filter(function(r) {{ return r.severity !== 'Info'; }})
          .map(function(r) {{
            var tag = pSev(r.severity) + ' ' + pEsc(r.name);
            if (r.path && r.path.length > 1) {{
              tag += ' <span class="muted">via ' + pEsc(r.path.join(' \u2192 ')) + '</span>';
            }}
            return tag;
          }}).join(' ');
      return {{
        member: m.upn || m.name,
        name: (m.upn && m.name) ? m.name : '—',
        roles: roleHtml || '—',
        priv: m.privileged ? 'Yes' : '—'
      }};
    }});
    var membersHtml = memberRows.length
        ? '<table class="minor-table"><thead><tr><th>Member</th><th>Name</th><th>Directory roles</th><th>Privileged</th></tr></thead><tbody>'
          + memberRows.map(function(r) {{
              return '<tr><td>' + pEsc(r.member) + '</td><td>' + pEsc(r.name) + '</td><td>' + r.roles + '</td><td>' + pEsc(r.priv) + '</td></tr>';
            }}).join('') + '</tbody></table>'
        : '<p class="muted">No user members recorded.</p>';
    if (capped) membersHtml += '<p class="muted">Showing first ' + MEMBER_CAP + ' of ' + allMembers.length + ' members.</p>';
    var allSpMembers = g.sp_members || [];
    var cappedSp = allSpMembers.length > MEMBER_CAP;
    var shownSpMembers = cappedSp ? allSpMembers.slice(0, MEMBER_CAP) : allSpMembers;
    var spMemberRows = shownSpMembers.map(function(m) {{
      var roleHtml = (m.roles || []).filter(function(r) {{ return r.severity !== 'Info'; }})
          .map(function(r) {{
            var tag = pSev(r.severity) + ' ' + pEsc(r.name);
            if (r.kind === 'app') {{
              tag += ' <span class="muted">@ ' + pEsc(r.resource || 'app role') + '</span>';
            }} else if (r.path && r.path.length > 1) {{
              tag += ' <span class="muted">via ' + pEsc(r.path.join(' \u2192 ')) + '</span>';
            }}
            return tag;
          }}).join(' ');
      return {{
        name: '<button type="button" class="dtab-sp-link obj-link" data-obj-id="' + pEsc(m.id) + '" data-obj-kind="sp">' + pEsc(m.name) + '</button>',
        object_id: m.id,
        roles: roleHtml || '—',
        status: m.enabled ? 'Enabled' : 'Disabled'
      }};
    }});
    var spMembersHtml = spMemberRows.length
        ? '<table class="minor-table"><thead><tr><th>Service principal</th><th>ObjectId</th><th>Roles</th><th>Status</th></tr></thead><tbody>'
          + spMemberRows.map(function(r) {{
              return '<tr><td>' + r.name + '</td><td class="mono">' + pEsc(r.object_id) + '</td><td>' + r.roles + '</td><td>' + pEsc(r.status) + '</td></tr>';
            }}).join('') + '</tbody></table>'
        : '<p class="muted">No app (service principal) members recorded.</p>';
    if (cappedSp) spMembersHtml += '<p class="muted">Showing first ' + MEMBER_CAP + ' of ' + allSpMembers.length + ' SP members.</p>';
    var panes = [
      ['overview', 'Overview', overview],
      ['azure', 'Azure roles (' + (g.az_roles ? g.az_roles.length : 0) + ')', azTableHtml(g.az_roles || [], false)],
      ['user-members', 'User Members (' + (g.user_member_count || 0) + ')', membersHtml],
      ['sp-members', 'App Members (' + (g.sp_members ? g.sp_members.length : 0) + ')', spMembersHtml]
    ];
    var tabsHtml = '<div class="drawer-tabs">' + panes.map(function(pt) {{
      return '<button type="button" class="drawer-tab' + (pt[0] === 'overview' ? ' active' : '') + '" data-dtab="' + pt[0] + '">' + pEsc(pt[1]) + '</button>';
    }}).join('') + '</div>';
    var panesHtml = panes.map(function(pt) {{
      return '<div class="dtab-pane' + (pt[0] === 'overview' ? ' active' : '') + '" data-dtab="' + pt[0] + '">' + pt[2] + '</div>';
    }}).join('');
    var wrap = document.createElement('div');
    wrap.className = 'drawer-tabs-wrap';
    wrap.innerHTML = tabsHtml + panesHtml;
    container.appendChild(wrap);
    attachDrawerTabs(wrap);
    Array.prototype.forEach.call(wrap.querySelectorAll('.obj-link'), function(b) {{
      b.addEventListener('click', function() {{
        var oid = b.getAttribute('data-obj-id');
        var kind = b.getAttribute('data-obj-kind');
        container.innerHTML = '';
        var backRow = document.createElement('div');
        backRow.className = 'drawer-back-row';
        backRow.innerHTML = '<button type="button" class="drawer-tab drawer-back">&larr; Back to ' + pEsc(g.group_name || 'group') + '</button>';
        container.appendChild(backRow);
        Array.prototype.forEach.call(backRow.querySelectorAll('.drawer-back'), function(x) {{
          x.addEventListener('click', function() {{
            container.innerHTML = '';
            renderGroupTabs(g, container);
          }});
        }});
        var prof2 = PROFILES2.sp[oid];
        if (prof2) {{
          renderSpAppTabs(prof2, DETAILS.sp[oid] || null, container);
          return;
        }}
        if (window.REPORT_SERVE && kind === 'sp') {{
          fetchSpApp(oid, 'sp', container);
          return;
        }}
        if (kind === 'sp') {{ container.appendChild(section('Service Principal', DETAILS.sp[oid] || null)); return; }}
        container.appendChild(section('Application', DETAILS.app[oid] || null));
      }});
    }});
  }}

  function renderProfileTabs(p, container) {{
    var overview = openProfileHtml(p);
    var ownedLinks = (p.owned_objects || []).map(function(o) {{
      var isGroup = o.type === 'Group';
      var grants = (o.grants && o.grants.length)
          ? o.grants.map(function(g) {{ return g.permission + ' @ ' + g.resource; }}).join('; ')
          : '—';
      var creds = (o.pw || o.key) ? (o.pw + ' password, ' + o.key + ' key credential(s)') : '—';
      var status = (typeof o.status === 'boolean') ? (o.status ? 'Enabled' : 'Disabled') : '—';
      var kind = o.type === 'Application' ? 'app' : 'sp';
      var nameCell = '<button type="button" class="dtab-sp-link obj-link" data-obj-id="' + o.object_id + '" data-obj-kind="' + (o.type === 'Group' ? 'group' : kind) + '">' + pEsc(o.name) + '</button>';
      return {{
        type: o.type,
        name: nameCell,
        object_id: o.object_id, app_id: o.app_id || '—',
        grants: grants, creds: creds, status: status
      }};
    }});
    var ownedHtml = ownedLinks.length
        ? '<table class="minor-table"><thead><tr><th>Type</th><th>Name</th><th>ObjectId</th><th>AppId</th><th>Privileged grants</th><th>Credentials</th><th>Status</th></tr></thead><tbody>'
          + ownedLinks.map(function(r) {{
              return '<tr><td>' + pEsc(r.type) + '</td><td>' + r.name + '</td>'
                + '<td class="mono">' + pEsc(r.object_id) + '</td><td class="mono">' + pEsc(r.app_id) + '</td>'
                + '<td>' + pEsc(r.grants) + '</td><td>' + pEsc(r.creds) + '</td><td>' + pEsc(r.status) + '</td></tr>';
            }}).join('') + '</tbody></table>'
        : '<p class="muted">No owned objects recorded.</p>';
    var deviceLinks = (p.devices || []).map(function(d) {{
      return {{
        name: '<button type="button" class="dtab-sp-link obj-link" data-obj-id="' + d.object_id + '" data-obj-kind="device">' + pEsc(d.name) + '</button>',
        object_id: d.object_id,
        os: d.os || '—',
        ad: d.ad_bound ? 'Yes' : '—',
        last_logon: d.last_logon || '—',
        status: d.enabled ? 'Enabled' : 'Disabled'
      }};
    }});
    var devicesHtml = deviceLinks.length
        ? '<table class="minor-table"><thead><tr><th>Device</th><th>ObjectId</th><th>OS</th><th>AD-bound</th><th>Last logon</th><th>Status</th></tr></thead><tbody>'
          + deviceLinks.map(function(r) {{
              return '<tr><td>' + r.name + '</td><td class="mono">' + pEsc(r.object_id) + '</td><td>' + pEsc(r.os) + '</td>'
                + '<td>' + pEsc(r.ad) + '</td><td>' + pEsc(r.last_logon) + '</td><td>' + pEsc(r.status) + '</td></tr>';
            }}).join('') + '</tbody></table>'
        : '<p class="muted">No devices recorded for this user.</p>';
    var panes = [
      ['overview', 'Overview', overview],
      ['azure', 'Azure roles (' + (p.az_roles ? p.az_roles.length : 0) + ')', azTableHtml(p.az_roles || [], false)],
      ['owned', 'Owned objects (' + (p.owned_objects ? p.owned_objects.length : 0) + ')', ownedHtml],
      ['devices', 'Devices (' + (p.devices ? p.devices.length : 0) + ')', devicesHtml]
    ];
    var tabsHtml = '<div class="drawer-tabs">' + panes.map(function(pt) {{
      return '<button type="button" class="drawer-tab' + (pt[0] === 'overview' ? ' active' : '') + '" data-dtab="' + pt[0] + '">' + pEsc(pt[1]) + '</button>';
    }}).join('') + '</div>';
    var panesHtml = panes.map(function(pt) {{
      return '<div class="dtab-pane' + (pt[0] === 'overview' ? ' active' : '') + '" data-dtab="' + pt[0] + '">' + pt[2] + '</div>';
    }}).join('');
    var wrap = document.createElement('div');
    wrap.className = 'drawer-tabs-wrap';
    wrap.innerHTML = tabsHtml + panesHtml;
    container.appendChild(wrap);
    attachDrawerTabs(wrap);
    Array.prototype.forEach.call(wrap.querySelectorAll('.ca-link'), function(b) {{
      b.addEventListener('click', function() {{
        var name = b.getAttribute('data-ca-name');
        var entry = (p.ca_exclusions || []).find(function(x) {{ return x.name === name; }});
        if (!entry) return;
        container.innerHTML = '';
        var kv = '<table class="kv-table">'
          + '<tr><th>Policy</th><td>' + pEsc(entry.name || name) + '</td></tr>'
          + '<tr><th>State</th><td>' + pEsc(entry.state || '?') + '</td></tr>'
          + '<tr><th>Scope</th><td>' + pEsc(entry.scope || '?') + '</td></tr>'
          + '</table>';
        var exHtml = (entry.excluded && entry.excluded.length)
            ? '<ul class="profile-list">' + entry.excluded.map(function(u) {{
                return '<li>' + pEsc(u) + '</li>';
              }}).join('') + '</ul>'
            : '<p class="muted">None.</p>';
        var inHtml = (entry.included && entry.included.length)
            ? '<ul class="profile-list">' + entry.included.map(function(u) {{
                return '<li>' + pEsc(u) + '</li>';
              }}).join('') + '</ul>'
            : '<p class="muted">None recorded.</p>';
        container.innerHTML = kv
            + pSection('Excluded users (' + (entry.excluded ? entry.excluded.length : 0) + ')', exHtml)
            + pSection('Included users (' + (entry.included ? entry.included.length : 0) + ')', inHtml)
            + '<div class="drawer-back-row"><button type="button" class="drawer-tab drawer-back">&larr; Back to ' + pEsc(p.user_display || 'user') + '</button></div>';
        Array.prototype.forEach.call(container.querySelectorAll('.drawer-back'), function(x) {{
          x.addEventListener('click', function() {{
            container.innerHTML = '';
            renderProfileTabs(p, container);
          }});
        }});
      }});
    }});
    Array.prototype.forEach.call(wrap.querySelectorAll('.obj-link'), function(b) {{
      b.addEventListener('click', function() {{
        var oid = b.getAttribute('data-obj-id');
        var kind = b.getAttribute('data-obj-kind');
        container.innerHTML = '';
        var backRow = document.createElement('div');
        backRow.className = 'drawer-back-row';
        backRow.innerHTML = '<button type="button" class="drawer-tab drawer-back">&larr; Back to ' + pEsc(p.user_display || 'user') + '</button>';
        container.appendChild(backRow);
        Array.prototype.forEach.call(backRow.querySelectorAll('.drawer-back'), function(x) {{
          x.addEventListener('click', function() {{
            container.innerHTML = '';
            renderProfileTabs(p, container);
          }});
        }});
        var prof2 = null;
        if (kind === 'app') {{ prof2 = PROFILES2.app[oid]; }}
        else if (kind === 'sp') {{ prof2 = PROFILES2.sp[oid]; }}
        if (kind === 'group') {{
          var grp = GROUPS[oid];
          if (grp) {{ renderGroupTabs(grp, container); return; }}
          if (window.REPORT_SERVE) {{
            fetchProfile('group', oid, function(g) {{ renderGroupTabs(g, container); }}, container);
            return;
          }}
          container.appendChild(section('Group', null));
          return;
        }}
        if (prof2) {{
          renderSpAppTabs(prof2, kind === 'app' ? (DETAILS.app[oid] || null) : (DETAILS.sp[oid] || null), container);
          return;
        }}
        if (window.REPORT_SERVE && (kind === 'app' || kind === 'sp')) {{
          fetchSpApp(oid, kind, container);
          return;
        }}
        if (kind === 'app') {{ container.appendChild(section('Application', DETAILS.app[oid] || null)); return; }}
        if (kind === 'sp') {{ container.appendChild(section('Service Principal', DETAILS.sp[oid] || null)); return; }}
        if (window.REPORT_SERVE && kind === 'device') {{
          fetchDetailsAll([['device', oid]], container);
          return;
        }}
        container.appendChild(section('Device', DETAILS.device[oid] || null));
        container.appendChild(section('Owner', DETAILS.user[p.user_id] || null));
      }});
    }});
  }}

  function capAnnotate(items) {{
    return items.map(function(c) {{
      var line = c.name;
      if (c.roles && c.roles.length) {{
        line += ' \u2014 ' + c.roles.map(function(r) {{ return r.name + ' (' + r.severity + ')'; }}).join(', ');
      }}
      return line;
    }});
  }}

  function openProfileHtml(p) {{
    var html = '';
    html += pSection('Directory roles', pList(p.roles, function(r) {{
      return '<li>' + pSev(r.severity) + ' ' + pEsc(r.name) + ' <span class="muted">(' + pEsc(r.source) + ')</span></li>';
    }}));
    html += pSection('Eligible (PIM) roles', pList(p.eligible_roles, function(r) {{
      return '<li>' + pSev(r.severity) + ' ' + pEsc(r.name) + '</li>';
    }}));
    html += pSection('Privileged objects owned', pList(p.priv_apps, function(a) {{
      var grants = a.grants.map(function(g) {{
        return '<li>' + pEsc(g.permission) + ' <span class="muted">→ ' + pEsc(g.resource) + '</span> ' + pSev(g.severity) + '</li>';
      }}).join('');
      return '<li><b>' + pEsc(a.app_name) + '</b><ul>' + grants + '</ul></li>';
    }}));
    html += pSection('Service principals with directory roles (owned)', pList(p.dir_sp_roles, function(s) {{
      return '<li>' + pEsc(s.sp_name) + ' — ' + pEsc(s.role) + ' ' + pSev(s.severity) + '</li>';
    }}));
    var gl = (p.groups || []);
    var groupsHtml = '';
    if (gl.length) {{
      groupsHtml = '<ul class="profile-list">' + gl.map(function(g) {{
        var extra = '';
        if (g.capable) extra += ' <span class="tag-chip tag-privileged" title="Role-capable group (assignable to directory roles / role-bearing)">role-capable</span>';
        if (g.roles && g.roles.length) extra += ' <span class="muted">— ' + g.roles.map(function(r) {{ return r.name; }}).join(', ') + '</span>';
        return '<li><button type="button" class="dtab-sp-link obj-link" data-obj-id="' + pEsc(g.group_id) + '" data-obj-kind="group">' + pEsc(g.name) + '</button>' + extra + '</li>';
      }}).join('') + '</ul>';
    }} else {{
      groupsHtml = '<p class="muted">Not a member of any captured group.</p>';
    }}
    if (p.owned_count) {{
      groupsHtml += '<p class="muted">Owns ' + p.owned_count + ' group(s)';
      if (p.owned_cap.length) groupsHtml += ', incl. role-capable: ' + pEsc(capAnnotate(p.owned_cap).join('; '));
      groupsHtml += '</p>';
    }}
    html += pSection('Groups (' + gl.length + ')', groupsHtml);
    var caHtml = (p.ca_exclusions && p.ca_exclusions.length)
        ? '<ul class="profile-list">' + p.ca_exclusions.map(function(x) {{
            return '<li><button type="button" class="dtab-sp-link ca-link" data-ca-name="' + pEsc(x.name) + '">' + pEsc(x.name) + '</button> <span class="muted">(' + pEsc(x.state || '?') + ')</span></li>';
          }}).join('') + '</ul>'
        : '';
    html += pSection('CA exclusions (' + (p.ca_exclusions ? p.ca_exclusions.length : 0) + ')', caHtml);
    var bits = [];
    if (p.hybrid) bits.push('On-prem synced');
    if (p.user_type === 'Guest') bits.push('Guest user');
    if (p.ca_exclusions && p.ca_exclusions.length) bits.push('Excluded from ' + p.ca_exclusions.length + ' CA polic' + (p.ca_exclusions.length === 1 ? 'y' : 'ies'));
    bits.push(p.user_enabled ? 'Account enabled' : 'Account disabled');
    html += pSection('Context', '<ul class="profile-list"><li>' + pEsc(bits.join(' · ')) + '</li></ul>');
    return html;
  }}

  function renderKV(record) {{
    var table = document.createElement('table');
    table.className = 'kv-table';
    Object.keys(record).sort().forEach(function(key) {{
      var val = record[key];
      var tr = document.createElement('tr');
      var th = document.createElement('th');
      th.textContent = key;
      var td = document.createElement('td');
      if (val !== null && typeof val === 'object') {{
        var pre = document.createElement('pre');
        pre.textContent = JSON.stringify(val, null, 2);
        td.appendChild(pre);
      }} else {{
        td.textContent = String(val);
      }}
      tr.appendChild(th);
      tr.appendChild(td);
      table.appendChild(tr);
    }});
    return table;
  }}

  function section(label, record) {{
    var wrap = document.createElement('div');
    wrap.className = 'detail-section';
    var h4 = document.createElement('h4');
    h4.textContent = label;
    wrap.appendChild(h4);
    if (!record || Object.keys(record).length === 0) {{
      var p = document.createElement('p');
      p.className = 'muted';
      p.textContent = 'Not available in the collected data.';
      wrap.appendChild(p);
    }} else {{
      wrap.appendChild(renderKV(record));
    }}
    return wrap;
  }}

  function drawerFor(row) {{
    var key = row.getAttribute('data-detail-key');
    if (!key) return null;
    var sib = row.nextElementSibling;
    if (sib && sib.getAttribute('data-detail-for') === key && sib.classList.contains('drawer')) return sib;
    return null;
  }}

  function populateDrawer(row) {{
    var drawer = drawerFor(row);
    if (!drawer || drawer.dataset.filled) return;
    drawer.dataset.filled = '1';
    var body = drawer.querySelector('.drawer-body');
    if (!body) return;
    var profileId = row.getAttribute('data-profile-id') || '';
    var p = PROFILES[profileId];
    if (profileId && p) {{
      renderProfileTabs(p, body);
      return;
    }}
    if (profileId && window.REPORT_SERVE) {{
      fetch('/api/user/' + encodeURIComponent(profileId)).then(function(r) {{ return r.json(); }}).then(function(prof) {{
        if (prof && prof.user_id) {{
          PROFILES[profileId] = prof;
          renderProfileTabs(prof, body);
        }} else {{
          var mp = document.createElement('p');
          mp.className = 'muted';
          mp.textContent = 'No captured signals for this user.';
          body.appendChild(mp);
        }}
      }}).catch(function() {{
        var mp = document.createElement('p');
        mp.className = 'muted';
        mp.textContent = 'Failed to load profile.';
        body.appendChild(mp);
      }});
      return;
    }}
    var gid2 = row.getAttribute('data-group-id') || '';
    if (gid2 && GROUPS[gid2]) {{
      renderGroupTabs(GROUPS[gid2], body);
      return;
    }}
    if (gid2 && window.REPORT_SERVE) {{
      fetchProfile('group', gid2, function(g) {{ renderGroupTabs(g, body); }}, body);
      return;
    }}
    var pid2 = row.getAttribute('data-policy-id') || '';
    if (pid2 && POLICIES[pid2]) {{
      renderPolicyTabs(POLICIES[pid2], body);
      return;
    }}
    if (pid2 && window.REPORT_SERVE) {{
      fetchProfile('policy', pid2, function(pol) {{ renderPolicyTabs(pol, body); }}, body);
      return;
    }}
    var spId2 = row.getAttribute('data-sp-id') || '';
    var appId2 = row.getAttribute('data-app-id') || '';
    if (window.REPORT_SERVE && spId2 && !PROFILES2.sp[spId2]) {{
      // in serve mode the SP profile may not be cached yet even when the app
      // profile is (e.g. after navigating app -> back); prefer the SP drawer
      fetchSpApp(spId2, 'sp', body);
      return;
    }}
    var prof2 = (spId2 && PROFILES2.sp[spId2]) ? PROFILES2.sp[spId2]
              : (appId2 && PROFILES2.app[appId2]) ? PROFILES2.app[appId2] : null;
    if (prof2) {{
      var rec2 = (spId2 && PROFILES2.sp[spId2]) ? (DETAILS.sp[spId2] || null) : (DETAILS.app[appId2] || null);
      renderSpAppTabs(prof2, rec2, body);
      return;
    }}
    if (window.REPORT_SERVE && (spId2 || appId2)) {{
      fetchSpApp(spId2 || appId2, spId2 ? 'sp' : 'app', body);
      return;
    }}
    var wants = [];
    if (row.getAttribute('data-device-id')) wants.push(['device', row.getAttribute('data-device-id')]);
    if (row.getAttribute('data-app-id')) wants.push(['app', row.getAttribute('data-app-id')]);
    if (row.getAttribute('data-sp-id')) wants.push(['sp', row.getAttribute('data-sp-id')]);
    if (wants.length && window.REPORT_SERVE) {{
      fetchDetailsAll(wants, body);
      return;
    }}
    if (row.getAttribute('data-device-id')) body.appendChild(section('Device', DETAILS.device[row.getAttribute('data-device-id') || '']));
    if (row.getAttribute('data-app-id')) body.appendChild(section('Application', DETAILS.app[row.getAttribute('data-app-id') || '']));
    if (row.getAttribute('data-sp-id')) body.appendChild(section('Service Principal', DETAILS.sp[row.getAttribute('data-sp-id') || '']));
    if (row.getAttribute('data-owner-id')) body.appendChild(section('Owner', DETAILS.user[row.getAttribute('data-owner-id') || '']));
    if (!body.children.length) {{
      body.appendChild(mutedP('No additional details captured for this object.'));
    }}
  }}

  function mutedP(msg) {{
    var mp = document.createElement('p');
    mp.className = 'muted';
    mp.textContent = msg;
    return mp;
  }}

  function fetchProfile(kind, oid, cb, body) {{
    fetch('/api/profile/' + kind + '/' + encodeURIComponent(oid)).then(function(r) {{ return r.json(); }}).then(function(data) {{
      if (!data || data.error) {{ body.appendChild(mutedP('No data for this object.')); return; }}
      if (kind === 'group') GROUPS[oid] = data;
      else if (kind === 'policy') POLICIES[oid] = data;
      cb(data);
    }}).catch(function() {{ body.appendChild(mutedP('Failed to load.')); }});
  }}

  function fetchSpApp(oid, kind, body) {{
    var p1 = fetch('/api/profile/' + kind + '/' + encodeURIComponent(oid)).then(function(r) {{ return r.json(); }});
    var p2 = fetch('/api/details/' + kind + '/' + encodeURIComponent(oid)).then(function(r) {{ return r.json(); }}).catch(function() {{ return null; }});
    Promise.all([p1, p2]).then(function(res) {{
      var prof = res[0], rec = res[1];
      if (!prof || prof.error) {{ body.appendChild(mutedP('No data for this principal.')); return; }}
      if (rec && rec.error) rec = null;  // details missing: render from the profile alone
      if (kind === 'sp') {{ PROFILES2.sp[oid] = prof; DETAILS.sp[oid] = rec; }}
      else {{ PROFILES2.app[oid] = prof; DETAILS.app[oid] = rec; }}
      renderSpAppTabs(prof, rec, body);
    }}).catch(function() {{ body.appendChild(mutedP('Failed to load.')); }});
  }}

  function fetchDetailsAll(wants, body) {{
    var pending = wants.length;
    var done = [];
    function finish() {{
      done.forEach(function(pair) {{
        var label = pair[0] === 'device' ? 'Device' : pair[0] === 'app' ? 'Application' : 'Service Principal';
        body.appendChild(section(label, pair[2]));
      }});
      if (!body.children.length) body.appendChild(mutedP('No additional details captured for this object.'));
    }}
    wants.forEach(function(pair) {{
      var kind = pair[0], oid = pair[1];
      var cached = DETAILS[kind] && DETAILS[kind][oid];
      if (cached) {{ done.push([kind, oid, cached]); if (--pending === 0) finish(); return; }}
      fetch('/api/details/' + kind + '/' + encodeURIComponent(oid)).then(function(r) {{ return r.json(); }}).then(function(d) {{
        if (!DETAILS[kind]) DETAILS[kind] = {{}};
        DETAILS[kind][oid] = d;
        done.push([kind, oid, d]);
        if (--pending === 0) finish();
      }}).catch(function() {{ if (--pending === 0) finish(); }});
    }});
  }}

  function toggleDrawer(row) {{
    var drawer = drawerFor(row);
    if (!drawer) return;
    if (drawer.classList.contains('open')) {{
      drawer.classList.remove('open');
      return;
    }}
    populateDrawer(row);
    drawer.classList.add('open');
  }}

  document.addEventListener('click', function(e) {{
    var btn = e.target.closest('.expand-btn');
    if (!btn) return;
    var row = btn.closest('tr');
    if (!row) return;
    toggleDrawer(row);
  }});

  // User identity cells (User / UPN) open the same profile drawer as '+'
  // instead of the aggregate drilldown popup.
  document.addEventListener('click', function(e) {{
    var cell = e.target.closest('td.clickable');
    if (!cell) return;
    var field = cell.getAttribute('data-field') || '';
    if (field !== 'user' && field !== 'userUpn' && field !== 'adUser' && field !== 'adUpn') return;
    var row = cell.closest('tr');
    if (!row) return;
    var pid = row.getAttribute('data-profile-id') || '';
    if (!pid) return;
    if (!PROFILES[pid] && !window.REPORT_SERVE) return;
    e.stopImmediatePropagation();
    toggleDrawer(row);
  }}, true);

  // Application cell in the ownership tables opens the app drawer; rows
  // without a local app registration (foreign SPs) open the SP drawer.
  document.addEventListener('click', function(e) {{
    var cell = e.target.closest('td.clickable');
    if (!cell) return;
    var field = cell.getAttribute('data-field') || '';
    if (field !== 'app') return;
    var row = cell.closest('tr');
    if (!row) return;
    if (!row.getAttribute('data-app-id')) {{
      e.stopImmediatePropagation();
      toggleDrawer(row);
      return;
    }}
    e.stopImmediatePropagation();
    openAppDrawer(row.getAttribute('data-app-id'), row);
  }}, true);

  // App-link buttons (SP drawer's Application row) navigate to the app drawer.
  document.addEventListener('click', function(e) {{
    var btn = e.target.closest('.app-link');
    if (!btn) return;
    var drawerTr = btn.closest('tr.drawer');
    var key = drawerTr ? drawerTr.getAttribute('data-detail-for') : '';
    // scope the row lookup to the drawer's own table - data-detail-key values
    // collide across tables (every table numbers rows from 0)
    var table = drawerTr ? drawerTr.closest('table') : null;
    var row = (table && key) ? table.querySelector('tr[data-detail-key="' + key + '"]') : null;
    // Prefer the row's app id (the same id the column-cell path uses and is
    // known to resolve); fall back to the profile-derived id for rows that
    // carry no app id (e.g. Azure Roles table rows).
    var oid = (row && row.getAttribute('data-app-id')) || btn.getAttribute('data-app-oid');
    if (!oid) return;
    if (row) {{
      openAppDrawer(oid, row);
    }} else {{
      openAppDrawerInPlace(oid, btn.closest('.drawer-body'));
    }}
  }});

  function openAppDrawer(oid, row) {{
    var drawer = drawerFor(row);
    if (!drawer) return;
    delete drawer.dataset.filled;  // back must re-populate even if the drawer was filled once
    if (!drawer.classList.contains('open')) drawer.classList.add('open');
    var body = drawer.querySelector('.drawer-body');
    body.innerHTML = '';
    var backRow = document.createElement('div');
    backRow.className = 'drawer-back-row';
    backRow.innerHTML = '<button type="button" class="drawer-tab drawer-back">&#8592; Back to service principal</button>';
    body.appendChild(backRow);
    backRow.querySelector('.drawer-back').addEventListener('click', function() {{
      body.innerHTML = '';
      populateDrawer(row);
    }});
    renderApp(oid, body);
  }}

  function openAppDrawerInPlace(oid, body) {{
    body.innerHTML = '';
    renderApp(oid, body);
  }}

  function renderApp(oid, body) {{
    if (window.REPORT_SERVE) {{
      fetchSpApp(oid, 'app', body);
      return;
    }}
    var prof = PROFILES2.app[oid];
    if (prof) {{
      renderSpAppTabs(prof, DETAILS.app[oid] || null, body);
    }} else {{
      body.appendChild(section('Application', DETAILS.app[oid] || null));
    }}
  }}
}})();

(function() {{
  function allTables() {{
    return Array.prototype.slice.call(document.querySelectorAll('table.findings'));
  }}
  var input = document.getElementById('filter-input');
  var advToggle = document.getElementById('advanced-toggle');
  var suggestWrap = document.getElementById('suggest-wrap');
  var suggestList = document.getElementById('suggest-list');
  var errorEl = document.getElementById('filter-error');
  var advOn = false;
  var suggestionRange = null;
  var activeSuggestion = -1;
  var SUGGEST = {{}};
  try {{ SUGGEST = JSON.parse(document.getElementById('suggest-data').textContent); }} catch (e) {{}}
  Object.keys(SUGGEST).forEach(function(k) {{ SUGGEST[k.toLowerCase()] = SUGGEST[k]; }});

  function rowFieldMap(row) {{
    var map = {{ check: (row.getAttribute('data-check-id') || '').toLowerCase(), category: '' }};
    var sec = row.closest('section');
    if (sec) map.category = (sec.getAttribute('data-category') || '').toLowerCase();
    Array.prototype.forEach.call(row.cells, function(td) {{
      var f = td.getAttribute('data-field');
      if (f) map[f.toLowerCase()] = td.getAttribute('data-value') || '';
    }});
    return map;
  }}

  function setRowVisibility(test) {{
    allTables().forEach(function(table) {{
      Array.prototype.forEach.call(table.tBodies[0].rows, function(row) {{
        if (row.classList.contains('drawer')) return;
        var show = test(row);
        row.classList.toggle('hidden', !show);
        var next = row.nextElementSibling;
        if (next && next.getAttribute('data-detail-for') === row.getAttribute('data-detail-key')) {{
          next.classList.toggle('hidden', !show);
        }}
      }});
    }});
  }}

  function hideSuggest() {{
    suggestWrap.classList.add('hidden');
    suggestList.innerHTML = '';
    suggestionRange = null;
    activeSuggestion = -1;
  }}

  function knownFields() {{
    var out = [];
    (ADV_FILTER.columns() || []).forEach(function(c) {{
      out.push(c.display);
    }});
    return out;
  }}

  function fieldValueSuggest(fieldName, prefix) {{
    var internal = ADV_FILTER.fieldsFor(fieldName) || [];
    var seen = {{}}, out = [];
    internal.forEach(function(f) {{
      (SUGGEST[f] || []).forEach(function(v) {{
        if (String(v).toLowerCase().indexOf(prefix.toLowerCase()) === 0 && !seen[v]) {{
          seen[v] = true;
          out.push(v);
        }}
      }});
    }});
    return out;
  }}

  function tokenRange() {{
    var value = input.value;
    var caret = input.selectionStart == null ? value.length : input.selectionStart;
    var start = caret;
    while (start > 0 && !/[\\s()]/.test(value[start - 1])) start--;
    var end = caret;
    while (end < value.length && !/[\\s()]/.test(value[end])) end++;
    return {{ start: start, end: end, token: value.slice(start, end) }};
  }}

  function buildSuggestions() {{
    if (!advOn || document.activeElement !== input) {{ hideSuggest(); return; }}
    var r = tokenRange();
    var token = r.token;
    var items = [];
    var ci = token.indexOf(':');
    if (ci !== -1) {{
      var field = token.slice(0, ci);
      var prefix = token.slice(ci + 1).toLowerCase();
      fieldValueSuggest(field, prefix).slice(0, 8).forEach(function(v) {{
        items.push({{ text: field + ':' + v, display: field + ':' + v, hint: 'value' }});
      }});
    }} else if (token) {{
      var pre = ADV_FILTER.normalizeField(token);
      knownFields().forEach(function(display) {{
        if (ADV_FILTER.normalizeField(display).indexOf(pre) === 0) {{
          items.push({{ text: display + ':', display: display + ':', hint: 'column' }});
        }}
      }});
    }} else {{
      ['AND', 'OR', 'NOT', 'contains:'].forEach(function(op) {{
        items.push({{ text: op, display: op, hint: 'operator' }});
      }});
    }}
    if (!items.length) {{ hideSuggest(); return; }}
    suggestionRange = r;
    activeSuggestion = -1;
    suggestList.innerHTML = '';
    items.slice(0, 8).forEach(function(it) {{
      var li = document.createElement('li');
      li.textContent = it.display;
      li.dataset.sugg = it.text;
      var hint = document.createElement('span');
      hint.className = 'sugg-hint';
      hint.textContent = it.hint;
      li.appendChild(hint);
      suggestList.appendChild(li);
    }});
    suggestWrap.classList.remove('hidden');
  }}

  function acceptSuggestion(item) {{
    if (!suggestionRange) return;
    var r = suggestionRange;
    var value = input.value;
    input.value = value.slice(0, r.start) + item + ' ' + value.slice(r.end);
    var pos = r.start + item.length + 1;
    input.setSelectionRange(pos, pos);
    hideSuggest();
    input.dispatchEvent(new Event('input', {{ bubbles: true }}));
  }}

  function applyRowFilter() {{
    var q = input.value;
    if (!advOn) {{
      var needle = q.toLowerCase();
      setRowVisibility(function(row) {{
        return q.length === 0 || row.textContent.toLowerCase().indexOf(needle) !== -1;
      }});
      errorEl.classList.add('hidden');
      hideSuggest();
      return;
    }}
    var parsed = ADV_FILTER.parse(q);
    if (parsed.error) {{
      errorEl.textContent = 'Filter error: ' + parsed.error;
      errorEl.classList.remove('hidden');
      hideSuggest();
      return;
    }}
    errorEl.classList.add('hidden');
    if (q.trim() === '') {{
      setRowVisibility(function() {{ return true; }});
      buildSuggestions();
      return;
    }}
    var ast = parsed.ast;
    setRowVisibility(function(row) {{
      return ADV_FILTER.evaluate(ast, rowFieldMap(row), row.textContent);
    }});
  }}

  input.addEventListener('input', function() {{
    applyRowFilter();
    if (advOn) buildSuggestions();
  }});

  input.addEventListener('keydown', function(e) {{
    if (!advOn || suggestWrap.classList.contains('hidden')) return;
    var items = suggestList.querySelectorAll('li');
    if (!items.length) return;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {{
      e.preventDefault();
      activeSuggestion += e.key === 'ArrowDown' ? 1 : -1;
      if (activeSuggestion >= items.length) activeSuggestion = 0;
      if (activeSuggestion < 0) activeSuggestion = items.length - 1;
      Array.prototype.forEach.call(items, function(li, i) {{
        li.classList.toggle('active', i === activeSuggestion);
      }});
    }} else if (e.key === 'Enter' || e.key === 'Tab') {{
      var idx = activeSuggestion >= 0 ? activeSuggestion : 0;
      if (items[idx]) {{
        e.preventDefault();
        acceptSuggestion(items[idx].dataset.sugg);
      }}
    }} else if (e.key === 'Escape') {{
      hideSuggest();
    }}
  }});

  suggestList.addEventListener('mousedown', function(e) {{
    var li = e.target.closest('li');
    if (!li) return;
    e.preventDefault();
    acceptSuggestion(li.dataset.sugg);
  }});

  input.addEventListener('blur', function() {{
    setTimeout(hideSuggest, 150);
  }});

  advToggle.addEventListener('click', function() {{
    advOn = !advOn;
    advToggle.setAttribute('aria-pressed', String(advOn));
    input.placeholder = advOn
        ? 'Advanced: severity:High AND target:contains:admin&hellip;'
        : 'Filter all tables by target, owner, evidence&hellip;';
    hideSuggest();
    errorEl.classList.add('hidden');
    input.dispatchEvent(new Event('input', {{ bubbles: true }}));
  }});

  // ---- column reordering (drag headers; session only) --------------------
  var suppressSortClick = 0;

  function stampColumnIds() {{
    allTables().forEach(function(table) {{
      Array.prototype.forEach.call(table.tHead.rows[0].cells, function(th, i) {{
        if (!th.classList.contains('no-sort')) {{
          if (th.dataset.colidx === undefined) th.dataset.colidx = String(i);
          th.title = 'Click to sort · drag to reorder';
        }}
      }});
    }});
  }}

  function applyColumnOrder(table) {{
    // Rebuild every data row so its cells follow the thead's current order
    // (clone-based: all interactive handlers are document-delegated).
    var theadCells = table.tHead.rows[0].cells;
    var order = [];
    var identity = true;
    for (var i = 0; i < theadCells.length; i++) {{
      var cidx = theadCells[i].dataset.colidx;
      var o = cidx === undefined ? i : parseInt(cidx, 10);
      if (o !== i) identity = false;
      order.push(o);
    }}
    if (identity) return;
    Array.prototype.forEach.call(table.tBodies[0].rows, function(row) {{
      if (row.classList.contains('drawer')) return;
      var cells = Array.prototype.slice.call(row.cells);
      var reordered = [];
      for (var o = 0; o < order.length; o++) reordered.push(cells[order[o]].cloneNode(true));
      row.innerHTML = '';
      for (var c = 0; c < reordered.length; c++) row.appendChild(reordered[c]);
    }});
  }}

  function moveColumn(table, sourceTh, targetTh) {{
    var headerRow = table.tHead.rows[0];
    var srcIdx = Array.prototype.indexOf.call(headerRow.cells, sourceTh);
    var tgtIdx = Array.prototype.indexOf.call(headerRow.cells, targetTh);
    if (srcIdx < 0 || tgtIdx < 0) return;
    headerRow.insertBefore(sourceTh, targetTh);
    // keep colgroup widths aligned with the header order
    var cols = table.querySelectorAll('colgroup col');
    if (cols.length) {{
      var srcCol = cols[srcIdx];
      var tgtCol = cols[tgtIdx];
      if (srcCol && tgtCol) srcCol.parentNode.insertBefore(srcCol, tgtCol);
    }}
    applyColumnOrder(table);
  }}

  var dragState = null;
  document.addEventListener('mousedown', function(e) {{
    if (e.button !== 0) return;
    var th = e.target.closest('th');
    if (!th || th.classList.contains('no-sort') || e.target.closest('.col-resizer')) return;
    var table = th.closest('table.findings');
    if (!table) return;
    e.preventDefault();  // avoid text selection while starting a drag
    dragState = {{ table: table, th: th, startX: e.clientX, moved: false, dropTarget: null }};
  }});

  document.addEventListener('mousemove', function(e) {{
    if (!dragState) return;
    if (!dragState.moved && Math.abs(e.clientX - dragState.startX) < 8) return;
    if (!dragState.moved) {{
      dragState.moved = true;
      document.body.classList.add('col-dragging');
      dragState.th.classList.add('col-drag-source');
    }}
    var over = document.elementFromPoint(e.clientX, e.clientY);
    var target = over ? over.closest('th') : null;
    if (target && (target.closest('table') !== dragState.table
                   || target.classList.contains('no-sort')
                   || target === dragState.th)) {{
      target = null;
    }}
    var prev = dragState.dropTarget;
    if (prev && prev !== target) prev.classList.remove('col-drop-target');
    if (target && target !== prev) target.classList.add('col-drop-target');
    dragState.dropTarget = target;
  }});

  document.addEventListener('mouseup', function() {{
    if (!dragState) return;
    var st = dragState;
    dragState = null;
    document.body.classList.remove('col-dragging');
    st.th.classList.remove('col-drag-source');
    if (st.dropTarget) st.dropTarget.classList.remove('col-drop-target');
    if (!st.moved || !st.dropTarget) return;
    suppressSortClick = Date.now();  // the following click is a drag, not a sort
    window.__suppressSortClickUntil = suppressSortClick;
    moveColumn(st.table, st.th, st.dropTarget);
  }});

  stampColumnIds();
  window.__applyColumnOrder = applyColumnOrder;

  allTables().forEach(function(table) {{
    var headers = table.tHead.rows[0].cells;
    Array.prototype.forEach.call(headers, function(th, colIndex) {{
      if (th.classList.contains('no-sort')) return;
      var asc = true;
      th.addEventListener('click', function() {{
        if (suppressSortClick && Date.now() - suppressSortClick < 300) return;
        var idx = Array.prototype.indexOf.call(table.tHead.rows[0].cells, th);
        var mantissa = Array.prototype.filter.call(table.tBodies[0].rows, function(r) {{
          return !r.classList.contains('drawer');
        }});
        var drawers = Array.prototype.filter.call(table.tBodies[0].rows, function(r) {{
          return r.classList.contains('drawer');
        }});
        drawers.forEach(function(d) {{ d.remove(); }});
        mantissa.sort(function(a, b) {{
          var av = a.cells[idx].textContent.trim().toLowerCase();
          var bv = b.cells[idx].textContent.trim().toLowerCase();
          if (av < bv) return asc ? -1 : 1;
          if (av > bv) return asc ? 1 : -1;
          return 0;
        }});
        var order = [];
        mantissa.forEach(function(r) {{
          order.push(r);
          var key = r.getAttribute('data-detail-key');
          var d = drawers.find(function(x) {{ return x.getAttribute('data-detail-for') === key; }});
          if (d) order.push(d);
        }});
        order.forEach(function(r) {{ table.tBodies[0].appendChild(r); }});
        Array.prototype.forEach.call(headers, function(h) {{ h.classList.remove('sorted'); }});
        th.classList.add('sorted');
        asc = !asc;
      }});
    }});
  }});

  function makeColumnsResizable(table) {{
    if (!table) return;
    var cols = table.querySelectorAll('colgroup col');
    var headers = table.tHead.rows[0].cells;
    Array.prototype.forEach.call(headers, function(th, index) {{
      if (index === headers.length - 1 || !cols[index] || th.classList.contains('no-sort')) return;
      var handle = document.createElement('span');
      handle.className = 'col-resizer';
      handle.addEventListener('click', function(e) {{ e.stopPropagation(); }});
      handle.addEventListener('mousedown', function(e) {{
        e.preventDefault();
        e.stopPropagation();
        var col = cols[Array.prototype.indexOf.call(table.tHead.rows[0].cells, th)];
        var startX = e.clientX;
        var startWidth = col.getBoundingClientRect().width;
        handle.classList.add('resizing');
        document.body.style.userSelect = 'none';
        function onMouseMove(e2) {{
          var newWidth = Math.max(50, startWidth + (e2.clientX - startX));
          col.style.width = newWidth + 'px';
        }}
        function onMouseUp() {{
          document.removeEventListener('mousemove', onMouseMove);
          document.removeEventListener('mouseup', onMouseUp);
          handle.classList.remove('resizing');
          document.body.style.userSelect = '';
        }}
        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
      }});
      th.appendChild(handle);
    }});
  }}
  allTables().forEach(makeColumnsResizable);
}})();

(function() {{
  if (!window.REPORT_SERVE) return;
  var filterInput = document.getElementById('filter-input');
  function makeLoader(table) {{
    var pager = table.closest('.table-scroll') ? table.closest('.table-scroll').nextElementSibling : null;
    if (!pager || !pager.classList.contains('table-pager')) return;
    var state = {{ page: 1, size: 25, q: '', sort: '', dir: 'asc' }};
    var tbody = table.tBodies[0];
    var info = pager.querySelector('.tp-info');
    var prev = pager.querySelector('.tp-prev');
    var next = pager.querySelector('.tp-next');
    var sizeSel = pager.querySelector('.tp-size');
    var timer = null;
    function load() {{
      var params = 'page=' + state.page + '&size=' + state.size;
      if (state.q) params += '&q=' + encodeURIComponent(state.q);
      var adv = document.getElementById('advanced-toggle');
      if (adv && adv.getAttribute('aria-pressed') === 'true') params += '&mode=advanced';
      if (state.sort) params += '&sort=' + state.sort + '&dir=' + state.dir;
      fetch('/api/table/' + encodeURIComponent(table.id) + '?' + params)
        .then(function(r) {{ return r.json(); }})
        .then(function(d) {{
          if (!d || d.rows_html == null) return;
          tbody.innerHTML = d.rows_html;
          if (window.__applyColumnOrder) window.__applyColumnOrder(table);
          info.textContent = 'Page ' + d.page + ' of ' + d.pages + ' (' + d.total + ' rows)';
          pager.classList.remove('hidden');
          prev.disabled = d.page <= 1;
          next.disabled = d.page >= d.pages;
        }});
    }}
    prev.addEventListener('click', function() {{ state.page = Math.max(1, state.page - 1); load(); }});
    next.addEventListener('click', function() {{ state.page += 1; load(); }});
    sizeSel.addEventListener('change', function() {{ state.size = parseInt(sizeSel.value, 10) || 25; state.page = 1; load(); }});
    filterInput.addEventListener('input', function() {{
      clearTimeout(timer);
      var v = filterInput.value;
      timer = setTimeout(function() {{ state.q = v; state.page = 1; load(); }}, 250);
    }});
    table.tHead.addEventListener('click', function(e) {{
      var th = e.target.closest('th');
      if (!th || th.classList.contains('no-sort')) return;
      e.stopPropagation();
      if (window.__suppressSortClickUntil && Date.now() - window.__suppressSortClickUntil < 300) return;
      var col = th.dataset.colidx || String(Array.prototype.indexOf.call(table.tHead.rows[0].cells, th));
      if (state.sort === String(col)) state.dir = state.dir === 'asc' ? 'desc' : 'asc';
      else {{ state.sort = String(col); state.dir = 'asc'; }}
      state.page = 1;
      load();
    }}, true);
    load();
  }}
  document.querySelectorAll('table.findings[data-serve="1"]').forEach(makeLoader);
}})();
</script>
</body>
</html>
"""


def build_tenant_summary(graph, results=None):
    """Facts about the tenant for the top summary bar (independent of check selection)."""
    users = len(graph["user"])
    enabled = sum(1 for u in graph["user"].values() if u.get("accountEnabled"))
    synced = sum(1 for u in graph["user"].values() if u.get("dirSyncEnabled") in (1, True))

    realms = set()
    sid_prefix = None
    for u in graph["user"].values():
        dn = u.get("onPremisesDistinguishedName") or ""
        dcs = [p.strip()[3:].strip() for p in dn.split(",") if p.strip()[:3].upper() == "DC="]
        if dcs:
            realms.add(".".join(dcs))
        sid = u.get("onPremisesSecurityIdentifier") or ""
        if sid and not sid_prefix:
            dash = sid.rfind("-")
            if dash > 0:
                sid_prefix = sid[: dash + 1]

    connectors = [rec.get("displayName") or "" for rec in graph["sp"].values()
                  if (rec.get("displayName") or "").startswith("ConnectSyncProvisioning_")]
    adsync_groups = any("ADSync" in (rec.get("displayName") or "") for rec in graph["group"].values())
    host = None
    if connectors:
        parts = connectors[0].split("_")
        host = parts[1] if len(parts) > 2 else None
    if synced and (connectors or adsync_groups):
        engine = "Microsoft Entra Connect (on-prem)" + (f" · {host}" if host else "")
    elif synced:
        engine = "Likely Entra Cloud Sync"
    else:
        engine = "No sync observed"

    writeback = None  # None = unknown, True/False when the sync summary check ran
    if results:
        for res in results:
            if res["id"] != "ad_sync_summary":
                continue
            wb = (res["findings"][0].get("writeback") or {})
            writeback = bool(wb.get("count"))

    domains = []
    for d in json_list(graph["tenant"].get("verified_domains")):
        if isinstance(d, dict) and d.get("name"):
            domains.append({"name": d["name"], "default": bool(d.get("default"))})
    domains.sort(key=lambda d: (not d["default"], d["name"]))

    return {
        "tenant": graph["tenant"].get("display_name") or "Unknown",
        "tenant_id": graph["tenant"].get("object_id") or "",
        "domains": [d["name"] for d in domains],
        "realm": ", ".join(sorted(realms)) or "",
        "sid_prefix": sid_prefix or "",
        "engine": engine,
        "writeback": writeback,
        "users": users,
        "enabled": enabled,
        "synced": synced,
        "apps": len(graph["app"]),
        "sps": len(graph["sp"]),
        "groups": len(graph["group"]),
        "devices": len(graph["device"]),
    }


# ---------------------------------------------------------------------------
# Live serve mode (--serve): same report shell; the users table, user profiles
# and user-field drilldowns are served on demand from the in-memory results so
# the page stays small at 50k+ users. Bound to 127.0.0.1, read-only.
# ---------------------------------------------------------------------------

SERVE_STATE = {"shell": "", "user_findings": [], "tables": {},
               "profiles2": {"sp": {}, "app": {}}, "group_profiles": {},
               "policy_profiles": {}, "details": {"sp": {}, "app": {}, "device": {}},
               "records": []}

# ---- server-side drilldown (mirrors the DOM record model + DRILLDOWN_COLUMNS) --

SERVE_FIELD_LABELS = {
    "severity": "Privileges", "owner": "Owner", "ownerUpn": "Owner UPN",
    "ownerStatus": "Owner Status", "app": "Application",
    "resource": "Resource", "permission": "Permission", "spStatus": "SP Status",
    "target": "Target", "targetType": "Target Type", "id": "Object ID",
    "status": "Target Status", "pw": "Passwords", "keys": "Keys", "roleCount": "Role assignment",
    "userUpn": "UPN", "roles": "Directory roles", "eligible": "Eligible roles",
    "privApps": "Privileged apps owned",
    "capGroups": "Role-capable group memberships", "grpOwned": "Groups owned",
    "hybrid": "Account Source", "caExcl": "CA exclusions", "userStatus": "Status",
    "group": "Group", "grpType": "Type", "grpRoles": "Directory roles",
    "grpMembers": "Members", "grpPriv": "Privileged members", "grpOwners": "Owners",
    "polName": "Policy", "polState": "State", "polScope": "Scope", "polApps": "Apps",
    "polControls": "Controls", "polInc": "Included users", "polExc": "Excluded users",
    "dynGroup": "Group", "dynRule": "Membership rule", "dynAttrs": "Referenced attributes",
    "dynMods": "attribute modifiable by",
    "adUser": "User", "adUpn": "UPN", "adCn": "AD CN", "adDn": "AD DN", "adSid": "SID",
    "adPw": "On-prem pw change", "adTags": "Targeting tags", "adStatus": "Status",
}

SERVE_DRILLDOWN_COLUMNS = {
    "owner":      ["app", "resource", "permission", "severity", "spStatus"],
    "ownerUpn":   ["app", "resource", "permission", "severity", "spStatus"],
    "app":        ["ownerUpn", "resource", "permission", "severity", "spStatus"],
    "resource":   ["app", "ownerUpn", "permission", "severity", "spStatus"],
    "permission": ["app", "ownerUpn", "resource", "severity", "spStatus"],
    "target":     ["targetType", "id", "roleCount", "pw", "keys", "severity", "status"],
    "roles":      ["userUpn", "privApps", "capGroups", "grpOwned", "severity"],
    "eligible":   ["userUpn", "group", "severity"],
    "group":      ["group", "grpType", "grpRoles", "grpMembers", "grpPriv", "grpOwners", "severity"],
    "grpRoles":   ["group", "grpMembers", "grpPriv", "severity"],
    "polName":    ["polState", "polScope", "polApps", "polControls", "polInc", "polExc", "severity"],
    "dynGroup":   ["dynRule", "dynAttrs", "dynMods"],
    "dynAttrs":   ["dynGroup", "dynRule", "dynMods"],
    "dynRule":    ["dynGroup", "dynAttrs", "dynMods"],
    "dynMods":    ["dynGroup", "dynRule", "dynAttrs"],
}

SERVE_CONTAINS_FIELDS = {"roles", "eligible", "grpRoles", "dynMods", "dynAttrs"}

CHECK_ID_CATEGORY = {spec["id"]: spec["category"] for spec in CHECK_SPECS}


def _serve_table_id(res_id):
    return {
        "privileged_users": "privileged-users-table",
        "groups": "groups-table",
        "ad_sync_users": "ad-sync-users-table",
        "app_dir_roles": "app-dir-roles-table",
        "ca_exposure": "table-ca_exposure",
    }.get(res_id, f"table-{res_id}")


def serve_field_map(table_id, f, owner=None):
    """Field map for one finding row in a serve table — mirrors the DOM
    data-field/data-value model plus the implicit 'check' and 'category'
    fields. Used by the advanced filter and the serve drilldown records."""
    fields = {"check": f.get("check_id", ""),
              "category": CHECK_ID_CATEGORY.get(f.get("check_id", ""), "")}
    if table_id == "privileged-users-table":
        fields.update({
            "user": f.get("user_display") or "", "userUpn": f.get("user_upn") or "",
            "roles": ", ".join(r["name"] for r in f.get("roles", [])),
            "eligible": ", ".join(r["name"] for r in f.get("eligible_roles", [])),
            "privApps": str(len(f.get("priv_apps", []))),
            "capGroups": str(len(f.get("cap_member", []))),
            "grpOwned": str(f.get("owned_count", 0)),
            "caExcl": str(len(f.get("ca_exclusions", []))),
            "hybrid": "AD" if f.get("hybrid") else "Cloud",
            "userStatus": "Enabled" if f.get("user_enabled") else "Disabled",
            "severity": f.get("severity", "Info"),
        })
    elif table_id == "groups-table":
        fields.update({
            "group": f.get("group_name") or "",
            "grpType": ", ".join(f.get("types", [])),
            "grpRoles": ", ".join(r["name"] for r in f.get("dir_roles", [])),
            "eligible": ", ".join(r["name"] for r in f.get("eligible_roles", [])),
            "grpMembers": str(f.get("member_count", 0)),
            "grpPriv": str(f.get("priv_member_count", 0)),
            "grpOwners": str(len(f.get("owners", []))),
            "severity": f.get("severity", "Info"),
        })
    elif table_id == "dynamic-groups-table":
        fields.update({
            "dynGroup": f.get("group_name") or "", "dynRule": f.get("dyn_rule") or "",
            "dynAttrs": ", ".join(f.get("dyn_attrs", [])),
            "dynMods": ", ".join(f.get("dyn_mods", [])),
        })
    elif table_id in ("owned-table", "unowned-table"):
        owners = [owner] if owner is not None else f.get("owners", [])
        fields.update({
            "owner": ", ".join(o.get("display_name") or "" for o in owners),
            "ownerUpn": ", ".join(o.get("upn") or "" for o in owners),
            "ownerStatus": ", ".join("Enabled" if o.get("enabled") else "Disabled"
                                     for o in owners),
            "app": f.get("display_name") or "",
            "pw": str(f.get("pw")) if f.get("pw") is not None else "",
            "keys": str(f.get("keys")) if f.get("keys") is not None else "",
            "resource": f.get("resource_name") or "",
            "permission": f.get("permission") or "",
            "spStatus": "Enabled" if f.get("sp_enabled") else "Disabled",
            "severity": f.get("severity", "Info"),
        })
    elif table_id == "ad-sync-users-table":
        fields.update({
            "adUser": f.get("user_display") or "", "adUpn": f.get("user_upn") or "",
            "adCn": f.get("ad_cn") or "", "adDn": f.get("ad_dn") or "",
            "adSid": f.get("ad_sid") or "", "adPw": f.get("pw_change") or "",
            "adTags": ", ".join(f.get("tags", [])),
            "caExcl": str(len(f.get("ca_exclusions", []))),
            "adStatus": "Enabled" if (f.get("status") or {}).get("enabled") else "Disabled",
        })
    elif table_id == "table-ca_exposure":
        fields.update({
            "polName": f.get("policy_name") or "", "polState": f.get("state") or "",
            "polScope": f.get("scope") or "",
            "polApps": ", ".join((f.get("conditions_html") or {}).get("apps") or []),
            "polControls": ", ".join((f.get("conditions_html") or {}).get("controls") or []),
            "polInc": str(len(f.get("included", []))),
            "polExc": str(len(f.get("excluded", []))),
            "severity": f.get("severity", "Info"),
        })
    elif table_id == "app-dir-roles-table":
        t = f.get("target") or {}
        fields.update({
            "app": t.get("name") or "", "id": t.get("id") or "",
            "appDirRoles": ", ".join(r["name"] for r in f.get("dir_role_tags", [])),
            "status": (f.get("status") or {}).get("label") or "",
            "severity": f.get("severity", "Info"),
        })
    else:  # generic table-<check_id>
        t = f.get("target") or {}
        fields.update({
            "target": t.get("name") or "", "targetType": t.get("type") or "",
            "id": t.get("id") or "",
            "pw": str(f.get("pw")) if f.get("pw") is not None else "",
            "keys": str(f.get("keys")) if f.get("keys") is not None else "",
            "roleCount": str(f.get("roles")) if f.get("roles") is not None else "",
            "status": (f.get("status") or {}).get("label") or "",
            "severity": f.get("severity", "Info"),
        })
    return fields


def build_serve_records(results):
    """All findings as drilldown records, mirroring the DOM record model so
    serve-mode drilldowns match over the full dataset (not just loaded pages)."""
    records = []

    def add(fields, sp="", app="", owner="", gid="", pid=""):
        rec = {"__ids": {"sp": sp, "app": app, "owner": owner}, "__gid": gid, "__pid": pid}
        rec.update(fields)
        records.append(rec)

    for res in results:
        for f in res["findings"]:
            o = f.get("object_ids") or {}
            sp_id = next(iter(o.get("sp", set())), "")
            app_id = next(iter(o.get("app", set())), "")
            owner_id = next(iter(o.get("user", set())), "")
            if res["id"] == "priv_app_ownership":
                for owner in f.get("owners", []):
                    add(serve_field_map("owned-table", f, owner),
                        sp=f.get("principal_id", ""), app=f.get("app_object_id") or "",
                        owner=owner.get("object_id", ""))
            elif res["id"] == "groups":
                gid = f.get("group_id", "")
                add(serve_field_map("groups-table", f), gid=gid)
                if f.get("dyn_rule"):
                    add(serve_field_map("dynamic-groups-table", f), gid=gid)
            elif res["id"] == "ad_sync_users":
                add(serve_field_map("ad-sync-users-table", f), owner=f.get("user_id", ""))
            elif res["id"] == "ca_exposure":
                add(serve_field_map("table-ca_exposure", f), pid=f.get("policy_id", ""))
            else:
                t = f.get("target") or {}
                add(serve_field_map(_serve_table_id(res["id"]), f),
                    sp=sp_id, app=app_id, owner=owner_id,
                    pid=t.get("id", "") if t.get("type") == "Policy" else "")
    return records


def _serve_int(qs, key, default, lo, hi):
    try:
        return min(hi, max(lo, int((qs.get(key) or [str(default)])[0] or default)))
    except (ValueError, TypeError):
        return default


def serve_table_response(table_id, qs):
    entry = SERVE_STATE["tables"].get(table_id)
    if not entry:
        return {"error": f"unknown table: {table_id}"}, 404
    q = (qs.get("q") or [""])[0]
    mode = (qs.get("mode") or [""])[0]
    page = _serve_int(qs, "page", 1, 1, 10 ** 9)
    size = _serve_int(qs, "size", 25, 25, 2000)
    sort = (qs.get("sort") or [""])[0]
    desc = ((qs.get("dir") or ["asc"])[0]).lower() == "desc"
    skmap = entry.get("sort_keys") or {}
    sort_key = skmap.get(sort, sort)
    findings = entry["findings"]
    row_q = q
    if mode == "advanced" and q:
        try:
            ast = parse_advanced_query(q)
        except AdvancedParseError:
            ast = None  # fall back to substring behaviour below
        if ast is not None:
            if table_id == "owned-table":
                # the owned table renders one row per owner: filter at the
                # (finding, owner) row level so owner predicates keep only the
                # matching owner rows (same semantics as the static report)
                filtered = []
                for f in findings:
                    owners = [o for o in f.get("owners", [])
                              if evaluate_advanced(
                                  ast, serve_field_map("owned-table", f, o),
                                  entry["search"](f))]
                    if owners:
                        f2 = dict(f)
                        f2["owners"] = owners
                        filtered.append(f2)
                findings = filtered
            else:
                findings = [f for f in findings
                            if evaluate_advanced(ast, serve_field_map(table_id, f),
                                                 entry["search"](f))]
            row_q = ""
    if table_id == "owned-table":
        # one row per owner: paginate by row, not by finding
        rows_html, _ = entry["rows"](findings, q=row_q, sort_key=sort_key, desc=desc)
        total = len(rows_html)
        pages = max(1, -(-total // size))
        page = min(page, pages)
        start = (page - 1) * size
        return {
            "rows_html": "".join(rows_html[start:start + size]),
            "total": total,
            "page": page,
            "pages": pages,
            "size": size,
        }, 200
    rows, total = entry["rows"](findings, q=row_q, sort_key=sort_key, desc=desc)
    pages = max(1, -(-total // size))
    page = min(page, pages)
    start = (page - 1) * size
    return {
        "rows_html": "".join(rows[start:start + size]),
        "total": total,
        "page": page,
        "pages": pages,
        "size": size,
    }, 200


def serve_profile_response(kind, oid):
    if kind == "user":
        prof = next((f for f in SERVE_STATE["user_findings"] if f.get("user_id") == oid), None)
    elif kind in ("sp", "app"):
        prof = SERVE_STATE["profiles2"].get(kind, {}).get(oid)
    elif kind == "group":
        prof = SERVE_STATE["group_profiles"].get(oid)
    elif kind == "policy":
        prof = SERVE_STATE["policy_profiles"].get(oid)
    else:
        return {"error": f"unknown profile kind: {kind}"}, 400
    if prof is None:
        return {"error": "not found"}, 404
    return prof, 200


def serve_details_response(kind, oid):
    rec = SERVE_STATE["details"].get(kind, {}).get(oid)
    if rec is None:
        return {"error": "not found"}, 404
    return rec, 200


def serve_drilldown_response(qs):
    field = (qs.get("field") or [""])[0]
    value = (qs.get("value") or [""])[0]
    columns = SERVE_DRILLDOWN_COLUMNS.get(field)
    if not columns:
        return {"error": f"unsupported drilldown field: {field}"}, 400
    contains = field in SERVE_CONTAINS_FIELDS
    matches = []
    for rec in SERVE_STATE["records"]:
        v = rec.get(field, "") or ""
        if contains:
            hit = value in [x.strip() for x in v.split(",")]
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
    return {
        "title": f"{SERVE_FIELD_LABELS.get(field, field)}: {value}",
        "subtitle": f"{len(matches)} matching finding(s) in the collected set",
        "thead_html": thead,
        "rows_html": "".join(rows_html),
    }, 200


class AuditServeHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, body_bytes, ctype, code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        try:
            path = parsed.path
            if path in ("/", "/index.html"):
                self._send(SERVE_STATE["shell"].encode("utf-8"), "text/html; charset=utf-8")
            elif path == "/api/drilldown":
                data, code = serve_drilldown_response(qs)
                self._send(json.dumps(data).encode("utf-8"), "application/json; charset=utf-8", code)
            elif path.startswith("/api/table/"):
                tid = urllib.parse.unquote(path[len("/api/table/"):])
                data, code = serve_table_response(tid, qs)
                self._send(json.dumps(data).encode("utf-8"), "application/json; charset=utf-8", code)
            elif path.startswith("/api/profile/"):
                kind, _, oid = urllib.parse.unquote(path[len("/api/profile/"):]).partition("/")
                data, code = serve_profile_response(kind, oid)
                self._send(json.dumps(data, default=str).encode("utf-8"),
                           "application/json; charset=utf-8", code)
            elif path.startswith("/api/details/"):
                kind, _, oid = urllib.parse.unquote(path[len("/api/details/"):]).partition("/")
                data, code = serve_details_response(kind, oid)
                self._send(json.dumps(data, default=str).encode("utf-8"),
                           "application/json; charset=utf-8", code)
            elif path.startswith("/api/user/"):
                uid = urllib.parse.unquote(path[len("/api/user/"):])
                data, code = serve_profile_response("user", uid)
                self._send(json.dumps(data, default=str).encode("utf-8"),
                           "application/json; charset=utf-8", code)
            else:
                self._send(b'{"error": "not found"}', "application/json; charset=utf-8", 404)
        except Exception as exc:  # noqa: BLE001 - surface errors for debugging
            self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                       "application/json; charset=utf-8", 500)


def start_serve(port):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), AuditServeHandler)
    print(f"Serving audit report on http://127.0.0.1:{port} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="roadrecon.db", help="Path to the roadrecon SQLite database (default: roadrecon.db)")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="Path to the privileged-roles config JSON (default: privileged_roles.json)")
    parser.add_argument("--azure-config", default=str(DEFAULT_AZURE_CONFIG), help="Path to the azure-roles config JSON (default: azure_roles.json)")
    parser.add_argument("--output", default="entra-surface-report.html", help="Path to write the HTML report (default: entra-surface-report.html)")
    parser.add_argument("--include-disabled", action="store_true", help="Include disabled/soft-deleted service principals in the report")
    parser.add_argument("--check", action="append", metavar="CHECK[,CHECK...]",
                        help="Only run the given checks (comma-separated). See the module docstring for check ids.")
    parser.add_argument("--exclude-check", action="append", metavar="CHECK[,CHECK...]",
                        help="Skip the given checks (comma-separated).")
    parser.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default=None,
                        help="Drop findings below this severity (default: from config, usually Info)")
    parser.add_argument("--serve", action="store_true",
                        help="Serve the report over HTTP on 127.0.0.1 instead of writing a static file "
                             "(users table, profiles and drilldowns are fetched on demand - scales to large tenants)")
    parser.add_argument("--port", type=int, default=8787,
                        help="Port for --serve (default: 8787)")
    parser.add_argument("--timing", action="store_true",
                        help="Print per-phase timings and peak memory at the end of the run")
    args = parser.parse_args()

    db_path = Path(args.db)
    config_path = Path(args.config)
    output_path = Path(args.output)

    if not db_path.exists():
        print(f"error: database not found: {db_path}", file=sys.stderr)
        return 1
    if not config_path.exists():
        print(f"error: config not found: {config_path}", file=sys.stderr)
        return 1

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cur = conn.cursor()

    tenant_name = None
    try:
        cur.execute("SELECT displayName FROM TenantDetails LIMIT 1")
        row = cur.fetchone()
        tenant_name = row[0] if row else None
    except sqlite3.OperationalError:
        pass

    config_resources, check_cfg = load_config(config_path)

    def timed(label, fn):
        t0 = time.perf_counter()
        r = fn()
        if args.timing:
            print(f"[timing] {label:<36s} {time.perf_counter() - t0:7.1f}s")
        return r

    graph = timed("build_graph", lambda: build_graph(cur))
    azure_role_sev = load_azure_roles(args.azure_config)
    check_cfg["azure_roles"] = azure_role_sev
    timed("apply_azure_severity", lambda: apply_azure_severity(graph, azure_role_sev))
    # shared role resolution: computed once, reused by the checks, the
    # severity bump, the entity profiles and the report embed
    group_roles = timed("compute_group_roles",
                        lambda: compute_group_roles(graph, check_cfg))
    group_eligible_roles = timed("compute_group_eligible_roles",
                                 lambda: compute_group_eligible_roles(graph, check_cfg))
    sp_dir_resolver = make_sp_dir_resolver(graph, group_roles,
                                           check_cfg["directory_roles"],
                                           group_eligible_roles)
    results = timed("run_checks",
                    lambda: run_checks(graph, config_resources, check_cfg, args,
                                       group_roles=group_roles,
                                       group_eligible_roles=group_eligible_roles,
                                       sp_dir_resolver=sp_dir_resolver))

    sp_ids = set()
    app_ids = set()
    user_ids = set()
    device_ids = set()
    for res in results:
        for f in res["findings"]:
            o = f.get("object_ids") or {}
            sp_ids |= o.get("sp", set())
            app_ids |= o.get("app", set())
            user_ids |= o.get("user", set())
            device_ids |= o.get("device", set())
    # owned objects / devices inside user profiles need cards too when clicked
    for res in results:
        if res["id"] != "privileged_users":
            continue
        for f in res["findings"]:
            for obj in f.get("owned_objects", []):
                t = obj.get("type")
                if t == "Application":
                    app_ids.add(obj.get("object_id"))
                elif t == "Service Principal":
                    sp_ids.add(obj.get("object_id"))
            for dev in f.get("devices", []):
                device_ids.add(dev.get("object_id"))
    entity_details = timed(
        "fetch_full_details",
        lambda: fetch_full_details(cur, sp_ids, app_ids,
                                   set() if args.serve else user_ids, device_ids))
    if args.serve:
        # serve mode never uses raw user details (profiles come from the
        # in-memory findings on demand) - keep the shell lean
        entity_details["user"] = {}
    entity_profiles = timed("build_entity_profiles",
                            lambda: build_entity_profiles(
                                graph, check_cfg, sp_ids, app_ids,
                                group_roles=group_roles,
                                group_eligible_roles=group_eligible_roles,
                                sp_dir_resolver=sp_dir_resolver))
    tenant_summary = timed("build_tenant_summary",
                           lambda: build_tenant_summary(graph, results))
    conn.close()

    min_severity_label = args.min_severity or check_cfg.get("min_severity", "Info")
    serve_tables = {} if args.serve else None
    if args.serve:
        # nothing heavy gets embedded into the shell in serve mode; profiles
        # and raw details are fetched on demand from the endpoints below
        entity_details_render = {"sp": {}, "app": {}, "user": {}, "device": {}}
        entity_profiles_render = {"sp": {}, "app": {}}
    else:
        entity_details_render, entity_profiles_render = entity_details, entity_profiles
    report_html = timed("render_report",
                        lambda: render_report(results, tenant_name, db_path, config_path,
                                              args.include_disabled, entity_details_render,
                                              min_severity_label, entity_profiles_render,
                                              tenant_summary, graph=graph,
                                              serve_mode=args.serve, serve_tables=serve_tables,
                                              group_roles=group_roles,
                                              group_eligible_roles=group_eligible_roles))

    total = sum(len(res["findings"]) for res in results)

    if args.serve:
        SERVE_STATE["shell"] = report_html
        SERVE_STATE["tables"] = serve_tables or {}
        SERVE_STATE["user_findings"] = next(
            (res["findings"] for res in results if res["id"] == "privileged_users"), [])
        SERVE_STATE["profiles2"] = entity_profiles
        SERVE_STATE["group_profiles"] = {
            f["group_id"]: f for res in results if res["id"] == "groups"
            for f in res["findings"]}
        SERVE_STATE["policy_profiles"] = {
            f["policy_id"]: f for res in results if res["id"] == "ca_exposure"
            for f in res["findings"] if f.get("policy_id")}
        SERVE_STATE["details"] = {k: v for k, v in entity_details.items()
                                  if k in ("sp", "app", "device")}
        SERVE_STATE["records"] = build_serve_records(results)
        # Release the analysis working set before serving: everything the page
        # needs is embedded in the shell or held in SERVE_STATE above.
        del graph, results
        gc.collect()
        if args.timing:
            import resource
            print(f"[timing] peak RSS: {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.0f} MB")
        start_serve(args.port)
        return 0

    output_path.write_text(report_html, encoding="utf-8")
    print(f"Wrote {total} finding(s) to {output_path}")
    if args.timing:
        import resource
        print(f"[timing] peak RSS: {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.0f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())

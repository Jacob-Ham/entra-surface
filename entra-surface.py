#!/usr/bin/env python3
"""
Entra ID attack-surface.

Reads a roadrecon SQLite database (https://github.com/dirkjanm/ROADtools) and
runs a registry of checks that surface dangerous users, applications, service
principals, and tenant configuration. Each check emits structured findings
(check_id, category, severity, evidence, object ids); a single renderer turns
them into a sortable/filterable HTML report with drilldown and entity details,
served interactively over HTTP (rows, profiles and drilldowns are fetched on
demand, so it scales to large tenants). Without --db, it serves the GUI shell
with no analysis data. The tool always runs every enabled check and serves the
whole report; check selection lives in the config.

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
  azure_arc_machines      - Arc-enabled servers (Microsoft.HybridCompute managed
                            identities), with subscription and resource group
  azure_arc_sps           - principals holding Azure Arc ARM roles (matched by
                            built-in role-definition GUIDs) and service principals
                            created by the Arc deployment wizard (AzureArcSPN tag)
  azure_arc_providers     - first-party Microsoft Arc service principals present
                            in the tenant (subscription configured for Arc)
"""
import argparse
import datetime
import gc
import gzip
import hashlib
import html
import http.server
import json
import re
import sqlite3
import sys
import threading
import time
import urllib.parse
from collections import defaultdict, Counter
from pathlib import Path

from entra_surface import analysis
from entra_surface import collect as collect_backend
from entra_surface import settings as surface_settings

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

CATEGORY_ORDER = ["apps", "users", "ad", "groups", "configs", "arc"]
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
    "arc": "Azure Arc",
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


ELIGIBLE_SEVERITY_STEP = {
    "Critical": "High",
    "High": "Medium",
    "Medium": "Low",
    "Low": "Info",
    "Info": "Info",
}


def eligible_severity(severity):
    """PIM-eligible roles are rated one notch below the same role held
    actively: an eligible Global Administrator is High, not Critical, until
    the role is activated."""
    return ELIGIBLE_SEVERITY_STEP.get(severity, "Info")


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
    "azapp": ["azapp"], "azgroup": ["azgroup"], "azuser": ["azuser"],
    "azroles": ["azroles"], "azsproles": ["azsproles"], "azusrroles": ["azusrroles"],
    "azscopetype": ["azscopetype"], "azsub": ["azsub"], "azrg": ["azrg"],
    "azprovider": ["azprovider"], "azresource": ["azresource"],
    "arcmachine": ["arcmachine"], "arcsub": ["arcsub"], "arcrg": ["arcrg"],
    "arcresourceid": ["arcresourceid"], "arcstatus": ["arcstatus"],
    "arcprincipal": ["arcprincipal"], "arcprincipaltype": ["arcprincipaltype"],
    "arctag": ["arctag"], "arcazroles": ["arcazroles"], "arcprovider": ["arcprovider"],
    "pwlastset": ["pwlastset"],
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

    def is_value_terminator(tok):
        """A word token that ends an unquoted value: operators and uniq: clauses."""
        return (is_any_operator(tok)
                or (tok is not None and tok[0] == "word"
                    and tok[1].upper().startswith("UNIQ:")))

    def consume_value_words(value):
        """Append following plain words to an unquoted value so that values
        with spaces work without quotes: `roles:Global Administrator AND ...`."""
        while True:
            tok = peek()
            if tok is None or tok[0] != "word" or is_value_terminator(tok):
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
        if field.upper() == "UNIQ":
            names = [n.strip() for n in rest.split(",") if n.strip()]
            if not names:
                vt = peek()
                if vt is None or vt[0] not in ("word", "quoted"):
                    raise AdvancedParseError(f"expected field after 'uniq:'")
                advance()
                names = [vt[1]]
            fields = []
            for n in names:
                fields.extend(resolve_field(n))
            return {"op": "uniq", "fields": fields}
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
    if op == "uniq":
        # dedupe clauses are not predicates; the caller extracts them separately
        return True
    return False


def extract_uniq_fields(ast):
    """Collect the dedupe key fields from all uniq: clauses (order preserved,
    duplicates dropped). Empty when the query carries no uniq: clause."""
    out = []

    def walk(node):
        if not node:
            return
        if node.get("op") == "uniq":
            for f in node.get("fields") or []:
                if f not in out:
                    out.append(f)
            return
        for c in node.get("children") or []:
            walk(c)
        if node.get("child"):
            walk(node["child"])

    walk(ast or {})
    return out


# ---------------------------------------------------------------------------
# Entity graph
# ---------------------------------------------------------------------------

SP_GRAPH_FIELDS = [
    "objectId", "appId", "displayName", "appDisplayName", "accountEnabled",
    "deletionTimestamp", "servicePrincipalType", "appOwnerTenantId",
    "microsoftFirstParty", "appRoleAssignmentRequired", "passwordCredentials",
    "keyCredentials", "appRoles", "publicClient",
    "tags", "managedIdentityResourceId", "alternativeNames", "publisherName",
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
             "directory_settings": {},
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
    graph["directory_settings"] = load_table(
        "DirectorySettings", "id", ["id", "displayName", "templateId", "values"])

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
    graph["az_sub_names"] = sub_names

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
            "role_def_id": (extra.get("role_definition_id") or "").rsplit("/", 1)[-1],
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

    # ---- PIM (privileged identity management) -------------------------------
    # The legacy v1 tables (RoleAssignments / EligibleRoleAssignments, AAD
    # Graph) are always loaded above. The richer PIM v2 governance data comes
    # from `roadrecon pimgather` (api.azrbac.mspim.azure.com) and is frequently
    # absent: every table here loads defensively so empty databases render the
    # same as before. Populated tables upgrade the PIM checks below.
    graph["pim_providers"] = []
    try:
        cur.execute("SELECT id FROM PIMprivilegedAccesss")
        graph["pim_providers"] = [r[0] for r in cur.fetchall() if r[0]]
    except sqlite3.OperationalError:
        pass

    graph["pim_resources"] = {}
    try:
        cur.execute('SELECT id, "displayName", type, status FROM PIMgovernanceResources')
        graph["pim_resources"] = {
            r[0]: {"display_name": r[1], "type": r[2], "status": r[3]}
            for r in cur.fetchall() if r[0]}
    except sqlite3.OperationalError:
        pass

    graph["pim_role_defs"] = {}
    try:
        cur.execute('SELECT id, "resourceId", "displayName", "templateId" '
                    "FROM PIMgovernanceRoleDefinitions")
        graph["pim_role_defs"] = {
            r[0]: {"resource_id": r[1], "display_name": r[2], "template_id": r[3]}
            for r in cur.fetchall() if r[0]}
    except sqlite3.OperationalError:
        pass

    def _load_pim_settings_table(table, columns):
        out = {}
        try:
            cur.execute(f"PRAGMA table_info({table})")
            available = {r[1] for r in cur.fetchall()}
            cols = [c for c in columns if c in available]
            if cols:
                cur.execute(f"SELECT {', '.join(cols)} FROM {table}")
                for row in cur.fetchall():
                    rec = dict(zip(cols, row))
                    if rec.get("id"):
                        out[rec["id"]] = rec
        except sqlite3.OperationalError:
            pass
        return out

    graph["pim_role_settings"] = _load_pim_settings_table(
        "PIMgovernanceRoleSettings",
        ["id", "resourceId", "roleDefinitionId", "isDefault", "lastUpdatedDateTime",
         "adminEligibleSettings", "adminMemberSettings",
         "userEligibleSettings", "userMemberSettings"])
    graph["pim_role_settings_v2"] = _load_pim_settings_table(
        "PIMgovernanceRoleSettingV2s",
        ["id", "resourceId", "roleDefinitionId", "isDefault", "lastUpdatedDateTime",
         "lifeCycleManagement"])

    graph["pim_role_assignments"] = []
    try:
        cur.execute("SELECT id, resourceId, roleDefinitionId, subjectId, "
                    "linkedEligibleRoleAssignmentId, isPermanent, startDateTime, "
                    "endDateTime, memberType, assignmentState, status "
                    "FROM PIMgovernanceRoleAssignments")
        for row in cur.fetchall():
            if not row[0]:
                continue
            graph["pim_role_assignments"].append({
                "id": row[0], "resource_id": row[1], "role_definition_id": row[2],
                "subject_id": row[3], "linked_eligible_id": row[4],
                "is_permanent": bool(row[5]), "start": row[6], "end": row[7],
                "member_type": row[8], "assignment_state": row[9], "status": row[10],
            })
    except sqlite3.OperationalError:
        pass

    graph["pim_alerts"] = []
    try:
        cur.execute("SELECT id, resourceId, alertName, alertDescription, "
                    "numberOfAffectedItems, severityLevel, isActive, status, "
                    "mitigationSteps, howToPrevent, lastScannedDateTime "
                    "FROM PIMgovernanceAlerts")
        for row in cur.fetchall():
            if not row[0]:
                continue
            graph["pim_alerts"].append({
                "id": row[0], "resource_id": row[1], "name": row[2],
                "description": row[3], "affected": row[4], "severity_level": row[5],
                "is_active": bool(row[6]), "status": row[7],
                "mitigation": row[8], "prevention": row[9], "scanned": row[10],
            })
    except sqlite3.OperationalError:
        pass

    # PIM-governance role assignment subjects -> users/groups/SPs (v2 links)
    def _load_pim_subjects(table, column):
        out = {}
        try:
            cur.execute(f'SELECT "{column}", PIMgovernanceRoleAssignment '
                        f"FROM {table}")
            for subject_id, assign_id in cur.fetchall():
                if subject_id and assign_id:
                    out[assign_id] = subject_id
        except sqlite3.OperationalError:
            pass
        return out

    graph["pim_assign_subject"] = {}
    graph["pim_assign_subject"].update(
        _load_pim_subjects("lnk_pim_roleassignment_subjectuser", "User"))
    graph["pim_assign_subject"].update(
        _load_pim_subjects("lnk_pim_roleassignment_subjectgroup", "Group"))
    graph["pim_assign_subject"].update(
        _load_pim_subjects("lnk_pim_roleassignment_subjectserviceprincipal",
                           "ServicePrincipal"))

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
    roles (rated one notch below the same role held actively), ownership of
    apps/SPs that hold privileged grants (from the app-permission config) or
    directory roles, and membership/ownership of role-capable groups.
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

    # ---- directory roles on owned SPs (direct, legacy role membership, and
    # group-inherited incl. nesting) ----------------------------------------
    def sp_dir_roles(sp_oid):
        """Active directory roles of an SP: direct assignments, classic role
        memberships, and roles inherited through group memberships (nested)."""
        merged = {}

        def add(name):
            if name not in merged:
                merged[name] = name

        for ra in graph["directory_role_assigns"]:
            if ra["principal_id"] == sp_oid:
                add(def_name(ra["role_definition_id"]))
        for role_oid, sid in graph["role_member_sp"]:
            if sid == sp_oid:
                rec = graph["directory_role"].get(role_oid) or {}
                add(rec.get("displayName") or role_oid)
        stack = [gid for gid, sps in graph["group_member_sp"].items()
                 if sp_oid in sps]
        seen = set()
        while stack:
            gid = stack.pop()
            if gid in seen:
                continue
            seen.add(gid)
            for r in group_roles.get(gid) or []:
                add(r["name"])
            for parent, kids in graph["group_member_group"].items():
                if gid in kids:
                    stack.append(parent)
        return list(merged.values())

    for sp_oid, sp in graph["sp"].items():
        names = sp_dir_roles(sp_oid)
        if not names:
            continue
        entries = [{"sp_name": sp_name(sp), "role": name, "severity": sev_of(name)}
                   for name in names]
        owners = set(graph["sp_owners"].get(sp_oid, set()))
        # owners of the app registration behind the SP inherit the same
        # takeover (they can add credentials to the SP)
        for a_oid in graph["app_by_appid"].get(sp.get("appId"), []):
            owners |= graph["app_owners"].get(a_oid, set())
        for owner in owners:
            for entry in entries:
                ensure(owner)["dir_sp_roles"].append(dict(entry))

    for ea in graph["eligible_role_assigns"]:
        pid = ea["principal_id"]
        if pid in graph["user"]:
            p = ensure(pid)
            name = def_name(ea["role_definition_id"])
            p["eligible_roles"].append({
                "name": name, "severity": eligible_severity(sev_of(name)),
                "source": "PIM eligible",
                "scope": pim_scope_label(ea.get("resource_scopes")),
            })

    # v2-only eligible assignments (roadrecon pimgather) when the legacy v1
    # tables don't carry them
    for a in graph.get("pim_role_assignments") or []:
        if (a.get("assignment_state") or "").lower() != "eligible":
            continue
        subject = graph.get("pim_assign_subject", {}).get(a["id"]) or a.get("subject_id")
        if not subject or subject not in graph["user"]:
            continue
        name = _pim_role_def_name(graph, a.get("role_definition_id"))
        p = ensure(subject)
        if any(r["name"] == name for r in p["eligible_roles"]):
            continue
        p["eligible_roles"].append({
            "name": name, "severity": eligible_severity(sev_of(name)),
            "source": "PIM eligible",
        })

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
                p["eligible_roles"].append({
                    "name": r["name"], "severity": r["severity"],
                    "source": "PIM eligible via " + " \u2192 ".join(r["path"]),
                    "path": list(r["path"]),
                })
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
                {"app_name": app.get("displayName") or app_oid, "grants": app_grants,
                 "kind": "application"})

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
            ensure(uid)["priv_apps"].append(
                {"app_name": label, "grants": grants, "kind": "service principal"})

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
                entry = {"name": key, "severity": r["severity"], "source": src}
                for extra in ("scope", "path"):
                    if r.get(extra):
                        entry[extra] = r[extra]
                merged[key] = entry
            else:
                srcs = [s.strip() for s in merged[key]["source"].split("\u00b7")]
                if src not in srcs:
                    srcs.append(src)
                merged[key]["source"] = " \u00b7 ".join(srcs)
                for extra in ("scope", "path"):
                    if not merged[key].get(extra) and r.get(extra):
                        merged[key][extra] = r[extra]
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
        # PIM v2 schedule details (permanence / member type / activation
        # window) when `roadrecon pimgather` governance data is present.
        # Group-inherited eligibility matches the eligibility on the group.
        if graph.get("pim_role_assignments"):
            for r in p["eligible_roles"]:
                subjects = {uid} | set(r.get("path") or [])
                for a in graph["pim_role_assignments"]:
                    if (a.get("assignment_state") or "").lower() != "eligible":
                        continue
                    subject = graph["pim_assign_subject"].get(a["id"]) or a.get("subject_id")
                    if subject not in subjects:
                        continue
                    if _pim_role_def_name(graph, a.get("role_definition_id")) != r["name"]:
                        continue
                    r["schedule"] = {
                        "permanent": bool(a.get("is_permanent")),
                        "member_type": a.get("member_type") or "",
                        "start": str(a.get("start") or "")[:10],
                        "end": str(a.get("end") or "")[:10],
                        "assignment_state": a.get("assignment_state") or "",
                        "status": a.get("status") or "",
                    }
                    break
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
        # owning a role-capable group is a takeover path: rate by the roles
        # the group actually carries; capable-but-unassigned groups stay High
        for g in p["owned_cap"]:
            role_sevs = [r["severity"] for r in (g.get("roles") or [])]
            if role_sevs:
                sevs += role_sevs
            else:
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


# ---- sync authentication mode (PHS / PTA / federation) markers -------------
# The EnforceCloudPasswordPolicyForPasswordSyncedUsers value only exists in
# tenants using Password Hash Sync; the PTA agent and ADFS surface as
# well-known first-party service principals. Template/name constants are
# stable across tenants (never user-controlled display text).
PASSWORD_RULE_SETTINGS_TEMPLATE_ID = "5cf42378-d67d-4f36-ba46-e8b86229381d"
PHS_ENFORCE_SETTING = "EnforceCloudPasswordPolicyForPasswordSyncedUsers"
PTA_AGENT_SP_NAMES = {"Microsoft Azure AD Connect Authentication Agent"}
FEDERATION_SP_NAMES = {"Active Directory Federation Services", "ADFS"}


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

    # ---- authentication mode: PHS / PTA / federation -----------------------
    # PHS is an on-prem connector setting with no direct Entra-side flag; the
    # only PHS-specific marker visible from collected data is the
    # EnforceCloudPasswordPolicyForPasswordSyncedUsers directory setting
    # (present solely in PHS tenants). Writeback alone only proves PHS or PTA.
    phs_present, phs_enforce = False, None
    for rec in graph.get("directory_settings", {}).values():
        if (rec.get("templateId") or "") != PASSWORD_RULE_SETTINGS_TEMPLATE_ID:
            continue
        for v in json_list(rec.get("values")):
            if isinstance(v, dict) and v.get("name") == PHS_ENFORCE_SETTING:
                phs_present = True
                phs_enforce = str(v.get("value") or "").lower() in ("true", "1")
    pta = any(rec.get("displayName") in PTA_AGENT_SP_NAMES
              for rec in graph["sp"].values())
    federated = any(rec.get("displayName") in FEDERATION_SP_NAMES
                    for rec in graph["sp"].values())

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

    if phs_present:
        auth_mode = ("Password Hash Sync (PHS)"
                     + (" \u00b7 enforcing cloud password policy for synced users"
                        if phs_enforce else ""))
        auth_short = "PHS"
        auth_detail = (f"{PHS_ENFORCE_SETTING} = "
                       + ("True" if phs_enforce else "False"))
    elif pta:
        auth_mode = "Pass-through Authentication (PTA)"
        auth_short = "PTA"
        auth_detail = "PTA agent service principal present"
    elif federated:
        auth_mode = "Federated (ADFS)"
        auth_short = "Federated"
        auth_detail = "ADFS service principal present"
    elif onprem or writeback["count"]:
        auth_mode = "PHS or PTA"
        auth_short = "PHS / PTA"
        auth_detail = ("writeback requires the AD DS connector; collected data "
                       "does not distinguish PHS from PTA")
    else:
        auth_mode = "Unknown"
        auth_short = ""
        auth_detail = "no sync observed"
    auth = {"mode": auth_mode, "short": auth_short, "detail": auth_detail,
            "phs_present": phs_present, "phs_enforce": phs_enforce,
            "pta": pta, "federated": federated}

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
        "label": "Authentication mode", "present": bool(auth_short),
        "detail": f"{auth_mode} \u2014 {auth_detail}",
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
    f["auth_mode"] = auth
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
    # only — shown with an '(eligible)' marker, rated one notch below active.
    if group_eligible_roles is not None:
        for ea in graph["eligible_role_assigns"]:
            if ea["principal_id"] == sp_oid:
                name = _def_name(ea["role_definition_id"])
                if name not in seen:
                    seen.add(name)
                    roles.append({"name": name, "severity": eligible_severity(role_sev.get(name, "Info")),
                                  "path": None, "eligible": True})
        # v2-only direct eligibility (pimgather)
        for a in graph.get("pim_role_assignments") or []:
            if (a.get("assignment_state") or "").lower() != "eligible":
                continue
            subject = graph.get("pim_assign_subject", {}).get(a["id"]) or a.get("subject_id")
            if subject != sp_oid:
                continue
            name = _pim_role_def_name(graph, a.get("role_definition_id"))
            if name not in seen:
                seen.add(name)
                roles.append({"name": name, "severity": eligible_severity(role_sev.get(name, "Info")),
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
    data rated one notch below the active severity of the same role."""
    role_sev = check_cfg["directory_roles"]

    def _gdef_name(oid):
        rec = graph["role_definition"].get(oid)
        return rec.get("displayName") if rec else oid

    def _gsev(name):
        return eligible_severity(role_sev.get(name, "Info"))

    out = defaultdict(list)
    for ea in graph["eligible_role_assigns"]:
        if ea["principal_id"] in graph["group"]:
            name = _gdef_name(ea["role_definition_id"])
            out[ea["principal_id"]].append({"name": name, "severity": _gsev(name)})
    # v2-only group eligibility (pimgather) when the v1 tables don't carry it
    for a in graph.get("pim_role_assignments") or []:
        if (a.get("assignment_state") or "").lower() != "eligible":
            continue
        subject = graph.get("pim_assign_subject", {}).get(a["id"]) or a.get("subject_id")
        if not subject or subject not in graph["group"]:
            continue
        name = _pim_role_def_name(graph, a.get("role_definition_id"))
        if not any(r["name"] == name for r in out.get(subject, [])):
            out[subject].append({"name": name, "severity": _gsev(name)})
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
        eligible_roles = [dict(r) for r in group_eligible_roles.get(gid, [])]
        # enrich group eligibility with scope + PIM v2 schedule details
        for r in eligible_roles:
            for a in (graph.get("pim_role_assignments") or []):
                if (a.get("assignment_state") or "").lower() != "eligible":
                    continue
                subject = graph["pim_assign_subject"].get(a["id"]) or a.get("subject_id")
                if subject != gid:
                    continue
                if _pim_role_def_name(graph, a.get("role_definition_id")) != r["name"]:
                    continue
                r["schedule"] = {
                    "permanent": bool(a.get("is_permanent")),
                    "member_type": a.get("member_type") or "",
                    "start": str(a.get("start") or "")[:10],
                    "end": str(a.get("end") or "")[:10],
                    "assignment_state": a.get("assignment_state") or "",
                    "status": a.get("status") or "",
                }
                break
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


# ---------------------------------------------------------------------------
# PIM helpers (eligible-role drawer enrichment: scope + schedule details)
# ---------------------------------------------------------------------------

def _pim_role_def_name(graph, role_def_id):
    """Display name of a PIM role definition (v2 governance id or v1 object id)."""
    rec = graph["pim_role_defs"].get(role_def_id)
    if rec and rec.get("display_name"):
        return rec["display_name"]
    rec = graph["role_definition"].get(role_def_id)
    if rec:
        return rec.get("displayName") or role_def_id
    return role_def_id


def pim_scope_label(raw):
    parts = [p for p in json_list(raw) if isinstance(p, str)]
    if not parts:
        return "Tenant-wide"
    return "Tenant-wide" if parts == ["/"] else ", ".join(parts)


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
    registration: (count, most recent start date, per-credential note lines).
    Defensive against both Graph 'startDateTime' and legacy 'startDate' key
    spellings, and against SPs without a local app registration."""
    rec = (graph.get("sp") or {}).get(oid) or {}
    creds = list(json_list(rec.get("passwordCredentials")))
    for a_oid in (graph.get("app_by_appid") or {}).get(rec.get("appId")) or []:
        a_rec = (graph.get("app") or {}).get(a_oid) or {}
        creds += list(json_list(a_rec.get("passwordCredentials")))
    starts, lines = [], []
    for i, c in enumerate(creds):
        if not isinstance(c, dict):
            continue
        start = c.get("startDateTime") or c.get("startDate") or ""
        end = c.get("endDateTime") or c.get("endDate") or ""
        name = c.get("displayName") or c.get("customKeyIdentifier") or f"secret {i + 1}"
        if start:
            starts.append(start)
        lines.append(f"{name}: {start or '?'} \u2192 {end or '?'}")
    last = max(starts) if starts else ""
    return len(creds), last, "\n".join(lines)


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
        pw, pw_last, pw_note = _sp_password_credentials(graph, oid)
        app_oids = set((graph.get("app_by_appid") or {}).get(rec.get("appId")) or [])
        emit("Service Principal", oid,
             rec.get("displayName") or rec.get("appDisplayName") or oid,
             bool(rec.get("accountEnabled")), tagged, arc_roles,
             {"sp": {oid}, "app": app_oids}, {"pw": pw, "pw_last_set": pw_last,
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
                        "signal: directory roles (assigned or eligible — eligible is "
                        "rated one notch below the same role held actively), ownership of "
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
        "description": "One-line picture of the sync setup: engine in use (Entra Connect on-prem vs likely Cloud Sync), connector host, password-writeback channel, authentication mode (PHS / PTA / federated), Desktop SSO, and sync coverage.",
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
    {
        "id": "azure_arc_machines",
        "category": "arc",
        "title": "Azure Arc machines",
        "description": (""),
        "run": check_azure_arc_machines,
    },
    {
        "id": "azure_arc_sps",
        "category": "arc",
        "title": "Azure Arc access",
        "description": ("Principals holding Azure Arc ARM roles — matched by the built-in "
                        "role-definition GUIDs — and service principals created through the "
                        "Arc deployment wizard (AzureArcSPN tag). Arc role holders can "
                        "onboard machines and run commands on onboarded servers."),
        "run": check_azure_arc_sps,
    },
    {
        "id": "azure_arc_providers",
        "category": "arc",
        "title": "Azure Arc resource providers",
        "description": ("First-party Microsoft Arc service principals present in the tenant "
                        "(matched by appId) — at least one subscription is configured with "
                        "the resource providers required for Arc."),
        "run": check_azure_arc_providers,
    },
]

CHECK_IDS = {spec["id"] for spec in CHECK_SPECS}


def run_checks(graph, config_resources, check_cfg,
               group_roles=None, group_eligible_roles=None, sp_dir_resolver=None):
    """Run every enabled check and return the list of {spec, findings} results."""
    opts = {"include_disabled": True}
    check_config = dict(check_cfg)

    # ---- selection from the config only (the tool always serves the full
    # report: every check that the config has not explicitly disabled) ------
    selected = [spec for spec in CHECK_SPECS
                if not (spec["id"] in check_config["enabled"]
                        and not check_config["enabled"][spec["id"]])]

    min_rank = SEVERITY_ORDER.get(check_config.get("min_severity", "Info"), 4)
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
    "jobTitle", "department", "companyName", "officeLocation", "city", "country",
    "createdDateTime", "dirSyncEnabled",
    "onPremisesUserPrincipalName", "onPremisesObjectIdentifier", "onPremisesSecurityIdentifier",
    "onPremisesDistinguishedName", "onPremisesPasswordChangeTimestamp", "lastDirSyncTime",
    "immutableId", "hasOnPremisesShadow", "isResourceAccount", "creationType",
    "provisioningErrors",
    "lastPasswordChangeDateTime", "refreshTokensValidFromDateTime", "isCompromised",
    "strongAuthenticationDetail", "employeeId", "employeeType", "usageLocation",
]


def fetch_full_details(cur, sp_ids, app_ids, user_ids, device_ids=None):
    """Fetch attributes for the 'expand' drawers. SPs and applications get every
    captured column (for the Raw tab); users and devices keep a curated set.
    SP raw records additionally carry the linked Application row and the raw
    ARM role assignments, so the Raw tab shows everything captured about the
    principal."""
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

    def clean(record):
        return {c: v for c, v in record.items()
                if v is not None and v != "" and v != [] and v != {}}

    def enrich_sp_raw(sp_records):
        """Add 'application' (full Applications row behind the SP) and
        'azure_roles' (raw ARM role assignments incl. eligibility) to every SP
        raw record. Defensive: AZ* tables only exist after azgather."""
        try:
            cur.execute("PRAGMA table_info(Applications)")
            app_cols = {r[1] for r in cur.fetchall()}
            if {"appId", "objectId"}.issubset(app_cols):
                for rec in sp_records.values():
                    app_id = rec.get("appId")
                    if not app_id or "application" in rec:
                        continue
                    cur.execute("SELECT * FROM Applications WHERE appId=? LIMIT 1",
                                (app_id,))
                    row = cur.fetchone()
                    if row is None:
                        continue
                    cols = [d[0] for d in cur.description]
                    app = clean({c: json_safe_value(v) for c, v in zip(cols, row)})
                    if app:
                        rec["application"] = app
        except sqlite3.OperationalError:
            pass
        rd_roles = {}
        try:
            # AZroleDefinitions.name holds the bare GUID while assignment
            # role_definition_id is the full provider path — map in Python
            cur.execute("SELECT name, role_name FROM AZroleDefinitions")
            rd_roles = {guid: rname for guid, rname in cur.fetchall()
                        if guid and rname}
        except sqlite3.OperationalError:
            pass
        try:
            cur.execute("PRAGMA table_info(AZroleAssignments)")
            ra_cols = {r[1] for r in cur.fetchall()}
            if {"id", "scope", "role_definition_id"}.issubset(ra_cols):
                cur.execute(
                    "SELECT sp.ServicePrincipal, ra.id, ra.scope, ra.role_definition_id, "
                    "ra.created_on, ra.condition "
                    "FROM lnk_az_roleassignment_serviceprincipal sp "
                    "JOIN AZroleAssignments ra ON ra.id = sp.AZroleAssignment")
                for oid, ra_id, scope, rd_id, created, cond in cur.fetchall():
                    rec = sp_records.get(oid)
                    if rec is None:
                        continue
                    rec.setdefault("azure_roles", []).append(clean({
                        "id": ra_id, "scope": scope,
                        "role_definition_id": rd_id,
                        "role": rd_roles.get((rd_id or "").rsplit("/", 1)[-1], ""),
                        "created_on": created, "condition": cond,
                    }))
        except sqlite3.OperationalError:
            pass
        try:
            cur.execute("PRAGMA table_info(AZroleEligibilityScheduleInstances)")
            ec_cols = {r[1] for r in cur.fetchall()}
            if {"id", "scope", "role_definition_id"}.issubset(ec_cols):
                cur.execute(
                    "SELECT sp.ServicePrincipal, e.id, e.scope, e.role_definition_id, "
                    "e.status, e.start_date_time, e.end_date_time "
                    "FROM lnk_az_roleassignment_eligible_serviceprincipal sp "
                    "JOIN AZroleEligibilityScheduleInstances e "
                    "  ON e.id = sp.AZroleEligibilityScheduleInstance")
                for oid, eid, scope, rd_id, status, start, end in cur.fetchall():
                    rec = sp_records.get(oid)
                    if rec is None:
                        continue
                    rec.setdefault("azure_roles", []).append(clean({
                        "id": eid, "scope": scope,
                        "role_definition_id": rd_id,
                        "role": rd_roles.get((rd_id or "").rsplit("/", 1)[-1], ""),
                        "eligible": True, "status": status,
                        "start": start, "end": end,
                    }))
        except sqlite3.OperationalError:
            pass
        return sp_records

    sp_records = fetch_all("ServicePrincipals", "objectId", sp_ids, None)
    sp_records = enrich_sp_raw(sp_records)
    return {
        "sp": sp_records,
        "app": fetch_all("Applications", "objectId", app_ids, None),
        "user": fetch_all("Users", "objectId", user_ids, USER_DETAIL_FIELDS),
        "device": fetch_all("Devices", "objectId", device_ids or set(), DEVICE_DETAIL_FIELDS),
    }


def make_profile_builder(graph, check_cfg, group_roles=None, group_eligible_roles=None,
                         sp_dir_resolver=None):
    """On-demand builder for the tabbed SP/app 'more info' drawer profiles.

    Indexes the app-role assignment list (by resource and by principal) and
    the group memberships (SP -> groups) once, so building a single profile
    costs O(roles of that principal) instead of full-table scans. Profiles are
    memoized; the batch wrapper build_entity_profiles() uses this builder."""
    role_sev = check_cfg["directory_roles"]
    role_labels = check_cfg.get("role_labels") or {}
    if group_roles is None:
        group_roles = compute_group_roles(graph, check_cfg)
    if group_eligible_roles is None:
        group_eligible_roles = compute_group_eligible_roles(graph, check_cfg)
    if sp_dir_resolver is None:
        sp_dir_resolver = make_sp_dir_resolver(graph, group_roles, role_sev,
                                               group_eligible_roles)
    app_roles_cache = {}   # sp_oid -> {role_id: {value, description}}
    profile_cache = {}     # sp_oid / app_oid -> profile

    ra_by_resource = defaultdict(list)
    ra_by_principal = defaultdict(list)
    for ra in graph["role_assigns"]:
        ra_by_resource[ra["resource_id"]].append(ra)
        if ra["principal_type"] == "ServicePrincipal":
            ra_by_principal[ra["principal_id"]].append(ra)
    sp_groups = defaultdict(list)
    for gid, members in graph["group_member_sp"].items():
        for sid in members:
            sp_groups[sid].append(gid)

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
                for g in sp_groups.get(sp_oid, ())]

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

    def sp_profile(sp_oid):
        if sp_oid in profile_cache:
            return profile_cache[sp_oid]
        if sp_oid not in graph["sp"]:
            return None
        granted = []   # roles this SP exposes, held by other principals
        for ra in ra_by_resource.get(sp_oid, ()):
            role = resource_roles(sp_oid).get(ra["app_role_id"])
            granted.append({
                "principal_name": principal_label(ra["principal_id"], ra["principal_type"]),
                "principal_type": ra["principal_type"] or "ServicePrincipal",
                "role": role_label(sp_oid, ra["app_role_id"]),
                "description": role["description"] if role else "",
            })
        assigned = []  # roles other SPs expose, held by this SP
        for ra in ra_by_principal.get(sp_oid, ()):
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
        prof = {
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
        profile_cache[sp_oid] = prof
        return prof

    def app_profile(app_oid):
        if app_oid in profile_cache:
            return profile_cache[app_oid]
        app = graph["app"].get(app_oid)
        if not app:
            return None
        sp_oids = graph["sp_by_appid"].get(app.get("appId"), [])
        granted, assigned, dir_roles, groups = [], [], [], []
        owner_ids = set(graph["app_owners"].get(app_oid, set()))
        for sp_oid in sp_oids:
            prof = sp_profile(sp_oid)
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
        entry = {
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
        profile_cache[app_oid] = entry
        return entry

    return {"sp": sp_profile, "app": app_profile}


def build_entity_profiles(graph, check_cfg, sp_ids, app_ids,
                          group_roles=None, group_eligible_roles=None,
                          sp_dir_resolver=None):
    """Relationship data for every referenced SP/app drawer profile (batch
    wrapper around make_profile_builder)."""
    builder = make_profile_builder(graph, check_cfg, group_roles,
                                   group_eligible_roles, sp_dir_resolver)
    profiles = {"sp": {}, "app": {}}
    for sp_oid in sorted(sp_ids):
        if sp_oid in graph["sp"]:
            profiles["sp"][sp_oid] = builder["sp"](sp_oid)
    for app_oid in sorted(app_ids):
        if app_oid in graph["app"]:
            profiles["app"][app_oid] = builder["app"](app_oid)
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


# ---------------------------------------------------------------------------
# Column catalog
# ---------------------------------------------------------------------------
# Every main table declares an ordered list of default columns plus add-on
# columns ("extras"). Each field maps to a renderer returning (inner_html,
# data_value); cells are assembled by row_html() so the default output stays
# byte-identical to the legacy per-table templates. The same catalog drives:
#   * serve mode (the `cols=` request parameter renders any subset/order),
#   * shell-rendered azure-roles tables (extras delivered via data blobs),
#   * the client-side column manager (window.__TABLE_CATALOG).
#
# Extra families: "sp", "user", "group", "policy" (see COLUMN_FAMILIES).

COLUMN_FAMILIES = {
    "sp": "SP / application",
    "user": "User",
    "group": "Group",
    "policy": "CA policy",
}

DASH_INNER = '<span class="muted">&mdash;</span>'
SORT_TITLE = "Click to sort \u00b7 drag to reorder"

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
    # --- group --------------------------------------------------------------
    "group": {"label": "Group", "width": 220, "cls": "clickable"},
    "grpType": {"label": "Type", "width": 180},
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
    chips = "".join(
        f'<span class="badge {severity_class(x["severity"])} role-badge" data-role="{esc(x["name"])}" data-role-field="roles" title="{esc(x["source"])}">{esc(x["name"])}</span> '
        for x in f["roles"])
    return chips, ", ".join(x["name"] for x in f["roles"])


def _cell_eligible(f, r):
    elig = f.get("eligible_roles") or []
    if "group_id" in f:  # groups table flavour: dash inside the count span
        titles = "\n".join(f"{x['name']} (PIM eligible)" for x in elig)
        inner = (f'<span class="perm" title="{esc(titles or "")}">'
                 f'{len(elig) if elig else DASH_INNER}</span>')
    else:
        titles = "\n".join(f"{x['name']} ({x['source']})" for x in elig)
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
    value = ", ".join(types
                      + (["Public"] if f.get("is_public") else [])
                      + (["assignable"] if f.get("assignable") else [])
                      + (["dynamic"] if f.get("dynamic") else []))
    return ("".join(chips) or DASH_INNER), value


def _cell_grp_roles(f, r):
    chips = "".join(
        f'<span class="badge {severity_class(x["severity"])} role-badge" data-role="{esc(x["name"])}" data-role-field="grpRoles" title="{esc(x["name"])}">{esc(x["name"])}</span> '
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
    if not rule:
        gid = (r or {}).get("group_id")
        rec = (_graph_of(r).get("group") or {}).get(gid) if gid else None
        rule = (rec or {}).get("membershipRule") or ""
    if not rule:
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
        f'<span class="badge badge-info role-badge" '
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
    "arcProvider": _cell_arc_provider,
}


# ---- per-table specs -------------------------------------------------------

# User-attribute columns a row can resolve through its owner (SP tables).
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
        "defaults": ["severity", "polName", "polState", "polScope", "polApps",
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
                     "pw", "pwLastSet", "arcStatus"],
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
            continue
        inner, value = renderer(f, r)
        if field in fields:
            cls = cell_cls(table_id, field, field in extras)
            cls_attr = f' class="{cls}"' if cls else ""
            cells.append(
                f'<td{cls_attr} data-field="{field}" data-value="{esc(value)}">{inner}</td>')
        if blob is not None and field in extras \
                and not (value == "" and inner == DASH_INNER):
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


def user_search_text(f):
    parts = [f.get("user_display") or "", f.get("user_upn") or "", f.get("severity") or ""]
    parts += [r["name"] for r in f.get("roles", [])]
    parts += [r["name"] for r in f.get("eligible_roles", [])]
    parts += [g.get("name") or "" for g in f.get("groups", [])]
    parts += [a.get("role", "") for a in f.get("az_roles", [])]
    if f.get("hybrid"):
        parts.append("AD")
    return " ".join(parts).lower()


def user_sort_value(f, key, ctx=None):
    if key == "severity":
        return SEVERITY_ORDER.get(f.get("severity", "Info"), 4)
    if key == "user":
        return (f.get("user_display") or "").lower()
    if key == "userUpn":
        return (f.get("user_upn") or "").lower()
    if key == "roles":
        return ", ".join(r["name"] for r in f.get("roles", [])).lower()
    if key == "eligible":
        return len(f.get("eligible_roles", []))
    if key == "privApps":
        return len(f.get("priv_apps", []))
    if key == "capGroups":
        return len(f.get("cap_member", []))
    if key == "grpOwned":
        return f.get("owned_count", 0)
    if key == "caExcl":
        return len(f.get("ca_exclusions", []))
    if key == "hybrid":
        return "AD" if f.get("hybrid") else "Cloud"
    if key == "userStatus":
        return 0 if f.get("user_enabled") else 1
    if key in ("adDn", "adSid", "immutableId"):
        rec = graph_user_record((ctx or {}).get("graph"), f.get("user_id")) or {}
        if key == "adDn":
            return (rec.get("onPremisesDistinguishedName") or "").lower()
        if key == "adSid":
            return (rec.get("onPremisesSecurityIdentifier") or "").lower()
        return (rec.get("immutableId") or "").lower()
    return 0


def user_rows_html(findings, start=0, stop=None, q="", sort_key=None, desc=False,
                   columns=None, ctx=None):
    """Pre-rendered <tr> html for the privileged-users table (served by the
    table endpoint)."""
    tid = "privileged-users-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    items = findings
    if q:
        q = q.lower()
        items = [f for f in items if q in user_search_text(f)]
    if sort_key:
        items = sorted(items, key=lambda f: user_sort_value(f, sort_key, ctx),
                       reverse=bool(desc))
    else:
        items = sorted(items, key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "Info"), 4),
                                             (f.get("user_display") or "").lower()))
    if stop is None:
        stop = len(items)
    out = []
    for f in items[start:stop]:
        key = f"row-{len(out)}"
        r = {"graph": (ctx or {}).get("graph"), "user_id": f["user_id"], "tid": tid}
        tr_attrs = (f'data-sp-id="" data-app-id="" '
                    f'data-owner-id="{esc(f["user_id"])}" '
                    f'data-profile-id="{esc(f["user_id"])}"')
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
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


def sp_extra_sort_value(sp_id, app_id, key, ctx):
    graph = (ctx or {}).get("graph")
    if key == "appId":
        return sp_app_id(sp_id, app_id, graph).lower()
    rec = ((graph or {}).get("sp") or {}).get(sp_id)
    return ((rec or {}).get("servicePrincipalType") or "").lower()


def owner_attr_sort_value(rec, key):
    """Sort key for owner-resolved user attribute columns (rec = graph user)."""
    rec = rec or {}
    if key == "ownerSource":
        return 0 if rec.get("dirSyncEnabled") in (1, True) else 1
    if key == "ownerAdDn":
        return (rec.get("onPremisesDistinguishedName") or "").lower()
    if key == "ownerAdSid":
        return (rec.get("onPremisesSecurityIdentifier") or "").lower()
    return (rec.get("immutableId") or "").lower()


OWNER_FIELDS = ("owner", "ownerUpn", "ownerStatus") + OWNER_USER_FIELDS


def legacy_sort_value(f, key, ctx=None):
    owner = (f.get("owners") or [{}])[0]
    if key == "severity":
        return severity_rank(f.get("severity", "Info"))
    if key == "owner":
        return (owner.get("display_name") or "").lower()
    if key == "ownerUpn":
        return (owner.get("upn") or "").lower()
    if key == "ownerStatus":
        return 0 if owner.get("enabled") else 1
    if key in OWNER_FIELDS:
        return owner_attr_sort_value(
            graph_user_record((ctx or {}).get("graph"), owner.get("object_id")), key)
    if key == "app":
        return (f.get("display_name") or "").lower()
    if key == "pw":
        return f.get("pw") or 0
    if key == "keys":
        return f.get("keys") or 0
    if key == "resource":
        return (f.get("resource_name") or "").lower()
    if key == "permission":
        return (f.get("permission") or "").lower()
    if key == "spStatus":
        return 0 if f.get("sp_enabled") else 1
    if key in ("appId", "spType"):
        return sp_extra_sort_value(f.get("principal_id"), f.get("app_object_id"),
                                   key, ctx)
    return 0


def legacy_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                     columns=None, ctx=None):
    tid = "owned-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                            legacy_search_text,
                            lambda f, k: legacy_sort_value(f, k, ctx))
    out = []
    for f in selected:
        for owner in f["owners"]:
            key = f"row-{len(out)}"
            r = {"graph": (ctx or {}).get("graph"), "owner": owner, "tid": tid,
                 "sp_id": f.get("principal_id"), "app_id": f.get("app_object_id")}
            tr_attrs = (f'data-sp-id="{esc(f["principal_id"])}" '
                        f'data-app-id="{esc(f["app_object_id"] or "")}" '
                        f'data-owner-id="{esc(owner["object_id"])}"')
            out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


def unowned_search_text(f):
    return " ".join([f.get("display_name") or "", f.get("resource_name") or "",
                     f.get("permission") or "", f.get("severity") or ""]).lower()


def unowned_sort_value(f, key, ctx=None):
    if key == "severity":
        return severity_rank(f.get("severity", "Info"))
    if key == "app":
        return (f.get("display_name") or "").lower()
    if key == "pw":
        return f.get("pw") or 0
    if key == "keys":
        return f.get("keys") or 0
    if key == "resource":
        return (f.get("resource_name") or "").lower()
    if key == "permission":
        return (f.get("permission") or "").lower()
    if key == "spStatus":
        return 0 if f.get("sp_enabled") else 1
    if key in ("appId", "spType"):
        return sp_extra_sort_value(f.get("principal_id"), f.get("app_object_id"),
                                   key, ctx)
    return 0


def legacy_unowned_rows_html(findings, q="", sort_key=None, desc=False, start=0,
                             stop=None, columns=None, ctx=None):
    tid = "unowned-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                            unowned_search_text,
                            lambda f, k: unowned_sort_value(f, k, ctx))
    out = []
    for f in selected:
        key = f"row-{len(out)}"
        r = {"graph": (ctx or {}).get("graph"), "tid": tid,
             "sp_id": f.get("principal_id"), "app_id": f.get("app_object_id")}
        tr_attrs = (f'data-sp-id="{esc(f["principal_id"])}" '
                    f'data-app-id="{esc(f["app_object_id"] or "")}" '
                    f'data-owner-id=""')
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


# ---- generic (per-check) rows ----------------------------------------------

def generic_search_text(f):
    t = f.get("target") or {}
    return " ".join([t.get("name") or "", t.get("type") or "", t.get("id") or "",
                     f.get("severity") or ""]).lower()


def generic_sort_value(f, key, ctx=None):
    t = f.get("target") or {}
    if key == "severity":
        return severity_rank(f.get("severity", "Info"))
    if key == "target":
        return (t.get("name") or "").lower()
    if key == "targetType":
        return (t.get("type") or "").lower()
    if key == "id":
        return (t.get("id") or "").lower()
    if key == "pw":
        return f.get("pw") or 0
    if key == "keys":
        return f.get("keys") or 0
    if key == "roleCount":
        return f.get("roles") or 0
    if key == "status":
        return ((f.get("status") or {}).get("label") or "").lower()
    o = f.get("object_ids") or {}
    if key in OWNER_FIELDS:
        owner = row_owner_dict(f, ctx) or {}
        if key == "owner":
            return (owner.get("display_name") or "").lower()
        if key == "ownerUpn":
            return (owner.get("upn") or "").lower()
        if key == "ownerStatus":
            return 0 if owner.get("enabled") else 1
        return owner_attr_sort_value(
            graph_user_record((ctx or {}).get("graph"), owner.get("object_id")), key)
    if key in ("appId", "spType"):
        return sp_extra_sort_value(next(iter(o.get("sp", ()) or ()), ""),
                                   next(iter(o.get("app", ()) or ()), ""), key, ctx)
    return 0


def generic_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                      columns=None, ctx=None):
    tid = "table-generic"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                            generic_search_text,
                            lambda f, k: generic_sort_value(f, k, ctx))
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
        r = {"graph": (ctx or {}).get("graph"), "tid": tid,
             "owner": row_owner_dict(f, ctx), "sp_id": sp_id, "app_id": app_id}
        tr_attrs = (f'data-sp-id="{esc(sp_id)}" data-app-id="{esc(app_id)}" '
                    f'data-owner-id="{esc(owner_id)}" data-device-id="{esc(device_id)}" '
                    f'data-policy-id="{policy_id}" data-check-id="{esc(f["check_id"])}"')
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


# ---- azure arc rows ---------------------------------------------------------

def arc_search_text(f):
    parts = [f.get("machine_name") or "", f.get("arc_principal") or "",
             f.get("arc_provider") or "", f.get("arc_sub") or "",
             f.get("arc_rg") or "", f.get("arc_resource_id") or "",
             f.get("severity") or ""]
    parts += [a.get("role", "") for a in f.get("arc_roles", [])]
    if f.get("arc_tagged"):
        parts.append("AzureArcSPN")
    return " ".join(parts).lower()


def arc_sort_value(f, key, ctx=None):
    if key == "severity":
        return severity_rank(f.get("severity", "Info"))
    if key in ("arcMachine", "arcPrincipal", "arcProvider"):
        return (f.get("machine_name") or f.get("arc_principal")
                or f.get("arc_provider") or "").lower()
    if key == "arcSub":
        return (f.get("arc_sub") or "").lower()
    if key == "arcRg":
        return (f.get("arc_rg") or "").lower()
    if key == "arcResourceId":
        return (f.get("arc_resource_id") or "").lower()
    if key == "arcPrincipalType":
        return (f.get("arc_principal_type") or "").lower()
    if key == "arcTag":
        return 0 if f.get("arc_tagged") else 1
    if key == "arcAzRoles":
        return ", ".join(a.get("role", "") for a in f.get("arc_roles", [])).lower()
    if key == "pw":
        return f.get("pw") or 0
    if key == "pwLastSet":
        return (f.get("pw_last_set") or "").lower()
    if key == "arcStatus":
        st = f.get("arc_status") or {}
        return (st.get("label") or "").lower()
    if key == "appId":
        o = f.get("object_ids") or {}
        return sp_extra_sort_value(next(iter(o.get("sp", ()) or ()), ""), "", key, ctx)
    if key == "id":
        return ((f.get("target") or {}).get("id") or "").lower()
    return 0


def arc_machines_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                           columns=None, ctx=None):
    tid = "arc-machines-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                                arc_search_text, lambda f, k: arc_sort_value(f, k, ctx))
    out = []
    for f in selected:
        sp_id = (f.get("target") or {}).get("id") or ""
        key = f"row-{len(out)}"
        r = {"graph": (ctx or {}).get("graph"), "tid": tid, "sp_id": sp_id}
        tr_attrs = f'data-sp-id="{esc(sp_id)}" data-check-id="{esc(f["check_id"])}"'
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


def arc_principals_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                             columns=None, ctx=None):
    tid = "arc-principals-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                                arc_search_text, lambda f, k: arc_sort_value(f, k, ctx))
    out = []
    graph = (ctx or {}).get("graph")
    for f in selected:
        oid = (f.get("target") or {}).get("id") or ""
        kind = f.get("arc_principal_type") or ""
        key = f"row-{len(out)}"
        r = {"graph": graph, "tid": tid}
        if kind == "Service Principal":
            r["sp_id"] = oid
            r["owner"] = sp_owner_dict(oid, graph)
            tr_attrs = f'data-sp-id="{esc(oid)}" data-check-id="{esc(f["check_id"])}"'
        elif kind == "User":
            tr_attrs = f'data-profile-id="{esc(oid)}" data-check-id="{esc(f["check_id"])}"'
        else:
            gid = f.get("arc_group_id") or oid
            tr_attrs = f'data-group-id="{esc(gid)}" data-check-id="{esc(f["check_id"])}"'
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


def arc_providers_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                            columns=None, ctx=None):
    tid = "arc-providers-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                                arc_search_text, lambda f, k: arc_sort_value(f, k, ctx))
    out = []
    for f in selected:
        sp_id = (f.get("target") or {}).get("id") or ""
        key = f"row-{len(out)}"
        r = {"graph": (ctx or {}).get("graph"), "tid": tid, "sp_id": sp_id}
        tr_attrs = f'data-sp-id="{esc(sp_id)}" data-check-id="{esc(f["check_id"])}"'
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


ARC_TABLE_ROWS = {
    "arc-machines-table": arc_machines_rows_html,
    "arc-principals-table": arc_principals_rows_html,
    "arc-providers-table": arc_providers_rows_html,
}


# ---- app directory roles rows ------------------------------------------------

def app_dir_search_text(f):
    t = f.get("target") or {}
    roles = ", ".join(r["name"] for r in f.get("dir_role_tags", []))
    return " ".join([t.get("name") or "", f.get("severity") or "", roles]).lower()


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


def app_dir_sort_value(f, key, ctx=None):
    t = f.get("target") or {}
    if key == "severity":
        return severity_rank(f.get("severity", "Info"))
    if key == "app":
        return (t.get("name") or "").lower()
    if key == "id":
        return (t.get("id") or "").lower()
    if key == "appDirRoles":
        return ", ".join(r["name"] for r in f.get("dir_role_tags", [])).lower()
    if key == "status":
        return 0 if (f.get("status") or {}).get("enabled") else 1
    if key in OWNER_FIELDS:
        owner = sp_owner_dict(f.get("sp_id"), (ctx or {}).get("graph")) or {}
        if key == "owner":
            return (owner.get("display_name") or "").lower()
        if key == "ownerUpn":
            return (owner.get("upn") or "").lower()
        if key == "ownerStatus":
            return 0 if owner.get("enabled") else 1
        return owner_attr_sort_value(
            graph_user_record((ctx or {}).get("graph"), owner.get("object_id")), key)
    if key in ("appId", "spType"):
        sp_id = f.get("sp_id") or (t.get("id")
                                   if t.get("type") == "ServicePrincipal" else "")
        return sp_extra_sort_value(sp_id, "", key, ctx)
    return 0


def app_dir_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                      columns=None, ctx=None):
    tid = "app-dir-roles-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    need_owner = any(x in fields for x in OWNER_FIELDS)
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                                app_dir_search_text,
                                lambda f, k: app_dir_sort_value(f, k, ctx))
    out = []
    for f in selected:
        key = f"row-{len(out)}"
        sp_id = f.get("sp_id") or ""
        r = {"graph": (ctx or {}).get("graph"), "tid": tid, "sp_id": sp_id}
        if need_owner:
            r["owner"] = sp_owner_dict(sp_id, (ctx or {}).get("graph"))
        tr_attrs = f'data-sp-id="{esc(sp_id)}"'
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


# ---- groups / dynamic rows ---------------------------------------------------

def group_search_text(f):
    roles = ", ".join(r["name"] for r in f.get("dir_roles", []))
    elig = ", ".join(r["name"] for r in f.get("eligible_roles", []))
    return " ".join([f.get("group_name") or "", f.get("severity") or "",
                     roles, elig, " ".join(f.get("types", []))]).lower()


def group_sort_value(f, key, ctx=None):
    if key == "severity":
        return severity_rank(f.get("severity", "Info"))
    if key == "group":
        return (f.get("group_name") or "").lower()
    if key == "grpType":
        return " ".join(f.get("types", [])).lower()
    if key == "grpRoles":
        return ", ".join(r["name"] for r in f.get("dir_roles", [])).lower()
    if key == "eligible":
        return len(f.get("eligible_roles", []))
    if key == "grpMembers":
        return f.get("member_count", 0)
    if key == "grpPriv":
        return f.get("priv_member_count", 0)
    if key == "grpOwners":
        return len(f.get("owners", []))
    if key == "dynRule":
        return (f.get("dyn_rule") or "").lower()
    return 0


def group_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                    columns=None, ctx=None):
    tid = "groups-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                            group_search_text,
                            lambda f, k: group_sort_value(f, k, ctx))
    out = []
    for f in selected:
        key = f"row-{len(out)}"
        r = {"graph": (ctx or {}).get("graph"), "group_id": f.get("group_id"),
             "tid": tid}
        tr_attrs = f'data-group-id="{esc(f["group_id"])}"'
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


def dynamic_search_text(f):
    return " ".join([f.get("group_name") or "", f.get("dyn_rule") or "",
                     " ".join(f.get("dyn_attrs", [])),
                     " ".join(f.get("dyn_mods", []))]).lower()


def dynamic_sort_value(f, key, ctx=None):
    if key == "dynGroup":
        return (f.get("group_name") or "").lower()
    if key == "dynRule":
        return (f.get("dyn_rule") or "").lower()
    if key == "dynAttrs":
        return " ".join(f.get("dyn_attrs", [])).lower()
    if key == "dynMods":
        return " ".join(f.get("dyn_mods", [])).lower()
    if key == "grpMembers":
        return f.get("member_count", 0)
    if key == "grpOwners":
        return len(f.get("owners", []))
    return 0


def dynamic_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                      columns=None, ctx=None):
    tid = "dynamic-groups-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                            dynamic_search_text,
                            lambda f, k: dynamic_sort_value(f, k, ctx))
    out = []
    for f in selected:
        key = f"row-{len(out)}"
        r = {"graph": (ctx or {}).get("graph"), "group_id": f.get("group_id"),
             "tid": tid}
        tr_attrs = f'data-group-id="{esc(f["group_id"])}"'
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


# ---- AD roster rows -----------------------------------------------------------

def ad_search_text(f):
    return " ".join([f.get("user_display") or "", f.get("user_upn") or "",
                     f.get("ad_cn") or "", f.get("ad_dn") or "",
                     f.get("ad_sid") or "", " ".join(f.get("tags", [])),
                     " ".join(x.get("name") or "" for x in f.get("ca_exclusions", []))]).lower()


def ad_sort_value(f, key, ctx=None):
    if key == "adUser":
        return (f.get("user_display") or "").lower()
    if key == "adUpn":
        return (f.get("user_upn") or "").lower()
    if key == "adCn":
        return (f.get("ad_cn") or "").lower()
    if key == "adDn":
        return (f.get("ad_dn") or "").lower()
    if key == "adSid":
        return (f.get("ad_sid") or "").lower()
    if key == "adPw":
        return (f.get("pw_change") or "").lower()
    if key == "adTags":
        return " ".join(f.get("tags", [])).lower()
    if key == "caExcl":
        return len(f.get("ca_exclusions", []))
    if key == "adStatus":
        return 0 if (f.get("status") or {}).get("enabled") else 1
    if key == "immutableId":
        rec = graph_user_record((ctx or {}).get("graph"), f.get("user_id")) or {}
        return (rec.get("immutableId") or "").lower()
    return 0


def ad_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                 columns=None, ctx=None):
    tid = "ad-sync-users-table"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                            ad_search_text,
                            lambda f, k: ad_sort_value(f, k, ctx))
    out = []
    for f in selected:
        key = f"row-{len(out)}"
        r = {"graph": (ctx or {}).get("graph"), "user_id": f.get("user_id"),
             "tid": tid}
        tr_attrs = (f'data-sp-id="" data-app-id="" '
                    f'data-owner-id="{esc(f["user_id"])}" '
                    f'data-profile-id="{esc(f["user_id"])}"')
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


def _serve_pager():
    """Pager markup for serve-mode tables (Prev/Next + rows-per-page select)."""
    return ('<div class="table-pager hidden">'
            '<button type="button" class="icon-btn tp-prev">&#8592; Prev</button>'
            '<span class="tp-info muted"></span>'
            '<button type="button" class="icon-btn tp-next">Next &#8594;</button>'
            '<label class="muted">Rows '
            '<select class="tp-size">'
            '<option value="25" selected>25</option><option value="50">50</option><option value="100">100</option><option value="250">250</option>'
            '<option value="500">500</option><option value="1000">1000</option>'
            '</select></label></div>')


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
    ownersource: ['ownersource'], owneraddn: ['owneraddn'],
    ownersid: ['ownersid'], ownerimmutableid: ['ownerimmutableid'],
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
    azapp: ['azapp'], azgroup: ['azgroup'], azuser: ['azuser'],
    azroles: ['azroles'], azsproles: ['azsproles'], azusrroles: ['azusrroles'],
    azscopetype: ['azscopetype'], azsub: ['azsub'], azrg: ['azrg'],
    azprovider: ['azprovider'], azresource: ['azresource'],
    arcmachine: ['arcmachine'], arcsub: ['arcsub'], arcrg: ['arcrg'],
    arcresourceid: ['arcresourceid'], arcstatus: ['arcstatus'],
    arcprincipal: ['arcprincipal'], arcprincipaltype: ['arcprincipaltype'],
    arctag: ['arctag'], arcazroles: ['arcazroles'], arcprovider: ['arcprovider'],
    pwlastset: ['pwlastset'],
    appid: ['appid'], spty: ['spty'], servicetype: ['spty'],
    poltype: ['poltype'], polcreated: ['polcreated'], created: ['polcreated'],
    polmodified: ['polmodified'], lastmodified: ['polmodified'],
    immutableid: ['immutableid'],
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
    ownersource: 'Owner Source', owneraddn: 'Owner AD DN', ownersid: 'Owner SID',
    ownerimmutableid: 'Owner Immutable ID',
    spstatus: 'SP Status', membershiprule: 'Membership rule',
    referencedattributes: 'Referenced attributes', modifiableby: 'Modifiable by',
    aduser: 'User', adupn: 'UPN', adcn: 'AD CN', addn: 'AD DN', sid: 'SID',
    onprempwchange: 'On-prem pw change', targetingtags: 'Targeting tags',
    appid: 'App ID', spty: 'SP type', poltype: 'Policy type',
    polcreated: 'Created', polmodified: 'Last modified', immutableid: 'Immutable ID',
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
    ['On-prem pw change', 'onprempwchange'], ['Targeting tags', 'targetingtags'],
    ['App ID', 'appid'], ['SP type', 'spty'], ['Policy type', 'poltype'],
    ['Immutable ID', 'immutableid']
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
      function isValueTerminator(tok) {
        return isAnyOperator(tok) ||
          (!!tok && tok.t === 'word' && tok.v.toUpperCase().indexOf('UNIQ:') === 0);
      }
      function consumeValueWords(value) {
        // append following plain words so unquoted values with spaces work
        while (true) {
          var tok = pos < tokens.length ? tokens[pos] : null;
          if (!tok || tok.t !== 'word' || isValueTerminator(tok)) return value;
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
        if (field.toUpperCase() === 'UNIQ') {
          var names = rest.split(',').map(function(s) { return s.trim(); }).filter(Boolean);
          if (!names.length) {
            var vt3 = peek();
            if (!vt3 || (vt3.t !== 'word' && vt3.t !== 'quoted')) {
              throw new Error("expected field after 'uniq:'");
            }
            advance();
            names = [vt3.v];
          }
          var ufields = [];
          names.forEach(function(n) {
            var resolved = resolveField(n);
            if (resolved) ufields = ufields.concat(resolved);
          });
          return {op: 'uniq', fields: ufields};
        }
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
    if (op === 'uniq') return true;
    return false;
  }

  function uniqFields(ast) {
    var out = [];
    function walk(node) {
      if (!node) return;
      if (node.op === 'uniq') {
        (node.fields || []).forEach(function(f) {
          if (out.indexOf(f) === -1) out.push(f);
        });
        return;
      }
      (node.children || []).forEach(walk);
      if (node.child) walk(node.child);
    }
    walk(ast);
    return out;
  }

  window.ADV_FILTER = {parse: parse, evaluate: evaluate, listFields: LIST_FIELDS,
                       fieldsFor: fieldsFor, columns: columns,
                       normalizeField: normalizeField, uniqFields: uniqFields};
})();
</script>
"""


# ---- conditional-access policy rows ------------------------------------------

def ca_search_text(f):
    ch = f.get("conditions_html") or {}
    return " ".join([f.get("policy_name") or "", f.get("state") or "",
                     f.get("scope") or "",
                     " ".join(ch.get("apps") or []),
                     " ".join(ch.get("controls") or []),
                     " ".join(f.get("included") or []),
                     " ".join(f.get("excluded") or [])]).lower()


def ca_sort_value(f, key, ctx=None):
    ch = f.get("conditions_html") or {}
    if key == "severity":
        return severity_rank(f.get("severity", "Info"))
    if key == "polName":
        return (f.get("policy_name") or "").lower()
    if key == "polState":
        return (f.get("state") or "").lower()
    if key == "polScope":
        return (f.get("scope") or "").lower()
    if key == "polApps":
        return ", ".join(ch.get("apps") or []).lower()
    if key == "polControls":
        return ", ".join(ch.get("controls") or []).lower()
    if key == "polInc":
        return len(f.get("included", []))
    if key == "polExc":
        return len(f.get("excluded", []))
    if key == "polType":
        v = f.get("policy_type")
        return ("" if v is None else str(v)).lower()
    if key == "polCreated":
        return (f.get("created") or "").lower()
    if key == "polModified":
        return (f.get("modified") or "").lower()
    return 0


def ca_rows_html(findings, q="", sort_key=None, desc=False, start=0, stop=None,
                 columns=None, ctx=None):
    tid = "table-ca_exposure"
    spec = table_spec(tid)
    fields = list(columns) if columns else list(spec["defaults"])
    selected, total = page_rows(findings, q, sort_key, desc, start, stop,
                                ca_search_text,
                                lambda f, k: ca_sort_value(f, k, ctx))
    out = []
    for f in selected:
        key = f"row-{len(out)}"
        r = {"graph": (ctx or {}).get("graph"), "tid": tid,
             "policy_id": f.get("policy_id")}
        tr_attrs = f'data-policy-id="{esc(f.get("policy_id", ""))}"'
        out.append(row_html(tid, tr_attrs, key, fields, f, r))
    return out, total


def render_report(results, tenant_name, db_path, config_path,
                  tenant_summary=None, graph=None,
                  serve_tables=None, group_roles=None,
                  group_eligible_roles=None, cache_meta=None, diff=None):
    all_findings = [f for res in results for f in res["findings"]]

    category_counts = Counter(res["category"] for res in results for _ in res["findings"])

    EXPAND_BUTTON = '<button type="button" class="icon-btn expand-btn" aria-label="View full details">+</button>'

    # ---- drawer (inline dropdown) helper ---------------------------------
    def drawer_for(key, colspan):
        return (f'<tr class="drawer" data-detail-for="{esc(key)}">'
                f'<td colspan="{colspan}"><div class="drawer-body"></div></td></tr>')

    serve_pager = _serve_pager
    col_ctx = {"graph": graph}
    extras_blobs = {}
    catalog_tids = []

    def register_catalog_table(tid, findings, rows_fn, search_fn):
        """Register a catalog-driven table for serving and the column catalog."""
        if serve_tables is not None:
            serve_tables[tid] = {"findings": findings, "rows": rows_fn,
                                 "search": search_fn, "ctx": col_ctx}
        if tid not in catalog_tids:
            catalog_tids.append(tid)

    def catalog_rows(tid, findings, rows_fn, search_fn):
        """Register a catalog table; rows are fetched from the table endpoint."""
        register_catalog_table(tid, findings, rows_fn, search_fn)
        return ""

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
        spec = table_spec(table_id)
        fields = list(spec["defaults"])
        blob = {}
        body = []
        for label, rid, kind, a in rows:
            key = f"az-{table_id}-{len(body)}"
            if kind == "sp":
                data = f'data-sp-id="{esc(rid)}"'
            elif kind == "group":
                data = f'data-group-id="{esc(rid)}"'
            else:
                data = f'data-profile-id="{esc(rid)}"'
            row = {
                "severity": a.get("severity") or "Info",
                "principal": label,
                "role": a["role"],
                "eligible": bool(a.get("eligible")),
                "scope_type": a.get("scope_type") or "",
                "sub": az_sub(a),
                "scope_rg": a.get("scope_rg") or "",
                "scope_provider": a.get("scope_provider") or "",
                "scope_resource": a.get("scope_resource") or "",
            }
            r = {"graph": graph, "tid": table_id,
                 "sp_id": rid if kind == "sp" else "",
                 "group_id": rid if kind == "group" else "",
                 "user_id": rid if kind == "user" else ""}
            if kind == "sp":
                r["owner"] = sp_owner_dict(rid, graph)
            body.append(row_html(table_id, data, key, fields, row, r, blob))
        if blob:
            extras_blobs[table_id] = blob
        if table_id not in catalog_tids:
            catalog_tids.append(table_id)
        return f"""
  <section data-category="{esc(category)}">
    <h2>{esc(title)}</h2>
    <div class="table-scroll">
    <table id="{esc(table_id)}" class="findings">
      {table_head_html(table_id)}
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
        owned_rows = catalog_rows("owned-table", owned, legacy_rows_html, legacy_search_text)
        owned_pager = serve_pager()
        return f"""
  <section data-category="apps">
    <h2>{esc(priv["title"])}</h2>
    <div class="table-scroll">
    <table id="owned-table" class="findings" data-serve="1">
      {table_head_html("owned-table")}
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
        unowned_rows = catalog_rows("unowned-table", unowned, legacy_unowned_rows_html,
                                   unowned_search_text)
        unowned_pager = serve_pager()
        return f"""
  <section data-category="apps">
    <h2>Privileged applications / service principals with no recorded owner</h2>
    <div class="table-scroll">
    <table id="unowned-table" class="findings" data-serve="1">
      {table_head_html("unowned-table")}
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
        rows_html = catalog_rows(tid, res["findings"], generic_rows_html, generic_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="{esc(res["category"])}">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="{esc(tid)}" class="findings" data-serve="1">
      {table_head_html(tid)}
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    # ---- azure arc sections ------------------------------------------------
    def arc_section(res, table_id):
        rows_fn = ARC_TABLE_ROWS[table_id]
        rows_html = catalog_rows(table_id, res["findings"], rows_fn, arc_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="arc">
    <h2>{esc(res["title"])}</h2>
    <p class="sub">{esc(res["description"])}</p>
    <div class="table-scroll">
    <table id="{esc(table_id)}" class="findings" data-serve="1">
      {table_head_html(table_id)}
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    # ---- conditional-access policies section ----------------------------------
    def ca_section(res):
        rows_html = catalog_rows("table-ca_exposure", res["findings"], ca_rows_html,
                               ca_search_text)
        pager = serve_pager()
        caview = ' data-caview="main"'
        return f"""
  <section data-category="configs"{caview}>
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="table-ca_exposure" class="findings" data-serve="1">
      {table_head_html("table-ca_exposure")}
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    # ---- groups section ----------------------------------------
    def groups_section(res):
        rows_html = catalog_rows("groups-table", res["findings"], group_rows_html,
                               group_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="groups">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="groups-table" class="findings" data-serve="1">
      {table_head_html("groups-table")}
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
        rows_html = catalog_rows("dynamic-groups-table", dyn, dynamic_rows_html,
                               dynamic_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="groups">
    <h2>Dynamic membership groups ({len(dyn)})</h2>
    <div class="table-scroll">
    <table id="dynamic-groups-table" class="findings" data-serve="1">
      {table_head_html("dynamic-groups-table")}
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    {pager}
  </section>
"""

    def users_section(res):
        rows = catalog_rows("privileged-users-table", res["findings"], user_rows_html,
                            user_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="users">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="privileged-users-table" class="findings" data-serve="1">
      {table_head_html("privileged-users-table")}
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
        rows_html = catalog_rows("app-dir-roles-table", res["findings"], app_dir_rows_html,
                               app_dir_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="apps">
    <h2>{esc(res["title"])}</h2>
    <div class="table-scroll">
    <table id="app-dir-roles-table" class="findings" data-serve="1">
      {table_head_html("app-dir-roles-table")}
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
        auth = f.get("auth_mode") or {}
        sso = f.get("desktop_sso") or {}
        indicators = {i["label"]: i for i in (f.get("indicators") or [])}

        def v(label):
            i = indicators.get(label)
            return i["detail"] if i else ""

        rows = []
        rows.append(f"<tr><th>Engine</th><td><b>{esc(verdict)}</b></td></tr>")
        if auth.get("mode"):
            rows.append(f'<tr><th>Authentication</th><td><b>{esc(auth["mode"])}</b>'
                        + (f' <span class="muted">({esc(auth["detail"])})</span>'
                           if auth.get("detail") else "") + "</td></tr>")
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

        rows_html = catalog_rows("ad-sync-users-table", res["findings"], ad_rows_html,
                               ad_search_text)
        pager = serve_pager()
        return f"""
  <section data-category="ad">
    <h2>{esc(res["title"])}</h2>
    {realm_html}
    <div class="table-scroll">
    <table id="ad-sync-users-table" class="findings" data-serve="1">
      {table_head_html("ad-sync-users-table")}
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
    diff_entries = []
    if diff:
        for f in diff.get("added") or []:
            diff_entries.append({"kind": "added", "f": f})
        for f in diff.get("removed") or []:
            diff_entries.append({"kind": "removed", "f": f})
        for old, new in diff.get("changed") or []:
            diff_entries.append({"kind": "changed", "f": new, "old": old})
        diff_entries.sort(key=lambda e: ({"added": 0, "removed": 1,
                                          "changed": 2}[e["kind"]],
                                         e["f"].get("check_id", ""),
                                         ((e["f"].get("target") or {}).get("name")
                                          or "").lower()))
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
        elif res["id"] == "app_dir_roles":
            sections_html.append(app_dir_roles_section(res))
        elif res["id"] == "groups":
            sections_html.append(groups_section(res))
            dyn_html = dynamic_groups_table(res)
            if dyn_html:
                sections_html.append(dyn_html)
        elif res["id"] == "ca_exposure":
            sections_html.append("""
  <section data-category="configs" class="ca-view-tabs-section">
    <div class="drawer-tabs" id="ca-view-tabs">
      <button type="button" class="drawer-tab active" data-caview="main">Conditional Access</button>
      <button type="button" class="drawer-tab" data-caview="single">Single user</button>
    </div>
  </section>
""")
            sections_html.append(ca_section(res))
            sections_html.append("""
  <section data-category="configs" data-caview="main">
    <h2>CA coverage analysis</h2>
    <div class="ca-analysis">
      <p class="sub">Conditional Access coverage for the tenant: policy scope resolution, per-user and per-application coverage, legacy authentication, and exclusions.</p>
      <div class="ca-controls">
        <button type="button" class="mode-btn" id="ca-run-btn">Run full analysis</button>
      </div>
      <div class="ca-status hidden" id="ca-status"><ul id="ca-steps"></ul></div>
      <div class="ca-results" id="ca-results"></div>
    </div>
  </section>
  <section data-category="configs" data-caview="single" class="hidden">
    <h2>Single user analysis</h2>
    <div class="ca-analysis">
      <p class="sub">Scope the Conditional Access analysis to one user; optionally simulate memberships and a sign-in scenario.</p>
      <div class="ca-controls">
        <input type="text" id="ca-user-input" class="ca-user-input" placeholder="User UPN" autocomplete="off">
        <button type="button" class="mode-btn" id="ca-user-btn">Analyze user</button>
      </div>
      <div class="ca-whatif">
        <label>Require MFA <select id="ca-wi-require"><option value="">—</option><option value="mfa">MFA</option></select></label>
        <label>Platform <select id="ca-wi-platform"><option value="">—</option><option>windows</option><option>macos</option><option>linux</option><option>ios</option><option>android</option></select></label>
        <label>Client app <select id="ca-wi-client"><option value="">—</option><option>browser</option><option>mobileAppsAndDesktopClients</option><option>exchangeActiveSync</option><option>other</option></select></label>
        <label>Device state <select id="ca-wi-device"><option value="">—</option><option>compliant</option><option>unmanaged</option><option>domainJoined</option></select></label>
        <label>Trusted location <select id="ca-wi-location"><option value="">—</option><option value="true">trusted</option><option value="false">not trusted</option></select></label>
        <label>Sign-in risk <select id="ca-wi-signin"><option value="">—</option><option>none</option><option>low</option><option>medium</option><option>high</option></select></label>
        <label>User risk <select id="ca-wi-userrisk"><option value="">—</option><option>low</option><option>medium</option><option>high</option></select></label>
        <label>Resource / app <input type="text" id="ca-app-input" class="ca-small-input" placeholder="optional" autocomplete="off"></label>
        <label>Assume group(s) <input type="text" id="ca-assume-groups" class="ca-small-input" placeholder="names or IDs, comma-separated" autocomplete="off"></label>
        <label>Assume role(s) <input type="text" id="ca-assume-roles" class="ca-small-input" placeholder="names or IDs, comma-separated" autocomplete="off"></label>
      </div>
      <div class="ca-status hidden" id="ca-user-status"><ul id="ca-user-steps"></ul></div>
      <div class="ca-results" id="ca-user-results"></div>
    </div>
  </section>
""")
        elif res["id"] == "ad_sync_summary":
            sections_html.append(ad_summary_card(res))
        elif res["id"] == "ad_sync_users":
            sections_html.append(ad_users_section(res))
        elif res["id"] == "azure_arc_machines":
            sections_html.append(arc_section(res, "arc-machines-table"))
        elif res["id"] == "azure_arc_sps":
            sections_html.append(arc_section(res, "arc-principals-table"))
        elif res["id"] == "azure_arc_providers":
            sections_html.append(arc_section(res, "arc-providers-table"))
        else:
            sections_html.append(generic_section(res))

    # ---- changes since the last analysis (diff against the cache) ---------
    if diff_entries:
        check_titles = {spec["id"]: spec["title"] for spec in CHECK_SPECS}
        change_rows = []
        for e in diff_entries:
            f = e["f"]
            t = f.get("target") or {}
            sev = f.get("severity") or "Info"
            if e["kind"] == "changed":
                old_sev = e["old"].get("severity") or "Info"
                sev_html = f"{severity_badge(old_sev)} \u2192 {severity_badge(sev)}"
            else:
                sev_html = severity_badge(sev)
            kind_html = {
                "added": '<span class="badge badge-enabled">Added</span>',
                "removed": '<span class="badge sev-critical">Removed</span>',
                "changed": '<span class="badge sev-medium">Changed</span>',
            }[e["kind"]]
            target = ((t.get("name") or f.get("user_display") or f.get("display_name")
                       or f.get("group_name") or f.get("policy_name")
                       or f.get("machine_name") or f.get("arc_principal")
                       or f.get("arc_provider") or f.get("title")
                       or f.get("primary_id") or ""))
            check_label = check_titles.get(f.get("check_id"), f.get("check_id") or "")
            change_rows.append(
                f'<tr><td>{kind_html}</td>'
                f'<td>{esc(check_label)}</td>'
                f'<td title="{esc(f.get("evidence") or "")}">{esc(target)}</td>'
                f'<td>{sev_html}</td></tr>')
        changes_html = f"""
  <section data-category="changes">
    <h2>Changes since last analysis ({len(diff_entries)})</h2>
    <p class="sub">Compared against the cached analysis from {esc(cache_meta.get("previous_at") or "")}.</p>
    <div class="table-scroll">
    <table class="findings" id="changes-table">
      <thead><tr>
        <th data-type="text">Change</th>
        <th data-type="text">Check</th>
        <th data-type="text">Target</th>
        <th data-type="text">Severity</th>
      </tr></thead>
      <tbody>{''.join(change_rows)}</tbody>
    </table>
    </div>
  </section>
"""
        sections_html.insert(0, changes_html)
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
        "arcmachine", "arcprincipal", "arcprincipaltype", "arctag",
        "arcazroles", "arcprovider", "arcsub", "arcrg", "arcstatus",
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
    if db_path is not None:
        tabs_html.append(
            '<button type="button" class="tab-btn reanalyze-btn" id="reanalyze-btn">'
            'Re-analyze</button>')
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
    if ts.get("auth_mode"):
        bar.append(item("Auth", f'<span class="tag-chip tag-divergence">{esc(ts["auth_mode"])}</span>',
                        "Authentication mode (PHS / PTA / federated), see the sync summary"))
    if ts.get("pim"):
        pim = ts["pim"]
        pim_labels = {"aadroles": "AAD roles", "aadgroups": "groups",
                      "azureResources": "Azure resources"}
        providers = [p for p in ("aadroles", "aadgroups", "azureResources")
                     if p in (pim.get("providers") or [])]
        if providers:
            pim_title = "PIM registered for " + ", ".join(pim_labels[p] for p in providers)
            if not pim.get("governance"):
                pim_title += " — assignment schedules not collected (run roadrecon pimgather)"
            bar.append(item("PIM", f'<span class="mono">{esc(" \u00b7 ".join(pim_labels[p] for p in providers))}</span>',
                            pim_title))
        elif not pim.get("governance"):
            bar.append(item("PIM", "<b>not observed</b>",
                            "No privileged-access providers registered (PIM may not be licensed/enabled)"))
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
    arc_machines = next((r for r in results if r["id"] == "azure_arc_machines"), None)
    if arc_machines and arc_machines["findings"]:
        arc_principals = next((r for r in results if r["id"] == "azure_arc_sps"), None)
        arc_note = f'{len(arc_machines["findings"])} machines, {len(arc_principals["findings"]) if arc_principals else 0} Arc principals'
        bar.append(item("Arc", f"<b>{len(arc_machines['findings'])}</b>", arc_note))
    # ---- cache / diff chips ------------------------------------------------
    if cache_meta:
        at = cache_meta.get("generated_at") or ""
        if cache_meta.get("off"):
            bar.append(item("Cache", "<b>off</b>", "caching disabled (--no-cache)"))
        elif cache_meta.get("hit"):
            bar.append(item("Cache", "<b>hit</b>", f"last analyzed {at}"))
        else:
            label = "created" if cache_meta.get("fresh") else "updated"
            html = f"<b>{label}</b>"
            title = f"analyzed {at}"
            if diff_entries:
                html += f" \u00b7 <b>{len(diff_entries)}</b> changes"
            bar.append(item("Cache", html, title))
    summary_bar_html = "\n    ".join(bar)

    catalog_data = {}
    for tid in catalog_tids:
        entry = catalog_entry(tid)
        if entry:
            catalog_data[tid] = entry
    catalog_json = json.dumps(catalog_data, default=str).replace("</", "<\\/")
    extras_scripts = []
    for tid, blob in extras_blobs.items():
        if not blob:
            continue
        # only the shell-rendered azure-roles tables carry extras blobs;
        # loader-managed tables render extras on demand via cols=
        if not tid.startswith("azure-roles-"):
            continue
        blob_json = json.dumps(blob, default=str).replace("</", "<\\/")
        extras_scripts.append(
            f'<script type="application/json" id="extras-{tid}">{blob_json}</script>')
    extras_scripts_html = "\n".join(extras_scripts)

    return f"""<!doctype html>
<html lang="en">
<head>
    <script>window.REPORT_SERVE = true;</script>
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
  .app-main {{
    min-height: 100vh;
    transition: margin-left 0.18s ease;
  }}
  body.sidebar-open .app-main {{ margin-left: 260px; }}
  .sidebar {{
    position: fixed; inset: 0 auto 0 0; width: 260px; z-index: 90;
    display: flex; flex-direction: column;
    padding: 24px 18px 20px; overflow-y: auto;
    background: var(--surface-1); border-right: 1px solid var(--border);
    box-shadow: 10px 0 30px rgba(0,0,0,0.10);
    transform: translateX(-100%); visibility: hidden;
    transition: transform 0.18s ease, visibility 0.18s;
  }}
  body.sidebar-open .sidebar {{ transform: translateX(0); visibility: visible; }}
  .sidebar-title {{
    margin: 0; color: var(--text-muted); font-size: 10px; font-weight: 600;
    letter-spacing: 0.08em; text-transform: uppercase;
  }}
  .sidebar-head {{
    display: flex; align-items: center; justify-content: space-between;
    gap: 8px; position: relative;
  }}
  .sidebar-settings-btn {{
    width: 24px; height: 24px; padding: 0; flex: none;
    display: inline-flex; align-items: center; justify-content: center;
    background: transparent; color: var(--text-muted);
    border: 1px solid transparent; border-radius: 6px;
    font-family: inherit; cursor: pointer;
  }}
  .sidebar-settings-btn:hover,
  .sidebar-settings-btn[aria-expanded="true"] {{
    background: var(--row-hover); color: var(--text-primary);
    border-color: var(--border);
  }}
  .sidebar-theme {{
    margin-top: 14px; padding-top: 14px;
    border-top: 1px solid var(--gridline);
  }}
  .sidebar-theme .theme-toggle {{ width: 100%; }}
  .sidebar-theme .theme-toggle button {{
    flex: 1; padding: 6px 8px; font-size: 12px;
  }}
  .settings-overlay {{
    position: fixed; inset: 0; z-index: 200;
    background: rgba(0,0,0,0.45);
    display: flex; align-items: center; justify-content: center;
    padding: 24px;
  }}
  .settings-overlay.hidden {{ display: none; }}
  body.settings-open {{ overflow: hidden; }}
  .settings-box {{
    width: min(620px, 94vw); max-height: min(82vh, 720px);
    display: flex; flex-direction: column; overflow: hidden;
    background: var(--surface-1); border: 1px solid var(--border);
    border-radius: 12px; box-shadow: 0 24px 70px rgba(0,0,0,0.38);
  }}
  .settings-head {{
    display: flex; align-items: flex-start; justify-content: space-between;
    gap: 12px; padding: 14px 18px;
    border-bottom: 1px solid var(--gridline);
  }}
  .settings-head h3 {{ margin: 0; font-size: 16px; }}
  .settings-head .sub {{
    margin: 2px 0 0; color: var(--text-secondary); font-size: 12px;
  }}
  .settings-tabs {{
    display: flex; gap: 4px; padding: 10px 14px 0;
    border-bottom: 1px solid var(--gridline);
  }}
  .settings-tab {{
    background: transparent; border: 1px solid transparent; border-bottom: 0;
    border-radius: 7px 7px 0 0; color: var(--text-secondary);
    padding: 7px 14px; font: inherit; font-size: 12.5px; cursor: pointer;
  }}
  .settings-tab:hover {{ color: var(--text-primary); background: var(--row-hover); }}
  .settings-tab.active {{
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 10%, transparent);
    border-color: color-mix(in srgb, var(--accent) 28%, transparent);
    font-weight: 600;
  }}
  .settings-body {{ padding: 16px 18px; overflow: auto; }}
  .settings-panel.hidden {{ display: none; }}
  .settings-section + .settings-section {{
    margin-top: 16px; padding-top: 16px;
    border-top: 1px solid var(--gridline);
  }}
  .settings-section h4 {{
    margin: 0 0 6px; color: var(--text-muted); font-size: 10.5px;
    font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;
  }}
  .settings-value {{
    color: var(--text-secondary); font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 11.5px; line-height: 1.45; overflow-wrap: anywhere;
  }}
  .settings-note {{
    margin: 0; color: var(--text-secondary); font-size: 12.5px; line-height: 1.5;
  }}
  .settings-field {{
    display: flex; flex-direction: column; gap: 4px;
    color: var(--text-secondary); font-size: 12px;
  }}
  .settings-field input {{
    background: var(--page-plane); color: var(--text-primary);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 7px 9px; font-size: 12.5px; font-family: inherit;
  }}
  .settings-field input:focus {{
    outline: none;
    border-color: color-mix(in srgb, var(--accent) 55%, var(--border));
  }}
  .settings-grid {{
    display: grid; grid-template-columns: 1fr 1fr; gap: 10px 12px;
    margin-top: 12px;
  }}
  .settings-grid .wide {{ grid-column: 1 / -1; }}
  .settings-actions {{ margin-top: 12px; }}
  .settings-check {{
    display: flex; align-items: center; gap: 8px; margin-top: 10px;
    color: var(--text-secondary); font-size: 12.5px; cursor: pointer;
  }}
  .settings-check input {{ margin: 0; }}
  .settings-status {{
    margin-top: 10px; font-size: 12px; color: var(--text-secondary);
  }}
  .settings-status.error {{ color: var(--status-critical); }}
  .settings-status.hidden {{ display: none; }}
  @media (max-width: 520px) {{
    .settings-grid {{ grid-template-columns: 1fr; }}
  }}
  .settings-foot {{
    display: flex; justify-content: flex-end; gap: 8px;
    padding: 12px 18px; border-top: 1px solid var(--gridline);
  }}
  .sidebar-nav {{ display: flex; flex-direction: column; gap: 4px; margin-top: 14px; }}
  .sidebar-nav-item {{
    display: flex; align-items: center; width: 100%;
    background: transparent; border: 1px solid transparent; border-radius: 7px;
    padding: 8px 10px; color: var(--text-secondary); text-align: left;
    font-size: 13px; line-height: 1.35; font-family: inherit; cursor: pointer;
  }}
  .sidebar-nav-item:hover {{ background: var(--row-hover); color: var(--text-primary); }}
  .sidebar-nav-item.active {{
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    border-color: color-mix(in srgb, var(--accent) 30%, transparent);
    color: var(--accent); font-weight: 600;
  }}
  .sidebar-principal {{
    margin-top: auto; padding-top: 14px;
    border-top: 1px solid var(--gridline);
  }}
  .sidebar-principal-body {{
    display: flex; align-items: center; gap: 10px; margin-top: 10px;
    min-width: 0;
  }}
  .sidebar-principal-info {{ min-width: 0; }}
  .sidebar-principal-name {{
    font-size: 12.5px; font-weight: 600; overflow-wrap: anywhere;
  }}
  .sidebar-principal-sub {{
    color: var(--text-muted); font-size: 10.5px;
    margin-top: 2px; overflow-wrap: anywhere;
  }}
  .sidebar-principal-empty {{ color: var(--text-muted); font-size: 11.5px; }}
  .sidebar-toggle {{
    position: fixed; top: 50%; left: 0; transform: translateY(-50%);
    z-index: 95; width: 26px; height: 52px; padding: 0;
    display: flex; align-items: center; justify-content: center;
    background: var(--surface-1); color: var(--text-muted);
    border: 1px solid var(--border); border-left: 0;
    border-radius: 0 8px 8px 0;
    box-shadow: 4px 4px 16px rgba(0,0,0,0.12);
    font-size: 18px; line-height: 1; font-family: inherit; cursor: pointer;
    transition: left 0.18s ease, color 0.15s ease, background 0.15s ease;
  }}
  .sidebar-toggle:hover {{ color: var(--text-primary); background: var(--row-hover); }}
  body.sidebar-open .sidebar-toggle {{ left: 260px; }}
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
  .reanalyze-btn {{ margin-left: auto; }}
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
  .ca-analysis {{ margin: 4px 0; }}
  .ca-controls {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin: 4px 0 10px; }}
  .ca-sep {{ font-size: 12.5px; }}
  .ca-user-input {{
    flex: 1; min-width: 240px; max-width: 420px;
    background: var(--surface-1); color: var(--text-primary);
    border: 1px solid var(--border); border-radius: 6px; padding: 7px 10px; font-size: 13px;
  }}
  .ca-whatif select, .ca-small-input {{
    background: var(--surface-1); color: var(--text-primary);
    border: 1px solid var(--border); border-radius: 6px; padding: 5px 8px; font-size: 12px;
  }}
  .ca-small-input {{ min-width: 170px; }}
  .ca-whatif {{
    display: flex; flex-direction: column; gap: 6px; margin: 8px 0 4px; max-width: 460px;
  }}
  .ca-whatif label {{
    display: grid; grid-template-columns: 130px 1fr; align-items: center; gap: 8px;
    font-size: 12.5px; color: var(--text-secondary);
  }}
  .ca-whatif select, .ca-whatif .ca-small-input {{ width: 100%; }}
  .ca-status ul {{ list-style: none; margin: 6px 0 12px; padding: 0; }}
  .ca-status li {{ padding: 3px 0; font-size: 13px; color: var(--text-muted); }}
  .ca-status li.done {{ color: var(--text-primary); }}
  .ca-status li.done::before {{ content: "\\2713 "; color: var(--status-good); }}
  .ca-status li.error {{ color: var(--status-critical); }}
  .ca-status li .step-detail {{ color: var(--text-muted); margin-left: 6px; font-size: 12px; }}
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
  .colman {{ position: relative; display: flex; justify-content: flex-end; margin: 6px 0 8px; }}
  .table-head-row {{
    display: flex; align-items: flex-start; justify-content: space-between;
    gap: 12px; flex-wrap: wrap;
  }}
  .table-head-row h2 {{ margin: 0 0 4px; }}
  .table-head-row .colman {{ margin: 0; }}
  .colman-btn {{
    display: inline-flex; align-items: center; gap: 6px; cursor: pointer;
    background: var(--surface-1); color: var(--text-secondary); border: 1px solid var(--border);
    border-radius: 6px; padding: 4px 10px; font-size: 12px; font-family: inherit;
  }}
  .colman-btn:hover {{ color: var(--text-primary); }}
  .colman-badge {{
    background: var(--accent); color: #fff; border-radius: 999px; font-size: 10px;
    line-height: 1; padding: 2px 6px; font-weight: 600;
  }}
  .colman-pop {{
    position: absolute; right: 0; top: calc(100% + 4px); z-index: 30;
    min-width: 240px; max-height: 340px; overflow-y: auto; text-align: left;
    background: var(--surface-1); border: 1px solid var(--border); border-radius: 8px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.18); padding: 6px 0;
  }}
  .colman-group {{ padding: 2px 0 6px; }}
  .colman-group-title {{
    padding: 5px 12px 2px; font-size: 10px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.04em; color: var(--text-muted);
  }}
  .colman-item {{
    display: flex; align-items: center; gap: 8px; padding: 4px 12px;
    font-size: 12.5px; color: var(--text-secondary); cursor: pointer;
  }}
  .colman-item:hover {{ background: var(--row-hover); color: var(--text-primary); }}
  .colman-item input {{ margin: 0; }}
  .colman-foot {{ border-top: 1px solid var(--gridline); margin-top: 4px; padding: 8px 12px 2px; }}
  .colman-reset {{
    background: none; border: none; padding: 0; cursor: pointer; text-decoration: underline;
    color: var(--accent); font-size: 12px; font-family: inherit;
  }}
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
  .list-more-btn {{
    font-size: 11.5px; font-family: inherit; background: none; border: none;
    color: var(--accent); cursor: pointer; padding: 2px 0;
  }}
  .list-more-btn:hover {{ text-decoration: underline; }}
  tr.drawer {{ display: none; }}
  tr.drawer.open {{ display: table-row; }}
  tr.drawer td {{ padding: 8px 12px 12px; background: var(--page-plane); }}
  .drawer-body {{
    border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px;
    background: var(--surface-1);
  }}
  {collect_backend.styles_html()}
  {analysis.styles_html()}
  @media (max-width: 900px) {{
    body.sidebar-open .app-main {{ margin-left: 0; }}
    .sidebar {{ width: min(84vw, 320px); }}
    body.sidebar-open .sidebar-toggle {{ left: min(84vw, 320px); }}
  }}
</style>
</head>
<body class="sidebar-open">
{analysis.client_js()}
<aside class="sidebar" id="sidebar" aria-label="Sidebar" aria-hidden="false">
  <div class="sidebar-head">
    <h2 class="sidebar-title">Workspace</h2>
    <button type="button" class="sidebar-settings-btn" id="sidebar-settings-btn"
            aria-label="Settings" aria-haspopup="dialog" aria-expanded="false"
            aria-controls="settings-overlay" title="Settings">
      <svg width="15" height="15" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
        <path fill="currentColor" d="M19.43 12.98c.04-.32.07-.64.07-.98s-.03-.66-.07-.98l2.11-1.65c.19-.15.24-.42.12-.64l-2-3.46c-.12-.22-.39-.3-.61-.22l-2.49 1c-.52-.4-1.08-.73-1.69-.98l-.38-2.65C14.46 2.18 14.25 2 14 2h-4c-.25 0-.46.18-.49.42l-.38 2.65c-.61.25-1.17.59-1.69.98l-2.49-1c-.23-.09-.49 0-.61.22l-2 3.46c-.13.22-.07.49.12.64l2.11 1.65c-.04.32-.07.65-.07.98s.03.66.07.98l-2.11 1.65c-.19.15-.24.42-.12.64l2 3.46c.12.22.39.3.61.22l2.49-1c.52.4 1.08.73 1.69.98l.38 2.65c.03.24.24.42.49.42h4c.25 0 .46-.18.49-.42l.38-2.65c.61-.25 1.17-.59 1.69-.98l2.49 1c.23.09.49 0 .61-.22l2-3.46c.12-.22.07-.49-.12-.64l-2.11-1.65zM12 15.5c-1.93 0-3.5-1.57-3.5-3.5s1.57-3.5 3.5-3.5 3.5 1.57 3.5 3.5-1.57 3.5-3.5 3.5z"/>
      </svg>
    </button>
  </div>
  <nav class="sidebar-nav" id="sidebar-nav" aria-label="Workspace sections">
    <button type="button" class="sidebar-nav-item active" data-view="analysis" aria-current="page">Analysis</button>
    <button type="button" class="sidebar-nav-item" data-view="collect">Collect</button>
    <button type="button" class="sidebar-nav-item" data-view="tokens">Tokens</button>
  </nav>
  <div class="sidebar-principal">
    <div class="sidebar-title">Active token</div>
    <div class="sidebar-principal-body" id="sidebar-principal-body">
      <span class="sidebar-principal-empty">Loading...</span>
    </div>
  </div>
  <div class="sidebar-theme">
    <div class="theme-toggle" role="group" aria-label="Color theme">
      <button type="button" id="theme-light-btn" aria-pressed="false">Light</button>
      <button type="button" id="theme-dark-btn" aria-pressed="false">Dark</button>
    </div>
  </div>
</aside>
<button type="button" class="sidebar-toggle" id="sidebar-toggle" aria-controls="sidebar" aria-expanded="true" aria-label="Close sidebar" title="Close sidebar">
  <span class="sidebar-toggle-arrow" aria-hidden="true">&lsaquo;</span>
</button>
<div class="app-main">
<div class="wrap">
  <div class="app-view" data-view="analysis">
  <header>
    <div>
      <h1>Entra ID Attack Surface</h1>
    </div>
  </header>

  <div class="summary-bar">
    {summary_bar_html}
  </div>

  <div id="analysis-start-wrap" class="{'' if db_path is None else 'hidden'}">
    {analysis.start_panel_html(db_path)}
  </div>

  <div class="tabs" id="category-tabs" role="tablist">
      {tabs_html}
  </div>

  <div class="controls">
    <div class="filter-row">
      <input type="search" id="filter-input" placeholder="Filter all tables by target, owner, evidence&hellip;" autocomplete="off">
      <button type="button" id="advanced-toggle" class="mode-btn" aria-pressed="false" title="Toggle advanced filtering: field:value, AND, OR, NOT, contains:, uniq:column">Advanced</button>
      <div class="suggest-wrap hidden" id="suggest-wrap"><ul id="suggest-list"></ul></div>
    </div>
    <div class="filter-error hidden" id="filter-error"></div>
  </div>

  {''.join(sections_html)}

  {'<div class="empty">No database loaded. Start with --db to run the analysis.</div>' if not all_findings and db_path is None else ('<div class="empty">No findings were produced. Check the check configuration.</div>' if not all_findings else '')}

  </div>
  <div class="app-view hidden" data-view="collect">{collect_backend.view_html()}</div>
  <div class="app-view hidden" data-view="tokens">{collect_backend.tokens_view_html()}</div>
</div>
</div>

<div class="settings-overlay hidden" id="settings-overlay"
     role="dialog" aria-modal="true" aria-labelledby="settings-title">
  <div class="settings-box">
    <div class="settings-head">
      <div>
        <h3 id="settings-title">Settings</h3>
        <p class="sub">Local report and collection preferences.</p>
      </div>
      <button type="button" class="icon-btn" id="settings-close"
              aria-label="Close settings">&times;</button>
    </div>
    <div class="settings-tabs" role="tablist" aria-label="Settings sections">
      <button type="button" class="settings-tab active" id="settings-tab-general"
              data-settings-tab="general" role="tab" aria-selected="true"
              aria-controls="settings-panel-general">General</button>
      <button type="button" class="settings-tab" id="settings-tab-proxy"
              data-settings-tab="proxy" role="tab" aria-selected="false"
              aria-controls="settings-panel-proxy">Proxy</button>
    </div>
    <div class="settings-body">
      <section class="settings-panel" id="settings-panel-general"
               role="tabpanel" aria-labelledby="settings-tab-general">
        <div class="settings-section">
          <h4>Database</h4>
          <div class="settings-value"
               title="{esc(str(db_path)) if db_path is not None else 'No database loaded'}">{esc(str(db_path)) if db_path is not None else 'No database loaded'}</div>
        </div>
        <div class="settings-section">
          <h4>Appearance</h4>
          <p class="settings-note">Use the Light / Dark toggle at the bottom of
            the sidebar.</p>
        </div>
      </section>
      <section class="settings-panel hidden" id="settings-panel-proxy"
               role="tabpanel" aria-labelledby="settings-tab-proxy">
        <div class="settings-section">
          <h4>Proxy</h4>
          <p class="settings-note">Route collector and token-refresh traffic
            through an HTTP, HTTPS, SOCKS4, or SOCKS5 proxy.</p>
          <label class="settings-check">
            <input type="checkbox" id="settings-proxy-enabled">
            <span>Use a proxy for collection and token refresh</span>
          </label>
          <div class="settings-grid">
            <label class="settings-field wide">
              <span>Proxy URL</span>
              <input id="settings-proxy-url" type="text" autocomplete="off"
                     spellcheck="false"
                     placeholder="http://127.0.0.1:8080 or socks5h://127.0.0.1:1080">
            </label>
            <label class="settings-field">
              <span>Username (optional)</span>
              <input id="settings-proxy-user" type="text" autocomplete="off"
                     spellcheck="false">
            </label>
            <label class="settings-field">
              <span>Password (optional)</span>
              <input id="settings-proxy-pass" type="password"
                     autocomplete="new-password">
            </label>
            <label class="settings-field wide">
              <span>No-proxy hosts (optional)</span>
              <input id="settings-proxy-no-proxy" type="text" autocomplete="off"
                     spellcheck="false" placeholder="localhost,127.0.0.1">
            </label>
          </div>
          <p class="settings-note">SOCKS support requires PySocks in the
            collector virtualenv. Proxy credentials are stored in
            <span class="mono">.entra-surface-settings.json</span>.</p>
          <div class="settings-actions">
            <button type="button" class="mode-btn" id="settings-test">Test proxy</button>
          </div>
          <div class="settings-status hidden" id="settings-proxy-status"
               role="status" aria-live="polite"></div>
        </div>
      </section>
    </div>
    <div class="settings-foot">
      <button type="button" class="mode-btn" id="settings-save">Save</button>
      <button type="button" class="mode-btn" id="settings-done">Done</button>
    </div>
  </div>
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

<script type="application/json" id="suggest-data">{suggest_json}</script>

<script type="application/json" id="role-apps-data">{role_apps_json}</script>

<script type="application/json" id="table-catalog-data">{catalog_json}</script>

{extras_scripts_html}

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
  var gear = document.getElementById('sidebar-settings-btn');
  var overlay = document.getElementById('settings-overlay');
  var closeBtn = document.getElementById('settings-close');
  var doneBtn = document.getElementById('settings-done');
  var saveBtn = document.getElementById('settings-save');
  var testBtn = document.getElementById('settings-test');
  var proxyEnabled = document.getElementById('settings-proxy-enabled');
  var proxyUrl = document.getElementById('settings-proxy-url');
  var proxyUser = document.getElementById('settings-proxy-user');
  var proxyPass = document.getElementById('settings-proxy-pass');
  var proxyNoProxy = document.getElementById('settings-proxy-no-proxy');
  var proxyStatus = document.getElementById('settings-proxy-status');
  var tabs = Array.prototype.slice.call(
    document.querySelectorAll('#settings-overlay button[data-settings-tab]'));
  if (!gear || !overlay) return;

  function setProxyStatus(text, failed) {{
    if (!proxyStatus) return;
    proxyStatus.textContent = text || '';
    proxyStatus.classList.toggle('hidden', !text);
    proxyStatus.classList.toggle('error', !!failed);
  }}

  function fillProxy(proxy) {{
    proxy = proxy || {{}};
    if (proxyEnabled) proxyEnabled.checked = !!proxy.enabled;
    if (proxyUrl) proxyUrl.value = proxy.url || '';
    if (proxyUser) proxyUser.value = proxy.username || '';
    if (proxyPass) proxyPass.value = proxy.password || '';
    if (proxyNoProxy) proxyNoProxy.value = proxy.no_proxy || '';
  }}

  function proxyPayload() {{
    return {{
      enabled: !!(proxyEnabled && proxyEnabled.checked),
      url: proxyUrl ? proxyUrl.value.trim() : '',
      username: proxyUser ? proxyUser.value.trim() : '',
      password: proxyPass ? proxyPass.value : '',
      no_proxy: proxyNoProxy ? proxyNoProxy.value.trim() : ''
    }};
  }}

  function loadSettings() {{
    return fetch('/api/settings')
      .then(function(r) {{
        return r.json().then(function(data) {{
          if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
          return data;
        }});
      }})
      .then(function(data) {{
        fillProxy(data.proxy);
        setProxyStatus('', false);
      }})
      .catch(function(err) {{
        setProxyStatus(err.message || 'Could not load settings.', true);
      }});
  }}

  function saveSettings() {{
    var proxy = proxyPayload();
    if (proxy.enabled && !proxy.url) {{
      setProxyStatus('Enter a proxy URL.', true);
      selectTab('proxy');
      if (proxyUrl) proxyUrl.focus();
      return;
    }}
    if (saveBtn) saveBtn.disabled = true;
    setProxyStatus('Saving...', false);
    fetch('/api/settings', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ proxy: proxy }})
    }}).then(function(r) {{
      return r.json().then(function(data) {{
        if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
        return data;
      }});
    }}).then(function(data) {{
      fillProxy(data.proxy);
      setProxyStatus('Proxy settings saved.', false);
    }}).catch(function(err) {{
      setProxyStatus(err.message || 'Could not save settings.', true);
    }}).then(function() {{
      if (saveBtn) saveBtn.disabled = false;
    }});
  }}

  function testProxy() {{
    var proxy = proxyPayload();
    if (!proxy.enabled) {{
      setProxyStatus('Enable the proxy before testing it.', true);
      selectTab('proxy');
      return;
    }}
    if (!proxy.url) {{
      setProxyStatus('Enter a proxy URL.', true);
      selectTab('proxy');
      if (proxyUrl) proxyUrl.focus();
      return;
    }}
    if (testBtn) testBtn.disabled = true;
    setProxyStatus('Testing proxy...', false);
    fetch('/api/settings/test', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ proxy: proxy }})
    }}).then(function(r) {{
      return r.json().then(function(data) {{
        if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
        return data;
      }});
    }}).then(function(data) {{
      var bits = ['Proxy connection OK'];
      if (data.status) bits.push('HTTP ' + data.status);
      if (typeof data.elapsed_ms === 'number') bits.push(data.elapsed_ms + ' ms');
      setProxyStatus(bits.join(' \u00b7 ') + '.', false);
    }}).catch(function(err) {{
      setProxyStatus(err.message || 'Could not reach the proxy.', true);
    }}).then(function() {{
      if (testBtn) testBtn.disabled = false;
    }});
  }}

  function selectTab(name) {{
    tabs.forEach(function(tab) {{
      var active = tab.getAttribute('data-settings-tab') === name;
      tab.classList.toggle('active', active);
      tab.setAttribute('aria-selected', String(active));
      var panel = document.getElementById(
        'settings-panel-' + tab.getAttribute('data-settings-tab'));
      if (panel) panel.classList.toggle('hidden', !active);
    }});
  }}

  function setOpen(open) {{
    if (open) {{
      selectTab('general');
      overlay.classList.remove('hidden');
      document.body.classList.add('settings-open');
      gear.setAttribute('aria-expanded', 'true');
      if (closeBtn) closeBtn.focus();
      loadSettings();
    }} else {{
      overlay.classList.add('hidden');
      document.body.classList.remove('settings-open');
      gear.setAttribute('aria-expanded', 'false');
      gear.focus();
    }}
  }}

  gear.addEventListener('click', function(event) {{
    event.stopPropagation();
    setOpen(true);
  }});
  if (closeBtn) closeBtn.addEventListener('click', function() {{ setOpen(false); }});
  if (doneBtn) doneBtn.addEventListener('click', function() {{ setOpen(false); }});
  if (saveBtn) saveBtn.addEventListener('click', saveSettings);
  if (testBtn) testBtn.addEventListener('click', testProxy);
  overlay.addEventListener('click', function(event) {{
    if (event.target === overlay) setOpen(false);
  }});
  tabs.forEach(function(tab) {{
    tab.addEventListener('click', function() {{
      selectTab(tab.getAttribute('data-settings-tab'));
    }});
    tab.addEventListener('keydown', function(event) {{
      if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
      event.preventDefault();
      var index = tabs.indexOf(tab);
      var step = event.key === 'ArrowRight' ? 1 : -1;
      var next = tabs[(index + step + tabs.length) % tabs.length];
      selectTab(next.getAttribute('data-settings-tab'));
      next.focus();
    }});
  }});
  document.addEventListener('keydown', function(event) {{
    if (event.key !== 'Escape' || overlay.classList.contains('hidden')) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    setOpen(false);
  }});
}})();

(function() {{
  var body = document.body;
  var sidebar = document.getElementById('sidebar');
  var toggle = document.getElementById('sidebar-toggle');
  var arrow = toggle && toggle.querySelector('.sidebar-toggle-arrow');
  if (!sidebar || !toggle) return;

  function setOpen(open) {{
    body.classList.toggle('sidebar-open', open);
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', open ? 'Close sidebar' : 'Open sidebar');
    toggle.title = open ? 'Close sidebar' : 'Open sidebar';
    if (arrow) arrow.textContent = open ? '\u2039' : '\u203a';
    sidebar.setAttribute('aria-hidden', String(!open));
    sidebar.toggleAttribute('inert', !open);
    try {{ localStorage.setItem('entra-audit-sidebar', open ? 'open' : 'closed'); }} catch (e) {{}}
  }}
  var stored = null;
  try {{ stored = localStorage.getItem('entra-audit-sidebar'); }} catch (e) {{}}
  setOpen(stored !== 'closed');
  toggle.addEventListener('click', function() {{
    setOpen(!body.classList.contains('sidebar-open'));
  }});
  document.addEventListener('keydown', function(e) {{
    if (e.key === 'Escape' && body.classList.contains('sidebar-open')) {{
      setOpen(false);
      toggle.focus();
    }}
  }});
}})();

(function() {{
  var target = document.getElementById('sidebar-principal-body');
  if (!target) return;

  function showEmpty(text) {{
    target.innerHTML = '';
    var span = document.createElement('span');
    span.className = 'sidebar-principal-empty';
    span.textContent = text;
    target.appendChild(span);
  }}

  function render(data) {{
    var tokens = data.tokens || [];
    var active = null;
    for (var i = 0; i < tokens.length; i++) {{
      if (tokens[i].active) {{ active = tokens[i]; break; }}
    }}
    target.innerHTML = '';
    if (!active) {{
      showEmpty('No active token');
      return;
    }}
    var p = active.principal || {{}};
    var name = p.name || p.upn || 'Unredeemed refresh token';
    var activeClient = active.client_name || active.client_id || '';
    var sub = p.upn || (activeClient ? 'Client: ' + activeClient : '');
    var avatar = document.createElement('span');
    avatar.className = 'token-avatar';
    avatar.textContent = (name || '?').trim().charAt(0).toUpperCase() || '?';
    var info = document.createElement('div');
    info.className = 'sidebar-principal-info';
    var nameEl = document.createElement('div');
    nameEl.className = 'sidebar-principal-name';
    nameEl.textContent = name;
    info.appendChild(nameEl);
    if (sub) {{
      var subEl = document.createElement('div');
      subEl.className = 'sidebar-principal-sub';
      subEl.textContent = sub;
      info.appendChild(subEl);
    }}
    if (p.audience) {{
      var audEl = document.createElement('div');
      audEl.className = 'sidebar-principal-sub';
      var aud = String(active.audience_name || p.audience || '');
      if (aud.indexOf('https://') === 0) aud = aud.slice(8);
      else if (aud.indexOf('http://') === 0) aud = aud.slice(7);
      audEl.textContent = aud;
      if (active.audience_name && p.audience) audEl.title = p.audience;
      info.appendChild(audEl);
    }}
    target.appendChild(avatar);
    target.appendChild(info);
  }}

  function refresh() {{
    fetch('/api/tokens')
      .then(function(r) {{ return r.json(); }})
      .then(render)
      .catch(function() {{ showEmpty('Could not load active token'); }});
  }}

  document.addEventListener('app:view', refresh);
  document.addEventListener('tokens:changed', refresh);
  setInterval(refresh, 3000);
  refresh();
}})();

(function() {{
  var nav = document.getElementById('sidebar-nav');
  if (!nav) return;
  var items = Array.prototype.slice.call(nav.querySelectorAll('button[data-view]'));
  var views = Array.prototype.slice.call(document.querySelectorAll('.app-view[data-view]'));
  function apply(view) {{
    views.forEach(function(v) {{
      v.classList.toggle('hidden', v.getAttribute('data-view') !== view);
    }});
    items.forEach(function(b) {{
      var active = b.getAttribute('data-view') === view;
      b.classList.toggle('active', active);
      if (active) b.setAttribute('aria-current', 'page');
      else b.removeAttribute('aria-current');
    }});
    document.dispatchEvent(new CustomEvent('app:view', {{ detail: view }}));
    window.scrollTo(0, 0);
  }}
  items.forEach(function(b) {{
    b.addEventListener('click', function() {{ apply(b.getAttribute('data-view')); }});
  }});
}})();

(function() {{
  var tabsEl = document.getElementById('category-tabs');
  if (tabsEl) {{
    var btns = Array.prototype.slice.call(tabsEl.querySelectorAll('button[data-category]'));
    var sections = Array.prototype.slice.call(document.querySelectorAll('section[data-category]'));
    function apply(category) {{
      var caView = window.__caView || 'main';
      sections.forEach(function(s) {{
        var hidden = category !== 'all' && s.getAttribute('data-category') !== category;
        if (!hidden && s.hasAttribute('data-caview')) {{
          hidden = s.getAttribute('data-caview') !== caView;
        }}
        s.classList.toggle('hidden', hidden);
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
    ownerStatus: 'Owner Status', ownerSource: 'Owner Source',
    ownerAdDn: 'Owner AD DN', ownerAdSid: 'Owner SID',
    ownerImmutableId: 'Owner Immutable ID', app: 'Application',
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
    azProvider: 'Provider', azResource: 'Resource',
    appId: 'App ID', spType: 'SP type', polType: 'Policy type',
    polCreated: 'Created', polModified: 'Last modified', immutableId: 'Immutable ID'
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
    if (SERVE_DRILLDOWN_FIELDS[field]) {{
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
    if (SERVE_DRILLDOWN_FIELDS[field]) {{
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
  // runtime caches; populated on demand from the API endpoints
  var DETAILS = {{ sp: {{}}, app: {{}}, user: {{}}, device: {{}} }};
  var PROFILES = {{}};
  var PROFILES2 = {{ sp: {{}}, app: {{}} }};
  var GROUPS = {{}};
  var POLICIES = {{}};

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
        if (!spProf) return;
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
        ? '<p>' + g.eligible_roles.map(function(r) {{ return '<button type="button" class="elig-link dtab-sp-link" data-elig-role="' + pEsc(r.name) + '">' + pSev(r.severity) + ' ' + pEsc(r.name) + '</button> <span class="muted">(PIM eligible)</span>'; }}).join(' &nbsp;&middot;&nbsp; ') + '</p>'
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
        if (kind === 'sp') {{
          fetchSpApp(oid, 'sp', container);
          return;
        }}
        container.appendChild(section('Application', DETAILS.app[oid] || null));
      }});
    }});
    attachEligLinks(wrap, g, container, g.group_name || 'group', function() {{
      renderGroupTabs(g, container);
    }});
  }}

  function fillUserDetails(wrap, uid) {{
    var rec = DETAILS.user[uid] || null;
    var descEl = wrap.querySelector('.user-desc');
    if (descEl) {{
      var pairs = [
        ['Job title', rec ? rec.jobTitle : null],
        ['Department', rec ? rec.department : null],
        ['Company', rec ? rec.companyName : null],
        ['Office', rec ? rec.officeLocation : null],
        ['City', rec ? rec.city : null],
        ['Country', rec ? rec.country : null],
        ['Mail', rec ? rec.mail : null],
        ['Employee ID', rec ? rec.employeeId : null],
        ['Usage location', rec ? rec.usageLocation : null],
        ['Account type', rec ? rec.userType : null],
        ['Created', rec ? rec.createdDateTime : null]
      ];
      var items = pairs.filter(function(pair) {{ return pair[1]; }})
          .map(function(pair) {{
            return '<li><span class="muted">' + pEsc(pair[0]) + ':</span> '
                + pEsc(String(pair[1])) + '</li>';
          }});
      descEl.innerHTML = '<div class="detail-section"><h4>User details</h4>'
          + (items.length ? '<ul class="profile-list">' + items.join('') + '</ul>'
                          : '<p class="muted">No additional details captured for this user.</p>')
          + '</div>';
    }}
    var rawEl = wrap.querySelector('.user-raw');
    if (rawEl) {{
      rawEl.innerHTML = rec ? renderKVHtml(rec)
                            : '<p class="muted">Not available in the collected data.</p>';
    }}
  }}

  function renderProfileTabs(p, container) {{
    var overview = privilegeAnalysisHtml(p) + '<div class="user-desc"></div>' + openProfileHtml(p);
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
        ? cappedTableHtml(
            [['Type', 'type'], ['Name', 'name'], ['ObjectId', 'object_id'],
             ['AppId', 'app_id'], ['Privileged grants', 'grants'],
             ['Credentials', 'creds'], ['Status', 'status']],
            ownedLinks.map(function(r) {{
              return ['<td>' + pEsc(r.type) + '</td>', '<td>' + r.name + '</td>',
                      '<td class="mono">' + pEsc(r.object_id) + '</td>',
                      '<td class="mono">' + pEsc(r.app_id) + '</td>',
                      '<td>' + pEsc(r.grants) + '</td>',
                      '<td>' + pEsc(r.creds) + '</td>',
                      '<td>' + pEsc(r.status) + '</td>'];
            }}))
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
        ? cappedTableHtml(
            [['Device', 'name'], ['ObjectId', 'object_id'], ['OS', 'os'],
             ['AD-bound', 'ad'], ['Last logon', 'last_logon'], ['Status', 'status']],
            deviceLinks.map(function(r) {{
              return ['<td>' + r.name + '</td>',
                      '<td class="mono">' + pEsc(r.object_id) + '</td>',
                      '<td>' + pEsc(r.os) + '</td>', '<td>' + pEsc(r.ad) + '</td>',
                      '<td>' + pEsc(r.last_logon) + '</td>',
                      '<td>' + pEsc(r.status) + '</td>'];
            }}))
        : '<p class="muted">No devices recorded for this user.</p>';
    var uid = p.user_id || '';
    var rawPane = '<div class="user-raw" data-user-raw="' + pEsc(uid) + '"><p class="muted">Loading\u2026</p></div>';
    var panes = [
      ['overview', 'Overview', overview],
      ['azure', 'Azure roles (' + (p.az_roles ? p.az_roles.length : 0) + ')', azTableHtml(p.az_roles || [], false)],
      ['owned', 'Owned objects (' + (p.owned_objects ? p.owned_objects.length : 0) + ')', ownedHtml],
      ['devices', 'Devices (' + (p.devices ? p.devices.length : 0) + ')', devicesHtml],
      ['raw', 'Raw', rawPane]
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
    // user descriptions (overview) and the Raw pane are backed by the raw
    // user record, fetched on demand
    if (uid) {{
      if (DETAILS.user[uid]) {{
        fillUserDetails(wrap, uid);
      }} else {{
        fetch('/api/details/user/' + encodeURIComponent(uid))
          .then(function(r) {{ return r.json(); }})
          .then(function(rec) {{
            DETAILS.user[uid] = (rec && !rec.error) ? rec : null;
            fillUserDetails(wrap, uid);
          }})
          .catch(function() {{
            DETAILS.user[uid] = null;
            fillUserDetails(wrap, uid);
          }});
      }}
    }}
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
          fetchProfile('group', oid, function(g) {{ renderGroupTabs(g, container); }}, container);
          return;
        }}
        if (prof2) {{
          renderSpAppTabs(prof2, kind === 'app' ? (DETAILS.app[oid] || null) : (DETAILS.sp[oid] || null), container);
          return;
        }}
        if (kind === 'app' || kind === 'sp') {{
          fetchSpApp(oid, kind, container);
          return;
        }}
        if (kind === 'device') {{
          fetchDetailsAll([['device', oid]], container);
          return;
        }}
      }});
    }});
    attachEligLinks(wrap, p, container, p.user_display || 'user', function() {{
      renderProfileTabs(p, container);
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

  var LIST_CAP = 10;

  function cappedListHtml(items, renderFn) {{
    if (!items || !items.length) return '<p class="muted">None.</p>';
    var lis = items.map(renderFn);
    if (lis.length <= LIST_CAP) {{
      return '<ul class="profile-list">' + lis.join('') + '</ul>';
    }}
    return '<ul class="profile-list">' + lis.slice(0, LIST_CAP).join('') + '</ul>'
        + '<ul class="profile-list hidden" data-list-more="1">'
        + lis.slice(LIST_CAP).join('') + '</ul>'
        + '<button type="button" class="list-more-btn" data-list-more-btn="1">'
        + 'Show all (' + lis.length + ')</button>';
  }}

  function cappedTableHtml(headers, rows) {{
    function tableHtml(r) {{
      return '<table class="minor-table"><thead><tr>'
          + headers.map(function(c) {{ return '<th>' + pEsc(c[0]) + '</th>'; }}).join('')
          + '</tr></thead><tbody>'
          + r.map(function(row) {{
              return '<tr>' + row.map(function(c) {{ return '<td>' + c + '</td>'; }}).join('') + '</tr>';
            }}).join('')
          + '</tbody></table>';
    }}
    if (rows.length <= LIST_CAP) return tableHtml(rows);
    return '<div>' + tableHtml(rows.slice(0, LIST_CAP))
        + '<div class="hidden" data-table-more="1">' + tableHtml(rows.slice(LIST_CAP)) + '</div>'
        + '<button type="button" class="list-more-btn" data-table-more-btn="1">'
        + 'Show all (' + rows.length + ')</button></div>';
  }}

  // "Show all" buttons expand the hidden remainder of a capped list/table
  document.addEventListener('click', function(e) {{
    var btn = e.target.closest('.list-more-btn');
    if (!btn) return;
    var sec = btn.parentElement;
    var more = sec && sec.querySelector('ul[data-list-more="1"], div[data-table-more="1"]');
    if (more) {{
      more.classList.remove('hidden');
      btn.remove();
    }}
  }});

  function eligDetailHtml(entry) {{
    var rows = [
      ['Role', entry.name || '\u2014'],
      ['Severity', entry.severity || 'Info'],
      ['Source', entry.source || '\u2014'],
      ['Scope', entry.scope || 'Tenant-wide']
    ];
    if (entry.path && entry.path.length) {{
      rows.push(['Group path', entry.path.join(' \u2192 ')]);
    }}
    var s = entry.schedule;
    if (s) {{
      rows.push(['Assignment state', s.assignment_state || '\u2014']);
      rows.push(['Member type', s.member_type || '\u2014']);
      rows.push(['Permanent', s.permanent ? 'Yes' : 'No']);
      rows.push(['Starts', s.start || '\u2014']);
      rows.push(['Ends', s.end || (s.permanent ? 'Never' : '\u2014')]);
      rows.push(['Status', s.status || '\u2014']);
    }}
    return '<table class="kv-table">' + rows.map(function(r) {{
      return '<tr><th>' + pEsc(r[0]) + '</th><td>' + pEsc(String(r[1])) + '</td></tr>';
    }}).join('') + '</table>';
  }}

  function openEligDetail(p, name, container, backLabel, backFn) {{
    var entry = (p.eligible_roles || []).find(function(r) {{ return r.name === name; }});
    if (!entry) return;
    container.innerHTML = '';
    container.innerHTML = '<div class="detail-section"><h4>PIM eligibility \u2014 '
        + pEsc(entry.name) + ' ' + pSev(entry.severity) + '</h4>'
        + eligDetailHtml(entry) + '</div>'
        + '<div class="drawer-back-row"><button type="button" class="drawer-tab drawer-back">&larr; Back to '
        + pEsc(backLabel) + '</button></div>';
    Array.prototype.forEach.call(container.querySelectorAll('.drawer-back'), function(x) {{
      x.addEventListener('click', function() {{
        container.innerHTML = '';
        backFn();
      }});
    }});
  }}

  function attachEligLinks(scope, p, container, backLabel, backFn) {{
    Array.prototype.forEach.call(scope.querySelectorAll('.elig-link'), function(b) {{
      b.addEventListener('click', function() {{
        openEligDetail(p, b.getAttribute('data-elig-role'), container, backLabel, backFn);
      }});
    }});
  }}

  function privilegeAnalysisHtml(p) {{
    // every factor that contributed to the user's severity rating, with the
    // reason it was attributed ("via" path, naming the object type)
    function viaSource(s) {{
      s = s || 'assigned';
      if (s.indexOf('PIM eligible via ') === 0) {{
        return 'PIM eligibility in ' + s.slice('PIM eligible via '.length);
      }}
      if (s === 'PIM eligible') return 'PIM eligibility';
      if (s.indexOf('via ') === 0) return 'membership in ' + s.slice(4);
      return s;
    }}
    var factors = [];
    (p.roles || []).forEach(function(r) {{
      factors.push(pSev(r.severity) + ' ' + pEsc(r.name)
          + ' <span class="muted">\u2014 via ' + pEsc(viaSource(r.source)) + '</span>');
    }});
    (p.eligible_roles || []).forEach(function(r) {{
      factors.push('<button type="button" class="elig-link dtab-sp-link" data-elig-role="' + pEsc(r.name) + '">'
          + pSev(r.severity) + ' ' + pEsc(r.name) + '</button>'
          + ' <span class="muted">\u2014 via ' + pEsc(viaSource(r.source)) + '</span>');
    }});
    (p.priv_apps || []).forEach(function(a) {{
      var kind = a.kind === 'service principal' ? ' service principal' : ' application';
      (a.grants || []).forEach(function(g) {{
        factors.push(pSev(g.severity) + ' ' + pEsc(g.permission)
            + ' <span class="muted">on ' + pEsc(g.resource)
            + ' \u2014 via ownership of ' + pEsc(a.app_name) + kind + '</span>');
      }});
    }});
    (p.dir_sp_roles || []).forEach(function(s) {{
      factors.push(pSev(s.severity) + ' ' + pEsc(s.role)
          + ' <span class="muted">\u2014 via ownership of ' + pEsc(s.sp_name)
          + ' service principal</span>');
    }});
    if (p.cap_member && p.cap_member.length) {{
      factors.push(pSev('Medium') + ' member of role-capable group(s)'
          + ' <span class="muted">\u2014 via membership in '
          + pEsc(p.cap_member.map(function(g) {{ return g.name; }}).join(', ')) + ' group(s)</span>');
    }}
    (p.owned_cap || []).forEach(function(g) {{
      var roles = g.roles || [];
      if (roles.length) {{
        roles.forEach(function(r) {{
          factors.push(pSev(r.severity) + ' ' + pEsc(r.name)
              + ' <span class="muted">\u2014 via ownership of ' + pEsc(g.name) + ' group</span>');
        }});
      }} else {{
        factors.push(pSev('High') + ' ' + pEsc(g.name)
            + ' <span class="muted">\u2014 via ownership of role-capable group</span>');
      }}
    }});
    var head = 'Privilege Analysis ' + pSev(p.severity || 'Info');
    if (!factors.length) {{
      return '<div class="detail-section"><h4>' + head
          + '</h4><p class="muted">No privilege signals captured.</p></div>';
    }}
    return '<div class="detail-section"><h4>' + head + '</h4>'
        + cappedListHtml(factors, function(f) {{ return '<li>' + f + '</li>'; }})
        + '</div>';
  }}

  function openProfileHtml(p) {{
    function groupRank(g) {{
      return (g.roles && g.roles.length) ? 2 : (g.capable ? 1 : 0);
    }}
    var html = '';
    html += pSection('Directory roles', cappedListHtml(p.roles, function(r) {{
      return '<li>' + pSev(r.severity) + ' ' + pEsc(r.name) + ' <span class="muted">(' + pEsc(r.source) + ')</span></li>';
    }}));
    html += pSection('Eligible (PIM) roles', cappedListHtml(p.eligible_roles, function(r) {{
      var extra = '';
      if (r.schedule && r.schedule.permanent) extra = ' <span class="tag-chip tag-privileged">permanent</span>';
      if (r.path && r.path.length) extra += ' <span class="muted">via ' + pEsc(r.path.join(' \u2192 ')) + '</span>';
      return '<li><button type="button" class="elig-link dtab-sp-link" data-elig-role="' + pEsc(r.name) + '">'
          + pSev(r.severity) + ' ' + pEsc(r.name) + '</button>' + extra + '</li>';
    }}));
    html += pSection('Privileged objects owned', cappedListHtml(p.priv_apps, function(a) {{
      var grants = a.grants.map(function(g) {{
        return '<li>' + pEsc(g.permission) + ' <span class="muted">→ ' + pEsc(g.resource) + '</span> ' + pSev(g.severity) + '</li>';
      }}).join('');
      return '<li><b>' + pEsc(a.app_name) + '</b><ul>' + grants + '</ul></li>';
    }}));
    html += pSection('Service principals with directory roles (owned)', cappedListHtml(p.dir_sp_roles, function(s) {{
      return '<li>' + pEsc(s.sp_name) + ' — ' + pEsc(s.role) + ' ' + pSev(s.severity) + '</li>';
    }}));
    var ownedCap = (p.owned_cap || []).slice().sort(function(a, b) {{
      var ra = groupRank(a), rb = groupRank(b);
      if (ra !== rb) return rb - ra;
      return (a.name || '').toLowerCase() < (b.name || '').toLowerCase() ? -1 : 1;
    }});
    html += pSection('Owned role-capable groups (' + ownedCap.length + ')',
        cappedListHtml(ownedCap, function(g) {{
          var roles = (g.roles || []).map(function(r) {{
            return pSev(r.severity) + ' ' + pEsc(r.name);
          }}).join(' &nbsp;&middot;&nbsp; ');
          return '<li><b>' + pEsc(g.name) + '</b>'
              + (roles ? ' &mdash; ' + roles : '') + '</li>';
        }}));
    // role-bearing groups first, then role-capable, then alphabetical
    var gl = (p.groups || []).slice().sort(function(a, b) {{
      var ra = groupRank(a), rb = groupRank(b);
      if (ra !== rb) return rb - ra;
      return (a.name || '').toLowerCase() < (b.name || '').toLowerCase() ? -1 : 1;
    }});
    var groupsHtml = cappedListHtml(gl, function(g) {{
      var extra = '';
      if (g.capable) extra += ' <span class="tag-chip tag-privileged" title="Role-capable group (assignable to directory roles / role-bearing)">role-capable</span>';
      if (g.roles && g.roles.length) extra += ' <span class="muted">— ' + g.roles.map(function(r) {{ return r.name; }}).join(', ') + '</span>';
      return '<li><button type="button" class="dtab-sp-link obj-link" data-obj-id="' + pEsc(g.group_id) + '" data-obj-kind="group">' + pEsc(g.name) + '</button>' + extra + '</li>';
    }});
    if (!gl.length) {{
      groupsHtml = '<p class="muted">Not a member of any captured group.</p>';
    }}
    if (p.owned_count) {{
      groupsHtml += '<p class="muted">Owns ' + p.owned_count + ' group(s)';
      if (p.owned_cap.length) groupsHtml += ', incl. role-capable: ' + pEsc(capAnnotate(p.owned_cap).join('; '));
      groupsHtml += '</p>';
    }}
    html += pSection('Groups (' + gl.length + ')', groupsHtml);
    html += pSection('CA exclusions (' + (p.ca_exclusions ? p.ca_exclusions.length : 0) + ')',
        cappedListHtml(p.ca_exclusions, function(x) {{
          return '<li><button type="button" class="dtab-sp-link ca-link" data-ca-name="' + pEsc(x.name) + '">' + pEsc(x.name) + '</button> <span class="muted">(' + pEsc(x.state || '?') + ')</span></li>';
        }}));
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
    var spId2 = row.getAttribute('data-sp-id') || '';
    var appId2 = row.getAttribute('data-app-id') || '';
    if (spId2 && !PROFILES2.sp[spId2]) {{
      // the SP profile may not be cached yet even when the app profile is
      // (e.g. after navigating app -> back); prefer the SP drawer
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
    if (spId2 || appId2) {{
      fetchSpApp(spId2 || appId2, spId2 ? 'sp' : 'app', body);
      return;
    }}
    var profileId = row.getAttribute('data-profile-id') || '';
    var p = PROFILES[profileId];
    if (profileId && p) {{
      renderProfileTabs(p, body);
      return;
    }}
    if (profileId) {{
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
    if (gid2) {{
      fetchProfile('group', gid2, function(g) {{ renderGroupTabs(g, body); }}, body);
      return;
    }}
    var pid2 = row.getAttribute('data-policy-id') || '';
    if (pid2 && POLICIES[pid2]) {{
      renderPolicyTabs(POLICIES[pid2], body);
      return;
    }}
    if (pid2) {{
      fetchProfile('policy', pid2, function(pol) {{ renderPolicyTabs(pol, body); }}, body);
      return;
    }}
    var wants = [];
    if (row.getAttribute('data-device-id')) wants.push(['device', row.getAttribute('data-device-id')]);
    if (row.getAttribute('data-app-id')) wants.push(['app', row.getAttribute('data-app-id')]);
    if (row.getAttribute('data-sp-id')) wants.push(['sp', row.getAttribute('data-sp-id')]);
    if (wants.length) {{
      fetchDetailsAll(wants, body);
      return;
    }}
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
    if (!PROFILES[pid]) return;
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
    fetchSpApp(oid, 'app', body);
  }}

  window.__renderProfileTabs = renderProfileTabs;

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
    // merge extras-blob values so uniq/filters cover non-rendered columns too
    var tbl = row.closest('table');
    if (tbl && window.__columns && window.__columns.extras) {{
      var blob = window.__columns.extras(tbl.id);
      var key = row.getAttribute('data-detail-key');
      if (blob && key && blob[key]) {{
        Object.keys(blob[key]).forEach(function(f) {{
          if (!Object.prototype.hasOwnProperty.call(map, f.toLowerCase())) {{
            map[f.toLowerCase()] = (blob[key][f] && blob[key][f][1]) || '';
          }}
        }});
      }}
    }}
    return map;
  }}

  function setRowVisibility(test, uniqFields) {{
    var seenByTable = {{}};
    allTables().forEach(function(table) {{
      var seen = (uniqFields && uniqFields.length) ? (seenByTable[table.id] = {{}}) : null;
      Array.prototype.forEach.call(table.tBodies[0].rows, function(row) {{
        if (row.classList.contains('drawer')) return;
        var show = test(row);
        if (show && seen) {{
          var map = rowFieldMap(row);
          var key = uniqFields.map(function(f) {{
            return (map[f] || '').toLowerCase();
          }}).join('\\u0001');
          if (Object.prototype.hasOwnProperty.call(seen, key)) show = false;
          else seen[key] = true;
        }}
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
      if (field.toLowerCase() === 'uniq') {{
        knownFields().forEach(function(display) {{
          if (ADV_FILTER.normalizeField(display).indexOf(prefix) === 0) {{
            items.push({{ text: 'uniq:' + display, display: 'uniq:' + display, hint: 'column' }});
          }}
        }});
      }} else {{
        fieldValueSuggest(field, prefix).slice(0, 8).forEach(function(v) {{
          items.push({{ text: field + ':' + v, display: field + ':' + v, hint: 'value' }});
        }});
      }}
    }} else if (token) {{
      var pre = ADV_FILTER.normalizeField(token);
      knownFields().forEach(function(display) {{
        if (ADV_FILTER.normalizeField(display).indexOf(pre) === 0) {{
          items.push({{ text: display + ':', display: display + ':', hint: 'column' }});
        }}
      }});
    }} else {{
      ['AND', 'OR', 'NOT', 'contains:', 'uniq:'].forEach(function(op) {{
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
    var uf = ADV_FILTER.uniqFields ? ADV_FILTER.uniqFields(ast) : [];
    setRowVisibility(function(row) {{
      return ADV_FILTER.evaluate(ast, rowFieldMap(row), row.textContent);
    }}, uf);
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
        ? 'Advanced: severity:High AND target:contains:admin, uniq:owner&hellip;'
        : 'Filter all tables by target, owner, evidence&hellip;';
    hideSuggest();
    errorEl.classList.add('hidden');
    input.dispatchEvent(new Event('input', {{ bubbles: true }}));
  }});

  // ---- column reordering (drag headers; session only) --------------------
  var suppressSortClick = 0;

  function stampColumnIds() {{
    // Legacy column-identity stamping: only for tables without a column
    // catalog (the dynamic CA-analysis tables), which keep index-based sort.
    allTables().forEach(function(table) {{
      if (window.__columns && window.__columns.isManaged(table)) return;
      Array.prototype.forEach.call(table.tHead.rows[0].cells, function(th, i) {{
        if (!th.classList.contains('no-sort')) {{
          if (th.dataset.colidx === undefined) th.dataset.colidx = String(i);
          th.title = 'Click to sort · drag to reorder';
        }}
      }});
    }});
  }}

  function moveColumn(table, sourceTh, targetTh) {{
    var headerRow = table.tHead.rows[0];
    var colCount = headerRow.cells.length;
    var srcIdx = Array.prototype.indexOf.call(headerRow.cells, sourceTh);
    var tgtIdx = Array.prototype.indexOf.call(headerRow.cells, targetTh);
    if (srcIdx < 0 || tgtIdx < 0 || srcIdx === tgtIdx) return;
    headerRow.insertBefore(sourceTh, targetTh);
    // keep colgroup widths aligned with the header order
    var cols = table.querySelectorAll('colgroup col');
    if (cols.length) {{
      var srcCol = cols[srcIdx];
      var tgtCol = cols[tgtIdx];
      if (srcCol && tgtCol) srcCol.parentNode.insertBefore(srcCol, tgtCol);
    }}
    // Mirror the exact same single-cell move on every data row. A relative
    // move composes across drags; rebuilding cells from original column
    // identities would assume they are still in original order and misfile
    // them after the first drag.
    Array.prototype.forEach.call(table.tBodies[0].rows, function(row) {{
      if (row.classList.contains('drawer')) return;
      if (row.cells.length !== colCount) return;  // malformed row: leave it alone
      row.insertBefore(row.cells[srcIdx], row.cells[tgtIdx]);
    }});
    if (window.__columns && window.__columns.isManaged(table)) {{
      window.__columns.onReorder(table);
    }}
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
  window.__stampColumnIds = stampColumnIds;

  function wireTableSort(table) {{
    if (!table || !table.tHead || table.__sortWired) return;
    table.__sortWired = true;
    table.tHead.addEventListener('click', function(e) {{
      if (table.__loaderMade) return;  // serve-mode loader owns sorting
      var th = e.target.closest('th');
      if (!th || !table.tHead.contains(th) || th.classList.contains('no-sort')) return;
      if (suppressSortClick && Date.now() - suppressSortClick < 300) return;
      var headers = table.tHead.rows[0].cells;
      var idx = Array.prototype.indexOf.call(headers, th);
      if (idx < 0) return;
      var asc = th.__asc === undefined ? true : !!th.__asc;
      var mantissa = Array.prototype.filter.call(table.tBodies[0].rows, function(r) {{
        return !r.classList.contains('drawer');
      }});
      var drawers = Array.prototype.filter.call(table.tBodies[0].rows, function(r) {{
        return r.classList.contains('drawer');
      }});
      drawers.forEach(function(d) {{ d.remove(); }});
      mantissa.sort(function(a, b) {{
        var ac = a.cells[idx], bc = b.cells[idx];
        var av = ac ? ac.textContent.trim().toLowerCase() : '';
        var bv = bc ? bc.textContent.trim().toLowerCase() : '';
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
      th.__asc = !asc;
    }});
  }}
  allTables().forEach(wireTableSort);
  window.__wireTableSort = wireTableSort;

  function colForTh(table, th) {{
    var cg = table.querySelector('colgroup');
    if (!cg || !table.tHead) return null;
    var idx = Array.prototype.indexOf.call(table.tHead.rows[0].cells, th);
    return cg.children[idx] || null;
  }}

  function makeColumnsResizable(table) {{
    if (!table || !table.tHead) return;
    var headers = table.tHead.rows[0].cells;
    Array.prototype.forEach.call(headers, function(th, index) {{
      if (index === headers.length - 1 || th.classList.contains('no-sort')) return;
      if (th.querySelector(':scope > .col-resizer')) return;
      var handle = document.createElement('span');
      handle.className = 'col-resizer';
      handle.addEventListener('click', function(e) {{ e.stopPropagation(); }});
      handle.addEventListener('mousedown', function(e) {{
        e.preventDefault();
        e.stopPropagation();
        var col = colForTh(table, th);
        if (!col) return;
        var startX = e.clientX;
        var startWidth = col.getBoundingClientRect().width;
        var moved = false;
        handle.classList.add('resizing');
        document.body.style.userSelect = 'none';
        function onMouseMove(e2) {{
          if (!moved && Math.abs(e2.clientX - startX) > 3) moved = true;
          var newWidth = Math.max(50, startWidth + (e2.clientX - startX));
          col.style.width = newWidth + 'px';
        }}
        function onMouseUp() {{
          document.removeEventListener('mousemove', onMouseMove);
          document.removeEventListener('mouseup', onMouseUp);
          handle.classList.remove('resizing');
          document.body.style.userSelect = '';
          // The browser fires a click after the drag on the mousedown/mouseup
          // common ancestor; if it lands on the header it would toggle the
          // sort. Suppress sort clicks for a beat, exactly like column drags.
          if (moved) {{
            suppressSortClick = Date.now();
            window.__suppressSortClickUntil = suppressSortClick;
          }}
        }}
        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
      }});
      th.appendChild(handle);
    }});
  }}
  allTables().forEach(makeColumnsResizable);
  window.__makeColumnsResizable = makeColumnsResizable;

  window.__applyCurrentFilter = applyRowFilter;

  // ---- column manager (add/remove columns per table) ---------------------
  var COLUMN_CATALOG = {{}};
  try {{ COLUMN_CATALOG = JSON.parse(document.getElementById('table-catalog-data').textContent) || {{}}; }} catch (e) {{}}
  var COLUMN_EXTRAS = {{}};
  var COLUMN_STORE = 'entra-surface:cols:v1:';
  var FAMILY_LABELS = {{ sp: 'SP / application', user: 'User', group: 'Group', policy: 'CA policy', arc: 'Azure Arc' }};

  function columnMeta(tid) {{
    var meta = {{}};
    var entry = COLUMN_CATALOG[tid];
    ((entry && entry.fields) || []).forEach(function(f) {{ meta[f.id] = f; }});
    return meta;
  }}

  function columnExtras(tid) {{
    if (Object.prototype.hasOwnProperty.call(COLUMN_EXTRAS, tid)) return COLUMN_EXTRAS[tid];
    var el = document.getElementById('extras-' + tid);
    var blob = null;
    if (el) {{ try {{ blob = JSON.parse(el.textContent) || {{}}; }} catch (e) {{ blob = null; }} }}
    COLUMN_EXTRAS[tid] = blob;
    return blob;
  }}

  function isManagedColumnTable(table) {{
    return !!(table && table.id && COLUMN_CATALOG[table.id] && table.tHead);
  }}

  function columnFields(table) {{
    var out = [];
    Array.prototype.forEach.call(table.tHead.rows[0].cells, function(th) {{
      var f = th.getAttribute('data-field');
      if (f) out.push(f);
    }});
    return out;
  }}

  function defaultColumnFields(tid) {{
    var entry = COLUMN_CATALOG[tid] || {{}};
    return (entry.fields || []).filter(function(f) {{ return f['default']; }})
        .map(function(f) {{ return f.id; }});
  }}

  function readColumnState(tid) {{
    try {{
      var raw = localStorage.getItem(COLUMN_STORE + tid);
      if (!raw) return null;
      var arr = JSON.parse(raw);
      if (!Array.isArray(arr)) return null;
      var meta = columnMeta(tid), seen = {{}}, out = [];
      arr.forEach(function(id) {{
        if (meta[id] && !seen[id]) {{ seen[id] = 1; out.push(id); }}
      }});
      return out.length ? out : null;
    }} catch (e) {{ return null; }}
  }}

  function writeColumnState(tid, fields) {{
    try {{
      if (fields.join(',') === defaultColumnFields(tid).join(',')) {{
        localStorage.removeItem(COLUMN_STORE + tid);
      }} else {{
        localStorage.setItem(COLUMN_STORE + tid, JSON.stringify(fields));
      }}
    }} catch (e) {{}}
  }}

  function syncCols(table) {{
    var cg = table.querySelector('colgroup');
    if (!cg || !table.tHead) return;
    var headers = table.tHead.rows[0].cells;
    var widths = {{}};
    Array.prototype.forEach.call(cg.children, function(col, i) {{
      var th = headers[i];
      var f = th && th.getAttribute('data-field');
      if (f && col.style && col.style.width) widths[f] = col.style.width;
    }});
    var meta = columnMeta(table.id);
    var html = '';
    Array.prototype.forEach.call(headers, function(th) {{
      var f = th.getAttribute('data-field');
      if (!f) {{ html += '<col style="width:44px">'; return; }}
      var m = meta[f] || {{}};
      html += '<col style="width:' + (widths[f] || ((m.width || 120) + 'px')) + '">';
    }});
    cg.innerHTML = html;
  }}

  function extraCell(tid, detailKey, field, meta) {{
    var blob = columnExtras(tid);
    var pair = blob && blob[detailKey] ? blob[detailKey][field] : null;
    if (!pair) return null;
    var td = document.createElement('td');
    if (meta && meta.cls) td.className = meta.cls;
    td.setAttribute('data-field', field);
    td.setAttribute('data-value', pair[1] || '');
    td.innerHTML = pair[0];
    return td;
  }}

  function rebuildTable(table, fields) {{
    var tid = table.id;
    var meta = columnMeta(tid);
    var theadRow = table.tHead.rows[0];
    var thByField = {{}};
    Array.prototype.forEach.call(theadRow.cells, function(th) {{
      var f = th.getAttribute('data-field');
      if (f) thByField[f] = th;
    }});
    var ordered = [];
    Array.prototype.slice.call(theadRow.cells).forEach(function(th) {{
      if (th.getAttribute('data-field')) {{
        if (fields.indexOf(th.getAttribute('data-field')) < 0) th.remove();
      }} else {{
        ordered.push(th);
      }}
    }});
    fields.forEach(function(f) {{
      var th = thByField[f];
      if (!th) {{
        th = document.createElement('th');
        th.setAttribute('data-type', 'text');
        th.setAttribute('data-field', f);
        th.title = 'Click to sort \u00b7 drag to reorder';
        th.textContent = (meta[f] && meta[f].label) || f;
      }}
      ordered.push(th);
    }});
    ordered.forEach(function(th) {{ theadRow.appendChild(th); }});
    Array.prototype.forEach.call(table.tBodies[0].rows, function(row) {{
      if (row.classList.contains('drawer')) {{
        var dtd = row.querySelector('td');
        if (dtd) dtd.colSpan = fields.length + 1;
        return;
      }}
      var tdByField = {{}};
      var expander = null;
      Array.prototype.slice.call(row.cells).forEach(function(td) {{
        var f = td.getAttribute('data-field');
        if (f) {{
          if (fields.indexOf(f) >= 0) tdByField[f] = td;
          else td.remove();
        }} else if (expander === null) {{
          expander = td;
        }}
      }});
      if (!expander) return;
      var detailKey = row.getAttribute('data-detail-key') || '';
      var frag = document.createDocumentFragment();
      frag.appendChild(expander);
      fields.forEach(function(f) {{
        var td = tdByField[f];
        if (!td) td = extraCell(tid, detailKey, f, meta[f]);
        if (td) frag.appendChild(td);
      }});
      row.appendChild(frag);
    }});
    syncCols(table);
    if (window.__makeColumnsResizable) window.__makeColumnsResizable(table);
    if (window.__wireTableSort) window.__wireTableSort(table);
    if (window.__applyCurrentFilter) window.__applyCurrentFilter();
  }}

  function applyColumnList(table, fields) {{
    table.__columnFields = fields.slice();
    table.__pendingCols = null;
    writeColumnState(table.id, fields);
    if (table.__loaderMade && table.__reload) {{
      table.__reload();
    }} else {{
      rebuildTable(table, fields);
    }}
    updateColumnUI(table);
  }}

  function updateColumnUI(table) {{
    var ui = table.__colman;
    if (!ui) return;
    var visible = {{}};
    window.__columns.getFields(table).forEach(function(f) {{ visible[f] = 1; }});
    var hidden = 0;
    defaultColumnFields(table.id).forEach(function(f) {{ if (!visible[f]) hidden++; }});
    ui.badge.textContent = hidden ? String(hidden) : '';
    ui.badge.classList.toggle('hidden', !hidden);
  }}

  function escHtml(s) {{
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }}

  function closeColumnPops() {{
    Array.prototype.forEach.call(document.querySelectorAll('.colman-pop'), function(p) {{
      p.classList.add('hidden');
    }});
    Array.prototype.forEach.call(document.querySelectorAll('.colman-btn'), function(b) {{
      b.setAttribute('aria-expanded', 'false');
    }});
  }}
  document.addEventListener('click', closeColumnPops);

  function renderColumnPop(table) {{
    var ui = table.__colman;
    var entry = COLUMN_CATALOG[table.id];
    if (!ui || !entry) return;
    var visible = {{}};
    window.__columns.getFields(table).forEach(function(f) {{ visible[f] = 1; }});
    var byFamily = {{}}, order = [];
    (entry.fields || []).forEach(function(f) {{
      var fam = f.family || 'sp';
      if (!byFamily[fam]) {{ byFamily[fam] = []; order.push(fam); }}
      byFamily[fam].push(f);
    }});
    var famOrder = order.filter(function(f) {{ return f === entry.family; }})
        .concat(order.filter(function(f) {{ return f !== entry.family; }}));
    var html = '';
    famOrder.forEach(function(fam) {{
      html += '<div class="colman-group"><div class="colman-group-title">'
          + escHtml(FAMILY_LABELS[fam] || fam) + '</div>';
      byFamily[fam].forEach(function(f) {{
        html += '<label class="colman-item"><input type="checkbox" data-field="'
            + escHtml(f.id) + '"' + (visible[f.id] ? ' checked' : '') + '> <span>'
            + escHtml(f.label || f.id) + '</span></label>';
      }});
      html += '</div>';
    }});
    html += '<div class="colman-foot"><button type="button" class="colman-reset">'
        + 'Reset to defaults</button></div>';
    ui.pop.innerHTML = html;
    var reset = ui.pop.querySelector('.colman-reset');
    if (reset) reset.addEventListener('click', function(e) {{
      e.stopPropagation();
      applyColumnList(table, defaultColumnFields(table.id));
      renderColumnPop(table);
    }});
  }}

  function buildColumnUI(table) {{
    if (table.__colman || !COLUMN_CATALOG[table.id]) return;
    var scroll = table.closest('.table-scroll');
    if (!scroll) return;
    var wrap = document.createElement('div');
    wrap.className = 'colman';
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'colman-btn';
    btn.setAttribute('aria-expanded', 'false');
    btn.textContent = 'Columns \u25be';
    var badge = document.createElement('span');
    badge.className = 'colman-badge hidden';
    btn.appendChild(badge);
    var pop = document.createElement('div');
    pop.className = 'colman-pop hidden';
    wrap.appendChild(btn);
    wrap.appendChild(pop);
    // lift the picker onto the section's title line (h2 + button share a row)
    var section = table.closest('section');
    var h2 = section ? section.querySelector(':scope > h2') : null;
    if (section && h2) {{
      var headRow = document.createElement('div');
      headRow.className = 'table-head-row';
      section.insertBefore(headRow, h2);
      headRow.appendChild(h2);
      headRow.appendChild(wrap);
    }} else {{
      scroll.parentNode.insertBefore(wrap, scroll);
    }}
    table.__colman = {{ wrap: wrap, btn: btn, badge: badge, pop: pop }};
    btn.addEventListener('click', function(e) {{
      e.stopPropagation();
      var open = !pop.classList.contains('hidden');
      closeColumnPops();
      if (!open) {{
        renderColumnPop(table);
        pop.classList.remove('hidden');
        btn.setAttribute('aria-expanded', 'true');
      }}
    }});
    // keep the popover open while the user toggles columns inside it
    pop.addEventListener('click', function(e) {{ e.stopPropagation(); }});
    pop.addEventListener('change', function(e) {{
      var cb = e.target;
      if (!cb || cb.tagName !== 'INPUT') return;
      var field = cb.getAttribute('data-field');
      var current = window.__columns.getFields(table);
      if (cb.checked) {{
        if (current.indexOf(field) < 0) current.push(field);
      }} else {{
        if (current.length <= 1) {{ cb.checked = true; return; }}
        current = current.filter(function(x) {{ return x !== field; }});
      }}
      applyColumnList(table, current);
      renderColumnPop(table);
    }});
    updateColumnUI(table);
  }}

  window.__columns = {{
    catalog: COLUMN_CATALOG,
    isManaged: isManagedColumnTable,
    extras: columnExtras,
    getFields: function(table) {{
      if (table.__pendingCols) return table.__pendingCols.slice();
      return table.__columnFields ? table.__columnFields.slice() : columnFields(table);
    }},
    setFields: function(table, fields) {{
      table.__columnFields = fields.slice();
      updateColumnUI(table);
    }},
    colForTh: colForTh,
    syncCols: syncCols,
    apply: applyColumnList,
    reset: function(table) {{ applyColumnList(table, defaultColumnFields(table.id)); }},
    onReorder: function(table) {{
      table.__columnFields = columnFields(table);
      table.__pendingCols = null;
      writeColumnState(table.id, table.__columnFields);
      updateColumnUI(table);
    }}
  }};

  allTables().forEach(function(table) {{
    if (!isManagedColumnTable(table)) return;
    var saved = readColumnState(table.id);
    if (saved) {{
      table.__columnFields = saved.slice();
      if (table.getAttribute('data-serve') === '1') {{
        table.__pendingCols = saved.slice();
      }} else {{
        rebuildTable(table, saved);
      }}
    }}
    buildColumnUI(table);
  }});
}})();

(function() {{
  var filterInput = document.getElementById('filter-input');
  function makeLoader(table) {{
    if (table.__loaderMade) return;
    var pager = table.closest('.table-scroll') ? table.closest('.table-scroll').nextElementSibling : null;
    if (!pager || !pager.classList.contains('table-pager')) return;
    table.__loaderMade = true;
    var state = {{ page: 1, size: 25, q: '', sort: '', dir: 'asc' }};
    var tbody = table.tBodies[0];
    var info = pager.querySelector('.tp-info');
    var prev = pager.querySelector('.tp-prev');
    var next = pager.querySelector('.tp-next');
    var sizeSel = pager.querySelector('.tp-size');
    var timer = null;
    var fieldsKey = null;
    if (window.__columns && window.__columns.isManaged(table) && !table.__pendingCols) {{
      fieldsKey = window.__columns.getFields(table).join(',');
    }}
    function load() {{
      var params = 'page=' + state.page + '&size=' + state.size;
      if (state.q) params += '&q=' + encodeURIComponent(state.q);
      var adv = document.getElementById('advanced-toggle');
      if (adv && adv.getAttribute('aria-pressed') === 'true') params += '&mode=advanced';
      if (state.sort) params += '&sort=' + encodeURIComponent(state.sort) + '&dir=' + state.dir;
      var managed = window.__columns && window.__columns.isManaged(table);
      if (managed) params += '&cols=' + encodeURIComponent(window.__columns.getFields(table).join(','));
      fetch('/api/table/' + encodeURIComponent(table.id) + '?' + params)
        .then(function(r) {{ return r.json(); }})
        .then(function(d) {{
          if (!d || d.rows_html == null) return;
          if (managed && d.fields && window.__columns) {{
            var key = d.fields.join(',');
            if (key !== fieldsKey) {{
              fieldsKey = key;
              if (d.thead_html != null && table.tHead) table.tHead.rows[0].innerHTML = d.thead_html;
              var cg = table.querySelector('colgroup');
              if (cg && d.colgroup_html != null) cg.innerHTML = d.colgroup_html;
              if (window.__makeColumnsResizable) window.__makeColumnsResizable(table);
              if (window.__wireTableSort) window.__wireTableSort(table);
            }}
            window.__columns.setFields(table, d.fields);
            table.__pendingCols = null;
          }}
          tbody.innerHTML = d.rows_html;
          info.textContent = 'Page ' + d.page + ' of ' + d.pages + ' (' + d.total + ' rows)';
          pager.classList.remove('hidden');
          prev.disabled = d.page <= 1;
          next.disabled = d.page >= d.pages;
        }});
    }}
    table.__reload = function() {{ state.page = 1; load(); }};
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
      var managed = window.__columns && window.__columns.isManaged(table);
      var col = managed
          ? th.getAttribute('data-field')
          : (th.dataset.colidx || String(Array.prototype.indexOf.call(table.tHead.rows[0].cells, th)));
      if (!col) return;
      if (state.sort === String(col)) state.dir = state.dir === 'asc' ? 'desc' : 'asc';
      else {{ state.sort = String(col); state.dir = 'asc'; }}
      state.page = 1;
      Array.prototype.forEach.call(table.tHead.rows[0].cells, function(h) {{ h.classList.remove('sorted'); }});
      th.classList.add('sorted');
      load();
    }}, true);
    load();
  }}
  document.querySelectorAll('table.findings[data-serve="1"]').forEach(makeLoader);
  window.__makeLoader = makeLoader;

  // ---- on-demand CA coverage analysis ----------------------------------
  var caRun = document.getElementById('ca-run-btn');
  var caUserBtn = document.getElementById('ca-user-btn');
  var caUserInput = document.getElementById('ca-user-input');

  // CA view tabs: 'Conditional Access' vs 'Single user'
  var caViewTabs = document.querySelectorAll('#ca-view-tabs .drawer-tab');
  if (caViewTabs.length) {{
    Array.prototype.forEach.call(caViewTabs, function(tab) {{
      tab.addEventListener('click', function() {{
        window.__caView = tab.getAttribute('data-caview');
        Array.prototype.forEach.call(caViewTabs, function(t) {{
          t.classList.toggle('active', t === tab);
        }});
        var activeCat = document.querySelector('#category-tabs .tab-btn.active');
        if (activeCat) activeCat.click();  // re-applies category + view visibility
      }});
    }});
  }}

  if (caRun || caUserBtn) {{
    var caStatusEl = document.getElementById('ca-status');
    var caStepsEl = document.getElementById('ca-steps');
    var caResultsEl = document.getElementById('ca-results');
    var caUserStatusEl = document.getElementById('ca-user-status');
    var caUserStepsEl = document.getElementById('ca-user-steps');
    var caUserResultsEl = document.getElementById('ca-user-results');
    var caTimer = null;
    var caUserTimer = null;
    var caButtons = [caRun, caUserBtn].filter(function(b) {{ return !!b; }});

    function caSetBusy(busy) {{
      caButtons.forEach(function(b) {{ b.disabled = busy; }});
    }}

    function caStepState(d, stepsEl) {{
      stepsEl.innerHTML = '';
      (d.steps || []).forEach(function(s) {{
        var li = document.createElement('li');
        li.className = s.status;
        li.textContent = s.label;
        if (s.detail) {{
          var span = document.createElement('span');
          span.className = 'step-detail';
          span.textContent = s.detail;
          li.appendChild(span);
        }}
        stepsEl.appendChild(li);
      }});
      if (d.error) {{
        var err = document.createElement('li');
        err.className = 'error';
        err.textContent = 'Error: ' + d.error;
        stepsEl.appendChild(err);
      }}
    }}

    function caRenderResults(d, resultsEl) {{
      if (d.status === 'done' && d.result) {{
        resultsEl.innerHTML = (d.result.summary_html || '') + (d.result.sections_html || '');
        // these tables are created after load: stamp fresh headers with their
        // column identities so drag-reorder and serve-mode paging stay aligned
        if (window.__stampColumnIds) window.__stampColumnIds();
        Array.prototype.forEach.call(
            resultsEl.querySelectorAll('table.findings'), function(t) {{
              if (window.__wireTableSort) window.__wireTableSort(t);
              if (window.__makeColumnsResizable) window.__makeColumnsResizable(t);
              if (window.__makeLoader) window.__makeLoader(t);
            }});
      }}
    }}

    function caPoll(isUser) {{
      fetch('/api/ca-analysis/status').then(function(r) {{ return r.json(); }})
        .then(function(d) {{
          if (!d || !d.steps) return;
          if (isUser) {{
            caStepState(d, caUserStepsEl);
            if (d.status === 'running') {{ caUserTimer = setTimeout(function() {{ caPoll(true); }}, 600); return; }}
            caSetBusy(false);
            caRenderResults(d, caUserResultsEl);
          }} else {{
            caStepState(d, caStepsEl);
            if (d.status === 'running') {{ caTimer = setTimeout(function() {{ caPoll(false); }}, 600); return; }}
            caSetBusy(false);
            caRenderResults(d, caResultsEl);
          }}
        }}).catch(function() {{ caSetBusy(false); }});
    }}

    function startCa(upn, isUser) {{
      caSetBusy(true);
      var statusEl = isUser ? caUserStatusEl : caStatusEl;
      var stepsEl = isUser ? caUserStepsEl : caStepsEl;
      var resultsEl = isUser ? caUserResultsEl : caResultsEl;
      if (!isUser) {{ resultsEl.innerHTML = ''; }}
      statusEl.classList.remove('hidden');
      stepsEl.innerHTML = '';
      function val(id) {{
        var el = document.getElementById(id);
        return el ? el.value.trim() : '';
      }}
      var payload = {{
        upn: upn || '',
        assume_groups: val('ca-assume-groups'),
        assume_roles: val('ca-assume-roles'),
        scenario: {{
          platform: val('ca-wi-platform'), client_app: val('ca-wi-client'),
          device_state: val('ca-wi-device'), trusted_location: val('ca-wi-location'),
          signin_risk: val('ca-wi-signin'), user_risk: val('ca-wi-userrisk'),
          app_id: val('ca-app-input'), require: val('ca-wi-require')
        }}
      }};
      var body = JSON.stringify(payload);
      fetch('/api/ca-analysis', {{
        method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: body
      }})
        .then(function(r) {{ return r.json(); }})
        .then(function(d) {{
          if (d && d.status === 'running') {{
            if (isUser) caUserTimer = setTimeout(function() {{ caPoll(true); }}, 600);
            else caTimer = setTimeout(function() {{ caPoll(false); }}, 600);
          }} else {{
            caSetBusy(false);
          }}
        }}).catch(function() {{ caSetBusy(false); }});
    }}

    if (caRun) caRun.addEventListener('click', function() {{ startCa('', false); }});
    if (caUserBtn) caUserBtn.addEventListener('click', function() {{
      startCa(caUserInput ? caUserInput.value.trim() : '', true);
    }});
    if (caUserInput) {{
      caUserInput.addEventListener('keydown', function(e) {{
        if (e.key === 'Enter' && caUserBtn) caUserBtn.click();
      }});
    }}
  }}
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
    auth_mode = None
    if results:
        for res in results:
            if res["id"] != "ad_sync_summary":
                continue
            wb = (res["findings"][0].get("writeback") or {})
            writeback = bool(wb.get("count"))
            auth_mode = (res["findings"][0].get("auth_mode") or {}).get("short") or None

    domains = []
    for d in json_list(graph["tenant"].get("verified_domains")):
        if isinstance(d, dict) and d.get("name"):
            domains.append({"name": d["name"], "default": bool(d.get("default"))})
    domains.sort(key=lambda d: (not d["default"], d["name"]))

    pim = {
        "providers": list(graph.get("pim_providers") or []),
        "governance": bool(graph.get("pim_resources") or graph.get("pim_alerts")
                           or graph.get("pim_role_assignments")
                           or graph.get("pim_role_settings")),
    }

    return {
        "tenant": graph["tenant"].get("display_name") or "Unknown",
        "tenant_id": graph["tenant"].get("object_id") or "",
        "domains": [d["name"] for d in domains],
        "realm": ", ".join(sorted(realms)) or "",
        "sid_prefix": sid_prefix or "",
        "engine": engine,
        "writeback": writeback,
        "auth_mode": auth_mode,
        "pim": pim,
        "users": users,
        "enabled": enabled,
        "synced": synced,
        "apps": len(graph["app"]),
        "sps": len(graph["sp"]),
        "groups": len(graph["group"]),
        "devices": len(graph["device"]),
    }


# ---------------------------------------------------------------------------
# Live serving: the report shell; the users table, user profiles
# and user-field drilldowns are served on demand from the in-memory results so
# the page stays small at 50k+ users. Bound to 127.0.0.1, read-only.
# ---------------------------------------------------------------------------

SERVE_STATE = {"shell": "", "user_findings": [], "tables": {},
               "profiles2": {"sp": {}, "app": {}}, "group_profiles": {},
               "policy_profiles": {}, "details": {"sp": {}, "app": {}, "device": {}},
               "records": [], "db_path": None, "ca_analysis": None,
               "graph": {}, "check_cfg": {}, "group_roles": {},
               "group_eligible_roles": {}, "profile_builder": None,
               "profiles_lru": {}, "details_lru": {}}


def _install_analysis_state(results, graph, group_roles, group_eligible_roles,
                            check_cfg, report_html, serve_tables, db_path):
    SERVE_STATE["shell"] = report_html
    SERVE_STATE["db_path"] = str(db_path) if db_path is not None else None
    SERVE_STATE["ca_analysis"] = None
    SERVE_STATE["tables"] = serve_tables or {}
    SERVE_STATE["user_findings"] = next(
        (res["findings"] for res in results if res["id"] == "privileged_users"), [])
    SERVE_STATE["group_profiles"] = {
        f["group_id"]: f for res in results if res["id"] == "groups"
        for f in res["findings"]}
    SERVE_STATE["policy_profiles"] = {
        f["policy_id"]: f for res in results if res["id"] == "ca_exposure"
        for f in res["findings"] if f.get("policy_id")}
    SERVE_STATE["records"] = build_serve_records(results)
    SERVE_STATE["graph"] = graph
    SERVE_STATE["check_cfg"] = check_cfg
    SERVE_STATE["group_roles"] = group_roles
    SERVE_STATE["group_eligible_roles"] = group_eligible_roles
    SERVE_STATE["profile_builder"] = None
    SERVE_STATE["profiles_lru"] = {}
    SERVE_STATE["details_lru"] = {}
    SERVE_STATE.pop("ca_table_ids", None)


def run_runtime_analysis(db_path, use_cache=True):
    """Analyze a database chosen from the UI and swap the live report shell."""
    db_path = Path(db_path)
    config_path = Path(SERVE_STATE.get("config_path") or DEFAULT_CONFIG)
    azure_config = Path(SERVE_STATE.get("azure_config_path") or DEFAULT_AZURE_CONFIG)
    if not config_path.exists():
        raise RuntimeError(f"config not found: {config_path}")
    cache_path, cache_meta_path = cache_paths(db_path)

    analysis.set_message("Loading database")
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        cur = conn.cursor()
        tenant_name = None
        try:
            cur.execute("SELECT displayName FROM TenantDetails LIMIT 1")
            row = cur.fetchone()
            tenant_name = row[0] if row else None
        except sqlite3.OperationalError:
            pass
        fingerprint = compute_db_fingerprint(db_path, cur)

        config_resources, check_cfg = load_config(config_path)
        azure_role_sev = load_azure_roles(azure_config)
        check_cfg["azure_roles"] = azure_role_sev

        analysis.set_message("Building graph")
        graph = build_graph(cur)
        apply_azure_severity(graph, azure_role_sev)
    finally:
        conn.close()

    cached = load_cache(cache_path) if use_cache else None
    cache_hit = bool(
        use_cache and cached and cached.get("version") == CACHE_VERSION
        and cached.get("fingerprint") == fingerprint)

    if cache_hit:
        analysis.set_message("Using cached analysis")
        results = cached["results"]
        group_roles = cached.get("group_roles") or {}
        group_eligible_roles = cached.get("group_eligible_roles") or {}
        tenant_summary = build_tenant_summary(graph, results)
        diff = None
        cache_meta = {"hit": True,
                      "generated_at": cached.get("generated_at") or ""}
    else:
        analysis.set_message("Computing group roles")
        group_roles = compute_group_roles(graph, check_cfg)
        group_eligible_roles = compute_group_eligible_roles(graph, check_cfg)
        sp_dir_resolver = make_sp_dir_resolver(graph, group_roles,
                                               check_cfg["directory_roles"],
                                               group_eligible_roles)

        analysis.set_message("Running checks")
        results = run_checks(graph, config_resources, check_cfg,
                             group_roles=group_roles,
                             group_eligible_roles=group_eligible_roles,
                             sp_dir_resolver=sp_dir_resolver)

        tenant_summary = build_tenant_summary(graph, results)
        diff = compute_diff(cached.get("results", []), results) if cached else None
        if use_cache:
            cache_meta = {
                "hit": False,
                "off": False,
                "fresh": cached is None,
                "generated_at": datetime.datetime.now(
                    datetime.timezone.utc).isoformat(timespec="seconds"),
                "previous_at": cached.get("generated_at") if cached else None,
            }
        else:
            cache_meta = {"hit": False, "off": True}

    analysis.set_message("Rendering report")
    serve_tables = {}
    report_html = render_report(results, tenant_name, db_path, config_path,
                                tenant_summary, graph=graph,
                                serve_tables=serve_tables,
                                group_roles=group_roles,
                                group_eligible_roles=group_eligible_roles,
                                cache_meta=cache_meta, diff=diff)
    _install_analysis_state(results, graph, group_roles, group_eligible_roles,
                            check_cfg, report_html, serve_tables, db_path)

    if use_cache and not cache_hit:
        write_analysis_cache(cache_path, cache_meta_path, db_path, fingerprint,
                             cache_meta["generated_at"], results,
                             tenant_summary, group_roles, group_eligible_roles)


PROFILE_LRU_MAX = 4000
DETAIL_LRU_MAX = 4000

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
        "azure_arc_machines": "arc-machines-table",
        "azure_arc_sps": "arc-principals-table",
        "azure_arc_providers": "arc-providers-table",
    }.get(res_id, f"table-{res_id}")


def serve_field_map(table_id, f, owner=None):
    """Field map for one finding row in a serve table — mirrors the DOM
    data-field/data-value model plus the implicit 'check' and 'category'
    fields. Used by the advanced filter and the serve drilldown records."""
    fields = {"check": f.get("check_id", ""),
              "category": CHECK_ID_CATEGORY.get(f.get("check_id", ""), "")}
    if table_id.startswith("ca-"):
        # CA-analysis rows carry their own field map
        fields.update(f.get("fields") or {})
        return fields
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
    elif table_id == "arc-machines-table":
        fields.update({
            "arcMachine": f.get("machine_name") or "",
            "arcSub": f.get("arc_sub") or "",
            "arcRg": f.get("arc_rg") or "",
            "arcResourceId": f.get("arc_resource_id") or "",
            "arcStatus": (f.get("arc_status") or {}).get("label") or "",
        })
    elif table_id == "arc-principals-table":
        fields.update({
            "arcPrincipal": f.get("arc_principal") or "",
            "arcPrincipalType": f.get("arc_principal_type") or "",
            "arcTag": "AzureArcSPN" if f.get("arc_tagged") else "",
            "arcAzRoles": ", ".join(a.get("role", "") for a in f.get("arc_roles", [])),
            "pw": str(f.get("pw")) if f.get("pw") is not None else "",
            "pwLastSet": (f.get("pw_last_set") or "")[:10],
            "arcStatus": (f.get("arc_status") or {}).get("label") or "",
        })
    elif table_id == "arc-providers-table":
        fields.update({
            "arcProvider": f.get("arc_provider") or "",
            "arcStatus": (f.get("arc_status") or {}).get("label") or "",
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
    spec = table_spec(table_id)
    q = (qs.get("q") or [""])[0]
    mode = (qs.get("mode") or [""])[0]
    page = _serve_int(qs, "page", 1, 1, 10 ** 9)
    size = _serve_int(qs, "size", 25, 25, 2000)
    sort = (qs.get("sort") or [""])[0]
    desc = ((qs.get("dir") or ["asc"])[0]).lower() == "desc"
    row_kwargs = {}
    thead_html = None
    colgroup_html = None
    if spec is not None:
        fields = parse_cols_param((qs.get("cols") or [""])[0], table_id)
        sort_key = sort if sort in allowed_fields(table_id) else ""
        row_kwargs = {"columns": fields, "ctx": entry.get("ctx")}
        thead_html = table_thead_row_html(table_id, fields)
        colgroup_html = table_colgroup_inner_html(fields)
    else:
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
            uniq_fields = extract_uniq_fields(ast)

            def _uniq_key(field_map):
                return tuple((field_map.get(f) or "").lower()
                             for f in uniq_fields)

            if table_id == "owned-table":
                # the owned table renders one row per owner: filter at the
                # (finding, owner) row level so owner predicates keep only the
                # matching owner rows (same semantics as the client)
                filtered = []
                seen = set()
                for f in findings:
                    owners = [o for o in f.get("owners", [])
                              if evaluate_advanced(
                                  ast, serve_field_map("owned-table", f, o),
                                  entry["search"](f))]
                    if uniq_fields:
                        deduped_owners = []
                        for o in owners:
                            key = _uniq_key(
                                {k.lower(): v for k, v in
                                 serve_field_map("owned-table", f, o).items()})
                            if key in seen:
                                continue
                            seen.add(key)
                            deduped_owners.append(o)
                        owners = deduped_owners
                    if owners:
                        f2 = dict(f)
                        f2["owners"] = owners
                        filtered.append(f2)
                findings = filtered
            else:
                findings = [f for f in findings
                            if evaluate_advanced(ast, serve_field_map(table_id, f),
                                                 entry["search"](f))]
                if uniq_fields:
                    seen = set()
                    deduped = []
                    for f in findings:
                        key = _uniq_key(
                            {k.lower(): v for k, v in serve_field_map(table_id, f).items()})
                        if key in seen:
                            continue
                        seen.add(key)
                        deduped.append(f)
                    findings = deduped
            row_q = ""
    payload = {}
    if thead_html is not None:
        payload["fields"] = fields
        payload["thead_html"] = thead_html
        payload["colgroup_html"] = colgroup_html
    if table_id == "owned-table":
        # one row per owner: paginate by row, not by finding
        rows_html, _ = entry["rows"](findings, q=row_q, sort_key=sort_key,
                                     desc=desc, **row_kwargs)
        total = len(rows_html)
        pages = max(1, -(-total // size))
        page = min(page, pages)
        start = (page - 1) * size
        payload.update({
            "rows_html": "".join(rows_html[start:start + size]),
            "total": total,
            "page": page,
            "pages": pages,
            "size": size,
        })
        return payload, 200
    rows, total = entry["rows"](findings, q=row_q, sort_key=sort_key,
                                desc=desc, **row_kwargs)
    pages = max(1, -(-total // size))
    page = min(page, pages)
    start = (page - 1) * size
    payload.update({
        "rows_html": "".join(rows[start:start + size]),
        "total": total,
        "page": page,
        "pages": pages,
        "size": size,
    })
    return payload, 200


def _lru_get(cache, key):
    if key in cache:
        value = cache[key]
        del cache[key]
        cache[key] = value  # move to most-recently-used end
        return value
    return None


def _lru_put(cache, key, value, max_size):
    cache[key] = value
    while len(cache) > max_size:
        cache.pop(next(iter(cache)))


def _profile_builder():
    if SERVE_STATE.get("profile_builder") is None:
        graph = SERVE_STATE.get("graph") or {}
        check_cfg = SERVE_STATE.get("check_cfg") or {}
        builder = make_profile_builder(graph, check_cfg,
                                       SERVE_STATE.get("group_roles") or {},
                                       SERVE_STATE.get("group_eligible_roles") or {})
        SERVE_STATE["profile_builder"] = builder
    return SERVE_STATE["profile_builder"]


def _fetch_one_detail(kind, oid):
    """One raw record (with Arc enrichment) read from the collected database.
    The DB is opened read-only per request; results are LRU-cached."""
    db_path = SERVE_STATE.get("db_path")
    if not db_path:
        return None
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = con.cursor()
        recs = fetch_full_details(cur,
                                  {oid} if kind == "sp" else set(),
                                  {oid} if kind == "app" else set(),
                                  {oid} if kind == "user" else set(),
                                  {oid} if kind == "device" else set())
        con.close()
        return (recs.get(kind) or {}).get(oid)
    except sqlite3.Error:
        return None


def serve_profile_response(kind, oid):
    if kind == "user":
        prof = next((f for f in SERVE_STATE["user_findings"] if f.get("user_id") == oid), None)
    elif kind in ("sp", "app"):
        cache = SERVE_STATE["profiles_lru"]
        prof = _lru_get(cache, (kind, oid))
        if prof is None:
            builder = _profile_builder()
            prof = builder[kind](oid)
            if prof is not None:
                _lru_put(cache, (kind, oid), prof, PROFILE_LRU_MAX)
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
    if kind not in ("sp", "app", "user", "device"):
        return {"error": f"unknown detail kind: {kind}"}, 400
    cache = SERVE_STATE["details_lru"]
    rec = _lru_get(cache, (kind, oid))
    if rec is None:
        rec = _fetch_one_detail(kind, oid)
        if rec is not None:
            _lru_put(cache, (kind, oid), rec, DETAIL_LRU_MAX)
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


# ---------------------------------------------------------------------------
# On-demand CA coverage analysis (runs on button click)
# ---------------------------------------------------------------------------

CA_ANALYSIS_STEPS = [
    ("load", "Load CA policy and directory data"),
    ("scopes", "Resolve policy scopes (users / groups / roles)"),
    ("users", "Analyze per-user coverage"),
    ("apps", "Analyze application coverage"),
    ("legacy", "Analyze legacy authentication"),
    ("exclusions", "Analyze privileged-user exclusions"),
    ("render", "Render results"),
]

CA_GUEST_TOKENS = {
    "AllGuestUsers", "AllExternalUsers", "GuestOrExternalUsers",
    "GuestsOrExternalUsers", "GuestsAndExternalUsers",
}

CA_LEGACY_CLIENT_TYPES = {
    "EasSupported", "EasUnsupported", "OtherLegacy", "LegacySmtp", "LegacyPop",
    "LegacyImap", "LegacyMapi", "LegacyOffice",
}

CA_ALL_PLATFORMS = {"android", "windows", "windows_phone", "macos", "linux", "ios"}


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
    parsed = json_safe_value(detail)
    try:
        inner = json.loads(parsed[0]) if parsed and isinstance(parsed, list) \
            and isinstance(parsed[0], str) else (parsed[0] if parsed else None)
        return inner if isinstance(inner, dict) else {}
    except (json.JSONDecodeError, ValueError, TypeError, IndexError):
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
            trusted = False
            try:
                parsed = json_safe_value(detail)
                inner = json.loads(parsed[0]) if parsed and isinstance(parsed, list) \
                    and isinstance(parsed[0], str) else {}
                trusted = "trusted" in [str(c).lower() for c in (inner.get("Categories") or [])]
            except (json.JSONDecodeError, ValueError, TypeError, IndexError):
                pass
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
        cur.execute("SELECT objectId, userPrincipalName, displayName, userType, accountEnabled FROM Users")
        for oid, upn, disp, utype, enabled in cur.fetchall():
            data["users"][oid] = {"upn": upn or "", "name": disp or upn or oid,
                                  "type": utype or "Member", "enabled": bool(enabled)}
        cur.execute("SELECT objectId, displayName, appId FROM ServicePrincipals")
        for oid, disp, app_id in cur.fetchall():
            data["sps"][oid] = {"name": disp or oid, "appId": app_id or ""}
        for table, left, right, target in (
                ("lnk_group_member_user", "Group", "User", "group_member_user"),
                ("lnk_group_member_group", "Group", "childGroup", "group_member_group"),
                ("lnk_role_member_user", "DirectoryRole", "User", "role_member_user")):
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


def run_ca_analysis(db_path, progress, target_upn=None,
                    assume_groups=None, assume_roles=None, scenario=None):
    """Conditional Access coverage analysis. `progress(step_id, detail)` marks
    each step complete as it finishes. When `target_upn` is given, the analysis
    is scoped to that single user; `assume_groups`/`assume_roles` simulate
    memberships (names or IDs), and `scenario` is an optional what-if sign-in
    context (platform, client app, trusted location, risk levels, device state).
    Returns {summary_html, sections_html, tables}."""
    assume_groups = assume_groups or []
    assume_roles = assume_roles or []
    scenario = scenario or {}
    progress("load")
    data = load_ca_dataset(db_path)
    if target_upn:
        needle = (target_upn or "").strip().lower()
        target_uid = None
        for uid, rec in data["users"].items():
            if (rec.get("upn") or "").lower() == needle:
                target_uid = uid
                break
        if target_uid is None:
            raise ValueError(f"user '{target_upn}' not found in the collected users")

    progress("scopes")

    def _expand_group(gid, memo):
        if gid in memo:
            return memo[gid]
        out = set(data["group_member_user"].get(gid, ()))
        for child in data["group_member_group"].get(gid, ()):
            out |= _expand_group(child, memo)
        memo[gid] = out
        return out

    def _role_members(rid):
        return data["role_member_user"].get(rid, set()) | data["role_template_members"].get(rid, set())

    policies = []
    group_memo = {}
    for p in data["policies"]:
        inner = p["inner"]
        controls = [c for block in inner.get("Controls") or []
                    for c in (block.get("Control") or []) if isinstance(c, str)]
        state = (inner.get("State") or "").strip() or "Unknown"
        inc_users, inc_all, inc_guest = set(), False, False
        inc_group_list, inc_role_list = [], []
        for block in _ca_blocks(inner, "Users", "Include"):
            for uid in block.get("Users") or []:
                if uid == "All":
                    inc_all = True
                elif uid in CA_GUEST_TOKENS:
                    inc_guest = True
                else:
                    inc_users.add(uid)
            for gid in block.get("Groups") or []:
                if gid not in inc_group_list:
                    inc_group_list.append(gid)
                inc_users |= _expand_group(gid, group_memo)
            for rid in block.get("Roles") or []:
                if rid not in inc_role_list:
                    inc_role_list.append(rid)
                inc_users |= _role_members(rid)
        exc_users = set()
        exc_group_list, exc_role_list = [], []
        for block in _ca_blocks(inner, "Users", "Exclude"):
            for uid in block.get("Users") or []:
                if uid not in CA_GUEST_TOKENS and uid != "All":
                    exc_users.add(uid)
            for gid in block.get("Groups") or []:
                if gid not in exc_group_list:
                    exc_group_list.append(gid)
                exc_users |= _expand_group(gid, group_memo)
            for rid in block.get("Roles") or []:
                if rid not in exc_role_list:
                    exc_role_list.append(rid)
                exc_users |= _role_members(rid)
        apps_inc, apps_exc = [], []
        for block in _ca_blocks(inner, "Applications", "Include"):
            apps_inc.extend(block.get("Applications") or [])
        for block in _ca_blocks(inner, "Applications", "Exclude"):
            apps_exc.extend(block.get("Applications") or [])
        # client types (legacy auth etc.) — modern 'ClientTypes' section,
        # with fallback to the older 'ClientApplications' shape
        client_inc, client_exc = [], []
        for block in _ca_blocks(inner, "ClientTypes", "Include"):
            client_inc.extend(block.get("ClientTypes") or [])
        for block in _ca_blocks(inner, "ClientTypes", "Exclude"):
            client_exc.extend(block.get("ClientTypes") or [])
        for block in _ca_blocks(inner, "ClientApplications", "Include"):
            client_inc.extend(block.get("IncludeClientApplications") or [])
        for block in _ca_blocks(inner, "ClientApplications", "Exclude"):
            client_exc.extend(block.get("ExcludeClientApplications") or [])
        # device platforms + device states (live under DevicePlatforms)
        platforms_inc, platforms_exc = [], []
        device_states_inc, device_states_exc = [], []
        for block in _ca_blocks(inner, "DevicePlatforms", "Include"):
            platforms_inc.extend(block.get("DevicePlatforms") or block.get("IncludeDevicePlatforms") or [])
            device_states_inc.extend(block.get("IncludeDeviceStates") or [])
        for block in _ca_blocks(inner, "DevicePlatforms", "Exclude"):
            platforms_exc.extend(block.get("DevicePlatforms") or block.get("ExcludeDevicePlatforms") or [])
            device_states_exc.extend(block.get("ExcludeDeviceStates") or [])
        # named locations + trusted locations
        locations_inc, locations_exc, trusted_locations = [], [], False
        for block in _ca_blocks(inner, "Locations", "Include"):
            locations_inc.extend(block.get("IncludeLocations") or [])
            if block.get("IncludeTrustedLocations"):
                trusted_locations = True
        for block in _ca_blocks(inner, "Locations", "Exclude"):
            locations_exc.extend(block.get("ExcludeLocations") or [])
            if block.get("ExcludeTrustedLocations"):
                trusted_locations = True
        # risk-level conditions
        conds = inner.get("Conditions") or {}
        risk_signin = conds.get("SignInRiskLevels") or []
        risk_user = conds.get("UserRiskLevels") or []
        auth_strength = bool(sum((b.get("AuthStrengthIds") or [] for b in inner.get("Controls") or []), []))
        policies.append({
            "id": p["id"], "name": p["name"], "state": state,
            "enabled": state == "Enabled",
            "controls": controls,
            "mfa": "Mfa" in controls,
            "block": "Block" in controls,
            "compliant": "RequireCompliantDevice" in controls,
            "auth_strength": auth_strength,
            "inc_users": inc_users, "inc_all": inc_all, "inc_guest": inc_guest,
            "exc_users": exc_users,
            "inc_group_list": inc_group_list, "inc_role_list": inc_role_list,
            "exc_group_list": exc_group_list, "exc_role_list": exc_role_list,
            "apps_inc": apps_inc, "apps_exc": apps_exc,
            "client_inc": client_inc, "client_exc": client_exc,
            "platforms_inc": platforms_inc, "platforms_exc": platforms_exc,
            "device_states_inc": device_states_inc, "device_states_exc": device_states_exc,
            "locations_inc": locations_inc, "locations_exc": locations_exc,
            "trusted_locations": trusted_locations,
            "risk_signin": risk_signin, "risk_user": risk_user,
        })
    enabled = [p for p in policies if p["enabled"]]
    progress("scopes", f"{len(policies)} policy(ies), {len(enabled)} enabled")

    def applies_to(p, uid):
        if not (p["inc_all"] or uid in p["inc_users"] or p["inc_guest"]):
            return False
        return uid not in p["exc_users"]

    # privileged roster comes from the already-computed user findings; in
    # single-user mode the target is analyzed regardless of privilege level
    priv_users = {}
    if target_upn:
        rec = data["users"].get(target_uid) or {}
        sev = "Info"
        for f in SERVE_STATE.get("user_findings", []):
            if f.get("user_id") == target_uid:
                sev = f.get("severity", "Info")
                break
        priv_users[target_uid] = {"uid": target_uid,
                                  "upn": rec.get("upn") or target_upn,
                                  "name": rec.get("name") or target_upn,
                                  "severity": sev}
    else:
        for f in SERVE_STATE.get("user_findings", []):
            if is_privileged(f.get("severity", "Info")):
                uid = f.get("user_id")
                if not uid:
                    continue
                rec = data["users"].get(uid) or {}
                priv_users[uid] = {"uid": uid,
                                   "upn": rec.get("upn") or f.get("user_upn") or uid,
                                   "name": rec.get("name") or f.get("user_display") or uid,
                                   "severity": f.get("severity", "Info")}

    progress("users")
    zero_coverage, no_mfa, no_compliant, report_only_bypass = [], [], [], []
    for uid in sorted(priv_users, key=lambda u: (severity_rank(priv_users[u]["severity"]),
                                                 priv_users[u]["upn"].lower())):
        applying = [p for p in enabled if applies_to(p, uid)]
        reporting = [p for p in policies
                     if p["state"] != "Enabled" and applies_to(p, uid)]
        if not applying:
            zero_coverage.append(priv_users[uid])
            if reporting:
                report_only_bypass.append({
                    **priv_users[uid],
                    "policies": ", ".join(p["name"] for p in reporting),
                })
        else:
            if not any(p["mfa"] for p in applying):
                no_mfa.append(priv_users[uid])
            if not any(p["compliant"] for p in applying):
                no_compliant.append(priv_users[uid])
    progress("users", f"{len(zero_coverage)} zero coverage, "
                      f"{len(no_mfa)} without MFA, {len(no_compliant)} without compliant-device policy, "
                      f"{len(report_only_bypass)} report-only bypass")

    progress("apps")
    priv_sp_ids = {}
    for rec in SERVE_STATE.get("records", []):
        if is_privileged(rec.get("severity", "Info")):
            sid = (rec.get("__ids") or {}).get("sp")
            if sid and sid not in priv_sp_ids:
                priv_sp_ids[sid] = rec.get("severity", "Info")
    app_gaps = []
    for sid in sorted(priv_sp_ids):
        sp = data["sps"].get(sid) or {"name": sid, "appId": ""}
        app_id = (sp.get("appId") or "").lower()
        covered = any(
            "All" in p["apps_inc"] or "Office365" in p["apps_inc"]
            or any(str(a).lower() == app_id for a in p["apps_inc"] if a)
            for p in enabled)
        if not covered:
            app_gaps.append({"sp_id": sid, "name": sp.get("name") or sid,
                             "severity": priv_sp_ids[sid]})
    progress("apps", f"{len(app_gaps)} privileged app(s) without coverage")

    progress("legacy")
    legacy_blockers = [p for p in enabled if p["block"] and (
        any(t in CA_LEGACY_CLIENT_TYPES for t in p["client_inc"])
        or "All" in p["client_inc"])]
    legacy_gap = sorted(
        (priv_users[uid] for uid in priv_users
         if not any(applies_to(p, uid) for p in legacy_blockers)),
        key=lambda u: (severity_rank(u["severity"]), u["upn"].lower()))
    progress("legacy",
             f"{len(legacy_blockers)} legacy-auth block policy(ies), "
             f"{len(legacy_gap)} privileged user(s) outside them")

    progress("exclusions")
    excl_rows = []
    for uid in sorted(priv_users, key=lambda u: (severity_rank(priv_users[u]["severity"]),
                                                 priv_users[u]["upn"].lower())):
        exclusions = [p for p in enabled if uid in p["exc_users"]]
        if exclusions:
            excl_rows.append({
                **priv_users[uid],
                "count": len(exclusions),
                "policies": ", ".join(p["name"] for p in exclusions),
            })
    progress("exclusions", f"{len(excl_rows)} privileged user(s) with exclusions")

    progress("render")

    def build_table(tid, title, cols, rows, sort_fields, subtitle=""):
        """cols: [(label, width), ...] for data columns (expand col implicit);
        rows: list of {'_html', '_text', 'fields'}; sort_fields: {col_idx: field}."""
        cells = ['<th class="no-sort"></th>']
        for label, _w in cols:
            cells.append(f'<th data-type="text">{esc(label)}</th>')
        colgroup = '<col style="width:44px">' + "".join(
            f'<col style="width:{width}">' for _, width in cols)
        return {
            "id": tid, "title": title, "subtitle": subtitle,
            "cols": cols, "rows": rows, "sort_fields": sort_fields,
            "colspan": len(cols) + 1,
            "section": f"""
  <section data-category="configs">
    <h2>{esc(title)}</h2>
    {subtitle}
    <div class="table-scroll">
    <table id="{esc(tid)}" class="findings" data-serve="1">
      <colgroup>{colgroup}</colgroup>
      <thead><tr>{''.join(cells)}</tr></thead>
      <tbody></tbody>
    </table>
    </div>
    {_serve_pager()}
  </section>
""",
        }

    def user_row(r, key, extra_cell=""):
        sev = r.get("severity") or "Info"
        text = f"{r['name']} {r['upn']} {sev}".lower()
        html = (f'<tr data-profile-id="{esc(r["uid"])}" data-detail-key="{key}">'
                f'<td class="expand-cell">{EXPAND_BUTTON_HTML}</td>'
                f'<td data-field="severity" data-value="{sev}">{severity_badge(sev)}</td>'
                f'<td class="clickable" data-field="user" data-value="{esc(r["name"])}">{esc(r["name"])}</td>'
                f'<td class="clickable" data-field="userUpn" data-value="{esc(r["upn"])}">{esc(r["upn"])}</td>'
                f'{extra_cell}</tr>{drawer_for_html(key, 4 + (1 if extra_cell else 0))}')
        return {"_html": html, "_text": text,
                "fields": {"severity": sev, "user": r["name"], "upn": r["upn"]}}

    user_cols = [("Privileges", "100px"), ("User", "220px"), ("UPN", "260px")]
    user_sort = {"1": "severity", "3": "upn"}

    def user_rows_for(entries, key_prefix, extra=None):
        out = []
        for i, r in enumerate(entries):
            extra_cell = ""
            if extra:
                extra_cell = (f'<td data-field="caExcl" data-value="{esc(str(r["count"]))}">'
                              f'<span class="perm" title="{esc(r["policies"])}">{r["count"]}</span></td>')
            out.append(user_row(r, f"{key_prefix}-{i}", extra_cell))
        return out

    app_rows = []
    for i, r in enumerate(app_gaps):
        sev = r.get("severity") or "High"
        app_rows.append({
            "_html": (f'<tr data-sp-id="{esc(r["sp_id"])}" data-detail-key="ca-apps-{i}">'
                      f'<td class="expand-cell">{EXPAND_BUTTON_HTML}</td>'
                      f'<td data-field="severity" data-value="{sev}">{severity_badge(sev)}</td>'
                      f'<td class="clickable" data-field="app" data-value="{esc(r["name"])}">{esc(r["name"])}</td>'
                      f'</tr>{drawer_for_html("ca-apps-" + str(i), 3)}'),
            "_text": f"{r['name']} {sev}".lower(),
            "fields": {"severity": sev, "app": r["name"]},
        })

    legacy_rows = []
    if legacy_blockers:
        legacy_rows = user_rows_for(legacy_gap, "ca-legacy")

    def conds_row(p, key):
        def fmt(items, all_label="All"):
            if not items:
                return "—"
            items = sorted(str(x) for x in items if x)
            if "All" in items:
                return all_label
            return ", ".join(items)
        controls = []
        if p["mfa"]:
            controls.append("MFA")
        if p["compliant"]:
            controls.append("Compliant device")
        if p["block"]:
            controls.append("Block")
        if p["auth_strength"]:
            controls.append("Auth strength")
        platforms = fmt_platforms(p["platforms_inc"], p["platforms_exc"]) or "—"
        device_states = fmt(p["device_states_inc"], "Any device state")
        if p["device_states_exc"]:
            device_states += f" (excl. {', '.join(sorted(p['device_states_exc']))})"
        locations = ""
        loc_bits = []
        if p["trusted_locations"]:
            loc_bits.append("Trusted locations")
        for lid in p["locations_inc"]:
            low = str(lid).lower()
            if low == "all":
                loc_bits.append("All")
            elif low == "alltrusted":
                loc_bits.append("AllTrusted")
            else:
                rec = data["locations"].get(lid)
                loc_bits.append(f"{rec['name']}{' (trusted)' if rec and rec['trusted'] else ''}"
                                if rec else lid)
        for lid in p["locations_exc"]:
            low = str(lid).lower()
            if low == "all":
                loc_bits.append("excl. All")
            elif low == "alltrusted":
                loc_bits.append("excl. AllTrusted")
            else:
                rec = data["locations"].get(lid)
                loc_bits.append(f"excl. {rec['name']}" if rec else f"excl. {lid}")
        locations = ", ".join(loc_bits) or "—"
        risks = " + ".join([", ".join(p["risk_signin"]), ", ".join(p["risk_user"])]).strip(" +")
        clients = fmt(p["client_inc"]) if p["client_inc"] else "—"
        fields = {"polname": p["name"], "polstate": p["state"],
                  "polcontrols": ", ".join(controls), "polapps": fmt(p["apps_inc"]),
                  "platforms": platforms, "devicestates": device_states,
                  "locations": locations, "risk": risks or "—", "clients": clients}
        text = " ".join(fields.values()).lower()
        cells = (
            f'<td class="clickable" data-field="polName" data-value="{esc(p["name"])}">{esc(p["name"])}</td>'
            f'<td data-field="polState" data-value="{esc(p["state"])}">{esc(p["state"])}</td>'
            f'<td data-field="polControls" data-value="{esc(", ".join(controls))}">{esc(", ".join(controls) or "—")}</td>'
            f'<td data-field="polApps" data-value="{esc(fmt(p["apps_inc"]))}">{esc(fmt(p["apps_inc"]))}</td>'
            f'<td>{esc(platforms)}</td><td>{esc(device_states)}</td><td>{esc(locations)}</td>'
            f'<td>{esc(risks or "—")}</td><td>{esc(clients)}</td>')
        html = (f'<tr data-policy-id="{esc(p["id"])}" data-detail-key="{key}">'
                f'<td class="expand-cell">{EXPAND_BUTTON_HTML}</td>{cells}</tr>'
                f'{drawer_for_html(key, 10)}')
        return {"_html": html, "_text": text, "fields": fields}

    conds_rows = [conds_row(p, f"ca-conds-{i}") for i, p in enumerate(enabled)]

    tables = []
    if zero_coverage:
        tables.append(build_table("ca-zero-table", "Privileged users with no CA coverage",
                                  user_cols, user_rows_for(zero_coverage, "ca-zero"), user_sort))
    if no_mfa:
        tables.append(build_table("ca-mfa-table", "Privileged users without MFA policy coverage",
                                  user_cols, user_rows_for(no_mfa, "ca-mfa"), user_sort))
    if no_compliant:
        tables.append(build_table("ca-compliant-table", "Privileged users without compliant-device policy coverage",
                                  user_cols, user_rows_for(no_compliant, "ca-compliant"), user_sort))
    if report_only_bypass:
        ro_rows = []
        for i, r in enumerate(report_only_bypass):
            extra = (f'<td><span class="perm" title="{esc(r["policies"])}">report-only</span></td>')
            row = user_row(r, f"ca-ro-{i}", extra)
            row["fields"]["ro"] = r["policies"]
            ro_rows.append(row)
        tables.append(build_table(
            "ca-reportonly-table",
            "REPORT_ONLY_BYPASS (privileged users covered only by report-only policies)",
            [("Privileges", "100px"), ("User", "220px"), ("UPN", "240px"), ("Coverage", "110px")],
            ro_rows, {"1": "severity", "3": "upn"}))
    if app_rows:
        tables.append(build_table("ca-apps-table", "Privileged apps with no CA coverage",
                                  [("Privileges", "100px"), ("Application", "240px")],
                                  app_rows, {"1": "severity", "2": "app"}))
    if legacy_blockers:
        tables.append(build_table("ca-legacy-table",
                                  "Legacy-auth block coverage (privileged users outside)",
                                  user_cols, legacy_rows, user_sort,
                                  subtitle=f'<p class="sub">Blocking policies: '
                                           f'{esc(", ".join(p["name"] for p in legacy_blockers))}</p>'))
    if excl_rows:
        excl_table_rows = []
        for i, r in enumerate(excl_rows):
            extra = (f'<td data-field="caExcl" data-value="{esc(str(r["count"]))}">'
                     f'<span class="perm" title="{esc(r["policies"])}">{r["count"]}</span></td>')
            row = user_row(r, f"ca-excl-{i}", extra)
            row["fields"]["caexcl"] = str(r["count"])
            excl_table_rows.append(row)
        tables.append(build_table("ca-excl-table", "CA exclusions (privileged users)",
                                  [("Privileges", "100px"), ("User", "220px"), ("UPN", "260px"), ("Exclusions", "80px")],
                                  excl_table_rows, {"1": "severity", "3": "upn", "4": "caexcl"}))
    if enabled:
        tables.append(build_table("ca-conditions-table", "Enabled CA policy conditions",
                                  [("Policy", "240px"), ("State", "90px"), ("Controls", "150px"),
                                   ("Apps", "130px"), ("Platforms", "150px"), ("Device states", "130px"),
                                   ("Locations", "150px"), ("Risk", "120px"), ("Client types", "160px")],
                                  conds_rows, {"1": "polname", "2": "polstate"}))

    sections_html = "".join(t["section"] for t in tables if t)
    if not legacy_blockers:
        sections_html += ('  <section data-category="configs"><h2>Legacy authentication</h2>'
                          '<p class="sub">No enabled policy blocks legacy authentication.</p></section>')

    if target_upn:
        target = priv_users[target_uid]

        # ---- resolve assumed group/role names (or IDs) ---------------------
        def _resolve_assumed(names, table):
            ids, missing = [], []
            for raw in names:
                raw = (raw or "").strip()
                if not raw:
                    continue
                needle = raw.lower()
                hit = None
                for oid, label in table.items():
                    if oid.lower() == needle or (label or "").lower() == needle:
                        hit = oid
                        break
                if hit:
                    ids.append(hit)
                else:
                    missing.append(raw)
            return ids, missing

        assumed_gids, missing_g = _resolve_assumed(assume_groups, data["groups"])
        assumed_rids, missing_r = _resolve_assumed(assume_roles, data["roles"])
        if missing_g or missing_r:
            raise ValueError(
                ("unresolved assumed group(s): " + ", ".join(missing_g) + " · " if missing_g else "")
                + ("unresolved assumed role(s): " + ", ".join(missing_r) if missing_r else ""))

        # ---- the user's memberships, for targeting reasons -----------------
        user_roles = {rid for rid, members in data["role_member_user"].items()
                      if target_uid in members}
        for template_id, members in data["role_template_members"].items():
            if target_uid in members:
                user_roles.add(template_id)
        user_groups = {gid for gid, members in data["group_member_user"].items()
                       if target_uid in members}
        referenced_gids = set()
        for p in policies:
            referenced_gids.update(p["inc_group_list"])
            referenced_gids.update(p["exc_group_list"])
        containing = user_groups | {
            gid for gid in referenced_gids if target_uid in _expand_group(gid, group_memo)}
        all_groups = user_groups | set(assumed_gids)
        all_roles = user_roles | set(assumed_rids)

        def _gname(gid):
            label = data["groups"].get(gid, gid)
            return f"{label}" + ("" if gid in all_groups else " (nested)")

        def _rname(rid):
            label = data["roles"].get(rid, rid)
            return f"{label}" + ("" if rid not in assumed_rids or rid in user_roles else " (assumed)")

        def _included_sim(p):
            if p["inc_all"] or p["inc_guest"]:
                return True
            if target_uid in p["inc_users"]:
                return True
            if any(g in containing for g in p["inc_group_list"]):
                return True
            return any(r in all_roles for r in p["inc_role_list"])

        def _excluded_sim(p):
            if target_uid in p["exc_users"]:
                return True
            if any(g in containing for g in p["exc_group_list"]):
                return True
            return any(r in all_roles for r in p["exc_role_list"])

        def _include_reason(p):
            if p["inc_all"]:
                return "All users"
            matched = [g for g in p["inc_group_list"] if g in containing]
            if matched:
                return "via group: " + ", ".join(_gname(g) for g in matched[:3])
            matched_r = [r for r in p["inc_role_list"] if r in all_roles]
            if matched_r:
                return "via role: " + ", ".join(_rname(r) for r in matched_r[:3])
            if target_uid in p["inc_users"]:
                return "direct user"
            return "included"

        def _exclude_reason(p):
            if target_uid in p["exc_users"]:
                return "direct user"
            matched = [g for g in p["exc_group_list"] if g in containing]
            if matched:
                return "via group: " + ", ".join(_gname(g) for g in matched[:3])
            matched_r = [r for r in p["exc_role_list"] if r in all_roles]
            if matched_r:
                return "via role: " + ", ".join(_rname(r) for r in matched_r[:3])
            return "excluded"

        applying = [p for p in enabled if _included_sim(p) and not _excluded_sim(p)]
        excl_pols = [p for p in enabled if _excluded_sim(p)]

        # ---- what-if condition evaluation ----------------------------------
        sc = {"app_id": scenario.get("app_id") or None,
              "client_app": scenario.get("client_app") or None,
              "platform": scenario.get("platform") or None,
              "device_state": scenario.get("device_state") or None,
              "signin_risk": scenario.get("signin_risk") or None,
              "user_risk": scenario.get("user_risk") or None,
              "require": (scenario.get("require") or "").strip().lower(),
              "trusted_location": (None if scenario.get("trusted_location") in (None, "")
                                   else str(scenario["trusted_location"]).lower() == "true")}

        def _list_match(inc, exc, value, all_token="all"):
            if exc and (all_token in [str(e).lower() for e in exc]
                        or (value is not None and str(value).lower() in [str(e).lower() for e in exc])):
                return False
            if inc and (all_token in [str(i).lower() for i in inc]
                        or (value is not None and str(value).lower() in [str(i).lower() for i in inc])):
                return True
            return False

        def _app_axis(p):
            if not p["apps_inc"] and not p["apps_exc"]:
                return True, None
            app_id = sc["app_id"]
            inc_l = [str(a).lower() for a in p["apps_inc"]]
            exc_l = [str(a).lower() for a in p["apps_exc"]]
            if app_id and ("all" in exc_l or app_id.lower() in exc_l):
                return False, "resource excluded"
            if "all" in inc_l or "office365" in inc_l:
                return True, None
            if not app_id:
                return None, "resource not specified"
            if app_id.lower() in inc_l:
                return True, None
            return False, "resource not targeted"

        def _client_axis(p):
            if not p["client_inc"] and not p["client_exc"]:
                return True, None
            client = sc["client_app"]
            if not client:
                return None, "client app not specified"
            inc_l = [str(c).lower() for c in p["client_inc"]]
            exc_l = [str(c).lower() for c in p["client_exc"]]
            if "all" in exc_l or client.lower() in exc_l:
                return False, "client app excluded"
            if "all" in inc_l or client.lower() in inc_l:
                return True, None
            if client.lower() in ("exchangeactivesync", "other") and any(
                    str(c).lower() in CA_LEGACY_CLIENT_TYPES for c in inc_l):
                return True, None
            if inc_l and client.lower() in ("exchangeactivesync", "other"):
                return None, "legacy client mapping uncertain"
            return False, "client app not targeted"

        def _platform_axis(p):
            if not p["platforms_inc"] and not p["platforms_exc"]:
                return True, None
            plat = sc["platform"]
            if not plat:
                return None, "platform not specified"
            exc_l = [str(x).lower() for x in p["platforms_exc"]]
            if plat.lower() in exc_l:
                return False, "platform excluded"
            inc_l = [str(x).lower() for x in p["platforms_inc"]]
            if "all" in inc_l or plat.lower() in inc_l:
                return True, None
            return False, "platform not targeted"

        def _device_state_axis(p):
            if not p["device_states_inc"] and not p["device_states_exc"]:
                return True, None
            state = sc["device_state"]
            if not state:
                return None, "device state not specified"
            exc_l = [str(x).lower() for x in p["device_states_exc"]]
            if state.lower() in exc_l:
                return False, "device state excluded"
            inc_l = [str(x).lower() for x in p["device_states_inc"]]
            if "all" in inc_l or state.lower() in inc_l:
                return True, None
            return False, "device state not targeted"

        def _location_axis(p):
            inc_l, exc_l = p["locations_inc"], p["locations_exc"]
            if not inc_l and not exc_l and not p["trusted_locations"]:
                return True, None
            trusted = sc["trusted_location"]
            for loc in exc_l:
                low = str(loc).lower()
                if low == "all":
                    return False, "all locations excluded"
                if low == "alltrusted":
                    if trusted is True:
                        return False, "trusted locations excluded"
                    continue
                rec = data["locations"].get(loc)
                if rec is None:
                    return None, "named location excluded (not found)"
                if trusted is not None and rec["trusted"] == trusted:
                    return False, f"location '{rec['name']}' excluded"
            if p["trusted_locations"] or any(str(l).lower() == "alltrusted" for l in inc_l):
                if trusted is None:
                    return None, "trusted location not specified"
                return trusted, None
            for loc in inc_l:
                low = str(loc).lower()
                if low == "all":
                    return True, None
                rec = data["locations"].get(loc)
                if rec is None:
                    return None, "named location (not found)"
                if trusted is None:
                    return None, f"location '{rec['name']}' not specified"
                if rec["trusted"] == trusted:
                    return True, None
                return False, f"location '{rec['name']}' does not match"
            return True, None

        def _risk_axis(name, policy_list, sc_value):
            if not policy_list:
                return True, None
            if not sc_value:
                return None, f"{name} not specified"
            if any(str(r).lower() == sc_value.lower() for r in policy_list):
                return True, None
            return False, f"{name} not targeted"

        def _effect(p):
            if p["block"]:
                return "Block"
            return "Grant" if p["controls"] else "Unknown"

        def whatif_eval(p):
            axes = [_app_axis(p), _client_axis(p), _platform_axis(p),
                    _device_state_axis(p), _location_axis(p),
                    _risk_axis("sign-in risk", p["risk_signin"], sc["signin_risk"]),
                    _risk_axis("user risk", p["risk_user"], sc["user_risk"])]
            notes = []
            for matched, note in axes:
                if matched is False:
                    return {"applies": "no", "note": note}
                if matched is None:
                    notes.append(note)
            if notes:
                return {"applies": "signal", "note": "; ".join(notes)}
            return {"applies": "yes", "note": None}

        whatif_rows = []
        for p in enabled:
            if not _included_sim(p) or _excluded_sim(p):
                continue
            verdict = whatif_eval(p)
            whatif_rows.append({**p, "verdict": verdict})

        def_en = [r for r in whatif_rows
                  if r["verdict"]["applies"] == "yes" and r["state"] == "Enabled"]
        def_rep = [r for r in whatif_rows
                   if r["verdict"]["applies"] == "yes" and r["state"] != "Enabled"]
        gap = None
        require = sc["require"]
        require_label = {"mfa": "MFA"}.get(require)
        if require == "mfa" and not any(r["mfa"] for r in def_en):
            gap = ("NO_MFA_ENFORCED",
                   "No definitively applying enabled policy requires MFA in this scenario.")
        elif not def_en and not def_rep:
            gap = ("NO_POLICIES_APPLY",
                   "No policy definitively applies in this scenario.")
        elif not def_en:
            gap = ("REPORT_ONLY_BYPASS",
                   "Only report-only policies definitively apply; no enforcement.")
        elif sc["trusted_location"] is True and not any(
                r["mfa"] or r["block"] for r in def_en):
            gap = ("TRUSTED_LOCATION_BYPASS",
                   "Definitive policies apply from the trusted location, but none enforce MFA or Block.")

        # ---- render: applying table with reasons ---------------------------
        apply_rows = []
        for i, p in enumerate(applying):
            controls = []
            if p["mfa"]:
                controls.append("MFA")
            if p["compliant"]:
                controls.append("Compliant device")
            if p["block"]:
                controls.append("Block")
            if p["auth_strength"]:
                controls.append("Auth strength")
            why = _include_reason(p)
            fields = {"polname": p["name"], "controls": ", ".join(controls),
                      "mfa": "Yes" if p["mfa"] else "—",
                      "compliant": "Yes" if p["compliant"] else "—",
                      "why": why}
            cells = (f'<td class="clickable" data-field="polName" data-value="{esc(p["name"])}">{esc(p["name"])}</td>'
                     f'<td>{esc(", ".join(controls) or "—")}</td>'
                     f'<td>{esc("Yes" if p["mfa"] else "—")}</td>'
                     f'<td>{esc("Yes" if p["compliant"] else "—")}</td>'
                     f'<td class="muted">{esc(why)}</td>')
            apply_rows.append({
                "_html": (f'<tr data-policy-id="{esc(p["id"])}" data-detail-key="ca-apply-{i}">'
                          f'<td class="expand-cell">{EXPAND_BUTTON_HTML}</td>{cells}</tr>'
                          f'{drawer_for_html("ca-apply-" + str(i), 6)}'),
                "_text": " ".join(fields.values()).lower(),
                "fields": fields,
            })
        tables = [build_table("ca-apply-table", f"Policies applying to {target['upn']}",
                              [("Policy", "240px"), ("Controls", "150px"), ("MFA", "55px"),
                               ("Compliant", "80px"), ("Why", "220px")],
                              apply_rows, {"1": "polname"})]

        # what-if table
        def _loc_label(lid):
            low = str(lid).lower()
            if low == "all":
                return "All"
            if low == "alltrusted":
                return "AllTrusted"
            rec = data["locations"].get(lid)
            if not rec:
                return str(lid)
            return rec["name"] + (" (trusted)" if rec["trusted"] else "")

        def signals_html(r):
            rows = []

            def axis(label, inc, exc):
                bits = []
                if inc:
                    bits.append("All" if "All" in [str(x) for x in inc]
                                else ", ".join(str(x) for x in inc))
                if exc:
                    bits.append("excl: " + ", ".join(str(x) for x in exc))
                if bits:
                    rows.append(f"<tr><th>{esc(label)}</th><td>{esc(' \u00b7 '.join(bits))}</td></tr>")

            plat = fmt_platforms(r["platforms_inc"], r["platforms_exc"])
            if plat:
                rows.append(f"<tr><th>Platform</th><td>{esc(plat)}</td></tr>")
            axis("Client types", r["client_inc"], r["client_exc"])
            axis("Device states", r["device_states_inc"], r["device_states_exc"])
            loc_bits = []
            if r["trusted_locations"]:
                loc_bits.append("Trusted locations")
            for l in r["locations_inc"]:
                loc_bits.append(_loc_label(l))
            for l in r["locations_exc"]:
                loc_bits.append("excl: " + _loc_label(l))
            if loc_bits:
                rows.append(f"<tr><th>Locations</th><td>{esc(', '.join(loc_bits))}</td></tr>")
            risks = [f"sign-in: {x}" for x in r["risk_signin"]] \
                + [f"user: {x}" for x in r["risk_user"]]
            if risks:
                rows.append(f"<tr><th>Risk</th><td>{esc(', '.join(risks))}</td></tr>")
            app_bits = []
            if "All" in [str(a) for a in r["apps_inc"]]:
                app_bits.append("All")
            elif r["apps_inc"]:
                app_bits.append(", ".join(str(a) for a in r["apps_inc"]))
            if r["apps_exc"]:
                app_bits.append("excl: " + ", ".join(str(a) for a in r["apps_exc"]))
            if app_bits:
                rows.append(f"<tr><th>Applications</th><td>{esc(' \u00b7 '.join(app_bits))}</td></tr>")
            if not rows:
                return ('<p class="muted">No platform, client, device, location, risk, or app '
                        'conditions — the policy applies whenever its user scope matches.</p>')
            return '<table class="kv-table">' + "".join(rows) + "</table>"

        wi_rows = []
        for i, r in enumerate(whatif_rows):
            v = r["verdict"]
            verdict_label = {"yes": "Applies", "no": "Does not apply",
                             "signal": "Applies (signal-dependent)"}[v["applies"]]
            fields = {"polname": r["name"], "state": r["state"],
                      "effect": _effect(r), "verdict": verdict_label,
                      "note": v["note"] or ""}
            cells = (f'<td class="clickable" data-field="polName" data-value="{esc(r["name"])}">{esc(r["name"])}</td>'
                     f'<td>{esc(r["state"])}</td>'
                     f'<td>{esc(_effect(r))}</td>'
                     f'<td>{esc(verdict_label)}</td>'
                     f'<td class="muted">{esc(v["note"] or "—")}</td>')
            summary = (f'<table class="kv-table">'
                       f'<tr><th>Policy</th><td>{esc(r["name"])}</td></tr>'
                       f'<tr><th>State</th><td>{esc(r["state"])}</td></tr>'
                       f'<tr><th>Effect</th><td>{esc(_effect(r))}</td></tr>'
                       f'<tr><th>Verdict</th><td>{esc(verdict_label)}</td></tr>'
                       + (f'<tr><th>Signal note</th><td>{esc(v["note"])}</td></tr>' if v.get("note") else "")
                       + "</table>")
            drawer_body = (summary
                           + '<div class="detail-section"><h4>Dependent signals</h4>'
                           + signals_html(r) + "</div>")
            drawer = (f'<tr class="drawer" data-detail-for="ca-whatif-{i}">'
                      f'<td colspan="6"><div class="drawer-body">{drawer_body}</div></td></tr>')
            wi_rows.append({
                "_html": (f'<tr data-detail-key="ca-whatif-{i}">'
                          f'<td class="expand-cell">{EXPAND_BUTTON_HTML}</td>{cells}</tr>'
                          f'{drawer}'),
                "_text": " ".join(fields.values()).lower(),
                "fields": fields,
            })
        wi_scenario = [x for x in [sc["require"] and f"require={require_label}",
                                   sc["platform"] and f"platform={sc['platform']}",
                                   sc["client_app"] and f"client={sc['client_app']}",
                                   sc["device_state"] and f"device={sc['device_state']}",
                                   sc["trusted_location"] is not None
                                       and f"trusted={sc['trusted_location']}",
                                   sc["signin_risk"] and f"signin-risk={sc['signin_risk']}",
                                   sc["user_risk"] and f"user-risk={sc['user_risk']}",
                                   sc["app_id"] and f"resource={sc['app_id']}"] if x]
        gap_html = (f'<p class="sub"><b>Gap: {esc(gap[0])}</b> — {esc(gap[1])}</p>' if gap else
                    f'<p class="sub">Coverage holds: a definitive enabled policy'
                    f'{f" enforces {esc(require_label)}" if require_label else ""} in this scenario.</p>')
        tables.append(build_table(
            "ca-whatif-table", "What-if evaluation",
            [("Policy", "240px"), ("State", "90px"), ("Effect", "70px"),
             ("Verdict", "150px"), ("Note", "240px")],
            wi_rows, {"1": "polname"},
            subtitle=f'<p class="sub">Scenario: {esc(" · ".join(wi_scenario)) if wi_scenario else "unspecified (all signal-dependent axes flagged)"}</p>'
                     + gap_html))

        flags = []
        if not applying:
            flags.append("no CA policy applies")
        else:
            if not any(p["mfa"] for p in applying):
                flags.append("no MFA policy")
            if not any(p["compliant"] for p in applying):
                flags.append("no compliant-device policy")
        if legacy_blockers and not any(
                _included_sim(p) and not _excluded_sim(p) for p in legacy_blockers):
            flags.append("outside legacy-auth block")
        if excl_pols:
            flags.append(f"excluded from {len(excl_pols)} policy(ies)")
        if gap:
            flags.append(f"what-if: {gap[0]}")
        elif require_label:
            flags.append(f"what-if: {require_label} enforced")
        summary_html = f"""
  <section data-category="configs">
    <h2>CA coverage analysis</h2>
    <div class="engine-card"><table class="kv-table">
      <tr><th>User</th><td>{esc(target['name'])} <span class="muted">({esc(target['upn'])})</span></td></tr>
      <tr><th>Privileges</th><td>{severity_badge(target['severity'])}</td></tr>
      <tr><th>Enabled CA policies applying</th><td>{len(applying)}</td></tr>
      <tr><th>MFA policies applying</th><td>{sum(1 for p in applying if p['mfa'])}</td></tr>
      <tr><th>Compliant-device policies applying</th><td>{sum(1 for p in applying if p['compliant'])}</td></tr>
      <tr><th>Exclusions</th><td>{len(excl_pols)}</td></tr>
      <tr><th>Assessment</th><td>{esc(' · '.join(flags)) if flags else 'all coverage controls apply'}</td></tr>
    </table></div>
  </section>
"""
        if excl_pols:
            items = "".join(
                f'<li>{esc(p["name"])} <span class="muted">({esc(p["state"])} · '
                f'{esc(_exclude_reason(p))})</span></li>'
                for p in excl_pols)
            excl_html = (f'  <section data-category="configs"><h2>Policies excluding '
                         f'{esc(target["upn"])}</h2><ul class="profile-list">{items}</ul></section>')
        else:
            excl_html = ""
        sections_html = "".join(t["section"] for t in tables) + excl_html
        progress("render", f"{len(applying)} applying policy(ies), {len(excl_pols)} exclusion(s), "
                           f"{len(whatif_rows)} what-if evaluation(s)")
        return {"summary_html": summary_html, "sections_html": sections_html, "tables": tables}

    summary_html = f"""
  <section data-category="configs">
    <h2>CA coverage analysis</h2>
    <div class="engine-card"><table class="kv-table">
      <tr><th>CA policies</th><td>{len(policies)} ({len(enabled)} enabled, {len(policies) - len(enabled)} report-only/disabled)</td></tr>
      <tr><th>MFA-requiring policies</th><td>{sum(1 for p in policies if p['mfa'])}</td></tr>
      <tr><th>Compliant-device policies</th><td>{sum(1 for p in policies if p['compliant'])}</td></tr>
      <tr><th>Block policies</th><td>{sum(1 for p in policies if p['block'])}</td></tr>
      <tr><th>Location-based policies</th><td>{sum(1 for p in policies if p['locations_inc'] or p['trusted_locations'])}</td></tr>
      <tr><th>Risk-based policies</th><td>{sum(1 for p in policies if p['risk_signin'] or p['risk_user'])}</td></tr>
      <tr><th>Privileged users analyzed</th><td>{len(priv_users)}</td></tr>
      <tr><th>Zero CA coverage</th><td>{len(zero_coverage)}</td></tr>
      <tr><th>Report-only bypass</th><td>{len(report_only_bypass)}</td></tr>
      <tr><th>No MFA policy coverage</th><td>{len(no_mfa)}</td></tr>
      <tr><th>No compliant-device policy coverage</th><td>{len(no_compliant)}</td></tr>
      <tr><th>Privileged apps without coverage</th><td>{len(app_gaps)}</td></tr>
      <tr><th>Legacy-auth block policies</th><td>{len(legacy_blockers)}</td></tr>
      <tr><th>Privileged users with CA exclusions</th><td>{len(excl_rows)}</td></tr>
    </table></div>
  </section>
"""
    progress("render", f"{len(zero_coverage) + len(no_mfa) + len(no_compliant) + len(report_only_bypass) + len(app_gaps) + len(legacy_gap) + len(excl_rows)} finding row(s)")
    return {"summary_html": summary_html, "sections_html": sections_html, "tables": tables}


def make_ca_rows_fn():
    """Rows function for CA-analysis result tables: substring q filtering,
    optional single-field sorting, pagination handled by the caller."""
    def rows_fn(rows, q="", sort_key=None, desc=False, start=0, stop=None):
        items = rows
        if q:
            needle = q.lower()
            items = [r for r in items if needle in (r.get("_text") or "")]
        if sort_key:
            if sort_key == "severity":
                items = sorted(items, key=lambda r: severity_rank(
                    (r.get("fields") or {}).get("severity", "Info")), reverse=desc)
            else:
                items = sorted(items, key=lambda r: str(
                    (r.get("fields") or {}).get(sort_key, "")).lower(), reverse=desc)
        return [r["_html"] for r in items], len(items)
    return rows_fn


def register_ca_tables(tables):
    """Register (or refresh) the CA-analysis result tables in the serve table
    pipeline so they paginate/sort/filter like the built-in tables."""
    for tid in SERVE_STATE.get("ca_table_ids") or []:
        SERVE_STATE["tables"].pop(tid, None)
    ids = []
    for t in tables:
        if not t:
            continue
        ids.append(t["id"])
        SERVE_STATE["tables"][t["id"]] = {
            "findings": t["rows"],
            "rows": make_ca_rows_fn(),
            "search": lambda f: (f or {}).get("_text", ""),
            "sort_keys": {str(i): field for i, field in (t.get("sort_fields") or {}).items()},
            "colspan": t.get("colspan", 4),
        }
    SERVE_STATE["ca_table_ids"] = ids


def start_ca_analysis(upn=None, assume_groups=None, assume_roles=None, scenario=None):
    """Kick off the analysis in a background thread; returns the status dict."""
    state = SERVE_STATE["ca_analysis"]
    if state and state.get("status") == "running":
        return state
    steps = [{"id": sid, "label": label, "status": "pending", "detail": ""}
             for sid, label in CA_ANALYSIS_STEPS]
    state = {"status": "running", "steps": steps, "result": None, "error": None}
    SERVE_STATE["ca_analysis"] = state

    def progress(sid, detail=""):
        for step in steps:
            if step["id"] == sid:
                step["status"] = "done"
                step["detail"] = detail

    def worker():
        try:
            result = run_ca_analysis(SERVE_STATE["db_path"], progress,
                                     target_upn=upn,
                                     assume_groups=assume_groups,
                                     assume_roles=assume_roles,
                                     scenario=scenario)
            register_ca_tables(result.get("tables") or [])
            state["result"] = {"summary_html": result.get("summary_html", ""),
                               "sections_html": result.get("sections_html", "")}
            state["status"] = "done"
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            state["status"] = "error"
            state["error"] = str(exc)

    threading.Thread(target=worker, daemon=True).start()
    return state


class AuditServeHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, body_bytes, ctype, code=200, headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body_bytes)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
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
            elif path == "/api/collect/status":
                self._send(json.dumps(collect_backend.get_status(),
                                      default=str).encode("utf-8"),
                           "application/json; charset=utf-8")
            elif path == "/api/settings":
                self._send(json.dumps(surface_settings.load_settings()).encode("utf-8"),
                           "application/json; charset=utf-8",
                           headers={"Cache-Control": "no-store"})
            elif path == "/api/tokens":
                self._send(json.dumps(collect_backend.get_auth_status()).encode("utf-8"),
                           "application/json; charset=utf-8")
            elif path == "/api/tokens/clients":
                data = collect_backend.get_token_clients()
                self._send(json.dumps(data).encode("utf-8"),
                           "application/json; charset=utf-8",
                           headers={"Cache-Control": "no-store"})
            elif path == "/api/tokens/resources":
                token_id = (qs.get("id") or [""])[0]
                client_id = (qs.get("client_id") or [""])[0]
                try:
                    data = collect_backend.get_token_resources(
                        token_id, client_id)
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                except RuntimeError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 500)
                    return
                self._send(json.dumps(data).encode("utf-8"),
                           "application/json; charset=utf-8",
                           headers={"Cache-Control": "no-store"})
            elif path == "/api/databases":
                db_dir = collect_backend.DEFAULT_DATA_DIR
                databases = []
                try:
                    db_dir.mkdir(parents=True, exist_ok=True)
                    for db_file in db_dir.glob("*.db"):
                        if not db_file.is_file():
                            continue
                        stat = db_file.stat()
                        cached = False
                        cached_at = ""
                        try:
                            cache_file, meta_file = cache_paths(db_file)
                            cache_meta = (load_cache_sidecar(meta_file)
                                          if cache_file.is_file() else None)
                            if cache_meta and cache_meta.get("version") == CACHE_VERSION:
                                conn = sqlite3.connect(
                                    f"file:{db_file}?mode=ro", uri=True)
                                try:
                                    fingerprint = compute_db_fingerprint(
                                        db_file, conn.cursor())
                                finally:
                                    conn.close()
                                if cache_meta.get("fingerprint") == fingerprint:
                                    cached = True
                                    cached_at = cache_meta.get("generated_at") or ""
                        except (OSError, sqlite3.Error):
                            cached = False
                        databases.append({
                            "name": db_file.name,
                            "path": str(db_file.resolve()),
                            "size": stat.st_size,
                            "modified": datetime.datetime.fromtimestamp(
                                stat.st_mtime, datetime.timezone.utc
                            ).isoformat(timespec="seconds"),
                            "cached": cached,
                            "cached_at": cached_at,
                        })
                except OSError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 500)
                    return
                databases.sort(key=lambda d: d["modified"], reverse=True)
                self._send(json.dumps({
                    "directory": str(db_dir.resolve()),
                    "databases": databases,
                }).encode("utf-8"), "application/json; charset=utf-8")
            elif path == "/api/analyze/status":
                self._send(json.dumps(analysis.get_status()).encode("utf-8"),
                           "application/json; charset=utf-8")
            elif path == "/api/ca-analysis/status":
                state = SERVE_STATE.get("ca_analysis")
                if state is None:
                    self._send(b'{"status": "idle", "steps": []}',
                               "application/json; charset=utf-8")
                else:
                    self._send(json.dumps(state, default=str).encode("utf-8"),
                               "application/json; charset=utf-8")
            else:
                self._send(b'{"error": "not found"}', "application/json; charset=utf-8", 404)
        except Exception as exc:  # noqa: BLE001 - surface errors for debugging
            self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                       "application/json; charset=utf-8", 500)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        try:
            if parsed.path == "/api/analyze":
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length:
                        payload = json.loads(self.rfile.read(length) or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}
                use_cache = payload.get("cache", True)
                if isinstance(use_cache, str):
                    use_cache = use_cache.strip().lower() not in (
                        "", "0", "false", "no", "off")
                try:
                    state = analysis.start(
                        payload.get("db") or "",
                        lambda path, cache=bool(use_cache):
                            run_runtime_analysis(path, cache))
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                except RuntimeError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 500)
                    return
                self._send(json.dumps(state).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            if parsed.path == "/api/tokens":
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length:
                        payload = json.loads(self.rfile.read(length) or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}
                try:
                    if payload.get("refresh_token"):
                        state = collect_backend.set_auth(
                            payload.get("refresh_token") or "",
                            payload.get("client_id") or "")
                    else:
                        state = collect_backend.set_access_token(
                            payload.get("access_token") or "")
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                except RuntimeError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 500)
                    return
                self._send(json.dumps(state).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            if parsed.path == "/api/tokens/clear":
                self._send(json.dumps(collect_backend.clear_auth()).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            if parsed.path == "/api/tokens/secrets":
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length:
                        payload = json.loads(self.rfile.read(length) or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}
                try:
                    data = collect_backend.get_token_secrets(payload.get("id") or "")
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                self._send(json.dumps(data).encode("utf-8"),
                           "application/json; charset=utf-8",
                           headers={"Cache-Control": "no-store"})
                return
            if parsed.path == "/api/tokens/redeem":
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length:
                        payload = json.loads(self.rfile.read(length) or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}
                try:
                    state = collect_backend.redeem_saved_token(
                        payload.get("id") or "",
                        payload.get("target") or "",
                        payload.get("resource") or "",
                        payload.get("client_id") or "")
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                except RuntimeError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 500)
                    return
                self._send(json.dumps(state).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            if parsed.path in ("/api/tokens/select", "/api/tokens/delete"):
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length:
                        payload = json.loads(self.rfile.read(length) or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}
                try:
                    if parsed.path == "/api/tokens/select":
                        state = collect_backend.select_token(payload.get("id") or "")
                    else:
                        state = collect_backend.delete_token(payload.get("id") or "")
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                self._send(json.dumps(state).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            if parsed.path == "/api/settings/test":
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length:
                        payload = json.loads(
                            self.rfile.read(length) or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}
                proxy = payload.get("proxy") if isinstance(payload, dict) else {}
                try:
                    result = collect_backend.test_proxy(proxy or {})
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                except RuntimeError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 502)
                    return
                except OSError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 502)
                    return
                self._send(json.dumps(result).encode("utf-8"),
                           "application/json; charset=utf-8",
                           headers={"Cache-Control": "no-store"})
                return
            if parsed.path == "/api/settings":
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length:
                        payload = json.loads(
                            self.rfile.read(length) or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}
                try:
                    state = surface_settings.save_settings(payload)
                except (ValueError, OSError) as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                self._send(json.dumps(state).encode("utf-8"),
                           "application/json; charset=utf-8",
                           headers={"Cache-Control": "no-store"})
                return
            if parsed.path == "/api/collect":
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    raw = self.rfile.read(length) if length else b""
                    ctype = (self.headers.get("Content-Type") or "").split(
                        ";", 1)[0].strip().lower()
                    if ctype == "application/x-www-form-urlencoded":
                        payload = {k: v[0] for k, v in urllib.parse.parse_qs(
                            raw.decode("utf-8", "replace")).items()}
                    else:
                        payload = json.loads(raw or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}

                def _flag(name, default=False):
                    value = payload.get(name, default)
                    if isinstance(value, bool):
                        return value
                    return str(value).strip().lower() in (
                        "1", "true", "yes", "on")

                try:
                    state = collect_backend.start_collection(
                        refresh_token=payload.get("refresh_token") or "",
                        out=payload.get("out") or "",
                        client_id=(payload.get("client_id") or "").strip(),
                        user_agent=(payload.get("user_agent") or "").strip(),
                        backend=(payload.get("backend") or "graph").strip().lower(),
                        evade=_flag("evade"),
                        gather_all=_flag("gather_all"),
                        autotoken=_flag("autotoken", True),
                        mfa=_flag("mfa"))
                except ValueError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 400)
                    return
                except RuntimeError as exc:
                    self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                               "application/json; charset=utf-8", 500)
                    return
                self._send(json.dumps(state).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            if parsed.path == "/api/ca-analysis":
                payload = {}
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if length:
                        payload = json.loads(self.rfile.read(length) or b"{}") or {}
                except (ValueError, json.JSONDecodeError):
                    payload = {}
                scenario = payload.get("scenario") or {}

                def _csv(key):
                    raw = payload.get(key)
                    if isinstance(raw, list):
                        return [str(x) for x in raw if str(x).strip()]
                    if isinstance(raw, str) and raw.strip():
                        return [x.strip() for x in raw.split(",") if x.strip()]
                    return []

                state = start_ca_analysis(
                    upn=(payload.get("upn") or "").strip(),
                    assume_groups=_csv("assume_groups"),
                    assume_roles=_csv("assume_roles"),
                    scenario=scenario)
                self._send(json.dumps({"status": state["status"]}).encode("utf-8"),
                           "application/json; charset=utf-8")
            else:
                self._send(b'{"error": "not found"}', "application/json; charset=utf-8", 404)
        except Exception as exc:  # noqa: BLE001
            self._send(json.dumps({"error": str(exc)}).encode("utf-8"),
                       "application/json; charset=utf-8", 500)


def start_serve(port, total=None, after_start=None):
    """Start the HTTP server (in a daemon thread), optionally run a callback
    (e.g. the cache write) once it is accepting connections, then idle until
    Ctrl+C. Serving first keeps the report usable while the cache is written."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), AuditServeHandler)
    count = f" ({total} findings)" if total else ""
    print(f"Serving audit report{count} on http://127.0.0.1:{port} (Ctrl+C to stop)",
          flush=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    if after_start:
        after_start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# Analysis cache + run-to-run diff
# ---------------------------------------------------------------------------
# The first run analyzes the tenant and stores the outcomes (findings, derived
# drawer data, group-role resolution) in ./.entra-surface.cache. Later launches reuse it
# when the database fingerprint is unchanged; when the database changed, the
# new analysis is diffed against the cached one and surfaced in the report.

CACHE_VERSION = 3
CACHE_DIR = SCRIPT_DIR / "data" / "databases" / ".cache"

CACHE_FINGERPRINT_TABLES = (
    "Users", "ServicePrincipals", "Applications", "Groups", "Devices",
    "RoleAssignments", "AppRoleAssignments", "AZroleAssignments", "Policys",
)


def cache_paths(db_path):
    """Per-database cache and sidecar metadata paths."""
    db = Path(db_path).resolve()
    digest = hashlib.sha1(str(db).encode("utf-8")).hexdigest()[:16]
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", db.stem).strip("-")[:60] or "db"
    return (CACHE_DIR / f"{safe}-{digest}.cache.gz",
            CACHE_DIR / f"{safe}-{digest}.meta.json")


def save_cache_sidecar(path, db_path, fingerprint, generated_at):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "version": CACHE_VERSION,
            "db": str(Path(db_path).resolve()),
            "fingerprint": fingerprint,
            "generated_at": generated_at,
        }, indent=2), encoding="utf-8")
    except OSError as exc:
        print(f"warning: could not write cache metadata: {exc}", file=sys.stderr)


def load_cache_sidecar(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_analysis_cache(cache_path, meta_path, db_path, fingerprint,
                         generated_at, results, tenant_summary,
                         group_roles, group_eligible_roles):
    save_cache(cache_path, {
        "version": CACHE_VERSION,
        "fingerprint": fingerprint,
        "generated_at": generated_at,
        "results": results,
        "tenant_summary": tenant_summary,
        "group_roles": group_roles,
        "group_eligible_roles": group_eligible_roles,
    })
    save_cache_sidecar(meta_path, db_path, fingerprint, generated_at)


def compute_db_fingerprint(db_path, cur):
    """Cheap fingerprint of the audited database: file metadata plus row
    counts of the core tables. Any change triggers a reanalysis."""
    parts = [db_path.stat().st_mtime_ns, db_path.stat().st_size]
    for table in CACHE_FINGERPRINT_TABLES:
        try:
            cur.execute(f'SELECT COUNT(*) FROM "{table}"')
            parts.append(cur.fetchone()[0])
        except sqlite3.OperationalError:
            parts.append(-1)
    return parts


def _json_default(obj):
    if isinstance(obj, set):
        return sorted(obj, key=str)
    return str(obj)


def _restore_object_ids(results):
    """JSON has no sets: turn object_ids list values back into sets in place
    (the only set-bearing field in findings)."""
    for res in results or []:
        for f in res.get("findings") or []:
            o = f.get("object_ids")
            if isinstance(o, dict):
                f["object_ids"] = {k: set(v) for k, v in o.items()}


def save_cache(path, payload):
    """Stream the payload to the cache file in small chunks (no full deep
    copy or monolithic string) and gzip it — findings JSON compresses very
    well, keeping the save-time memory spike flat and the file small."""
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            for chunk in json.JSONEncoder(default=_json_default,
                                          separators=(",", ":")).iterencode(payload):
                fh.write(chunk)
    except OSError as exc:
        print(f"warning: could not write cache: {exc}", file=sys.stderr)


def load_cache(path):
    try:
        try:
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                payload = json.loads(fh.read())
        except (OSError, ValueError):
            # older caches were written uncompressed
            payload = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    _restore_object_ids(payload.get("results"))
    return payload


def compute_diff(old_results, new_results):
    """Compare two analysis runs keyed on (check_id, primary_id): added and
    removed findings, plus changed severity/title/evidence for survivors."""
    def index(results):
        return {(f["check_id"], str(f["primary_id"])): f
                for res in results for f in res["findings"]}
    old_map = index(old_results)
    new_map = index(new_results)
    added = [new_map[k] for k in sorted(new_map) if k not in old_map]
    removed = [old_map[k] for k in sorted(old_map) if k not in new_map]
    changed = []
    for k in sorted(new_map):
        if k not in old_map:
            continue
        old, new = old_map[k], new_map[k]
        if (old.get("severity") != new.get("severity")
                or old.get("title") != new.get("title")
                or old.get("evidence") != new.get("evidence")):
            changed.append((old, new))
    return {"added": added, "removed": removed, "changed": changed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=None,
                        help="Path to the roadrecon SQLite database "
                             "(omit to serve the GUI shell with no data)")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="Path to the privileged-roles config JSON (default: privileged_roles.json)")
    parser.add_argument("--azure-config", default=str(DEFAULT_AZURE_CONFIG), help="Path to the azure-roles config JSON (default: azure_roles.json)")
    parser.add_argument("--port", type=int, default=8787,
                        help="Port to serve the report on (default: 8787)")
    parser.add_argument("--refresh", action="store_true",
                        help="Ignore the cache and re-run the full analysis")
    parser.add_argument("--no-cache", action="store_true",
                        help="Disable the analysis cache entirely: never read or write it")
    parser.add_argument("--timing", action="store_true",
                        help="Print per-phase timings and peak memory at the end of the run")
    args = parser.parse_args()

    db_path = Path(args.db) if args.db else None
    config_path = Path(args.config)
    SERVE_STATE["config_path"] = str(config_path)
    SERVE_STATE["azure_config_path"] = args.azure_config

    if db_path is None:
        print("no database: serving the empty GUI shell")
        with sqlite3.connect(":memory:") as empty_conn:
            graph = build_graph(empty_conn.cursor())
        results = []
        group_roles = {}
        group_eligible_roles = {}
        tenant_summary = build_tenant_summary(graph, results)
        check_cfg = dict(DEFAULT_CHECK_CFG)
        check_cfg["directory_roles"] = {}
        check_cfg["role_labels"] = dict(DEFAULT_ROLE_LABELS)
        check_cfg["azure_roles"] = {}
        serve_tables = {}
        report_html = render_report(
            results, None, None, config_path, tenant_summary, graph=graph,
            serve_tables=serve_tables, group_roles=group_roles,
            group_eligible_roles=group_eligible_roles)
        SERVE_STATE["shell"] = report_html
        SERVE_STATE["db_path"] = None
        SERVE_STATE["ca_analysis"] = None
        SERVE_STATE["tables"] = serve_tables
        SERVE_STATE["user_findings"] = []
        SERVE_STATE["group_profiles"] = {}
        SERVE_STATE["policy_profiles"] = {}
        SERVE_STATE["records"] = []
        SERVE_STATE["graph"] = graph
        SERVE_STATE["check_cfg"] = check_cfg
        SERVE_STATE["group_roles"] = group_roles
        SERVE_STATE["group_eligible_roles"] = group_eligible_roles
        SERVE_STATE["profile_builder"] = None
        start_serve(args.port, 0)
        return 0

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

    def now_iso():
        return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

    cache_path, cache_meta_path = cache_paths(db_path)
    fingerprint = compute_db_fingerprint(db_path, cur)
    cached = None if (args.refresh or args.no_cache) else load_cache(cache_path)
    cache_hit = bool(
        cached and cached.get("version") == CACHE_VERSION
        and cached.get("fingerprint") == fingerprint)

    graph = timed("build_graph", lambda: build_graph(cur))
    azure_role_sev = load_azure_roles(args.azure_config)
    check_cfg["azure_roles"] = azure_role_sev
    timed("apply_azure_severity", lambda: apply_azure_severity(graph, azure_role_sev))

    if cache_hit:
        print(f"cache hit: skipping analysis (last analyzed {cached.get('generated_at')})")
        results = cached["results"]
        group_roles = cached.get("group_roles") or {}
        group_eligible_roles = cached.get("group_eligible_roles") or {}
        tenant_summary = timed("build_tenant_summary",
                               lambda: build_tenant_summary(graph, results))
        conn.close()
        diff = None
        cache_meta = {"hit": True, "generated_at": cached.get("generated_at") or ""}
    else:
        print("cache miss: running full analysis")
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
                        lambda: run_checks(graph, config_resources, check_cfg,
                                           group_roles=group_roles,
                                           group_eligible_roles=group_eligible_roles,
                                           sp_dir_resolver=sp_dir_resolver))

        # raw details and drawer profiles are served lazily from the database
        # and the in-memory graph (tier-2 memory saving)
        tenant_summary = timed("build_tenant_summary",
                               lambda: build_tenant_summary(graph, results))
        diff = compute_diff(cached.get("results", []), results) if cached else None
        conn.close()
        cache_meta = {
            "hit": False,
            "off": args.no_cache,
            "fresh": cached is None and not args.no_cache,
            "generated_at": now_iso(),
            "previous_at": cached.get("generated_at") if cached else None,
        }
        # the cache is written after the server starts accepting connections
        # (see start_serve(after_start=...) below)

    serve_tables = {}
    report_html = timed("render_report",
                        lambda: render_report(results, tenant_name, db_path, config_path,
                                              tenant_summary, graph=graph,
                                              serve_tables=serve_tables,
                                              group_roles=group_roles,
                                              group_eligible_roles=group_eligible_roles,
                                              cache_meta=cache_meta, diff=diff))

    total = sum(len(res["findings"]) for res in results)

    SERVE_STATE["shell"] = report_html
    SERVE_STATE["db_path"] = str(db_path)
    SERVE_STATE["ca_analysis"] = None
    SERVE_STATE["tables"] = serve_tables or {}
    SERVE_STATE["user_findings"] = next(
        (res["findings"] for res in results if res["id"] == "privileged_users"), [])
    SERVE_STATE["group_profiles"] = {
        f["group_id"]: f for res in results if res["id"] == "groups"
        for f in res["findings"]}
    SERVE_STATE["policy_profiles"] = {
        f["policy_id"]: f for res in results if res["id"] == "ca_exposure"
        for f in res["findings"] if f.get("policy_id")}
    SERVE_STATE["records"] = build_serve_records(results)
    # lazy drawer inputs: the graph, role resolution and config stay resident;
    # raw details are read from the database on demand
    SERVE_STATE["graph"] = graph
    SERVE_STATE["check_cfg"] = check_cfg
    SERVE_STATE["group_roles"] = group_roles
    SERVE_STATE["group_eligible_roles"] = group_eligible_roles
    SERVE_STATE["profile_builder"] = None
    gc.collect()
    if args.timing:
        import resource
        print(f"[timing] peak RSS: {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.0f} MB")
    if args.no_cache or cache_hit:
        start_serve(args.port, total)
    else:
        def write_cache_now():
            print(f"Writing analysis cache to {cache_path}...", flush=True)
            write_analysis_cache(cache_path, cache_meta_path, db_path,
                                 fingerprint, cache_meta["generated_at"],
                                 results, tenant_summary, group_roles,
                                 group_eligible_roles)
            try:
                size = cache_path.stat().st_size
                print(f"Analysis cache written ({size:,} bytes)", flush=True)
            except OSError:
                print("Analysis cache written", flush=True)
        start_serve(args.port, total, after_start=write_cache_now)
    return 0


if __name__ == "__main__":
    sys.exit(main())

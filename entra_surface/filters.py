"""Advanced filter query language shared by the report and tests.

Pure module: the JavaScript mirror in JS_FILTER_MODULE must stay in sync with
the aliases, list fields, phrases and grammar defined here.
"""
from __future__ import annotations

import re


ADV_LIST_FIELDS = {
    "roles", "eligible", "grproles", "grptype", "dynmods", "dynattrs",
    "azroles", "azusrroles", "azsproles", "adtags", "appdirroles",
    "polapps", "polcontrols", "arcazroles",
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
    "user": ["user"], "upn": ["userupn", "upn"], "userupn": ["userupn"],
    "privapps": ["privapps"], "capablegrp": ["capgroups"], "capgroups": ["capgroups"],
    "groupsowned": ["grpowned"], "grpowned": ["grpowned"], "caexcl": ["caexcl"],
    "accountsource": ["hybrid"], "hybrid": ["hybrid"],
    "status": ["userstatus", "status", "spstatus", "ownerstatus", "adstatus"],
    "userstatus": ["userstatus"], "spstatus": ["spstatus"],
    "ownerstatus": ["ownerstatus"], "adstatus": ["adstatus"],
    "ownersource": ["ownersource"], "owneraddn": ["owneraddn"],
    "ownersid": ["ownersid"], "ownerimmutableid": ["ownerimmutableid"],
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
    "appid": ["appid"], "spty": ["spty"], "servicetype": ["spty"],
    "poltype": ["poltype"], "polcreated": ["polcreated"], "created": ["polcreated"],
    "polmodified": ["polmodified"], "lastmodified": ["polmodified"],
    "immutableid": ["immutableid"],
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
    ("Owner Source", "ownersource"), ("Owner AD DN", "owneraddn"),
    ("Owner SID", "ownersid"), ("Owner Immutable ID", "ownerimmutableid"),
    ("Membership rule", "membershiprule"),
    ("Referenced attributes", "referencedattributes"),
    ("Modifiable by", "modifiableby"),
    ("attribute modifiable by", "modifiableby"),
    ("Modifiable by", "modifiableby"),
    ("AD CN", "adcn"), ("AD DN", "addn"),
    ("On-prem pw change", "onprempwchange"), ("Targeting tags", "targetingtags"),
    ("App ID", "appid"), ("SP type", "spty"), ("Policy type", "poltype"),
    ("Created", "polcreated"), ("Last modified", "polmodified"),
    ("Immutable ID", "immutableid"),
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
        if field.upper() == "CONTAINS":
            # Bare `contains:` / `contains: value` is a text predicate, not an
            # equality predicate with a missing field list (B-033).
            if not rest:
                vt = peek()
                if vt is None or vt[0] not in ("word", "quoted"):
                    raise AdvancedParseError("expected value after 'contains:'")
                advance()
                return {"op": "text", "value": consume_value_words(vt[1])}
            return {"op": "text", "value": consume_value_words(rest)}
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
        fields = ast.get("fields") or ()
        if not fields:
            return False
        for field in fields:
            field_l = str(field).lower()
            value = (fields_l.get(field_l) or "").lower()
            if op == "contains":
                if has_glob:
                    if _glob_matches(needle, value, search=True):
                        return True
                elif needle in value:
                    return True
            elif field_l in ADV_LIST_FIELDS:
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

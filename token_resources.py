#!/usr/bin/env python3
"""Refresh-token resource mappings based on entrascopes.com data.

The public first-party scope dataset lists, for each client application, the
resources it can request access tokens for.  Only resources listed for the
token's client are suggested in the UI (which also accepts an explicit custom
application ID or resource URI).  The dataset is fetched on demand and cached
under data/token-resources/.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.request
from collections import defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
CACHE_DIR = SCRIPT_DIR / "data" / "token-resources"
BASE_URL = "https://entrascopes.com"
CACHE_TTL = 7 * 24 * 60 * 60
SOURCES = {
    "apps": "firstpartyscopes.json",
    "resources": "resources.json",
}

GRAPH_ID = "00000003-0000-0000-c000-000000000000"
AAD_GRAPH_ID = "00000002-0000-0000-c000-000000000000"
ARM_ID = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
EXCHANGE_ID = "00000002-0000-0ff1-ce00-000000000000"
SHAREPOINT_ID = "00000003-0000-0ff1-ce00-000000000000"

# Well-known resource identifiers used by the collector.  Everything else is
# requested by application ID, which Entra accepts as a resource identifier for
# every resource (and avoids guessing between cloud-specific URI aliases).
KNOWN_RESOURCES = {
    GRAPH_ID: "https://graph.microsoft.com",
    AAD_GRAPH_ID: "https://graph.windows.net",
    ARM_ID: "https://management.azure.com",
    EXCHANGE_ID: "https://outlook.office.com",
}
KNOWN_NAMES = {
    AAD_GRAPH_ID: "AAD Graph (Windows Azure Active Directory)",
}

PINNED = {
    GRAPH_ID: 0,
    AAD_GRAPH_ID: 1,
    ARM_ID: 2,
    EXCHANGE_ID: 3,
    SHAREPOINT_ID: 4,
}

KEYWORDS = {
    GRAPH_ID: ["msgraph", "graph"],
    AAD_GRAPH_ID: ["aad graph", "aadgraph", "azure ad graph"],
    ARM_ID: ["arm", "azrm", "azure rm"],
    EXCHANGE_ID: ["exchange", "outlook"],
    SHAREPOINT_ID: ["sharepoint", "onedrive"],
}

COMMON_RESOURCES = [
    {"id": GRAPH_ID, "name": "Microsoft Graph",
     "resource": KNOWN_RESOURCES[GRAPH_ID]},
    {"id": AAD_GRAPH_ID, "name": KNOWN_NAMES[AAD_GRAPH_ID],
     "resource": KNOWN_RESOURCES[AAD_GRAPH_ID]},
    {"id": ARM_ID, "name": "Azure Resource Manager",
     "resource": KNOWN_RESOURCES[ARM_ID]},
]

CLIENT_RANK = {
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": 0,  # Microsoft Azure CLI
    "d3590ed6-52b3-4102-aeff-aad2292ab01c": 1,  # Microsoft Office
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264": 2,  # Microsoft Teams
    "1b730954-1685-4b74-9bfd-dac224a7b894": 3,  # Azure Active Directory PowerShell
    "1950a258-227b-4e31-a9cf-717495945fc2": 4,  # Microsoft Azure PowerShell
    "29d9ed98-a469-4536-ade2-f981bc1d605e": 5,  # Microsoft Authentication Broker
}

GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE)
RESOURCE_SCHEME_RE = re.compile(r"^(https?://|api://|urn:)", re.IGNORECASE)
NOISY_HOST_PARTS = (
    "canary", "-sdf", "-tdf", "dod-", "microsoftonline", "sharepoint-df",
    "chinacloudapi", "microsoftazure", "localhost", "127.0.0.1",
)

_LOCK = threading.Lock()
_DATA = {}
_ERROR = ""
_ERROR_AT = 0.0
ERROR_TTL = 60


def _fetch(name: str):
    url = f"{BASE_URL}/{SOURCES[name]}"
    request = urllib.request.Request(
        url, headers={"User-Agent": "entra-surface-token-resources/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()
    data = json.loads(raw)
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = CACHE_DIR / (SOURCES[name] + f".{os.getpid()}.tmp")
        tmp.write_bytes(raw)
        os.replace(tmp, CACHE_DIR / SOURCES[name])
    except OSError:
        pass
    return data


def _load(name: str):
    path = CACHE_DIR / SOURCES[name]
    data = None
    if path.is_file():
        try:
            if time.time() - path.stat().st_mtime < CACHE_TTL:
                data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
    if data is None:
        try:
            data = _fetch(name)
        except Exception as exc:
            if path.is_file():
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    data = None
            if data is None:
                raise RuntimeError(
                    f"could not load token resource data: {exc}") from exc
    return data


def datasets():
    global _ERROR, _ERROR_AT
    with _LOCK:
        if not _DATA:
            if _ERROR and time.time() - _ERROR_AT < ERROR_TTL:
                raise RuntimeError(_ERROR)
            loaded = {}
            try:
                for name in SOURCES:
                    loaded[name] = _load(name)
            except RuntimeError as exc:
                _ERROR = str(exc)
                _ERROR_AT = time.time()
                raise
            _DATA.update(loaded)
            _ERROR = ""
            _ERROR_AT = 0.0
        return _DATA


def client_info(client_id: str) -> dict:
    """Return the display name and FOCI status for a client application."""
    client_id = (client_id or "").strip().lower()
    result = {"id": client_id, "name": "", "foci": False, "found": False}
    if not client_id:
        return result
    try:
        data = datasets()
    except RuntimeError:
        return result
    root = data.get("apps")
    apps = root.get("apps") if isinstance(root, dict) else None
    app = apps.get(client_id) if isinstance(apps, dict) else None
    if not isinstance(app, dict):
        return result
    foci = app.get("foci")
    if isinstance(foci, str):
        foci = foci.strip().lower() in ("1", "true", "yes")
    result.update({
        "name": KNOWN_NAMES.get(client_id)
        or " ".join(str(app.get("name") or "").split()),
        "foci": bool(foci),
        "found": True,
    })
    return result


def audience_info(audience: str) -> dict:
    """Resolve a bare GUID audience to a resource application name."""
    raw = str(audience or "").strip().rstrip("/")
    result = {"id": raw, "name": "", "found": False}
    if not GUID_RE.fullmatch(raw):
        return result
    try:
        data = datasets()
    except RuntimeError:
        return result
    key = raw.lower()
    name = ""
    rows = data.get("resources")
    if isinstance(rows, list):
        for item in rows:
            if not isinstance(item, dict):
                continue
            if str(item.get("resourceId") or "").lower() != key:
                continue
            name = " ".join(str(item.get("displayName") or "").split())
            break
    if not name:
        root = data.get("apps")
        apps = root.get("apps") if isinstance(root, dict) else None
        app = apps.get(key) if isinstance(apps, dict) else None
        if isinstance(app, dict):
            name = " ".join(str(app.get("name") or "").split())
    if name:
        result.update({
            "name": KNOWN_NAMES.get(key) or name,
            "found": True,
        })
    return result


def clients() -> list[dict]:
    """Return searchable client applications from the dataset."""
    data = datasets()
    root = data.get("apps")
    apps = root.get("apps") if isinstance(root, dict) else None
    if not isinstance(apps, dict):
        return []
    result = []
    for client_id, app in apps.items():
        if not isinstance(app, dict):
            continue
        key = str(client_id or "").strip().lower()
        if not key:
            continue
        name = " ".join(str(app.get("name") or "").split()) or key
        foci = app.get("foci")
        if isinstance(foci, str):
            foci = foci.strip().lower() in ("1", "true", "yes")
        result.append({
            "id": key,
            "name": KNOWN_NAMES.get(key) or name,
            "foci": bool(foci),
            "rank": CLIENT_RANK.get(key, 10),
        })
    result.sort(key=lambda item: (
        item["rank"],
        0 if item["name"] != item["id"] else 1,
        item["name"].lower(),
        item["id"],
    ))
    return result


def _clean_identifier(identifier: str) -> str:
    value = str(identifier or "").strip().rstrip("/")
    if value.lower().endswith("/.default"):
        value = value[:-9].rstrip("/")
    return value


def _resource_index(apps_data: dict) -> dict:
    index = defaultdict(list)
    if not isinstance(apps_data, dict):
        return index
    for identifier, resource_id in (apps_data.get("resourceidentifiers")
                                    or {}).items():
        resource_id = str(resource_id or "").lower()
        cleaned = _clean_identifier(identifier)
        if not resource_id or not cleaned or "*" in cleaned:
            continue
        if cleaned not in index[resource_id]:
            index[resource_id].append(cleaned)
    return index


def _uri_priority(uri: str):
    """Sort aliases for display; lower is friendlier."""
    low = str(uri or "").lower()
    if low.startswith("https://"):
        noisy = any(part in low for part in NOISY_HOST_PARTS)
        return (2 if noisy else 1, len(low), low)
    if low.startswith("api://"):
        return (3, len(low), low)
    return (4, len(low), low)


def _display_uri(resource_id: str, aliases: list[str],
                 resource: str) -> str:
    if resource != resource_id:
        return resource
    usable = [alias for alias in aliases if alias != resource_id]
    if not usable:
        return resource_id
    return sorted(usable, key=_uri_priority)[0]


def _rank(resource_id: str) -> int:
    return PINNED.get(resource_id, 10)


def _summarize(resource_id: str, name: str, resource: str,
               aliases: list[str]) -> dict:
    return {
        "id": resource_id,
        "name": name,
        "resource": resource,
        "display": _display_uri(resource_id, aliases, resource),
        "aliases": aliases,
        "keywords": KEYWORDS.get(resource_id, []),
        "rank": _rank(resource_id),
    }


def _fallback(reason: str = "", error: str = "") -> dict:
    resources = [_summarize(item["id"], item["name"], item["resource"], [])
                 for item in COMMON_RESOURCES]
    resources.sort(key=lambda item: (_rank(item["id"]), item["name"].lower()))
    result = {
        "found": False,
        "fallback": True,
        "client_id": "",
        "client_name": "",
        "foci": False,
        "reason": reason,
        "error": error,
        "allow_custom": True,
        "resources": resources,
    }
    return result


def resources_for_client(client_id: str) -> dict:
    """Return every resource this client can request tokens for."""
    client_id = (client_id or "").strip().lower()
    if not client_id:
        raise ValueError("client id is required")
    try:
        data = datasets()
    except RuntimeError as exc:
        return _fallback(error=str(exc))

    root = data.get("apps")
    apps = root.get("apps") if isinstance(root, dict) else {}
    if not isinstance(apps, dict):
        apps = {}
    app = apps.get(client_id)
    if not isinstance(app, dict):
        return _fallback(
            reason="client is not in the entrascopes first-party app dataset")

    resource_rows = data.get("resources")
    if not isinstance(resource_rows, list):
        resource_rows = []
    resource_names = {
        str(item.get("resourceId") or "").lower():
            item.get("displayName") or item.get("resourceId") or ""
        for item in resource_rows
        if isinstance(item, dict) and item.get("resourceId")
    }
    identifiers = _resource_index(root or {})
    resources = []
    seen = set()
    for resource_id in (app.get("scopes") or {}):
        resource_id = str(resource_id or "").lower()
        if not GUID_RE.fullmatch(resource_id) or resource_id in seen:
            continue
        seen.add(resource_id)
        aliases = identifiers.get(resource_id) or []
        resource = KNOWN_RESOURCES.get(resource_id) or resource_id
        name = " ".join(
            str(resource_names.get(resource_id) or resource_id).split())
        name = KNOWN_NAMES.get(resource_id) or name or resource_id
        resources.append(_summarize(resource_id, name, resource, aliases))
    resources.sort(key=lambda item: (
        _rank(item["id"]),
        1 if item["name"] == item["id"] else 0,
        item["name"].lower(),
        item["id"],
    ))
    foci = app.get("foci")
    if isinstance(foci, str):
        foci = foci.strip().lower() in ("1", "true", "yes")
    result = {
        "found": True,
        "fallback": False,
        "client_id": client_id,
        "client_name": " ".join(str(app.get("name") or "").split()),
        "foci": bool(foci),
        "reason": "",
        "error": "",
        "allow_custom": False,
        "resources": resources,
    }
    return result


def _normalize_resource(value: str) -> str:
    text = str(value or "").strip().rstrip("/")
    if text.lower().endswith("/.default"):
        text = text[:-9].rstrip("/")
    return text.lower()


def find_resource(data: dict, value: str) -> dict | None:
    """Find the resource entry matching any ID/URI alias for this client."""
    target = _normalize_resource(value)
    if not target:
        return None
    for item in data.get("resources") or []:
        candidates = [item.get("resource"), item.get("id"),
                      item.get("display")]
        candidates.extend(item.get("aliases") or [])
        if any(_normalize_resource(candidate) == target
               for candidate in candidates):
            return item
    return None


def normalize_custom_resource(value: str) -> str:
    """Validate a user-entered resource for clients absent from the dataset."""
    text = str(value or "").strip()
    if not text:
        raise ValueError("resource is required")
    if len(text) > 2048:
        raise ValueError("resource is too long")
    if any(ch.isspace() for ch in text):
        raise ValueError("resource must not contain spaces")
    text = text.rstrip("/")
    if text.lower().endswith("/.default"):
        text = text[:-9].rstrip("/")
    if not (GUID_RE.fullmatch(text) or RESOURCE_SCHEME_RE.match(text)):
        raise ValueError("resource must be an application ID or URI")
    return text

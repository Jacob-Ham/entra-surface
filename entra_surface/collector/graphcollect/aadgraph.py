"""Legacy AAD Graph (graph.windows.net) collector.

This is a focused, stdlib/requests implementation of the ROADrecon 2.x gather
flow.  It writes the same ROADrecon tables via :class:`graphcollect.store.Store`
so the resulting database can be analyzed by entra-surface.

The legacy AAD Graph API is paged with ``odata.nextLink``.  The client supports
normal requests and ROADrecon's ``--evade`` batch transport, which wraps each GET
in a one-part ``multipart/mixed`` request to ``/$batch``.
"""
from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import requests
from requests.utils import should_bypass_proxies

from .client import Degraded, log_throttle
from .collectors import Runner
from .tls import InsecureTLSAdapter

AAD_GRAPH_BASE = "https://graph.windows.net"
AAD_GRAPH_RES = "https://graph.windows.net"
AAD_GRAPH_AUDIENCES = {
    "https://graph.windows.net",
    "00000002-0000-0000-c000-000000000000",
}
API_VERSION = "1.61-internal"
BATCH_BOUNDARY = "batch_request_boundary"
WORKERS = 12
CHUNK = 100


class BatchResponse:
    """Small response object for one part of an AAD Graph $batch reply."""

    def __init__(self, status_code: int, headers: dict, body: bytes):
        self.status_code = status_code
        self.headers = headers
        self.content = body

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.text)


class AadGraphClient:
    """Paged AAD Graph HTTP client with optional batch/evade transport."""

    def __init__(self, token_getter, tenant_id: str, user_agent: str = "",
                 evade: bool = False, verbose: int = 0,
                 proxies: dict | None = None, no_proxy: str = "",
                 verify: bool = True):
        self._token_getter = token_getter
        self.tenant_id = (tenant_id or "myorganization").strip() or "myorganization"
        self.user_agent = (user_agent or "").strip()
        self.evade = bool(evade)
        self.verbose = int(verbose)
        self.proxies = proxies or None
        self.no_proxy = (no_proxy or "").strip()
        self.verify = bool(verify)
        self._local = threading.local()
        self._count_lock = threading.Lock()
        self.requests_made = 0
        self.throttled = 0

    # -- URL / request helpers ------------------------------------------------
    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            adapter_cls = (requests.adapters.HTTPAdapter if self.verify
                           else InsecureTLSAdapter)
            adapter = adapter_cls(
                pool_connections=16, pool_maxsize=32, max_retries=0)
            session.mount("https://", adapter)
            if not self.verify:
                session.mount("http://", adapter)
            if self.proxies:
                session.trust_env = False
            self._local.session = session
        return session

    def _proxy_for(self, url: str):
        if not self.proxies:
            return None
        if self.no_proxy and should_bypass_proxies(url, self.no_proxy):
            return {}
        return self.proxies

    def _headers(self) -> dict:
        headers = {"Authorization": f"Bearer {self._token_getter()}"}
        if self.user_agent:
            headers["User-Agent"] = self.user_agent
        return headers

    def _absolute(self, path: str) -> str:
        path = str(path or "")
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{AAD_GRAPH_BASE}/{self.tenant_id}/{path.lstrip('/')}"

    @staticmethod
    def _add_api_version(url: str) -> str:
        if "api-version=" in url:
            return url
        return url + ("&" if "?" in url else "?") + "api-version=" + API_VERSION

    def _next_url(self, previous: str, link: str) -> str:
        link = str(link or "").strip()
        if not link:
            return ""
        if link.startswith("http://") or link.startswith("https://"):
            return self._add_api_version(link)
        parts = urlsplit(previous)
        origin = f"{parts.scheme}://{parts.netloc}"
        if link.startswith("?"):
            return self._add_api_version(origin + parts.path + link)
        if link.startswith("/"):
            return self._add_api_version(origin + link)
        if "directoryObjects" in link:
            return self._add_api_version(
                f"{origin}/{self.tenant_id}/{link.lstrip('/')}")
        parent = parts.path.rstrip("/").rsplit("/", 1)[0]
        return self._add_api_version(f"{origin}{parent}/{link}")

    def _plain_get(self, url: str):
        retries = 5
        for attempt in range(retries):
            try:
                response = self._session().get(
                    url, headers=self._headers(), timeout=90,
                    proxies=self._proxy_for(url), verify=self.verify)
            except requests.RequestException:
                if attempt == retries - 1:
                    raise Degraded(0, url, "request failed")
                time.sleep(1 + attempt)
                continue
            with self._count_lock:
                self.requests_made += 1
            if response.status_code == 429:
                with self._count_lock:
                    self.throttled += 1
                    total = self.throttled
                wait = int(response.headers.get("Retry-After", "5") or 5)
                pause = min(wait, 60) + 1
                log_throttle("aadgraph", pause, f"total {total}")
                time.sleep(pause)
                continue
            if response.status_code in (500, 502, 503, 504) and attempt < retries - 1:
                time.sleep(1 + attempt)
                continue
            if response.status_code >= 400:
                raise Degraded(response.status_code, url, response.text[:500])
            return response
        raise Degraded(0, url, "retries exhausted")

    def _batch_get(self, url: str) -> BatchResponse:
        inner_url = url.replace(" ", "%20")
        body = (
            f"--{BATCH_BOUNDARY}\r\n"
            "Content-Type: application/http\r\n"
            "Content-Transfer-Encoding: binary\r\n\r\n"
            f"GET {inner_url} HTTP/1.1\r\n\r\n"
            f"--{BATCH_BOUNDARY}--\r\n"
        )
        batch_url = (f"{AAD_GRAPH_BASE}/{self.tenant_id}/$batch"
                     f"?api-version={API_VERSION}")
        retries = 5
        for attempt in range(retries):
            headers = self._headers()
            headers["Content-Type"] = (
                f"multipart/mixed; boundary={BATCH_BOUNDARY}")
            try:
                response = self._session().post(
                    batch_url, data=body.encode("utf-8"),
                    headers=headers, timeout=90,
                    proxies=self._proxy_for(batch_url), verify=self.verify)
            except requests.RequestException:
                if attempt == retries - 1:
                    raise Degraded(0, url, "batch request failed")
                time.sleep(1 + attempt)
                continue
            with self._count_lock:
                self.requests_made += 1
            if response.status_code == 429:
                with self._count_lock:
                    self.throttled += 1
                    total = self.throttled
                wait = int(response.headers.get("Retry-After", "5") or 5)
                pause = min(wait, 60) + 1
                log_throttle("aadgraph", pause, f"batch, total {total}")
                time.sleep(pause)
                continue
            if response.status_code in (500, 502, 503, 504) and attempt < retries - 1:
                time.sleep(1 + attempt)
                continue
            if response.status_code >= 400:
                raise Degraded(response.status_code, batch_url,
                               response.text[:500])
            return self._parse_batch(response, url)
        raise Degraded(0, url, "batch retries exhausted")

    @staticmethod
    def _parse_batch(response, url: str) -> BatchResponse:
        content_type = response.headers.get("Content-Type", "")
        match = re.search(r'boundary="?([^";]+)"?', content_type)
        boundary = match.group(1) if match else BATCH_BOUNDARY
        raw = response.content.decode("latin-1", "replace")
        for part in raw.split("--" + boundary):
            part = part.strip("\r\n")
            if not part or part == "--":
                continue
            if "content-type: application/http" not in part.lower():
                continue
            if "\r\n\r\n" in part:
                _, http_message = part.split("\r\n\r\n", 1)
            elif "\n\n" in part:
                _, http_message = part.split("\n\n", 1)
            else:
                continue
            http_message = http_message.lstrip("\r\n")
            if "\r\n\r\n" in http_message:
                header_block, inner_body = http_message.split("\r\n\r\n", 1)
            elif "\n\n" in http_message:
                header_block, inner_body = http_message.split("\n\n", 1)
            else:
                header_block, inner_body = http_message, ""
            status_line = header_block.splitlines()[0] if header_block else ""
            status_match = re.search(r"HTTP/\d\.\d\s+(\d{3})", status_line)
            status = int(status_match.group(1)) if status_match else 0
            inner_headers = {}
            for line in header_block.splitlines()[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    inner_headers[key.strip()] = value.strip()
            body = inner_body.encode("latin-1")
            if status >= 400:
                raise Degraded(status, url, body.decode("utf-8", "replace")[:500])
            return BatchResponse(status, inner_headers, body)
        raise Degraded(0, url, "no application/http part in batch response")

    def get_json(self, path: str):
        url = self._add_api_version(self._absolute(path))
        response = self._batch_get(url) if self.evade else self._plain_get(url)
        try:
            return response.json()
        except ValueError:
            raise Degraded(response.status_code, url, response.text[:500])

    def paged(self, path: str, max_pages: int = 100000):
        url = self._add_api_version(self._absolute(path))
        pages = 0
        while url:
            data = self.get_json(url)
            if isinstance(data, list):
                yield from data
                return
            if not isinstance(data, dict):
                return
            if "value" in data:
                yield from (data.get("value") or [])
            elif data:
                # Singular endpoints such as authorizationPolicy.
                yield data
                return
            link = data.get("odata.nextLink") or data.get("@odata.nextLink")
            url = self._next_url(url, link) if link else ""
            pages += 1
            if pages >= max_pages:
                raise Degraded(0, path, "pagination cap reached")

    # -- link helpers ---------------------------------------------------------
    @staticmethod
    def parse_link(obj: dict) -> tuple[str, str]:
        url = str((obj or {}).get("url") or "")
        if not url:
            return "", ""
        parts = url.rstrip("/").split("/")
        if len(parts) < 2:
            return "", ""
        object_id = parts[-2]
        object_type = parts[-1].rsplit(".", 1)[-1]
        return object_id, object_type


def _link_map(kind: str) -> dict:
    if kind == "group_member":
        return {
            "User": ("lnk_group_member_user", "User"),
            "Group": ("lnk_group_member_group", "childGroup"),
            "Contact": ("lnk_group_member_contact", "Contact"),
            "Device": ("lnk_group_member_device", "Device"),
            "ServicePrincipal": ("lnk_group_member_serviceprincipal",
                                 "ServicePrincipal"),
        }
    if kind == "group_owner":
        return {
            "User": ("lnk_group_owner_user", "User"),
            "ServicePrincipal": ("lnk_group_owner_serviceprincipal",
                                 "ServicePrincipal"),
        }
    if kind == "au_member":
        return {
            "User": ("lnk_au_member_user", "User"),
            "Group": ("lnk_au_member_group", "Group"),
            "Device": ("lnk_au_member_device", "Device"),
        }
    if kind == "role_member":
        return {
            "User": ("lnk_role_member_user", "User"),
            "Group": ("lnk_role_member_group", "Group"),
            "ServicePrincipal": ("lnk_role_member_serviceprincipal",
                                 "ServicePrincipal"),
        }
    if kind == "application_owner":
        return {
            "User": ("lnk_application_owner_user", "User"),
            "ServicePrincipal": ("lnk_application_owner_serviceprincipal",
                                 "ServicePrincipal"),
        }
    if kind == "sp_owner":
        return {
            "User": ("lnk_serviceprincipal_owner_user", "User"),
            "ServicePrincipal": ("lnk_serviceprincipal_owner_serviceprincipal",
                                 "childServicePrincipal"),
        }
    if kind == "device_owner":
        return {"User": ("lnk_device_owner", "User")}
    return {}


def _chunks(items: list, size: int):
    for index in range(0, len(items), size):
        yield items[index:index + size]


def _object_id(obj: dict) -> str:
    return str((obj or {}).get("objectId") or "")


def dump_objects(runner: Runner, path: str, table: str, pk: str,
                 keep: bool = False, extra: str = "") -> list:
    """Dump one paged collection into a table; return objects when requested."""
    section = runner.section(table)
    objects = []
    try:
        for obj in runner.c.paged(path + extra):
            if not isinstance(obj, dict) or not obj.get(pk):
                continue
            runner.s.upsert(table, pk, obj)
            if keep:
                objects.append(obj)
    except Exception as exc:
        runner.finish(section, "degraded", note=str(exc)[:180])
        return objects
    runner.finish(section, "ok", len(objects) if keep else runner.s.count(table))
    return objects


def dump_devices(runner: Runner) -> list:
    section = runner.section("Devices")
    devices = []
    expanded = True
    try:
        devices = list(runner.c.paged("/devices?$expand=registeredOwners"))
    except Exception:
        expanded = False
        try:
            devices = list(runner.c.paged("/devices"))
        except Exception as exc:
            runner.finish(section, "degraded", note=str(exc)[:180])
            return []
    owners = 0
    for device in devices:
        if not isinstance(device, dict) or not device.get("objectId"):
            continue
        runner.s.upsert("Devices", "objectId", device)
        for owner in device.get("registeredOwners") or []:
            owner_id = str(owner.get("objectId") or "")
            owner_type = str(
                owner.get("objectType")
                or (owner.get("@odata.type") or "").rsplit(".", 1)[-1])
            if not owner_id:
                owner_id, owner_type = AadGraphClient.parse_link(owner)
            table = _link_map("device_owner").get(owner_type)
            if owner_id and table:
                runner.s.add_link(table[0], {
                    "Device": device["objectId"], table[1]: owner_id})
                owners += 1
    note = "" if expanded else "registeredOwners expand unavailable"
    runner.finish(section, "ok" if devices else "partial",
                  len(devices), note=note)
    if owners:
        print(f"[aadgraph] device owner links: {owners}")
    return devices


def _fetch_group_links(client: AadGraphClient, group: dict) -> tuple:
    gid = _object_id(group)
    data = {"members": [], "owners": [], "errors": []}
    if not gid:
        return gid, data
    for key, path in (
            ("members", f"/groups/{gid}/$links/members"),
            ("owners", f"/groups/{gid}/$links/owners")):
        try:
            data[key] = list(client.paged(path))
        except Exception as exc:
            data["errors"].append(f"{key}: {str(exc)[:80]}")
    return gid, data


def _write_link_list(store, parent_col: str, parent_id: str, kind: str,
                     links: list) -> int:
    mapping = _link_map(kind)
    count = 0
    for link in links:
        object_id, object_type = AadGraphClient.parse_link(link)
        target = mapping.get(object_type)
        if object_id and target:
            store.add_link(target[0], {
                parent_col: parent_id, target[1]: object_id})
            count += 1
    return count


def collect_group_links(runner: Runner, groups: list) -> None:
    section = runner.section("Group memberships/owners")
    count = 0
    errors = 0
    processed = 0
    for chunk in _chunks(groups, CHUNK):
        with ThreadPoolExecutor(max_workers=min(WORKERS, len(chunk) or 1)) as ex:
            results = list(ex.map(lambda g: _fetch_group_links(runner.c, g),
                                  chunk))
        processed += len(chunk)
        for gid, data in results:
            if not gid:
                continue
            count += _write_link_list(runner.s, "Group", gid,
                                      "group_member", data["members"])
            count += _write_link_list(runner.s, "Group", gid,
                                      "group_owner", data["owners"])
            errors += len(data["errors"])
        if len(groups) > CHUNK:
            print(f"[aadgraph] groups processed: {processed}/{len(groups)}",
                  flush=True)
    note = f"{errors} link errors" if errors else ""
    runner.finish(section, "ok" if not errors else "partial", count, note=note)


def collect_au_links(runner: Runner, units: list) -> None:
    section = runner.section("Administrative unit members")
    count = 0
    for unit in units:
        uid = _object_id(unit)
        if not uid:
            continue
        try:
            links = list(runner.c.paged(
                f"/administrativeUnits/{uid}/$links/members"))
        except Exception:
            continue
        count += _write_link_list(runner.s, "AdministrativeUnit", uid,
                                  "au_member", links)
    runner.finish(section, "ok" if not count else "ok", count)


def collect_role_links(runner: Runner, roles: list) -> None:
    section = runner.section("Directory role members")
    count = 0
    for role in roles:
        rid = _object_id(role)
        if not rid:
            continue
        try:
            links = list(runner.c.paged(f"/directoryRoles/{rid}/$links/members"))
        except Exception:
            continue
        count += _write_link_list(runner.s, "DirectoryRole", rid,
                                  "role_member", links)
    runner.finish(section, "ok", count)


def _fetch_sp_links(client: AadGraphClient, sp: dict) -> tuple:
    sid = _object_id(sp)
    app_id = str((sp or {}).get("appId") or "")
    data = {"assigned": [], "assignments": [], "owners": [],
            "apprefs": [], "keys": None, "errors": []}
    if not sid:
        return sid, app_id, data
    for key, path in (
            ("assigned", f"/servicePrincipals/{sid}/appRoleAssignedTo"),
            ("assignments", f"/servicePrincipals/{sid}/appRoleAssignments"),
            ("owners", f"/servicePrincipals/{sid}/$links/owners")):
        try:
            data[key] = list(client.paged(path))
        except Exception as exc:
            data["errors"].append(f"{key}: {str(exc)[:80]}")
    if app_id:
        try:
            data["apprefs"] = list(client.paged(
                f"/servicePrincipals/{app_id}/applicationRefs"))
        except Exception as exc:
            data["errors"].append(f"apprefs: {str(exc)[:80]}")
    try:
        data["keys"] = client.get_json(
            f"/servicePrincipals/{sid}?$select=keyCredentials,objectId")
    except Exception as exc:
        data["errors"].append(f"keys: {str(exc)[:80]}")
    return sid, app_id, data


def collect_service_principal_links(runner: Runner,
                                   service_principals: list) -> None:
    section = runner.section("ServicePrincipal roles/owners/refs/credentials")
    count = 0
    errors = 0
    for chunk in _chunks(service_principals, CHUNK):
        with ThreadPoolExecutor(max_workers=min(WORKERS, len(chunk) or 1)) as ex:
            results = list(ex.map(
                lambda sp: _fetch_sp_links(runner.c, sp), chunk))
        for sid, app_id, data in results:
            errors += len(data["errors"])
            for obj in data["assigned"] + data["assignments"]:
                if isinstance(obj, dict) and obj.get("id"):
                    obj = dict(obj)
                    if not obj.get("objectId"):
                        obj["objectId"] = obj.get("id")
                    if obj.get("objectId"):
                        runner.s.upsert("AppRoleAssignments", "objectId", obj)
                        count += 1
            count += _write_link_list(runner.s, "ServicePrincipal", sid,
                                      "sp_owner", data["owners"])
            for obj in data["apprefs"]:
                if isinstance(obj, dict):
                    obj = dict(obj)
                    obj.setdefault("appId", app_id)
                    if obj.get("appId"):
                        runner.s.upsert("ApplicationRefs", "appId", obj)
                        count += 1
            keys = data["keys"]
            if isinstance(keys, dict) and keys.get("objectId"):
                runner.s.upsert("ServicePrincipals", "objectId", keys)
    note = f"{errors} request errors" if errors else ""
    runner.finish(section, "ok" if not errors else "partial", count, note=note)


def _fetch_application_links(client: AadGraphClient, app: dict) -> tuple:
    aid = _object_id(app)
    data = {"owners": [], "keys": None, "errors": []}
    if not aid:
        return aid, data
    try:
        data["owners"] = list(client.paged(
            f"/applications/{aid}/$links/owners"))
    except Exception as exc:
        data["errors"].append(f"owners: {str(exc)[:80]}")
    try:
        data["keys"] = client.get_json(
            f"/applications/{aid}?$select=keyCredentials,objectId")
    except Exception as exc:
        data["errors"].append(f"keys: {str(exc)[:80]}")
    return aid, data


def collect_application_links(runner: Runner, applications: list) -> None:
    section = runner.section("Application owners/credentials")
    count = 0
    errors = 0
    for chunk in _chunks(applications, CHUNK):
        with ThreadPoolExecutor(max_workers=min(WORKERS, len(chunk) or 1)) as ex:
            results = list(ex.map(
                lambda app: _fetch_application_links(runner.c, app), chunk))
        for aid, data in results:
            errors += len(data["errors"])
            count += _write_link_list(runner.s, "Application", aid,
                                      "application_owner", data["owners"])
            keys = data["keys"]
            if isinstance(keys, dict) and keys.get("objectId"):
                runner.s.upsert("Applications", "objectId", keys)
    note = f"{errors} request errors" if errors else ""
    runner.finish(section, "ok" if not errors else "partial", count, note=note)


def _fetch_role_assignments(client: AadGraphClient, role: dict) -> tuple:
    rid = _object_id(role)
    data = {"assignments": [], "eligible": [], "errors": []}
    if not rid:
        return rid, data
    for key, path in (
            ("assignments", f"/roleAssignments?$filter=roleDefinitionId eq '{rid}'"),
            ("eligible", f"/eligibleRoleAssignments?$filter=roleDefinitionId eq '{rid}'")):
        try:
            data[key] = list(client.paged(path))
        except Exception as exc:
            data["errors"].append(f"{key}: {str(exc)[:80]}")
    return rid, data


def collect_role_assignments(runner: Runner, roles: list) -> None:
    section = runner.section("Role assignments/eligibility")
    count = 0
    errors = 0
    if roles:
        with ThreadPoolExecutor(max_workers=min(WORKERS, len(roles))) as ex:
            results = list(ex.map(
                lambda role: _fetch_role_assignments(runner.c, role), roles))
        for rid, data in results:
            errors += len(data["errors"])
            for key, table in (("assignments", "RoleAssignments"),
                               ("eligible", "EligibleRoleAssignments")):
                for obj in data[key]:
                    if not isinstance(obj, dict):
                        continue
                    if not obj.get("id"):
                        obj = dict(obj)
                        obj["id"] = f"{rid}:{obj.get('principalId', '')}"
                    runner.s.upsert(table, "id", obj)
                    count += 1
    note = f"{errors} request errors" if errors else ""
    runner.finish(section, "ok" if not errors else "partial", count, note=note)


def _fetch_mfa(client: AadGraphClient, user: dict) -> tuple:
    uid = _object_id(user)
    if not uid:
        return "", None, ""
    try:
        data = client.get_json(
            f"/users/{uid}?$select=strongAuthenticationDetail,objectId")
        return uid, data, ""
    except Exception as exc:
        return uid, None, str(exc)[:80]


def collect_mfa_details(runner: Runner, users: list) -> None:
    section = runner.section("MFA details")
    count = 0
    errors = 0
    for chunk in _chunks(users, CHUNK):
        with ThreadPoolExecutor(max_workers=min(WORKERS, len(chunk) or 1)) as ex:
            results = list(ex.map(lambda user: _fetch_mfa(runner.c, user),
                                  chunk))
        for uid, data, error in results:
            if error:
                errors += 1
            if uid and isinstance(data, dict) and data.get("objectId"):
                runner.s.upsert("Users", "objectId", data)
                count += 1
    note = f"{errors} request errors" if errors else ""
    runner.finish(section, "ok" if not errors else "partial", count, note=note)


# -- conditional access policy scope links -----------------------------------

def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _policy_detail(raw):
    value = raw
    for _ in range(5):
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except (TypeError, ValueError):
                return None
        elif isinstance(value, list):
            if not value:
                return None
            value = value[0]
        else:
            break
    return value if isinstance(value, dict) else None


def _group_users(store, group_id: str, seen: set) -> set:
    if not group_id or group_id in seen:
        return set()
    seen.add(group_id)
    users = {row[0] for row in store.conn.execute(
        'SELECT "User" FROM lnk_group_member_user WHERE "Group"=?',
        (group_id,))}
    children = [row[0] for row in store.conn.execute(
        'SELECT "childGroup" FROM lnk_group_member_group WHERE "Group"=?',
        (group_id,))]
    for child in children:
        users |= _group_users(store, child, seen)
    return users


def _role_users(store, role_template_id: str) -> set:
    roles = [row[0] for row in store.conn.execute(
        'SELECT objectId FROM DirectoryRoles WHERE roleTemplateId=?',
        (role_template_id,))]
    users = set()
    for role_id in roles:
        users |= {row[0] for row in store.conn.execute(
            'SELECT "User" FROM lnk_role_member_user WHERE "DirectoryRole"=?',
            (role_id,))}
    return users


def _criteria_users(store, criteria: dict) -> set:
    if not isinstance(criteria, dict):
        return set()
    users = set()
    for kind, values in criteria.items():
        values = _as_list(values)
        lowered = [str(value).lower() for value in values]
        if "all" in lowered:
            return {"ALLUSERS"}
        if "none" in lowered:
            continue
        key = str(kind).lower()
        if key == "users":
            users |= {str(value) for value in values if value}
        elif key == "groups":
            seen = set()
            for group_id in values:
                users |= _group_users(store, str(group_id), seen)
        elif key == "roles":
            for role_id in values:
                users |= _role_users(store, str(role_id))
        elif key in ("guests", "guestsorexternalusers"):
            if key == "guests" or "guests" in lowered:
                users |= {row[0] for row in store.conn.execute(
                    'SELECT objectId FROM Users WHERE lower(userType)=?',
                    ("guest",))}
        # Applications / ServicePrincipals / filter rules only apply to
        # non-user scopes and are intentionally skipped here.
    return users


def analyze_policy_links(runner: Runner) -> None:
    section = runner.section("Conditional access scope links")
    count = 0
    failures = 0
    rows = list(runner.s.conn.execute(
        'SELECT objectId, displayName, policyDetail FROM Policys '
        'WHERE policyType=18'))
    for policy_id, _name, raw_detail in rows:
        try:
            detail = _policy_detail(raw_detail)
            if not detail:
                continue
            conditions = detail.get("Conditions") or detail.get("conditions")
            if not isinstance(conditions, dict):
                continue
            who = conditions.get("Users") or conditions.get("users")
            if not isinstance(who, dict):
                continue
            include = set()
            for criterion in _as_list(who.get("Include") or who.get("include")):
                include |= _criteria_users(runner.s, criterion)
            exclude = set()
            for criterion in _as_list(who.get("Exclude") or who.get("exclude")):
                exclude |= _criteria_users(runner.s, criterion)
            if "ALLUSERS" in include:
                runner.s.add_link("lnk_policy_user_include_allusers",
                                  {"Policy": policy_id})
                count += 1
                include = set()
            for user_id in include:
                runner.s.add_link("lnk_policy_user_include",
                                  {"Policy": policy_id, "User": user_id})
                count += 1
            for user_id in exclude:
                runner.s.add_link("lnk_policy_user_exclude",
                                  {"Policy": policy_id, "User": user_id})
                count += 1
        except Exception:
            failures += 1
    note = f"{failures} policy parse errors" if failures else ""
    runner.finish(section, "ok" if not failures else "partial",
                  count, note=note)


def _fetch_users(runner: Runner) -> list:
    section = runner.section("Users")
    users = []
    try:
        for user in runner.c.paged("/users"):
            if isinstance(user, dict) and user.get("objectId"):
                users.append(user)
                runner.s.upsert("Users", "objectId", user)
    except Exception as exc:
        runner.finish(section, "degraded", note=str(exc)[:180])
        return users
    runner.finish(section, "ok", len(users))
    return users


def collect_aadgraph(runner: Runner, mfa: bool = False) -> dict:
    """Collect the legacy AAD Graph object graph into the configured Store."""
    store = runner.s
    store.clear_links()

    users = _fetch_users(runner)
    dump_objects(runner, "/tenantDetails", "TenantDetails", "objectId")
    dump_objects(runner, "/policies", "Policys", "objectId")
    service_principals = dump_objects(
        runner, "/servicePrincipals", "ServicePrincipals", "objectId", keep=True)
    groups = dump_objects(runner, "/groups", "Groups", "objectId", keep=True)
    administrative_units = dump_objects(
        runner, "/administrativeUnits", "AdministrativeUnits", "objectId",
        keep=True)
    applications = dump_objects(
        runner, "/applications", "Applications", "objectId", keep=True)
    devices = dump_devices(runner)
    directory_roles = dump_objects(
        runner, "/directoryRoles", "DirectoryRoles", "objectId", keep=True)
    role_definitions = dump_objects(
        runner, "/roleDefinitions", "RoleDefinitions", "objectId", keep=True)
    dump_objects(runner, "/contacts", "Contacts", "objectId")
    dump_objects(runner, "/oauth2PermissionGrants", "OAuth2PermissionGrants",
                 "objectId")
    dump_objects(runner, "/authorizationPolicy", "AuthorizationPolicys", "id")
    dump_objects(runner, "/settings", "DirectorySettings", "id")

    collect_group_links(runner, groups)
    collect_au_links(runner, administrative_units)
    collect_role_links(runner, directory_roles)
    collect_service_principal_links(runner, service_principals)
    collect_application_links(runner, applications)
    collect_role_assignments(runner, role_definitions)
    if mfa:
        collect_mfa_details(runner, users)
    analyze_policy_links(runner)
    store.commit()
    return {
        "users": users,
        "groups": groups,
        "service_principals": service_principals,
        "applications": applications,
        "devices": devices,
        "directory_roles": directory_roles,
        "role_definitions": role_definitions,
    }


def collect_gatherall(graph, arm, store, groups: list,
                      verbose: int = 0) -> list:
    """Run the IG/PIM/ARM collectors from graphcollect against an AAD DB.

    Core directory objects deliberately come from the legacy AAD Graph pass;
    this adds the APIs that ROADrecon's ``gatherall`` handles separately.
    """
    from .collectors import (Runner as GraphRunner, check_arm, collect_arm,
                             collect_ig, collect_pim_directory,
                             collect_pim_groups, collect_pim_static)

    runner = GraphRunner(graph, store, verbose)
    collect_pim_static(runner)
    collect_pim_directory(runner)
    collect_pim_groups(runner, [
        {"id": _object_id(group)} for group in groups if _object_id(group)])
    collect_ig(runner)
    if arm is not None:
        try:
            subscriptions = check_arm(arm)
        except Exception:
            subscriptions = []
        if subscriptions:
            collect_arm(arm, runner, subscriptions)
    else:
        section = runner.section("AZ (ARM)")
        runner.finish(section, "skipped", note="no ARM token")
    store.commit()
    return runner.sections

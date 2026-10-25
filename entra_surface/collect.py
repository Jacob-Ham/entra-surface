#!/usr/bin/env python3
"""Collection backend and Collect/Tokens tab UI for entra-surface.

The actual Graph and AAD Graph collectors are bundled under
``entra_surface/collector``.  This module schedules its worker, streams output,
persists redeemed refresh tokens in ``.entra-surface-auth.json``, and exposes
the status to the report server.

CLI usage:

    python3 -m entra_surface.collect -rt <refresh-token> -c <client-id> \
        -o data/databases/collected.db
    python3 -m entra_surface.collect --backend aadgraph -rt <refresh-token> \
        -c <client-id> --evade --gather-all -o data/databases/aadgraph.db

Set ENTRA_COLLECTOR_DIR to override with an external collector checkout.
"""
from __future__ import annotations

import argparse
import base64
import html
import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from . import settings as surface_settings
from . import token_resources

PACKAGE_DIR = Path(__file__).resolve().parent
BASE_DIR = PACKAGE_DIR.parent
DEFAULT_COLLECTOR_DIR = PACKAGE_DIR / "collector"
DEFAULT_DATA_DIR = BASE_DIR / "data" / "databases"
DEFAULT_OUTPUT = DEFAULT_DATA_DIR / "collected.db"
DEFAULT_AADGRAPH_OUTPUT = DEFAULT_DATA_DIR / "aadgraph.db"
WORKER = PACKAGE_DIR / "collect_worker.py"
AUTH_FILE = Path(os.environ.get("ENTRA_SURFACE_AUTH")
                 or (Path.cwd() / ".entra-surface-auth.json")).expanduser()
GRAPH_AUDIENCES = {
    "https://graph.microsoft.com",
    "00000003-0000-0000-c000-000000000000",
}
AAD_GRAPH_AUDIENCES = {
    "https://graph.windows.net",
    "00000002-0000-0000-c000-000000000000",
}
REDEEM_TARGETS = {
    "graph": "https://graph.microsoft.com",
    "aadgraph": "https://graph.windows.net",
}
MAX_LOG_LINES = 400

_LOCK = threading.Lock()
_PROCESS = None
_JOB = {
    "status": "idle",
    "kind": "",
    "log": [],
    "output": "",
    "started_at": "",
    "finished_at": "",
    "returncode": None,
    "error": "",
}
_STORE = None


def collector_dir() -> Path:
    override = os.environ.get("ENTRA_COLLECTOR_DIR")
    return Path(override).expanduser().resolve() if override else DEFAULT_COLLECTOR_DIR


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _worker_env() -> dict:
    env = os.environ.copy()
    env["ENTRA_COLLECTOR_DIR"] = str(collector_dir())
    env["ENTRA_SURFACE_SETTINGS"] = str(surface_settings.SETTINGS_FILE)
    return env


# ---------------------------------------------------------------------------
# persisted auth store

def _empty_store() -> dict:
    return {"version": 1, "active_id": "", "tokens": []}


def _load_store() -> dict:
    global _STORE
    if _STORE is not None:
        return _STORE
    data = None
    try:
        data = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = None
    if not isinstance(data, dict) or not isinstance(data.get("tokens"), list):
        data = _empty_store()
    else:
        data.setdefault("version", 1)
        data.setdefault("active_id", "")
        data["tokens"] = [
            t for t in data["tokens"]
            if isinstance(t, dict) and (t.get("refresh_token") or t.get("access_token"))]
        ids = {t.get("id") for t in data["tokens"]}
        if data["active_id"] not in ids:
            data["active_id"] = data["tokens"][0]["id"] if data["tokens"] else ""
    _STORE = data
    return _STORE


def _save_store() -> None:
    store = _load_store()
    try:
        AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = AUTH_FILE.with_name(AUTH_FILE.name + ".tmp")
        tmp.write_text(json.dumps(store, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, AUTH_FILE)
    except OSError as exc:
        raise RuntimeError(f"could not write auth file: {exc}")


def _token_summary(rec: dict, active_id: str) -> dict:
    principal = dict(rec.get("principal") or {})
    if principal.get("audience"):
        principal["audience"] = str(principal["audience"]).rstrip("/")
    return {
        "id": rec.get("id") or "",
        "client_id": rec.get("client_id") or "",
        "parent_id": rec.get("parent_id") or "",
        "client_name": "",
        "client_foci": False,
        "audience_name": "",
        "added_at": rec.get("added_at") or "",
        "updated_at": rec.get("updated_at") or "",
        "last_used_at": rec.get("last_used_at") or "",
        "last_used_for": rec.get("last_used_for") or "",
        "last_used_mode": rec.get("last_used_mode") or "",
        "active": bool(rec.get("id") and rec.get("id") == active_id),
        "has_refresh_token": bool(rec.get("refresh_token")),
        "has_access_token": bool(rec.get("access_token")),
        "principal": principal,
    }


def _enrich_token_info(tokens: list[dict]) -> None:
    client_cache = {}
    audience_cache = {}
    for token in tokens:
        client_id = str(token.get("client_id") or "").strip()
        if client_id:
            key = client_id.lower()
            if key not in client_cache:
                client_cache[key] = token_resources.client_info(client_id)
            info = client_cache[key]
            token["client_name"] = info.get("name") or ""
            token["client_foci"] = bool(info.get("foci"))
        audience = str(
            (token.get("principal") or {}).get("audience") or "").strip()
        if audience:
            key = audience.lower()
            if key not in audience_cache:
                audience_cache[key] = token_resources.audience_info(audience)
            token["audience_name"] = audience_cache[key].get("name") or ""


def get_auth_status() -> dict:
    """Public token metadata for the Tokens tab; refresh tokens are omitted."""
    with _LOCK:
        store = _load_store()
        active_id = store.get("active_id") or ""
        active = next((t for t in store["tokens"]
                       if t.get("id") == active_id), None)
        tokens = sorted(store["tokens"],
                        key=lambda t: t.get("updated_at") or "", reverse=True)
        tokens.sort(key=lambda t: t.get("id") != active_id)
        can_refresh = bool(active and active.get("refresh_token")
                           and active.get("client_id"))
        can_access = bool(active and _record_is_graph_access(active))
        aadgraph_access = bool(active and _record_is_aadgraph_access(active))
        summaries = [_token_summary(t, active_id) for t in tokens]
        result = {
            "configured": can_refresh or can_access,
            "collect_mode": "refresh" if can_refresh else ("access" if can_access else ""),
            "aadgraph_configured": can_refresh or aadgraph_access,
            "aadgraph_mode": ("refresh" if can_refresh
                              else ("access" if aadgraph_access else "")),
            "active_id": active_id,
            "tokens": summaries,
            "auth_file": str(AUTH_FILE),
        }
    _enrich_token_info(summaries)
    return result


def get_token_secrets(token_id: str) -> dict:
    """Return the saved secrets for one token; only the local UI should call this."""
    with _LOCK:
        store = _load_store()
        rec = next((t for t in store["tokens"] if t.get("id") == token_id), None)
        if rec is None:
            raise ValueError("token not found")
        principal = rec.get("principal") or {}
        return {
            "id": rec.get("id") or "",
            "access_token": rec.get("access_token") or "",
            "refresh_token": rec.get("refresh_token") or "",
            "access_expires_at": principal.get("access_expires_at") or "",
        }


def clear_auth() -> dict:
    with _LOCK:
        store = _load_store()
        store["tokens"] = []
        store["active_id"] = ""
        _save_store()
    return get_auth_status()


def select_token(token_id: str) -> dict:
    with _LOCK:
        store = _load_store()
        if not any(t.get("id") == token_id for t in store["tokens"]):
            raise ValueError("token not found")
        store["active_id"] = token_id
        _save_store()
    return get_auth_status()


def delete_token(token_id: str) -> dict:
    with _LOCK:
        store = _load_store()
        before = len(store["tokens"])
        store["tokens"] = [t for t in store["tokens"] if t.get("id") != token_id]
        if len(store["tokens"]) == before:
            raise ValueError("token not found")
        if store.get("active_id") == token_id:
            store["active_id"] = store["tokens"][0]["id"] if store["tokens"] else ""
        _save_store()
    return get_auth_status()


def _update_token_secret(token_id: str, refresh_token: str = "",
                         access_token: str = "") -> None:
    if not token_id or not (refresh_token or access_token):
        return
    with _LOCK:
        store = _load_store()
        for rec in store["tokens"]:
            if rec.get("id") == token_id:
                if refresh_token:
                    rec["refresh_token"] = refresh_token
                if access_token:
                    rec["access_token"] = access_token
                rec["updated_at"] = _timestamp()
                _save_store()
                return


def _mark_token_used(token_id: str, output: str, mode: str) -> None:
    if not token_id:
        return
    with _LOCK:
        store = _load_store()
        for rec in store["tokens"]:
            if rec.get("id") == token_id:
                rec["last_used_at"] = _timestamp()
                rec["last_used_for"] = str(output)
                rec["last_used_mode"] = mode
                _save_store()
                return


# ---------------------------------------------------------------------------
# collector worker integration

def _collector_python() -> str:
    for candidate in (
            collector_dir() / ".venv" / "bin" / "python",
            BASE_DIR / ".venv" / "bin" / "python"):
        if candidate.is_file():
            return str(candidate)
    return sys.executable


def _worker_command(mode: str, refresh_token: str, client_id: str,
                    token_out: str = "", out_path: Path | None = None,
                    user_agent: str = "", access_out: str = "",
                    access_token: str = "", evade: bool = False,
                    gather_all: bool = False, autotoken: bool = False,
                    mfa: bool = False) -> list[str]:
    directory = collector_dir()
    if not (directory / "graphcollect").is_dir():
        raise RuntimeError(
            f"collector backend not found: {directory} "
            "(expected graphcollect/; set ENTRA_COLLECTOR_DIR for an "
            "external checkout)")
    if not WORKER.is_file():
        raise RuntimeError(f"collector worker not found: {WORKER}")
    if mode == "run-aadgraph":
        cmd = [_collector_python(), "-u", str(WORKER), "run-aadgraph"]
        if refresh_token:
            cmd += ["-rt", refresh_token]
        if client_id:
            cmd += ["-c", client_id]
        if access_token:
            cmd += ["-at", access_token]
        cmd += ["-o", str(out_path)]
        if user_agent:
            cmd += ["-ua", user_agent]
        if token_out:
            cmd += ["--token-out", token_out]
        if autotoken:
            cmd += ["--autotoken"]
        if evade:
            cmd += ["--evade"]
        if gather_all:
            cmd += ["--gather-all"]
        if mfa:
            cmd += ["--mfa"]
        return cmd
    if mode == "run-access":
        cmd = [_collector_python(), "-u", str(WORKER), "run-access",
               "-at", refresh_token, "-o", str(out_path)]
        if user_agent:
            cmd += ["-ua", user_agent]
        if evade:
            cmd += ["--evade"]
        return cmd
    client = (client_id or "").strip()
    if not client:
        raise ValueError("client id is required when a refresh token is provided")
    cmd = [_collector_python(), "-u", str(WORKER), mode,
           "-rt", refresh_token, "-c", client]
    if token_out:
        cmd += ["--token-out", token_out]
    if mode == "run":
        cmd += ["-o", str(out_path)]
        if user_agent:
            cmd += ["-ua", user_agent]
        if access_out:
            cmd += ["--access-out", access_out]
        if evade:
            cmd += ["--evade"]
    return cmd


def _temp_token_path() -> Path:
    fd, name = tempfile.mkstemp(prefix="entra-token-")
    os.close(fd)
    return Path(name)


def _read_token_out(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    finally:
        try:
            path.unlink()
        except OSError:
            pass


def test_proxy(proxy: dict, url: str = "") -> dict:
    """Run the collector's proxy connectivity check with an unsaved config."""
    proxy = surface_settings.validate_proxy(proxy or {})
    if not proxy.get("enabled"):
        raise ValueError("enable the proxy before testing it")
    directory = collector_dir()
    if not (directory / "graphcollect").is_dir():
        raise RuntimeError(
            f"collector backend not found: {directory} "
            "(expected graphcollect/; set ENTRA_COLLECTOR_DIR for an "
            "external checkout)")
    if not WORKER.is_file():
        raise RuntimeError(f"collector worker not found: {WORKER}")
    parent = surface_settings.SETTINGS_FILE.parent
    parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(
        prefix=".entra-proxy-test-", suffix=".json", dir=str(parent))
    path = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"proxy": proxy}, handle)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        env = _worker_env()
        env["ENTRA_SURFACE_SETTINGS"] = str(path)
        cmd = [_collector_python(), "-u", str(WORKER), "proxy-test"]
        if url:
            cmd += ["--url", url]
        try:
            proc = subprocess.run(
                cmd, cwd=str(BASE_DIR), env=env,
                capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("proxy test timed out") from exc
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip().splitlines()
            raise RuntimeError(detail[-1] if detail else "proxy test failed")
        try:
            result = json.loads(proc.stdout.strip() or "{}")
        except ValueError as exc:
            raise RuntimeError(
                "collector returned an invalid proxy test result") from exc
        if not isinstance(result, dict):
            raise RuntimeError("collector returned an invalid proxy test result")
        return result
    finally:
        try:
            path.unlink()
        except OSError:
            pass


def redeem_token(refresh_token: str, client_id: str,
                 resource: str = "https://graph.microsoft.com") -> tuple[str, dict, str]:
    """Exchange a refresh token once and return (rotated, principal, access)."""
    token = (refresh_token or "").strip()
    client = (client_id or "").strip()
    resource = (resource or "").strip()
    if not token:
        raise ValueError("refresh token is required")
    if not client:
        raise ValueError("client id is required when a refresh token is provided")
    if not resource:
        raise ValueError("redemption resource is required")
    token_out = _temp_token_path()
    cmd = _worker_command("probe", token, client, str(token_out))
    cmd += ["--resource-uri", resource]
    try:
        proc = subprocess.run(
            cmd, cwd=str(BASE_DIR), env=_worker_env(),
            capture_output=True, text=True, timeout=120)
        rotated = _read_token_out(token_out) or token
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip().splitlines()
            raise ValueError(detail[-1] if detail else "token redemption failed")
        try:
            payload = json.loads(proc.stdout.strip())
        except (ValueError, TypeError):
            raise RuntimeError("collector returned an invalid auth response")
        principal = payload.get("principal") or {}
        access_token = payload.get("access_token") or ""
        return rotated, principal, access_token
    finally:
        try:
            token_out.unlink()
        except OSError:
            pass


def _principal_key(principal: dict) -> tuple[str, str]:
    return (
        principal.get("tenant_id") or "",
        principal.get("object_id") or principal.get("oid")
        or principal.get("upn") or principal.get("identity") or "",
    )


def _find_access_record(store: dict, principal: dict,
                        exclude_id: str = "",
                        parent_id: str = "",
                        client_id: str = "") -> dict | None:
    """Find the record for this parent+client+principal+audience, if one
    exists."""
    key = _principal_key(principal)
    audience = str(principal.get("audience") or "").rstrip("/")
    for rec in store["tokens"]:
        if exclude_id and rec.get("id") == exclude_id:
            continue
        if (rec.get("parent_id") or "") != (parent_id or ""):
            continue
        if client_id and str(rec.get("client_id") or "").lower() != client_id.lower():
            continue
        old = rec.get("principal") or {}
        if (_principal_key(old) == key
                and str(old.get("audience") or "").rstrip("/") == audience):
            return rec
    return None


def _store_access_token(store: dict, access_token: str, principal: dict,
                        now: str, client_id: str = "",
                        exclude_id: str = "", parent_id: str = "") -> dict:
    """Create/update the access-only record for this parent+principal+audience."""
    match = _find_access_record(store, principal, exclude_id, parent_id,
                                client_id=client_id)
    if match is None and parent_id:
        # Migrate an unparented record from older versions, but only when this
        # is the sole refresh token for that client. Otherwise the old record
        # belongs to a different refresh and must be left intact.
        legacy = _find_access_record(store, principal, exclude_id, "")
        if legacy is not None:
            legacy_client = str(legacy.get("client_id") or "")
            current_client = str(
                client_id or principal.get("client_id") or "")
            current = next(
                (t for t in store["tokens"] if t.get("id") == parent_id), None)
            current_principal = (current or {}).get("principal") or {}
            same_client = [
                t for t in store["tokens"]
                if t.get("refresh_token")
                and str(t.get("client_id") or "") == current_client
                and _principal_key(t.get("principal") or {})
                == _principal_key(current_principal)
            ]
            if (legacy_client and current_client
                    and legacy_client == current_client
                    and len(same_client) == 1
                    and same_client[0].get("id") == parent_id):
                match = legacy
    if match is None:
        match = {
            "id": secrets.token_hex(8),
            "added_at": now,
            "refresh_token": "",
            "parent_id": parent_id,
            "client_id": client_id or principal.get("client_id") or "",
            "principal": principal,
        }
        store["tokens"].append(match)
    else:
        merged = dict(match.get("principal") or {})
        merged.update({k: v for k, v in principal.items() if v})
        match["principal"] = merged
        if not match.get("client_id"):
            match["client_id"] = client_id or principal.get("client_id") or ""
        if parent_id:
            match["parent_id"] = parent_id
    match["access_token"] = access_token
    match["updated_at"] = now
    return match


def _decode_access_claims(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload.encode()).decode("utf-8"))
    except Exception:
        raise ValueError("access token is not a valid JWT")
    if not isinstance(claims, dict):
        raise ValueError("access token is not a valid JWT")
    return claims


def _principal_from_claims(claims: dict) -> dict:
    audience = claims.get("aud") or ""
    if isinstance(audience, list):
        audience = ", ".join(str(a) for a in audience)
    audience = str(audience).rstrip("/")
    expires = claims.get("exp")
    expires_at = ""
    if expires:
        try:
            expires_at = datetime.fromtimestamp(
                int(expires), timezone.utc).isoformat(timespec="seconds")
        except (ValueError, TypeError, OSError):
            expires_at = ""
    identity = (claims.get("upn") or claims.get("unique_name")
                or claims.get("oid") or "")
    return {
        "upn": claims.get("upn") or claims.get("unique_name") or "",
        "name": claims.get("name") or "",
        "object_id": claims.get("oid") or "",
        "mail": claims.get("email") or "",
        "tenant_id": claims.get("tid") or "",
        "tenant_name": "",
        "client_id": claims.get("appid") or "",
        "audience": str(audience),
        "scopes": (claims.get("scp") or "").split(),
        "roles": claims.get("roles") or [],
        "access_expires_at": expires_at,
        "identity": identity,
    }


def _is_graph_audience(claims: dict) -> bool:
    audience = claims.get("aud") or ""
    values = audience if isinstance(audience, list) else [audience]
    return any(str(a).rstrip("/").lower() in GRAPH_AUDIENCES for a in values)


def _is_aadgraph_audience(claims: dict) -> bool:
    audience = claims.get("aud") or ""
    values = audience if isinstance(audience, list) else [audience]
    return any(str(a).rstrip("/").lower() in AAD_GRAPH_AUDIENCES
               for a in values)


def _record_is_graph_access(rec: dict) -> bool:
    token = rec.get("access_token") or ""
    if not token:
        return False
    try:
        return _is_graph_audience(_decode_access_claims(token))
    except ValueError:
        return False


def _record_is_aadgraph_access(rec: dict) -> bool:
    token = rec.get("access_token") or ""
    if not token:
        return False
    try:
        return _is_aadgraph_audience(_decode_access_claims(token))
    except ValueError:
        return False


def set_access_token(access_token: str) -> dict:
    token = (access_token or "").strip()
    if not token:
        raise ValueError("access token is required")
    principal = _principal_from_claims(_decode_access_claims(token))
    now = _timestamp()
    with _LOCK:
        store = _load_store()
        match = _find_access_record(store, principal)
        if match is None:
            match = {
                "id": secrets.token_hex(8),
                "added_at": now,
                "refresh_token": "",
                "parent_id": "",
                "client_id": principal.get("client_id") or "",
                "principal": principal,
            }
            store["tokens"].append(match)
        else:
            merged = dict(match.get("principal") or {})
            merged.update({k: v for k, v in principal.items() if v})
            match["principal"] = merged
            if not match.get("client_id"):
                match["client_id"] = principal.get("client_id") or ""
        match["access_token"] = token
        match["updated_at"] = now
        active_id = store.get("active_id") or ""
        if not active_id or active_id == match["id"]:
            store["active_id"] = match["id"]
        _save_store()
    return get_auth_status()


def set_auth(refresh_token: str, client_id: str) -> dict:
    """Save a refresh token without redeeming it."""
    token = (refresh_token or "").strip()
    client = (client_id or "").strip()
    if not token:
        raise ValueError("refresh token is required")
    if not client:
        raise ValueError("client id is required when a refresh token is provided")

    now = _timestamp()
    with _LOCK:
        store = _load_store()
        match = next(
            (rec for rec in store["tokens"]
             if rec.get("refresh_token") == token
             and rec.get("client_id") == client), None)
        if match is None:
            match = {
                "id": secrets.token_hex(8),
                "added_at": now,
                "principal": {},
                "access_token": "",
            }
            store["tokens"].append(match)
        match.update({
            "refresh_token": token,
            "client_id": client,
            "updated_at": now,
        })
        store["active_id"] = match["id"]
        _save_store()
    return get_auth_status()


def get_token_resources(token_id: str, client_id: str = "") -> dict:
    """List the resources one saved refresh token can request tokens for.

    When `client_id` names another FOCI client, the list is for that client;
    this is how the FOCI submenu builds its resource picker.
    """
    with _LOCK:
        store = _load_store()
        rec = next((t for t in store["tokens"] if t.get("id") == token_id),
                   None)
        if rec is None:
            raise ValueError("token not found")
        has_refresh = bool(rec.get("refresh_token"))
        source_client = rec.get("client_id") or ""
    if not has_refresh:
        raise ValueError("this token has no refresh token")
    if not source_client:
        raise ValueError("client id is missing for this token")
    target_client = (client_id or "").strip() or source_client
    if target_client.lower() != source_client.lower():
        info = token_resources.client_info(source_client)
        if not info.get("foci"):
            raise ValueError("this token's client is not FOCI; it cannot "
                             "redeem with another client")
        target_info = token_resources.client_info(target_client)
        if target_info.get("found") and not target_info.get("foci"):
            raise ValueError("selected client is not in the FOCI family")
    data = token_resources.resources_for_client(target_client)
    data["client_id"] = target_client
    data["source_client_id"] = source_client
    return data


def get_token_clients() -> dict:
    """List searchable client applications for the Add token form."""
    try:
        clients = token_resources.clients()
    except RuntimeError as exc:
        return {"clients": [], "error": str(exc)}
    return {"clients": clients, "error": ""}


def _resolve_redeem_resource(client_id: str, target: str,
                             resource: str) -> tuple[str, str]:
    """Resolve a requested resource, preferring the client's scope mappings."""
    requested = (resource or "").strip()
    if not requested:
        requested = REDEEM_TARGETS.get((target or "graph").strip().lower(), "")
    if not requested:
        raise ValueError("unknown redemption target")
    data = token_resources.resources_for_client(client_id)
    match = token_resources.find_resource(data, requested)
    if match:
        return match["resource"], match["name"] or match["resource"]
    custom = token_resources.normalize_custom_resource(requested)
    return custom, custom


def redeem_saved_token(token_id: str, target: str = "graph",
                       resource: str = "", client_id: str = "") -> dict:
    """Redeem one saved refresh token for a mapped or custom resource.

    `client_id` may name a sibling FOCI client; when omitted, the token's own
    saved client is used.
    """
    with _LOCK:
        store = _load_store()
        rec = next((t for t in store["tokens"] if t.get("id") == token_id), None)
        if rec is None:
            raise ValueError("token not found")
        refresh_token = rec.get("refresh_token") or ""
        source_client = rec.get("client_id") or ""
    if not refresh_token:
        raise ValueError("this token has no refresh token to redeem")
    if not source_client:
        raise ValueError("client id is required when a refresh token is provided")

    target_client = (client_id or "").strip() or source_client
    if target_client.lower() != source_client.lower():
        info = token_resources.client_info(source_client)
        if not info.get("foci"):
            raise ValueError("this token's client is not FOCI; it cannot "
                             "redeem with another client")
        target_info = token_resources.client_info(target_client)
        if target_info.get("found") and not target_info.get("foci"):
            raise ValueError("selected client is not in the FOCI family")

    redeem_resource, _ = _resolve_redeem_resource(target_client, target, resource)
    rotated, principal, access_token = redeem_token(
        refresh_token, target_client, redeem_resource)
    now = _timestamp()
    with _LOCK:
        store = _load_store()
        rec = next((t for t in store["tokens"] if t.get("id") == token_id), None)
        if rec is None:
            raise ValueError("token not found")

        # Keep the refresh entry refresh-only and put redeemed access tokens in
        # their own principal+audience entries.
        old_principal = dict(rec.get("principal") or {})
        old_access = rec.get("access_token") or ""
        if old_access and not old_principal.get("audience"):
            try:
                old_principal["audience"] = _principal_from_claims(
                    _decode_access_claims(old_access)).get("audience") or ""
            except ValueError:
                pass
        if old_access and old_principal.get("audience"):
            _store_access_token(store, old_access, old_principal, now,
                                client_id=source_client, exclude_id=rec["id"],
                                parent_id=rec["id"])
        if old_access:
            rec["access_token"] = ""

        merged = dict(old_principal)
        merged.update({k: v for k, v in principal.items() if v})
        merged["audience"] = ""
        merged["access_expires_at"] = ""

        if target_client.lower() == source_client.lower():
            rec.update({
                "refresh_token": rotated,
                "access_token": "",
                "principal": merged,
                "updated_at": now,
            })
            refresh_parent_id = rec["id"]
        else:
            # A FOCI sibling redemption gets its own refresh entry, with the
            # rotated refresh token and the new access token beneath it.
            new_rec = {
                "id": secrets.token_hex(8),
                "added_at": now,
                "refresh_token": rotated,
                "access_token": "",
                "client_id": target_client,
                "principal": merged,
                "updated_at": now,
            }
            store["tokens"].append(new_rec)
            refresh_parent_id = new_rec["id"]

        access_principal = dict(merged)
        access_principal["audience"] = principal.get("audience") or ""
        access_principal["access_expires_at"] = (
            principal.get("access_expires_at") or "")
        access_principal["scopes"] = principal.get("scopes") or []
        access_principal["roles"] = principal.get("roles") or []
        _store_access_token(store, access_token, access_principal, now,
                            client_id=target_client,
                            exclude_id=refresh_parent_id,
                            parent_id=refresh_parent_id)
        if not store.get("active_id") or store.get("active_id") == rec["id"]:
            store["active_id"] = refresh_parent_id
        _save_store()
    return get_auth_status()


# ---------------------------------------------------------------------------
# collection job

def _resolve_credentials(refresh_token: str = "",
                         client_id: str = "", backend: str = "graph",
                         autotoken: bool = True) -> dict:
    """Resolve the token(s) a collection backend should use."""
    token = (refresh_token or "").strip()
    client = (client_id or "").strip()
    if token:
        if not client:
            raise ValueError("client id is required when a refresh token is provided")
        return {"mode": "refresh", "refresh_token": token,
                "access_token": "", "client_id": client, "token_id": ""}
    with _LOCK:
        store = _load_store()
        active = next((t for t in store["tokens"]
                       if t.get("id") == store.get("active_id")), None)
        if active is None:
            raise ValueError("add and select a token in Tokens first")
        active_id = active.get("id") or ""
        rec_refresh = active.get("refresh_token") or ""
        rec_access = active.get("access_token") or ""
        rec_client = active.get("client_id") or ""
    if backend == "aadgraph":
        if rec_refresh and rec_client:
            if autotoken:
                return {"mode": "refresh", "refresh_token": rec_refresh,
                        "access_token": rec_access, "client_id": rec_client,
                        "token_id": active_id}
            if rec_access and _record_is_aadgraph_access(active):
                return {"mode": "access", "refresh_token": rec_refresh,
                        "access_token": rec_access, "client_id": rec_client,
                        "token_id": active_id}
            raise ValueError(
                "enable autotoken or select an AAD Graph access token")
        if rec_access and _record_is_aadgraph_access(active):
            return {"mode": "access", "refresh_token": "",
                    "access_token": rec_access, "client_id": rec_client,
                    "token_id": active_id}
        raise ValueError(
            "select a token with a refresh token or AAD Graph access token")
    if rec_refresh and rec_client:
        return {"mode": "refresh", "refresh_token": rec_refresh,
                "access_token": rec_access, "client_id": rec_client,
                "token_id": active_id}
    if rec_access and _record_is_graph_access(active):
        return {"mode": "access", "refresh_token": "",
                "access_token": rec_access, "client_id": rec_client,
                "token_id": active_id}
    raise ValueError(
        "select a token with a refresh token or a Microsoft Graph access token")


def _append_log(line: str) -> None:
    with _LOCK:
        _JOB["log"].append(line.rstrip("\n"))
        if len(_JOB["log"]) > MAX_LOG_LINES:
            del _JOB["log"][:-MAX_LOG_LINES]


def get_status() -> dict:
    with _LOCK:
        return {
            "status": _JOB["status"],
            "kind": _JOB.get("kind") or "",
            "log": list(_JOB["log"]),
            "output": _JOB["output"],
            "started_at": _JOB["started_at"],
            "finished_at": _JOB["finished_at"],
            "returncode": _JOB["returncode"],
            "error": _JOB["error"],
            "backend": str(collector_dir()),
        }


def start_collection(refresh_token: str = "", out: str = "",
                     client_id: str = "", user_agent: str = "",
                     backend: str = "graph", evade: bool = False,
                     gather_all: bool = False, autotoken: bool = True,
                     mfa: bool = False) -> dict:
    """Start one background collection job; only one can run at a time."""
    global _PROCESS
    backend = (backend or "graph").strip().lower()
    if backend not in ("graph", "aadgraph"):
        raise ValueError("unknown collection backend")
    creds = _resolve_credentials(refresh_token, client_id, backend, autotoken)
    default_out = (DEFAULT_AADGRAPH_OUTPUT if backend == "aadgraph"
                   else DEFAULT_OUTPUT)
    out_path = Path(out or default_out).expanduser()
    if not out_path.is_absolute():
        out_path = (Path.cwd() / out_path).resolve()
    token_out = None
    access_out = None
    if backend == "aadgraph":
        if creds["refresh_token"]:
            token_out = _temp_token_path()
        cmd = _worker_command(
            "run-aadgraph", creds["refresh_token"], creds["client_id"],
            token_out=str(token_out) if token_out else "",
            out_path=out_path, user_agent=user_agent,
            access_token=creds["access_token"], evade=evade,
            gather_all=gather_all,
            autotoken=bool(autotoken and creds["refresh_token"]), mfa=mfa)
        initial_log = "Starting AAD Graph collector..."
    elif creds["mode"] == "refresh":
        token_out = _temp_token_path()
        access_out = _temp_token_path()
        cmd = _worker_command("run", creds["refresh_token"],
                              creds["client_id"], str(token_out),
                              out_path=out_path, user_agent=user_agent,
                              access_out=str(access_out), evade=evade)
        initial_log = "Starting collector..."
    else:
        cmd = _worker_command("run-access", creds["access_token"], "",
                              out_path=out_path, user_agent=user_agent,
                              evade=evade)
        initial_log = "Starting collector..."
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with _LOCK:
        if _JOB["status"] == "running":
            raise RuntimeError("a collection is already running")
        _JOB.update({
            "status": "running",
            "kind": backend,
            "log": [initial_log],
            "output": str(out_path),
            "started_at": _timestamp(),
            "finished_at": "",
            "returncode": None,
            "error": "",
        })

    _mark_token_used(creds["token_id"], out_path,
                     "aadgraph" if backend == "aadgraph" else creds["mode"])
    thread = threading.Thread(target=_run_job,
                              args=(cmd, token_out, access_out,
                                    creds["token_id"]),
                              daemon=True)
    thread.start()
    return get_status()


def _run_job(cmd: list[str], token_out: Path | None,
             access_out: Path | None, token_id: str) -> None:
    global _PROCESS
    proc = None
    try:
        proc = subprocess.Popen(
            cmd, cwd=str(BASE_DIR), env=_worker_env(),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1)
        with _LOCK:
            _PROCESS = proc
        assert proc.stdout is not None
        for line in proc.stdout:
            _append_log(line)
        returncode = proc.wait()
        with _LOCK:
            _JOB["returncode"] = returncode
            _JOB["status"] = "done" if returncode == 0 else "error"
            _JOB["finished_at"] = _timestamp()
            if returncode != 0:
                _JOB["error"] = f"collector exited with status {returncode}"
    except Exception as exc:  # surfaced in the Collect tab
        with _LOCK:
            _JOB["status"] = "error"
            _JOB["finished_at"] = _timestamp()
            _JOB["error"] = str(exc)
            _JOB["log"].append(f"error: {exc}")
    finally:
        rotated = _read_token_out(token_out) if token_out else ""
        access_token = _read_token_out(access_out) if access_out else ""
        if rotated or access_token:
            try:
                _update_token_secret(token_id, rotated, access_token)
            except Exception:
                pass
        with _LOCK:
            _PROCESS = None


# ---------------------------------------------------------------------------
# UI

def styles_html() -> str:
    """Shared CSS for the Collect and Tokens views."""
    return """  .collect-panel { max-width: 780px; }
  .tokens-panel { max-width: none; }
  #token-pane-add { max-width: 780px; }
  .collect-panel h1 { font-size: 22px; margin: 0 0 4px; }
  .collect-tabs { margin-bottom: 14px; }
  .collect-panel .sub { margin: 0 0 18px; }
  .collect-card {
    background: var(--surface-1); border: 1px solid var(--border);
    border-radius: 10px; padding: 18px;
  }
  .collect-field {
    display: flex; flex-direction: column; gap: 6px; margin-bottom: 14px;
    color: var(--text-secondary); font-size: 12px;
  }
  .collect-field input, .collect-field select, .collect-field textarea {
    background: var(--page-plane); color: var(--text-primary);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 8px 10px; font-size: 13px; font-family: inherit;
  }
  .collect-field textarea {
    min-height: 54px; resize: vertical;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px;
  }
  .collect-check {
    display: flex; align-items: center; gap: 8px; margin: 0 0 10px;
    color: var(--text-secondary); font-size: 12px; cursor: pointer;
  }
  .collect-check input { margin: 0; }
  .collect-check-note {
    margin: -3px 0 12px; color: var(--text-muted);
    font-size: 11px; line-height: 1.35;
  }
  .client-search { position: relative; width: 100%; }
  .client-search input { width: 100%; box-sizing: border-box; }
  .client-menu {
    position: absolute; top: calc(100% + 4px); left: 0; right: 0;
    z-index: 1100; max-height: 280px; overflow-y: auto;
    background: var(--surface-1); border: 1px solid var(--border);
    border-radius: 8px; padding: 4px;
    box-shadow: 0 14px 34px rgba(0, 0, 0, 0.42);
  }
  .client-menu.hidden { display: none; }
  .client-option {
    display: flex; flex-direction: column; gap: 1px; width: 100%;
    background: transparent; border: 0; border-radius: 6px;
    color: var(--text-primary); text-align: left; padding: 6px 8px;
    cursor: pointer; font: inherit;
  }
  .client-option:hover, .client-option.active {
    background: color-mix(in srgb, var(--accent) 13%, transparent);
  }
  .client-option-name {
    font-size: 12px; font-weight: 600; line-height: 1.3;
    overflow-wrap: anywhere;
  }
  .client-option-name .token-type { margin-left: 6px; }
  .client-option-meta {
    font-size: 10.5px; color: var(--text-muted); line-height: 1.35;
    overflow-wrap: anywhere;
  }
  .client-note {
    padding: 6px 8px; color: var(--text-muted); font-size: 11px;
    line-height: 1.35;
  }
  .client-note.error { color: var(--status-critical); }
  .client-hint {
    color: var(--text-muted); font-size: 11px; line-height: 1.35;
    min-height: 14px; overflow-wrap: anywhere;
  }
  .client-hint b { color: var(--text-primary); font-weight: 600; }
  .client-hint .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 10.5px; }
  .collect-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .collect-actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .collect-actions .muted { flex: 1; min-width: 220px; }
  .collect-status {
    margin-top: 18px; background: var(--surface-1);
    border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px;
  }
  .collect-status-head {
    display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap;
    margin-bottom: 10px; font-size: 13px;
  }
  .collect-status-head .mono { font-size: 11.5px; }
  .collect-log {
    margin: 0; padding: 10px 12px; max-height: 360px; overflow: auto;
    background: var(--page-plane); border: 1px solid var(--border);
    border-radius: 7px; color: var(--text-secondary);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 11.5px; line-height: 1.45; white-space: pre-wrap;
  }
  .token-tabs { margin-bottom: 14px; }
  .token-tabs .tab-count { color: var(--text-muted); font-size: 11px; margin-left: 5px; }
  .tokens-flash {
    margin: 0 0 12px; padding: 8px 12px; border-radius: 7px; font-size: 12px;
    background: color-mix(in srgb, var(--accent) 10%, transparent);
    color: var(--accent); border: 1px solid color-mix(in srgb, var(--accent) 25%, transparent);
  }
  .tokens-flash.error {
    color: var(--status-critical); background: color-mix(in srgb, var(--status-critical) 10%, transparent);
    border-color: color-mix(in srgb, var(--status-critical) 25%, transparent);
  }
  .token-toolbar {
    display: flex; flex-wrap: wrap; gap: 6px; align-items: center;
    margin: 0 0 10px;
  }
  .token-toolbar input, .token-toolbar select {
    background: var(--surface-1); color: var(--text-primary);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 5px 8px; font-size: 11.5px; font-family: inherit;
  }
  .token-toolbar input { flex: 1; min-width: 180px; }
  .token-health {
    font-size: 10px; font-weight: 600; border-radius: 999px;
    padding: 2px 7px; border: 1px solid var(--border); white-space: nowrap;
  }
  .token-health.valid { color: var(--status-good); border-color: color-mix(in srgb, var(--status-good) 40%, transparent); }
  .token-health.expiring { color: var(--status-medium); border-color: color-mix(in srgb, var(--status-medium) 40%, transparent); }
  .token-health.expired { color: var(--status-critical); border-color: color-mix(in srgb, var(--status-critical) 40%, transparent); }
  .token-health.none { color: var(--text-muted); }
  .principal-list { display: flex; flex-direction: column; gap: 8px; }
  .principal-card {
    background: var(--surface-1); border: 1px solid var(--border);
    border-radius: 9px; overflow: hidden;
  }
  .principal-card.active { border-color: color-mix(in srgb, var(--accent) 45%, transparent); }
  .principal-head {
    display: flex; align-items: center; gap: 10px;
    padding: 10px 13px; cursor: pointer; list-style: none;
  }
  .principal-head::-webkit-details-marker { display: none; }
  .principal-main { display: flex; flex-direction: column; min-width: 0; flex: 1; }
  .principal-title { font-size: 14px; font-weight: 600; overflow-wrap: anywhere; }
  .principal-sub { color: var(--text-muted); font-size: 12px; margin-top: 1px; overflow-wrap: anywhere; }
  .token-avatar {
    width: 28px; height: 28px; border-radius: 50%; flex: none;
    display: inline-flex; align-items: center; justify-content: center;
    background: color-mix(in srgb, var(--accent) 14%, transparent);
    color: var(--accent); font-weight: 700; font-size: 12px;
  }
  .token-type {
    font-size: 10.5px; font-weight: 600; white-space: nowrap;
    padding: 2px 8px; border-radius: 999px; border: 1px solid var(--border);
  }
  .token-type.refresh {
    color: var(--status-medium);
    border-color: color-mix(in srgb, var(--status-medium) 40%, transparent);
  }
  .token-type.access {
    color: var(--status-low);
    border-color: color-mix(in srgb, var(--status-low) 40%, transparent);
  }
  .token-type.both {
    color: var(--status-good);
    border-color: color-mix(in srgb, var(--status-good) 40%, transparent);
  }
  .token-type.foci {
    color: var(--accent);
    border-color: color-mix(in srgb, var(--accent) 45%, transparent);
    letter-spacing: 0.04em;
  }
  .principal-count { color: var(--text-muted); font-size: 11.5px; white-space: nowrap; }
  .principal-chevron { color: var(--text-muted); font-size: 15px; transition: transform 0.15s; }
  .principal-card[open] .principal-chevron { transform: rotate(90deg); }
  .principal-tokens { border-top: 1px solid var(--gridline); }
  .token-access-children {
    margin-left: 20px; border-left: 2px solid var(--gridline);
  }
  .token-access-children .token-row { padding-left: 11px; }
  .token-row {
    display: flex; align-items: flex-start; gap: 10px;
    padding: 8px 13px; border-bottom: 1px solid var(--gridline);
  }
  .token-row:last-child { border-bottom: none; }
  .token-row-main { flex: 1; min-width: 0; }
  .token-row-head {
    display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  }
  .token-row-client {
    font-size: 12.5px; color: var(--text-primary); overflow-wrap: anywhere;
  }
  .token-client-id {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  .token-row-label { color: var(--text-muted); font-size: 11px; }
  .token-row-meta {
    color: var(--text-muted); font-size: 12px; line-height: 1.35;
    margin-top: 2px; overflow-wrap: anywhere;
  }
  .token-row-actions {
    display: flex; gap: 5px; align-items: center; flex: none;
    flex-wrap: wrap; justify-content: flex-end;
  }
  .token-row-actions .mode-btn { padding: 3px 8px; font-size: 11.5px; }
  .redeem-input {
    width: 168px; flex: none;
    background: var(--surface-1); color: var(--text-secondary);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 3px 7px; font-size: 11.5px; font-family: inherit;
  }
  .redeem-input::placeholder { color: var(--text-muted); }
  .redeem-input:focus {
    outline: none; color: var(--text-primary);
    border-color: color-mix(in srgb, var(--accent) 55%, var(--border));
  }
  .redeem-menu {
    position: fixed; z-index: 1200;
    background: var(--surface-1); border: 1px solid var(--border);
    border-radius: 8px; padding: 4px;
    box-shadow: 0 14px 34px rgba(0, 0, 0, 0.42);
    max-height: min(340px, calc(100vh - 16px)); overflow-y: auto;
  }
  .redeem-menu.hidden { display: none; }
  .redeem-option {
    display: flex; flex-direction: column; gap: 1px; width: 100%;
    background: transparent; border: 0; border-radius: 6px;
    color: var(--text-primary); text-align: left; padding: 6px 8px;
    cursor: pointer; font: inherit;
  }
  .redeem-option:hover, .redeem-option.active {
    background: color-mix(in srgb, var(--accent) 13%, transparent);
  }
  .redeem-option-name { font-size: 12px; font-weight: 600; line-height: 1.3; }
  .redeem-option-meta {
    font-size: 10.5px; color: var(--text-muted); line-height: 1.35;
    overflow-wrap: anywhere;
  }
  .redeem-option.redeem-submenu {
    flex-direction: row; align-items: center; gap: 10px;
  }
  .redeem-option-text {
    display: flex; flex-direction: column; gap: 1px; min-width: 0;
  }
  .redeem-option-chevron {
    margin-left: auto; color: var(--text-muted); font-size: 15px;
  }
  .redeem-submenu-head {
    display: flex; align-items: center; gap: 6px;
    padding: 2px 4px 5px; margin-bottom: 3px;
    border-bottom: 1px solid var(--gridline);
  }
  .redeem-back {
    border: 0; border-radius: 5px; background: transparent;
    color: var(--accent); padding: 3px 6px; font: inherit;
    font-size: 11.5px; font-weight: 600; cursor: pointer;
  }
  .redeem-back:hover {
    background: color-mix(in srgb, var(--accent) 13%, transparent);
  }
  .redeem-submenu-title {
    color: var(--text-muted); font-size: 10.5px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.04em;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .redeem-note {
    padding: 6px 8px; color: var(--text-muted); font-size: 11px;
    line-height: 1.35;
  }
  .redeem-note.error { color: var(--status-critical); }
  .redeem-note.subtle {
    border-bottom: 1px solid var(--gridline); margin-bottom: 3px;
  }
  .redeem-custom-bar {
    border-bottom: 1px solid var(--gridline);
    margin: 0 0 4px; padding: 0 2px 4px;
  }
  .redeem-custom-toggle {
    width: 100%; padding: 5px 6px; border: 0; border-radius: 6px;
    background: transparent; color: var(--accent); text-align: left;
    font: inherit; font-size: 11.5px; font-weight: 600; cursor: pointer;
  }
  .redeem-custom-toggle:hover,
  .redeem-custom-toggle.active {
    background: color-mix(in srgb, var(--accent) 13%, transparent);
  }
  .redeem-custom-form {
    display: flex; gap: 5px; padding: 2px 4px 0;
  }
  .redeem-custom-form.hidden { display: none; }
  .redeem-custom-input {
    flex: 1; min-width: 0;
    background: var(--surface-1); color: var(--text-primary);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 4px 7px; font-size: 11.5px; font-family: inherit;
  }
  .redeem-custom-input:focus {
    outline: none;
    border-color: color-mix(in srgb, var(--accent) 55%, var(--border));
  }
  .redeem-custom-form .mode-btn { padding: 3px 8px; font-size: 11.5px; }
  .redeem-custom-note {
    padding: 3px 6px 0; color: var(--text-muted);
    font-size: 10.5px; line-height: 1.35;
  }
  .token-secret {
    padding: 10px 13px 12px; background: var(--page-plane);
    border-bottom: 1px solid var(--gridline);
  }
  .token-secret:last-child { border-bottom: none; }
  .token-secret-field {
    display: flex; flex-direction: column; gap: 5px;
    margin: 6px 0; color: var(--text-muted); font-size: 11px;
  }
  .token-secret-head {
    display: flex; align-items: center; justify-content: space-between;
    gap: 8px;
  }
  .token-decode-btn { padding: 2px 8px; font-size: 11px; }
  .token-secret textarea {
    width: 100%; min-height: 96px; max-height: 240px; resize: vertical;
    background: var(--surface-1); color: var(--text-primary);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 8px 10px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12px; line-height: 1.4; overflow-wrap: anywhere;
  }
  .token-decode-overlay {
    position: fixed; inset: 0; z-index: 1300;
    background: rgba(0, 0, 0, 0.45);
    display: flex; align-items: center; justify-content: center;
    padding: 24px;
  }
  .token-decode-overlay.hidden { display: none; }
  .token-decode-box {
    display: flex; flex-direction: column;
    width: min(900px, 94vw); max-height: min(82vh, 760px);
    background: var(--surface-1); color: var(--text-primary);
    border: 1px solid var(--border); border-radius: 12px;
    box-shadow: 0 24px 70px rgba(0, 0, 0, 0.38);
    overflow: hidden;
  }
  .token-decode-head {
    display: flex; align-items: flex-start; justify-content: space-between;
    gap: 12px; padding: 14px 16px;
    border-bottom: 1px solid var(--gridline);
  }
  .token-decode-head h3 { margin: 0; font-size: 15px; }
  .token-decode-sub {
    color: var(--text-muted); font-size: 11px; margin-top: 2px;
    overflow-wrap: anywhere;
  }
  .token-decode-close {
    background: none; border: 1px solid var(--border);
    color: var(--text-secondary); font-size: 16px; line-height: 1;
    cursor: pointer; padding: 5px 10px; border-radius: 6px; flex: none;
  }
  .token-decode-close:hover {
    background: var(--row-hover); color: var(--text-primary);
  }
  .token-decode-body {
    display: flex; flex-direction: column; gap: 14px;
    padding: 14px 16px 18px; overflow: auto;
  }
  .token-decode-section h4 {
    margin: 0 0 6px; color: var(--text-muted); font-size: 10.5px;
    font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;
  }
  .token-decode-json {
    margin: 0; padding: 10px 12px; border-radius: 8px;
    background: var(--page-plane); border: 1px solid var(--border);
    color: var(--text-primary);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12px; line-height: 1.45; white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .token-decode-error {
    padding: 10px 12px; border-radius: 8px;
    background: color-mix(in srgb, var(--status-critical) 10%, transparent);
    border: 1px solid color-mix(in srgb, var(--status-critical) 28%, transparent);
    color: var(--status-critical); font-size: 12px; line-height: 1.4;
  }
  .token-empty { padding: 24px; text-align: center; color: var(--text-muted); }
  @media (max-width: 700px) {
    .collect-grid { grid-template-columns: 1fr; }
  }
"""


def view_html() -> str:
    """Markup and JS for the sidebar's Collect view."""
    default_out = html.escape(str(DEFAULT_OUTPUT))
    default_aad_out = html.escape(str(DEFAULT_AADGRAPH_OUTPUT))
    return r"""<section class="collect-panel">
  <h1>Collect</h1>
  <p class="sub">Run the Graph or AAD Graph collector to write a
    ROADrecon-compatible database. Authentication is configured in the Tokens tab.</p>
  <div class="drawer-tabs collect-tabs" id="collect-tabs">
    <button type="button" class="drawer-tab active" data-collect-view="graph">Graph</button>
    <button type="button" class="drawer-tab" data-collect-view="aadgraph">AAD Graph</button>
  </div>
  <div id="collect-pane-graph">
    <div class="collect-card">
      <label class="collect-field">
        <span>Output database</span>
        <input id="collect-out" type="text" spellcheck="false" value="__DEFAULT_OUT__">
      </label>
      <label class="collect-field">
        <span>User-Agent (optional)</span>
        <input id="collect-ua" type="text" autocomplete="off" spellcheck="false">
      </label>
      <label class="collect-check">
        <input type="checkbox" id="collect-evade">
        <span>Evade Graph detections (batch relationship requests)</span>
      </label>
      <div class="collect-check-note">
        Batches up to 20 relationship GETs per request. Top-level directory
        listings stay as normal paged requests. Uses the ADO.NET user agent
        when no User-Agent is supplied.
      </div>
      <div class="collect-actions">
        <button type="button" class="mode-btn" id="collect-start">Start collection</button>
        <button type="button" class="mode-btn" id="collect-go-analysis">Go to analysis</button>
        <span class="muted" id="collect-note"></span>
      </div>
    </div>
  </div>
  <div id="collect-pane-aadgraph" class="hidden">
    <div class="collect-card">
      <label class="collect-field">
        <span>Output database</span>
        <input id="collect-aad-out" type="text" spellcheck="false" value="__DEFAULT_AADGRAPH_OUT__">
      </label>
      <label class="collect-field">
        <span>User-Agent (optional)</span>
        <input id="collect-aad-ua" type="text" autocomplete="off" spellcheck="false">
      </label>
      <div class="collect-check-note">
        AAD Graph collection recreates the output database from a fresh snapshot.
      </div>
      <label class="collect-check">
        <input type="checkbox" id="collect-aad-autotoken" checked>
        <span>Request an AAD Graph token from the refresh token automatically</span>
      </label>
      <label class="collect-check">
        <input type="checkbox" id="collect-aad-evade">
        <span>Evade AAD Graph enumeration detections (batch requests)</span>
      </label>
      <label class="collect-check">
        <input type="checkbox" id="collect-aad-gatherall">
        <span>Gather all (also collect IG, PIM, and Azure data)</span>
      </label>
      <div class="collect-check-note">
        Gather all needs a refresh token so Microsoft Graph and ARM tokens can
        be requested.
      </div>
      <label class="collect-check">
        <input type="checkbox" id="collect-aad-mfa">
        <span>Dump MFA details (requires a privileged account)</span>
      </label>
      <div class="collect-actions">
        <button type="button" class="mode-btn" id="collect-aad-start">Start collection</button>
        <button type="button" class="mode-btn" id="collect-aad-go-analysis">Go to analysis</button>
        <span class="muted" id="collect-aad-note"></span>
      </div>
    </div>
  </div>
  <div class="collect-status hidden" id="collect-status">
    <div class="collect-status-head">
      <b id="collect-state">Idle</b>
      <span class="muted" id="collect-kind"></span>
      <span class="mono" id="collect-output"></span>
    </div>
    <pre class="collect-log" id="collect-log"></pre>
  </div>
</section>
<script>
(function() {
  var outEl = document.getElementById('collect-out');
  var uaEl = document.getElementById('collect-ua');
  var graphEvadeEl = document.getElementById('collect-evade');
  var startBtn = document.getElementById('collect-start');
  var noteEl = document.getElementById('collect-note');
  var aadOutEl = document.getElementById('collect-aad-out');
  var aadUaEl = document.getElementById('collect-aad-ua');
  var aadStartBtn = document.getElementById('collect-aad-start');
  var aadNoteEl = document.getElementById('collect-aad-note');
  var aadAutoEl = document.getElementById('collect-aad-autotoken');
  var aadEvadeEl = document.getElementById('collect-aad-evade');
  var aadGatherEl = document.getElementById('collect-aad-gatherall');
  var aadMfaEl = document.getElementById('collect-aad-mfa');
  var statusEl = document.getElementById('collect-status');
  var stateEl = document.getElementById('collect-state');
  var kindEl = document.getElementById('collect-kind');
  var outputEl = document.getElementById('collect-output');
  var logEl = document.getElementById('collect-log');
  var goAnalysisBtn = document.getElementById('collect-go-analysis');
  var aadGoAnalysisBtn = document.getElementById('collect-aad-go-analysis');
  var collectTabs = Array.prototype.slice.call(
    document.querySelectorAll('#collect-tabs button[data-collect-view]'));
  var collectPanes = {
    graph: document.getElementById('collect-pane-graph'),
    aadgraph: document.getElementById('collect-pane-aadgraph')
  };
  if (!startBtn || !aadStartBtn) return;

  function showCollectPane(name) {
    Object.keys(collectPanes).forEach(function(key) {
      collectPanes[key].classList.toggle('hidden', key !== name);
    });
    collectTabs.forEach(function(tab) {
      tab.classList.toggle('active', tab.getAttribute('data-collect-view') === name);
    });
  }

  collectTabs.forEach(function(tab) {
    tab.addEventListener('click', function() {
      showCollectPane(tab.getAttribute('data-collect-view'));
    });
  });
  var timer = null;
  var graphConfigured = false;
  var aadConfigured = false;
  var aadMode = '';
  var lastStatus = 'idle';

  function setGraphNote(text) { noteEl.textContent = text || ''; }
  function setAadNote(text) { aadNoteEl.textContent = text || ''; }

  function idleNote() {
    if (!graphConfigured) setGraphNote('Add and select a refresh token or Microsoft Graph access token in Tokens first.');
    else setGraphNote('');
  }

  function aadIdleNote() {
    if (!aadConfigured) {
      setAadNote('Add and select a refresh token or AAD Graph access token in Tokens first.');
    } else if (aadMode !== 'refresh') {
      setAadNote('Using an AAD Graph access token; autotoken and Gather all are unavailable.');
    } else {
      setAadNote('');
    }
  }

  function goToAnalysis() {
    var navBtn = document.querySelector('#sidebar-nav button[data-view="analysis"]');
    if (navBtn) navBtn.click();
    var wrap = document.getElementById('analysis-start-wrap');
    if (wrap && wrap.classList.contains('hidden')) {
      var toggle = document.getElementById('reanalyze-btn');
      if (toggle) toggle.click();
    }
    var select = document.getElementById('analysis-db-select');
    if (select) select.focus();
  }

  function kindLabel(kind) {
    return kind === 'aadgraph' ? 'AAD Graph' : (kind ? 'Microsoft Graph' : '');
  }

  function setKindNote(kind, text) {
    if (kind === 'aadgraph') setAadNote(text);
    else setGraphNote(text);
  }

  function render(data) {
    var running = data.status === 'running';
    var kind = data.kind || 'graph';
    lastStatus = data.status;
    startBtn.disabled = running;
    aadStartBtn.disabled = running;
    statusEl.classList.toggle('hidden', data.status === 'idle' && !(data.log || []).length);
    stateEl.textContent = {
      idle: 'Idle', running: 'Collecting...', done: 'Collection complete',
      error: 'Collection failed'
    }[data.status] || data.status;
    kindEl.textContent = data.status === 'idle' ? '' : kindLabel(kind);
    outputEl.textContent = data.output ? data.output : '';
    logEl.textContent = (data.log || []).join('\n');
    logEl.scrollTop = logEl.scrollHeight;
    if (data.status === 'done') {
      setKindNote(kind, 'Done. Use Go to analysis to load it.');
      if (kind === 'aadgraph') idleNote(); else aadIdleNote();
    } else if (data.status === 'error') {
      setKindNote(kind, data.error || 'Collection failed.');
      if (kind === 'aadgraph') idleNote(); else aadIdleNote();
    } else if (running) {
      setKindNote(kind, 'Collector is running...');
      setKindNote(kind === 'aadgraph' ? 'graph' : 'aadgraph',
                  'A different collection is running.');
    } else {
      idleNote();
      aadIdleNote();
    }
    return running;
  }

  function refreshAuth() {
    return fetch('/api/tokens')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        graphConfigured = !!data.configured;
        aadConfigured = !!data.aadgraph_configured;
        aadMode = data.aadgraph_mode || '';
        if (aadAutoEl) {
          var wasDisabled = aadAutoEl.disabled;
          aadAutoEl.disabled = aadMode !== 'refresh';
          if (aadMode !== 'refresh') aadAutoEl.checked = false;
          else if (wasDisabled) aadAutoEl.checked = true;
        }
        if (aadGatherEl) {
          aadGatherEl.disabled = aadMode !== 'refresh';
          if (aadMode !== 'refresh') aadGatherEl.checked = false;
        }
        if (lastStatus === 'idle') {
          idleNote();
          aadIdleNote();
        }
      })
      .catch(function() {});
  }

  function poll() {
    clearTimeout(timer);
    fetch('/api/collect/status')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (render(data)) timer = setTimeout(poll, 1000);
      })
      .catch(function() {
        timer = setTimeout(poll, 3000);
      });
  }

  function submitFormFallback(payload, btn, noteFn) {
    var frame = document.getElementById('collect-post-frame');
    if (!frame) {
      frame = document.createElement('iframe');
      frame.id = 'collect-post-frame';
      frame.name = 'collect-post-frame';
      frame.style.display = 'none';
      document.body.appendChild(frame);
    }
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = '/api/collect';
    form.target = 'collect-post-frame';
    form.style.display = 'none';
    Object.keys(payload).forEach(function(key) {
      var input = document.createElement('input');
      input.type = 'hidden';
      input.name = key;
      input.value = typeof payload[key] === 'boolean'
        ? (payload[key] ? '1' : '0') : payload[key];
      form.appendChild(input);
    });
    document.body.appendChild(form);
    form.submit();
    setTimeout(function() { form.remove(); }, 1500);
    setTimeout(function() {
      fetch('/api/collect/status')
        .then(function(r) { return r.json(); })
        .then(function(data) {
          if (data.status === 'running') {
            render(data);
            poll();
          } else if (data.status === 'done' || data.status === 'error') {
            render(data);
          } else {
            btn.disabled = false;
            noteFn('Could not start collection. Check that entra-surface is still running.');
          }
        })
        .catch(function() {
          btn.disabled = false;
          noteFn('Could not reach the local server. Check that entra-surface is still running.');
        });
    }, 800);
  }

  function startBackend(payload, btn, noteFn) {
    btn.disabled = true;
    noteFn('Starting collector...');
    fetch('/api/collect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).then(function(r) {
      return r.json().then(function(data) {
        if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
        return data;
      });
    }).then(function(data) {
      render(data);
      poll();
    }).catch(function(err) {
      if (err && err.name !== 'TypeError') {
        btn.disabled = false;
        noteFn(err.message || 'Could not start collection.');
        return;
      }
      // Some browsers/extensions block fetch to localhost; a normal form POST
      // still works and the status endpoint shows whether the job started.
      noteFn('Retrying collection start...');
      submitFormFallback(payload, btn, noteFn);
    });
  }

  if (goAnalysisBtn) goAnalysisBtn.addEventListener('click', goToAnalysis);
  if (aadGoAnalysisBtn) aadGoAnalysisBtn.addEventListener('click', goToAnalysis);

  startBtn.addEventListener('click', function() {
    if (!graphConfigured) {
      setGraphNote('Add and select a refresh token or Microsoft Graph access token in Tokens first.');
      return;
    }
    startBackend({
      backend: 'graph',
      out: outEl.value.trim(),
      user_agent: uaEl.value.trim(),
      evade: !!(graphEvadeEl && graphEvadeEl.checked)
    }, startBtn, setGraphNote);
  });

  aadStartBtn.addEventListener('click', function() {
    if (!aadConfigured) {
      setAadNote('Add and select a refresh token or AAD Graph access token in Tokens first.');
      return;
    }
    var payload = {
      backend: 'aadgraph',
      out: aadOutEl.value.trim(),
      user_agent: aadUaEl.value.trim(),
      autotoken: !!(aadAutoEl && aadAutoEl.checked),
      evade: !!(aadEvadeEl && aadEvadeEl.checked),
      gather_all: !!(aadGatherEl && aadGatherEl.checked),
      mfa: !!(aadMfaEl && aadMfaEl.checked)
    };
    startBackend(payload, aadStartBtn, setAadNote);
  });

  document.addEventListener('app:view', function(e) {
    if (e.detail === 'collect') {
      refreshAuth();
      poll();
    }
  });

  refreshAuth();
  poll();
})();
</script>
""".replace("__DEFAULT_OUT__", default_out).replace(
    "__DEFAULT_AADGRAPH_OUT__", default_aad_out)


def tokens_view_html() -> str:
    """Markup and JS for the Tokens view (add + collected token tabs)."""
    return r"""<section class="collect-panel tokens-panel">
  <h1>Tokens</h1>
  <p class="sub">Refresh and access tokens for the collector. They are stored in
    <span class="mono">__AUTH_FILE__</span> and never sent back to the browser
    until explicitly revealed.</p>
  <div class="drawer-tabs token-tabs" id="token-tabs">
    <button type="button" class="drawer-tab active" data-token-view="add">Add token</button>
    <button type="button" class="drawer-tab" data-token-view="collected">Collected tokens <span class="tab-count" id="token-count">0</span></button>
  </div>
  <div class="tokens-flash hidden" id="tokens-flash"></div>
  <div id="token-pane-add">
    <div class="collect-card">
      <label class="collect-field">
        <span>Token type</span>
        <select id="tokens-type">
          <option value="refresh">Refresh token</option>
          <option value="access">Access token</option>
        </select>
      </label>
      <div id="tokens-refresh-fields">
        <label class="collect-field">
          <span>Refresh token</span>
          <input id="tokens-token" type="password" autocomplete="off" spellcheck="false">
        </label>
        <label class="collect-field">
          <span>Client ID</span>
          <div class="client-search" id="tokens-client-search">
            <input id="tokens-client" type="text"
                   placeholder="Search client name or enter a client ID"
                   autocomplete="off" spellcheck="false"
                   role="combobox" aria-haspopup="listbox"
                   aria-autocomplete="list" aria-expanded="false"
                   aria-controls="tokens-client-menu">
            <div class="client-menu hidden" id="tokens-client-menu"
                 role="listbox" aria-label="Client applications"></div>
          </div>
          <div class="client-hint" id="tokens-client-hint"></div>
        </label>
      </div>
      <label class="collect-field hidden" id="tokens-access-field">
        <span>Access token</span>
        <textarea id="tokens-access" rows="2" spellcheck="false"></textarea>
      </label>
      <div class="collect-actions">
        <button type="button" class="mode-btn" id="tokens-save">Redeem &amp; save</button>
        <span class="muted" id="tokens-note"></span>
      </div>
    </div>
  </div>
  <div id="token-pane-collected" class="hidden">
    <div class="token-toolbar">
      <input id="token-filter-text" type="search"
             placeholder="Filter principal, client, audience..." autocomplete="off">
      <select id="token-filter-type">
        <option value="">All types</option>
        <option value="refresh">Refresh Token</option>
        <option value="access">Access Token</option>
        <option value="both">Refresh + Access Token</option>
      </select>
      <select id="token-filter-status">
        <option value="">All access states</option>
        <option value="valid">Valid</option>
        <option value="expiring">Expiring soon</option>
        <option value="expired">Expired</option>
        <option value="none">No access token</option>
      </select>
      <select id="token-filter-audience">
        <option value="">All audiences</option>
      </select>
    </div>
    <div class="principal-list" id="token-list"></div>
  </div>
  <div class="token-decode-overlay hidden" id="token-decode-overlay"
       role="dialog" aria-modal="true" aria-labelledby="token-decode-title">
    <div class="token-decode-box">
      <div class="token-decode-head">
        <div>
          <h3 id="token-decode-title">Decoded token</h3>
          <div class="token-decode-sub" id="token-decode-sub"></div>
        </div>
        <button type="button" class="token-decode-close" id="token-decode-close"
                aria-label="Close decoded token">&times;</button>
      </div>
      <div class="token-decode-body" id="token-decode-body"></div>
    </div>
  </div>
</section>
<script>
(function() {
  var tabs = Array.prototype.slice.call(
    document.querySelectorAll('#token-tabs button[data-token-view]'));
  var panes = {
    add: document.getElementById('token-pane-add'),
    collected: document.getElementById('token-pane-collected')
  };
  var typeEl = document.getElementById('tokens-type');
  var tokenEl = document.getElementById('tokens-token');
  var clientEl = document.getElementById('tokens-client');
  var clientSearch = document.getElementById('tokens-client-search');
  var clientMenu = document.getElementById('tokens-client-menu');
  var clientHint = document.getElementById('tokens-client-hint');
  var refreshFields = document.getElementById('tokens-refresh-fields');
  var accessField = document.getElementById('tokens-access-field');
  var accessEl = document.getElementById('tokens-access');
  var saveBtn = document.getElementById('tokens-save');
  var noteEl = document.getElementById('tokens-note');
  var flashEl = document.getElementById('tokens-flash');
  var listEl = document.getElementById('token-list');
  var countEl = document.getElementById('token-count');
  var filterText = document.getElementById('token-filter-text');
  var filterType = document.getElementById('token-filter-type');
  var filterStatus = document.getElementById('token-filter-status');
  var filterAudience = document.getElementById('token-filter-audience');
  var decodeOverlay = document.getElementById('token-decode-overlay');
  var decodeTitle = document.getElementById('token-decode-title');
  var decodeSub = document.getElementById('token-decode-sub');
  var decodeBody = document.getElementById('token-decode-body');
  var decodeClose = document.getElementById('token-decode-close');
  if (!saveBtn || !listEl) return;
  var lastTokenData = {tokens: []};
  var clientApps = null;
  var clientPromise = null;
  var clientError = '';
  var clientState = null;
  var resourceCache = {};
  var resourcePromises = {};
  var redeemMenu = document.createElement('div');
  redeemMenu.id = 'redeem-menu';
  redeemMenu.className = 'redeem-menu hidden';
  redeemMenu.setAttribute('role', 'listbox');
  redeemMenu.setAttribute('aria-label', 'Redeem options');
  document.body.appendChild(redeemMenu);
  var redeemState = null;
  var lastDecodeButton = null;

  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function setNote(text) { noteEl.textContent = text || ''; }

  function flash(text, failed) {
    flashEl.textContent = text || '';
    flashEl.classList.toggle('hidden', !text);
    flashEl.classList.toggle('error', !!failed);
  }

  function base64UrlDecode(value) {
    var input = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
    while (input.length % 4) input += '=';
    var binary = atob(input);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder('utf-8').decode(bytes);
  }

  function decodeJwt(token) {
    var parts = String(token || '').trim().split('.');
    if (parts.length !== 3) {
      throw new Error('Not a JWT; this token has no decodable header and payload.');
    }
    var header;
    var payload;
    try {
      header = JSON.parse(base64UrlDecode(parts[0]));
    } catch (err) {
      throw new Error('Could not decode the JWT header.');
    }
    try {
      payload = JSON.parse(base64UrlDecode(parts[1]));
    } catch (err) {
      throw new Error('Could not decode the JWT payload.');
    }
    return {header: header, payload: payload};
  }

  function closeDecode() {
    if (!decodeOverlay) return;
    decodeOverlay.classList.add('hidden');
    if (lastDecodeButton && document.contains(lastDecodeButton)) {
      lastDecodeButton.focus();
    }
    lastDecodeButton = null;
  }

  function openDecode(kind, token, button) {
    if (!decodeOverlay || !decodeBody) return;
    lastDecodeButton = button || null;
    var label = kind === 'refresh' ? 'Refresh token' : 'Access token';
    decodeTitle.textContent = 'Decoded ' + label.toLowerCase();
    decodeSub.textContent = label;
    var body;
    if (!token) {
      body = '<div class="token-decode-error">No token captured for this entry.</div>';
    } else {
      try {
        var decoded = decodeJwt(token);
        var details = [];
        var alg = decoded.header && decoded.header.alg;
        if (alg) details.push('alg ' + alg);
        var aud = decoded.payload && decoded.payload.aud;
        if (Array.isArray(aud)) aud = aud.join(', ');
        if (aud) details.push('aud ' + aud);
        var exp = decoded.payload && decoded.payload.exp;
        if (exp) {
          var expires = new Date(Number(exp) * 1000);
          if (!isNaN(expires.getTime())) {
            details.push('expires ' + expires.toISOString());
          }
        }
        decodeSub.textContent = label
          + (details.length ? ' · ' + details.join(' · ') : '');
        body = '<div class="token-decode-section"><h4>Header</h4>'
          + '<pre class="token-decode-json">'
          + esc(JSON.stringify(decoded.header, null, 2))
          + '</pre></div>'
          + '<div class="token-decode-section"><h4>Payload</h4>'
          + '<pre class="token-decode-json">'
          + esc(JSON.stringify(decoded.payload, null, 2))
          + '</pre></div>';
      } catch (err) {
        decodeSub.textContent = label + ' · not decodable';
        body = '<div class="token-decode-error">'
          + esc(err.message || 'Could not decode this token.') + '</div>';
      }
    }
    decodeBody.innerHTML = body;
    decodeOverlay.classList.remove('hidden');
    if (decodeClose) decodeClose.focus();
  }

  function formatDuration(ms) {
    var seconds = Math.max(0, Math.floor(ms / 1000));
    if (seconds < 60) return seconds + 's';
    var minutes = Math.floor(seconds / 60);
    if (minutes < 60) return minutes + 'm';
    var hours = Math.floor(minutes / 60);
    if (hours < 48) return hours + 'h';
    return Math.floor(hours / 24) + 'd';
  }

  function healthFromExpiry(iso) {
    if (!iso) return {key: 'none', label: 'No expiry'};
    var expires = new Date(iso).getTime();
    if (isNaN(expires)) return {key: 'none', label: 'No expiry'};
    var remaining = expires - Date.now();
    if (remaining <= 0) return {key: 'expired', label: 'Expired'};
    if (remaining <= 5 * 60 * 1000) {
      return {key: 'expiring', label: 'Expires in ' + formatDuration(remaining)};
    }
    return {key: 'valid', label: 'Expires in ' + formatDuration(remaining)};
  }

  function tokenHealth(t) {
    if (!t.has_access_token) return {key: 'none', label: 'No access token'};
    return healthFromExpiry((t.principal || {}).access_expires_at || '');
  }

  function tokenType(t) {
    if (t.has_refresh_token && t.has_access_token) return 'both';
    return t.has_refresh_token ? 'refresh' : 'access';
  }

  function tokenMatches(t) {
    var p = t.principal || {};
    var type = filterType.value;
    if (type && tokenType(t) !== type) return false;
    var status = filterStatus.value;
    if (status && tokenHealth(t).key !== status) return false;
    var audience = filterAudience.value;
    if (audience === '__none__') {
      if (p.audience) return false;
    } else if (audience && p.audience !== audience) {
      return false;
    }
    var query = (filterText.value || '').trim().toLowerCase();
    if (!query) return true;
    var text = [p.name, p.upn, p.identity, t.client_id, t.client_name,
                p.audience, t.audience_name,
                (t.client_foci && t.has_refresh_token) ? 'foci' : '',
                tokenHealth(t).label].join(' ').toLowerCase();
    return text.indexOf(query) >= 0;
  }

  function updateHealthLabels() {
    Array.prototype.forEach.call(
      listEl.querySelectorAll('.token-health'), function(el) {
        var health = healthFromExpiry(el.getAttribute('data-expires') || '');
        el.className = 'token-health ' + health.key;
        el.textContent = health.label;
      });
  }

  function updateAudienceOptions(data) {
    if (!filterAudience) return;
    var current = filterAudience.value;
    var all = data.tokens || [];
    var audiences = [];
    var labels = {};
    var hasNone = false;
    all.forEach(function(t) {
      var aud = (t.principal || {}).audience || '';
      if (!aud) {
        hasNone = true;
        return;
      }
      if (audiences.indexOf(aud) < 0) {
        audiences.push(aud);
        labels[aud] = t.audience_name || aud;
      } else if (t.audience_name && (!labels[aud] || labels[aud] === aud)) {
        labels[aud] = t.audience_name;
      }
    });
    audiences.sort(function(a, b) {
      var al = String(labels[a] || a).toLowerCase();
      var bl = String(labels[b] || b).toLowerCase();
      return al < bl ? -1 : (al > bl ? 1 : 0);
    });
    var html = '<option value="">All audiences</option>';
    audiences.forEach(function(aud) {
      html += '<option value="' + esc(aud) + '">'
        + esc(labels[aud] || aud) + '</option>';
    });
    if (hasNone) html += '<option value="__none__">No audience</option>';
    filterAudience.innerHTML = html;
    var keep = false;
    Array.prototype.forEach.call(filterAudience.options, function(option) {
      if (option.value === current) keep = true;
    });
    filterAudience.value = keep ? current : '';
  }

  function showPane(name) {
    Object.keys(panes).forEach(function(key) {
      panes[key].classList.toggle('hidden', key !== name);
    });
    tabs.forEach(function(tab) {
      tab.classList.toggle('active', tab.getAttribute('data-token-view') === name);
    });
  }

  function updateType() {
    var access = typeEl.value === 'access';
    refreshFields.classList.toggle('hidden', access);
    accessField.classList.toggle('hidden', !access);
    saveBtn.textContent = 'Save';
    setNote('');
    if (access) closeClientMenu();
    else updateClientHint();
  }

  typeEl.addEventListener('change', updateType);
  updateType();

  function looksLikeClientId(value) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
      .test(String(value || '').trim());
  }

  function clientById(value) {
    if (!clientApps) return null;
    var key = String(value || '').trim().toLowerCase();
    for (var i = 0; i < clientApps.length; i++) {
      if (clientApps[i].id === key) return clientApps[i];
    }
    return null;
  }

  function updateClientHint() {
    if (!clientHint || !clientEl) return;
    var value = (clientEl.value || '').trim();
    if (!value) {
      clientHint.textContent = '';
      return;
    }
    var app = clientById(value);
    if (app) {
      clientHint.innerHTML = '<b>' + esc(app.name) + '</b>'
        + (app.foci ? ' <span class="token-type foci">FOCI</span>' : '');
      return;
    }
    if (looksLikeClientId(value)) {
      clientHint.innerHTML = '<b>Custom client ID</b> '
        + '<span class="mono">' + esc(value) + '</span>';
      return;
    }
    clientHint.textContent = 'Select a client application or enter a client ID.';
  }

  function loadClientApps() {
    if (clientApps !== null) return Promise.resolve(clientApps);
    if (clientPromise) return clientPromise;
    clientPromise = fetch('/api/tokens/clients')
      .then(function(r) {
        return r.json().then(function(data) {
          if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
          return data;
        });
      })
      .then(function(data) {
        clientApps = data.clients || [];
        clientError = data.error || '';
        clientPromise = null;
        return clientApps;
      })
      .catch(function(err) {
        clientApps = [];
        clientError = err.message || 'Could not load client applications.';
        clientPromise = null;
        return clientApps;
      });
    return clientPromise;
  }

  function clientScore(app, query) {
    var q = query.toLowerCase();
    var name = String(app.name || '').toLowerCase();
    var id = String(app.id || '').toLowerCase();
    var hay = [name, id, app.foci ? 'foci' : ''].join(' ');
    var terms = q.split(/\s+/).filter(Boolean);
    for (var i = 0; i < terms.length; i++) {
      if (hay.indexOf(terms[i]) < 0) return -1;
    }
    if (name === q || id === q) return 0;
    if (name.indexOf(q) === 0 || id.indexOf(q) === 0) return 1;
    if (name.indexOf(q) >= 0) return 2;
    return 3;
  }

  function clientSearchMatches() {
    if (!clientState) return [];
    var query = (clientEl.value || '').trim();
    var matches = [];
    (clientApps || []).forEach(function(app) {
      var score = query ? clientScore(app, query) : 0;
      if (query && score < 0) return;
      matches.push({app: app, score: score});
    });
    matches.sort(function(a, b) {
      if (!query) {
        var ar = a.app.rank == null ? 10 : a.app.rank;
        var br = b.app.rank == null ? 10 : b.app.rank;
        if (ar !== br) return ar - br;
      } else {
        var ap = (a.app.rank == null ? 10 : a.app.rank) < 10 ? 1 : 0;
        var bp = (b.app.rank == null ? 10 : b.app.rank) < 10 ? 1 : 0;
        if (ap !== bp) return bp - ap;
        if (a.score !== b.score) return a.score - b.score;
        var aq = a.app.rank == null ? 10 : a.app.rank;
        var bq = b.app.rank == null ? 10 : b.app.rank;
        if (aq !== bq) return aq - bq;
      }
      var an = String(a.app.name || '').toLowerCase();
      var bn = String(b.app.name || '').toLowerCase();
      if (an !== bn) return an < bn ? -1 : 1;
      return a.app.id < b.app.id ? -1 : (a.app.id > b.app.id ? 1 : 0);
    });
    return matches.map(function(entry) { return entry.app; });
  }

  function renderClientMenu() {
    if (!clientState || !clientMenu || !clientEl) return;
    var state = clientState;
    if (state.loading) {
      clientMenu.innerHTML = '<div class="client-note">Loading client applications...</div>';
      clientMenu.classList.remove('hidden');
      clientEl.setAttribute('aria-expanded', 'true');
      return;
    }
    var html = '';
    if (clientError) {
      html += '<div class="client-note error">' + esc(clientError) + '</div>';
    }
    var query = (clientEl.value || '').trim();
    var matches = clientSearchMatches();
    var limit = 80;
    var visible = matches.slice(0, limit);
    state.matches = visible;
    var exact = clientById(query);
    var customAvailable = looksLikeClientId(query) && !exact;
    if (!matches.length && !customAvailable && !clientError) {
      html += '<div class="client-note">'
        + (query
          ? 'No matching client applications.'
          : 'No client applications are available.')
        + '</div>';
    } else if (matches.length) {
      if (matches.length > limit) {
        html += '<div class="client-note">Showing ' + limit + ' of '
          + matches.length + ' clients. Keep typing to narrow the list.</div>';
      }
      visible.forEach(function(app, idx) {
        html += '<button type="button" class="client-option"'
          + ' id="client-option-' + idx + '"'
          + ' data-client-index="' + idx + '" role="option">'
          + '<span class="client-option-name">' + esc(app.name || app.id)
          + (app.foci ? ' <span class="token-type foci">FOCI</span>' : '')
          + '</span>'
          + '<span class="client-option-meta">' + esc(app.id) + '</span>'
          + '</button>';
      });
    }
    state.custom = '';
    if (customAvailable) {
      state.custom = query;
      html += '<button type="button" class="client-option"'
        + ' id="client-option-custom" data-client-custom="1" role="option">'
        + '<span class="client-option-name">Use custom client ID</span>'
        + '<span class="client-option-meta">' + esc(query) + '</span>'
        + '</button>';
    }
    clientMenu.innerHTML = html;
    state.active = -1;
    clientEl.removeAttribute('aria-activedescendant');
    clientMenu.classList.remove('hidden');
    clientEl.setAttribute('aria-expanded', 'true');
  }

  function openClientMenu() {
    if (!clientMenu || !clientEl) return;
    if (clientState) return;
    clientState = {loading: true, matches: [], active: -1, custom: ''};
    clientEl.setAttribute('aria-expanded', 'true');
    clientMenu.classList.remove('hidden');
    clientMenu.innerHTML = '<div class="client-note">Loading client applications...</div>';
    updateClientHint();
    if (clientApps !== null) {
      clientState.loading = false;
      renderClientMenu();
      return;
    }
    loadClientApps().then(function() {
      if (!clientState) return;
      clientState.loading = false;
      renderClientMenu();
      updateClientHint();
    });
  }

  function closeClientMenu() {
    if (!clientMenu || !clientEl) return;
    clientState = null;
    clientMenu.classList.add('hidden');
    clientMenu.innerHTML = '';
    clientEl.setAttribute('aria-expanded', 'false');
    clientEl.removeAttribute('aria-activedescendant');
  }

  function selectClientApp(app) {
    if (!app || !clientEl) return;
    clientEl.value = app.id;
    closeClientMenu();
    updateClientHint();
  }

  function setClientActive(index) {
    if (!clientState || !clientMenu) return;
    var options = clientMenu.querySelectorAll('.client-option');
    if (!options.length) {
      clientState.active = -1;
      clientEl.removeAttribute('aria-activedescendant');
      return;
    }
    if (index < 0) index = options.length - 1;
    if (index >= options.length) index = 0;
    clientState.active = index;
    Array.prototype.forEach.call(options, function(el, i) {
      el.classList.toggle('active', i === index);
      if (i === index) {
        el.setAttribute('aria-selected', 'true');
        clientEl.setAttribute('aria-activedescendant', el.id);
        if (el.scrollIntoView) el.scrollIntoView({block: 'nearest'});
      } else {
        el.removeAttribute('aria-selected');
      }
    });
  }

  function chooseClient(index) {
    if (!clientState) return;
    if (index >= clientState.matches.length) {
      if (!clientState.custom) return;
      clientEl.value = clientState.custom;
      closeClientMenu();
      updateClientHint();
      return;
    }
    selectClientApp(clientState.matches[index]);
  }

  if (clientEl) {
    clientEl.addEventListener('focus', openClientMenu);
    clientEl.addEventListener('click', openClientMenu);
    clientEl.addEventListener('input', function() {
      if (!clientState) openClientMenu();
      else renderClientMenu();
      updateClientHint();
    });
    clientEl.addEventListener('keydown', function(event) {
      if (!clientState) return;
      var count = clientMenu.querySelectorAll('.client-option').length;
      if (event.key === 'ArrowDown') {
        event.preventDefault();
        setClientActive(clientState.active + 1);
      } else if (event.key === 'ArrowUp') {
        event.preventDefault();
        setClientActive(clientState.active - 1);
      } else if (event.key === 'Enter') {
        if (count) {
          event.preventDefault();
          chooseClient(clientState.active >= 0 ? clientState.active : 0);
        }
      } else if (event.key === 'Escape') {
        event.preventDefault();
        closeClientMenu();
      } else if (event.key === 'Tab') {
        closeClientMenu();
      }
    });
  }

  if (clientMenu) {
    clientMenu.addEventListener('mousedown', function(event) {
      if (event.target.closest('.client-option')) event.preventDefault();
    });
    clientMenu.addEventListener('click', function(event) {
      var option = event.target.closest('.client-option');
      if (!option || !clientState) return;
      event.stopPropagation();
      if (option.hasAttribute('data-client-custom')) {
        chooseClient(clientState.matches.length);
        return;
      }
      var index = parseInt(option.getAttribute('data-client-index'), 10);
      if (!isNaN(index)) chooseClient(index);
    });
  }

  document.addEventListener('click', function(event) {
    if (!clientState) return;
    if (clientSearch && clientSearch.contains(event.target)) return;
    closeClientMenu();
  });

  function principalKey(token) {
    var p = token.principal || {};
    var identity = p.object_id || p.upn || p.identity || '';
    if (!identity && !p.tenant_id) return 'token|' + token.id;
    return [p.tenant_id || '', identity].join('|');
  }

  function tokenRow(t, nested, parentClientId) {
    var p = t.principal || {};
    var hasRefresh = !!t.has_refresh_token;
    var hasAccess = !!t.has_access_token;
    var nestedAccess = !hasRefresh && !!nested;
    var viaClient = nestedAccess && parentClientId && t.client_id
      && String(t.client_id).toLowerCase()
        !== String(parentClientId).toLowerCase();
    var typeLabel = hasRefresh && hasAccess ? 'Refresh + Access Token'
      : (hasRefresh ? 'Refresh Token' : 'Access Token');
    var typeClass = hasRefresh && hasAccess ? 'both'
      : (hasRefresh ? 'refresh' : 'access');
    var savedLine = '';
    if (t.updated_at) {
      var stamp = (t.has_refresh_token && t.has_access_token) ? 'Redeemed ' : 'Saved ';
      savedLine = stamp + t.updated_at;
    }
    var expiresLine = p.access_expires_at
      ? 'Access expires ' + p.access_expires_at : '';
    var usedLine = '';
    if (t.last_used_at) {
      usedLine = 'Last used ' + t.last_used_at
        + (t.last_used_mode ? ' · ' + t.last_used_mode : '')
        + (t.last_used_for ? ' → ' + t.last_used_for : '');
    }
    var health = tokenHealth(t);
    var healthHtml = hasAccess
      ? '<span class="token-health ' + health.key + '" data-expires="'
        + esc(p.access_expires_at || '') + '">' + esc(health.label) + '</span>'
      : '';
    var secretFields = '';
    if (t.has_access_token) {
      secretFields += '<div class="token-secret-field">'
        + '<span class="token-secret-head">Access token'
        + '<button type="button" class="mode-btn token-decode-btn"'
        + ' data-decode-secret="access">Decode</button></span>'
        + '<textarea readonly data-secret="access" aria-label="Access token" spellcheck="false" placeholder="Not captured"></textarea></div>';
    }
    if (t.has_refresh_token) {
      secretFields += '<div class="token-secret-field">'
        + '<span class="token-secret-head">Refresh token'
        + '<button type="button" class="mode-btn token-decode-btn"'
        + ' data-decode-secret="refresh">Decode</button></span>'
        + '<textarea readonly data-secret="refresh" aria-label="Refresh token" spellcheck="false" placeholder="Not captured"></textarea></div>';
    }
    var clientHtml = t.client_name
      ? '<span>' + esc(t.client_name) + '</span>'
      : '<span class="token-client-id">' + esc(t.client_id || '—') + '</span>';
    var clientTitle = t.client_name && t.client_id
      ? ' title="' + esc(t.client_id) + '"' : '';
    var audienceText = t.audience_name || p.audience || '—';
    var audienceTitle = t.audience_name && p.audience
      ? ' title="' + esc(p.audience) + '"' : '';
    var fociHtml = t.client_foci && t.has_refresh_token
      ? '<span class="token-type foci" title="Member of a Family of Client IDs (FOCI)">FOCI</span>'
      : '';
    var headHtml = nestedAccess
      ? '<span class="token-row-client"' + audienceTitle + '>'
        + '<span class="token-row-label">Audience:</span> '
        + esc(audienceText) + '</span>'
      : '<span class="token-row-client"' + clientTitle + '>'
        + '<span class="token-row-label">Client:</span> '
        + clientHtml + '</span>';
    var actions = '';
    if (t.has_refresh_token) {
      actions += '<input type="search" class="redeem-input" data-redeem-id="'
        + esc(t.id) + '" placeholder="Redeem for..." aria-label="Redeem for"'
        + ' role="combobox" aria-haspopup="listbox" aria-autocomplete="list"'
        + ' aria-expanded="false" aria-controls="redeem-menu"'
        + ' autocomplete="off" spellcheck="false">';
    }
    actions += '<button type="button" class="mode-btn" data-action="view" data-id="' + esc(t.id) + '">View tokens</button>';
    actions += t.active
      ? '<span class="tag-chip tag-privileged">Active</span>'
      : '<button type="button" class="mode-btn" data-action="use" data-id="' + esc(t.id) + '">Use</button>';
    actions += '<button type="button" class="mode-btn" data-action="delete" data-id="' + esc(t.id) + '">Delete</button>';
    return '<div class="token-row">'
      + '<div class="token-row-main">'
      + '<div class="token-row-head">'
      + headHtml
      + '<span class="token-type ' + typeClass + '">' + typeLabel + '</span>'
      + fociHtml
      + healthHtml + '</div>'
      + (nestedAccess ? ''
        : '<div class="token-row-meta"' + audienceTitle + '>'
          + '<span class="token-row-label">Audience:</span> '
          + esc(audienceText) + '</div>')
      + (viaClient ? '<div class="token-row-meta">'
        + '<span class="token-row-label">Client:</span> '
        + clientHtml + '</div>' : '')
      + (savedLine ? '<div class="token-row-meta">' + esc(savedLine) + '</div>' : '')
      + (usedLine ? '<div class="token-row-meta">' + esc(usedLine) + '</div>' : '')
      + (expiresLine ? '<div class="token-row-meta">' + esc(expiresLine) + '</div>' : '')
      + '</div><div class="token-row-actions">' + actions + '</div></div>'
      + '<div class="token-secret hidden" data-secret-for="' + esc(t.id) + '">'
      + secretFields + '</div>';
  }

  function tokenRowsHtml(tokens) {
    var refreshTokens = tokens.filter(function(t) { return t.has_refresh_token; });
    var accessTokens = tokens.filter(function(t) { return !t.has_refresh_token; });
    var used = {};
    var html = '';
    refreshTokens.forEach(function(rt) {
      html += tokenRow(rt, false);
      var client = rt.client_id || '';
      var children = accessTokens.filter(function(at) {
        if (used[at.id]) return false;
        if (at.parent_id) return at.parent_id === rt.id;
        return (at.client_id || '') === client;
      });
      children.forEach(function(at) { used[at.id] = true; });
      if (children.length) {
        html += '<div class="token-access-children">'
          + children.map(function(at) {
              return tokenRow(at, true, rt.client_id);
            }).join('')
          + '</div>';
      }
    });
    accessTokens.forEach(function(at) {
      if (!used[at.id]) html += tokenRow(at, false);
    });
    return html;
  }

  function renderTokens(data) {
    closeRedeemMenu();
    lastTokenData = data;
    var hadPrevious = !!listEl.querySelector('details.principal-card');
    var previousOpenIds = {};
    var previousSecrets = [];
    if (hadPrevious) {
      Array.prototype.forEach.call(
        listEl.querySelectorAll('details.principal-card[open]'),
        function(el) {
          Array.prototype.forEach.call(
            el.querySelectorAll('.token-secret[data-secret-for]'),
            function(secret) {
              previousOpenIds[secret.getAttribute('data-secret-for')] = true;
            });
        });
      Array.prototype.forEach.call(
        listEl.querySelectorAll('.token-secret:not(.hidden)'), function(el) {
          previousSecrets.push(el.getAttribute('data-secret-for'));
        });
    }
    updateAudienceOptions(data);
    var allTokens = data.tokens || [];
    var tokens = allTokens.filter(tokenMatches);
    countEl.textContent = String(allTokens.length);
    document.dispatchEvent(new CustomEvent('tokens:changed'));
    if (!tokens.length) {
      listEl.innerHTML = '<div class="token-empty">'
        + (allTokens.length
          ? 'No tokens match the current filters.'
          : 'No tokens saved yet. Add one from the Add token tab.')
        + '</div>';
      return;
    }
    var groups = [];
    var byKey = {};
    tokens.forEach(function(t) {
      var key = principalKey(t);
      if (!byKey[key]) {
        byKey[key] = {key: key, principal: t.principal || {}, tokens: []};
        groups.push(byKey[key]);
      }
      byKey[key].tokens.push(t);
    });
    groups.forEach(function(g) {
      g.tokens.sort(function(a, b) {
        var aRefresh = a.has_refresh_token ? 0 : 1;
        var bRefresh = b.has_refresh_token ? 0 : 1;
        if (aRefresh !== bRefresh) return aRefresh - bRefresh;
        var aUpdated = a.updated_at || '';
        var bUpdated = b.updated_at || '';
        return aUpdated < bUpdated ? 1 : (aUpdated > bUpdated ? -1 : 0);
      });
    });
    var activeKey = null;
    groups.forEach(function(g) {
      if (g.tokens.some(function(t) { return t.active; })) activeKey = g.key;
    });
    var openGroups = {};
    if (hadPrevious) {
      groups.forEach(function(g) {
        if (g.tokens.some(function(t) { return previousOpenIds[t.id]; })) {
          openGroups[g.key] = true;
        }
      });
    } else if (activeKey) {
      openGroups[activeKey] = true;
    }
    listEl.innerHTML = groups.map(function(g) {
      var p = g.principal;
      var hasPrincipal = !!(p.name || p.upn || p.identity || p.object_id || p.tenant_id);
      var name = p.name || p.upn
        || (hasPrincipal ? 'Unknown principal' : 'Unredeemed refresh token');
      var initial = (name || '?').trim().charAt(0).toUpperCase() || '?';
      var tenant = p.tenant_name
        ? p.tenant_name + (p.tenant_id ? ' (' + p.tenant_id + ')' : '')
        : (p.tenant_id || '');
      var meta = [p.upn || p.identity || '', tenant].filter(Boolean).join(' · ');
      if (!meta && !hasPrincipal) {
        var clients = [];
        g.tokens.forEach(function(t) {
          var client = t.client_name || t.client_id;
          if (client && clients.indexOf(client) < 0) clients.push(client);
        });
        meta = clients.length
          ? 'Client ' + clients.join(', ') + ' · redeem to identify principal'
          : 'Redeem to identify principal';
      }
      var count = g.tokens.length;
      var hasActive = g.tokens.some(function(t) { return t.active; });
      var open = !!openGroups[g.key];
      return '<details class="principal-card' + (hasActive ? ' active' : '') + '"'
        + ' data-principal-key="' + esc(g.key) + '"'
        + (open ? ' open' : '') + '>'
        + '<summary class="principal-head">'
        + '<span class="token-avatar">' + esc(initial) + '</span>'
        + '<span class="principal-main">'
        + '<span class="principal-title">' + esc(name) + '</span>'
        + '<span class="principal-sub">' + esc(meta) + '</span></span>'
        + '<span class="principal-count">' + count + (count === 1 ? ' token' : ' tokens') + '</span>'
        + '<span class="principal-chevron" aria-hidden="true">›</span>'
        + '</summary>'
        + '<div class="principal-tokens">' + tokenRowsHtml(g.tokens) + '</div>'
        + '</details>';
    }).join('');
    previousSecrets.forEach(function(id) {
      var panel = listEl.querySelector(
        '.token-secret[data-secret-for="' + id + '"]');
      if (!panel) return;
      panel.classList.remove('hidden');
      var button = listEl.querySelector(
        'button[data-action="view"][data-id="' + id + '"]');
      if (button) button.textContent = 'Hide tokens';
    });
    updateHealthLabels();
  }

  function closeRedeemMenu() {
    if (redeemState && redeemState.input) {
      redeemState.input.classList.remove('redeem-open');
      redeemState.input.setAttribute('aria-expanded', 'false');
      redeemState.input.removeAttribute('aria-activedescendant');
    }
    redeemState = null;
    redeemMenu.classList.add('hidden');
    redeemMenu.innerHTML = '';
    redeemMenu.removeAttribute('aria-activedescendant');
  }

  function positionRedeemMenu(input) {
    if (!input || redeemMenu.classList.contains('hidden')) return;
    var rect = input.getBoundingClientRect();
    if (rect.bottom < 0 || rect.top > window.innerHeight) {
      closeRedeemMenu();
      return;
    }
    var maxWidth = Math.max(240, window.innerWidth - 16);
    var width = Math.min(Math.max(420, rect.width + 230), maxWidth);
    var left = Math.max(8,
      Math.min(rect.left, window.innerWidth - width - 8));
    redeemMenu.style.width = width + 'px';
    redeemMenu.style.left = left + 'px';
    var height = Math.min(redeemMenu.offsetHeight || 0, 340);
    var below = window.innerHeight - rect.bottom - 8;
    var top = below >= Math.min(height, 180)
      ? rect.bottom + 4
      : Math.max(8, rect.top - height - 4);
    top = Math.max(8, Math.min(top, window.innerHeight - height - 8));
    redeemMenu.style.top = top + 'px';
  }

  function redeemHaystack(item) {
    return [item.name || '', item.id || '', item.resource || '',
            item.display || '', (item.aliases || []).join(' '),
            (item.keywords || []).join(' ')]
      .join(' ').toLowerCase();
  }

  function normalizeRedeemQuery(value) {
    var q = String(value || '').trim().toLowerCase();
    q = q.replace(/\/+$/, '');
    if (q.slice(-9) === '/.default') q = q.slice(0, -9);
    return q.replace(/\/+$/, '');
  }

  function redeemScore(item, query) {
    var q = normalizeRedeemQuery(query);
    var terms = q.split(/\s+/).filter(Boolean).map(function(term) {
      return term.replace(/\/+$/, '');
    });
    var hay = redeemHaystack(item);
    for (var i = 0; i < terms.length; i++) {
      if (terms[i] && hay.indexOf(terms[i]) < 0) return -1;
    }
    var name = String(item.name || '').toLowerCase();
    var id = String(item.id || '').toLowerCase();
    var resource = String(item.resource || '').toLowerCase();
    var display = String(item.display || '').toLowerCase();
    if (name === q || id === q || resource === q || display === q) return 0;
    if (name.indexOf(q) === 0 || id.indexOf(q) === 0
        || display.indexOf(q) === 0 || resource.indexOf(q) === 0) return 1;
    if (name.indexOf(q) >= 0) return 2;
    return 3;
  }

  function looksLikeResource(value) {
    var normalized = normalizeRedeemQuery(value);
    return /^(https?:\/\/|api:\/\/|urn:)/i.test(normalized)
      || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
        .test(normalized);
  }

  function redeemMatches() {
    if (!redeemState) return [];
    var query = normalizeRedeemQuery(redeemState.query);
    var matches = [];
    for (var i = 0; i < redeemState.items.length; i++) {
      var item = redeemState.items[i];
      var score = query ? redeemScore(item, query) : 0;
      if (query && score < 0) continue;
      matches.push({item: item, score: score});
    }
    matches.sort(function(a, b) {
      if (!query) {
        var ar = a.item.rank == null ? 10 : a.item.rank;
        var br = b.item.rank == null ? 10 : b.item.rank;
        if (ar !== br) return ar - br;
        var au = a.item.name && a.item.name === a.item.id ? 1 : 0;
        var bu = b.item.name && b.item.name === b.item.id ? 1 : 0;
        if (au !== bu) return au - bu;
      } else {
        var ap = (a.item.rank == null ? 10 : a.item.rank) < 10 ? 1 : 0;
        var bp = (b.item.rank == null ? 10 : b.item.rank) < 10 ? 1 : 0;
        if (ap !== bp) return bp - ap;
        if (a.score !== b.score) return a.score - b.score;
        var aq = a.item.rank == null ? 10 : a.item.rank;
        var bq = b.item.rank == null ? 10 : b.item.rank;
        if (aq !== bq) return aq - bq;
      }
      var an = String(a.item.name || '').toLowerCase();
      var bn = String(b.item.name || '').toLowerCase();
      if (an !== bn) return an < bn ? -1 : 1;
      var ax = String(a.item.resource || '');
      var bx = String(b.item.resource || '');
      return ax < bx ? -1 : (ax > bx ? 1 : 0);
    });
    return matches.map(function(entry) { return entry.item; });
  }

  function setRedeemActive(index) {
    if (!redeemState) return;
    var options = redeemMenu.querySelectorAll('.redeem-option');
    if (!options.length) {
      redeemState.active = -1;
      redeemState.input.removeAttribute('aria-activedescendant');
      return;
    }
    if (index < 0) index = options.length - 1;
    if (index >= options.length) index = 0;
    redeemState.active = index;
    Array.prototype.forEach.call(options, function(el, i) {
      el.classList.toggle('active', i === index);
      if (i === index) {
        el.setAttribute('aria-selected', 'true');
        redeemState.input.setAttribute('aria-activedescendant', el.id);
        if (el.scrollIntoView) el.scrollIntoView({block: 'nearest'});
      } else {
        el.removeAttribute('aria-selected');
      }
    });
  }

  function redeemCustomBarHtml() {
    var state = redeemState;
    var open = !!(state && state.customOpen);
    var value = state && state.customValue ? state.customValue : '';
    return '<div class="redeem-custom-bar">'
      + '<button type="button" class="redeem-custom-toggle'
      + (open ? ' active' : '') + '" data-redeem-custom-toggle="1">'
      + 'Custom client ID...</button>'
      + '<div class="redeem-custom-form' + (open ? '' : ' hidden') + '">'
      + '<input type="text" class="redeem-custom-input"'
      + ' placeholder="Client ID or resource URI"'
      + ' aria-label="Custom client ID or resource URI"'
      + ' value="' + esc(value) + '" autocomplete="off" spellcheck="false">'
      + '<button type="button" class="mode-btn" data-redeem-custom-go="1">'
      + 'Redeem</button>'
      + '</div>'
      + '<div class="redeem-custom-note' + (open ? '' : ' hidden') + '">'
      + 'Enter an application/client ID or resource URI.</div>'
      + '</div>';
  }

  function focusCustomInput() {
    var customInput = redeemMenu.querySelector('.redeem-custom-input');
    if (!customInput) return;
    customInput.focus();
    customInput.select();
  }

  function submitCustomRedeem() {
    if (!redeemState) return;
    var state = redeemState;
    var customInput = redeemMenu.querySelector('.redeem-custom-input');
    var value = customInput
      ? customInput.value.trim() : state.customValue;
    if (!value) {
      if (customInput) customInput.focus();
      return;
    }
    state.customValue = value;
    if (!looksLikeResource(value)) {
      state.customError = 'Enter a client ID or resource URI.';
      renderRedeemMenu();
      focusCustomInput();
      return;
    }
    state.customError = '';
    var client = state.fociClient;
    redeemFor(state.tokenId, state.input, value, value,
              client ? client.id : '',
              client ? (client.name || client.id) : '');
  }

  function redeemStatusFor(data) {
    var result = {error: '', note: ''};
    if (data.allow_custom) {
      if (data.error) {
        result.error = data.error;
        result.note = 'Common resources are listed; type a resource URI to use a custom one.';
      } else {
        var reason = data.reason || 'This client is not in the entrascopes dataset';
        reason = reason.charAt(0).toUpperCase() + reason.slice(1);
        result.note = reason
          + '. Common resources are listed; type a resource URI to use a custom one.';
      }
    }
    return result;
  }

  function redeemSubmenuHtml(index, name, meta) {
    return '<button type="button" class="redeem-option redeem-submenu"'
      + ' id="redeem-option-' + index + '"'
      + ' data-redeem-index="' + index + '" role="option">'
      + '<span class="redeem-option-text">'
      + '<span class="redeem-option-name">' + esc(name) + '</span>'
      + '<span class="redeem-option-meta">' + esc(meta) + '</span>'
      + '</span><span class="redeem-option-chevron" aria-hidden="true">›</span>'
      + '</button>';
  }

  function redeemBackBarHtml(title) {
    return '<div class="redeem-submenu-head">'
      + '<button type="button" class="redeem-back" data-redeem-back="1">'
      + '‹ Back</button>'
      + '<span class="redeem-submenu-title">' + esc(title) + '</span>'
      + '</div>';
  }

  function resetRedeemQuery() {
    if (!redeemState) return;
    redeemState.query = '';
    redeemState.input.value = '';
    redeemState.customOpen = false;
    redeemState.customError = '';
  }

  function showRedeemRoot() {
    if (!redeemState) return;
    var state = redeemState;
    resetRedeemQuery();
    state.view = 'root';
    state.fociClient = null;
    state.loading = false;
    renderRedeemMenu();
    state.input.focus();
  }

  function showRedeemAccess() {
    if (!redeemState) return;
    var state = redeemState;
    resetRedeemQuery();
    state.view = 'access';
    state.fociClient = null;
    state.loading = false;
    state.items = state.sourceResources || [];
    state.clientName = state.sourceClientName || '';
    state.error = state.sourceError || '';
    state.note = state.sourceNote || '';
    renderRedeemMenu();
    state.input.focus();
  }

  function showRedeemFoci() {
    if (!redeemState) return;
    var state = redeemState;
    resetRedeemQuery();
    state.view = 'foci';
    state.fociClient = null;
    state.loading = false;
    state.items = [];
    state.error = '';
    state.note = '';
    state.fociLoading = !state.fociClients;
    renderRedeemMenu();
    state.input.focus();
    loadFociClients();
  }

  function loadFociClients() {
    if (!redeemState) return;
    var state = redeemState;
    if (state.fociClients) return;
    state.fociLoading = true;
    state.fociError = '';
    renderRedeemMenu();
    loadClientApps().then(function() {
      if (!redeemState || redeemState !== state) return;
      state.fociLoading = false;
      var current = String(state.sourceClientId || '').toLowerCase();
      state.fociClients = (clientApps || []).filter(function(app) {
        return app.foci
          && String(app.id || '').toLowerCase() !== current;
      });
      if (clientError && !state.fociClients.length) {
        state.fociError = clientError;
      }
      renderRedeemMenu();
    });
  }

  function chooseFociClient(index) {
    if (!redeemState) return;
    var state = redeemState;
    var app = (state.fociClients || [])[index];
    if (!app) return;
    resetRedeemQuery();
    state.view = 'foci-access';
    state.fociClient = app;
    state.items = [];
    state.matches = [];
    state.custom = '';
    state.loading = true;
    state.error = '';
    state.note = '';
    renderRedeemMenu();
    state.input.focus();
    loadTokenResources(state.tokenId, app.id).then(function(data) {
      if (!redeemState || redeemState !== state) return;
      state.loading = false;
      state.items = data.resources || [];
      state.clientName = data.client_name || app.name || '';
      var status = redeemStatusFor(data);
      state.error = status.error;
      state.note = status.note;
      renderRedeemMenu();
    }).catch(function(err) {
      if (!redeemState || redeemState !== state) return;
      state.loading = false;
      state.error = err.message || 'Could not load resources.';
      renderRedeemMenu();
    });
  }

  function backRedeem() {
    if (!redeemState) return;
    var state = redeemState;
    if (state.view === 'foci-access') {
      resetRedeemQuery();
      state.view = 'foci';
      state.fociClient = null;
      state.items = [];
      state.matches = [];
      state.custom = '';
      state.loading = false;
      state.error = '';
      state.note = '';
      renderRedeemMenu();
      state.input.focus();
      return;
    }
    showRedeemRoot();
  }

  function renderRedeemMenu() {
    if (!redeemState) return;
    var state = redeemState;
    var html = '';
    state.custom = '';
    if (state.view === 'root') {
      state.matches = state.sourceFoci
        ? [{kind: 'access'}, {kind: 'foci'}]
        : [{kind: 'access'}];
      html += redeemSubmenuHtml(0, 'Access Token',
        'Redeem for a resource with this client');
      if (state.sourceFoci) {
        html += redeemSubmenuHtml(1, 'FOCI',
          'Redeem with another FOCI client');
      }
    } else if (state.view === 'foci') {
      html += redeemBackBarHtml('FOCI clients');
      if (state.fociLoading) {
        state.matches = [];
        html += '<div class="redeem-note">Loading FOCI clients...</div>';
      } else {
        if (state.fociError) {
          html += '<div class="redeem-note error">'
            + esc(state.fociError) + '</div>';
        }
        var query = normalizeRedeemQuery(state.query);
        var apps = (state.fociClients || []).filter(function(app) {
          if (!query) return true;
          return clientScore(app, query) >= 0;
        });
        var limit = 80;
        var visible = apps.slice(0, limit);
        state.matches = visible;
        if (!visible.length) {
          if (!state.fociError) {
            html += '<div class="redeem-note">'
              + (query ? 'No matching FOCI clients.'
                       : 'No FOCI clients are available.')
              + '</div>';
          }
        } else {
          if (apps.length > limit) {
            html += '<div class="redeem-note subtle">Showing ' + limit
              + ' of ' + apps.length + ' FOCI clients. Keep typing to '
              + 'narrow the list.</div>';
          }
          visible.forEach(function(app, idx) {
            html += '<button type="button" class="redeem-option"'
              + ' id="redeem-option-' + idx + '"'
              + ' data-redeem-index="' + idx + '" role="option">'
              + '<span class="redeem-option-name">'
              + esc(app.name || app.id) + '</span>'
              + '<span class="redeem-option-meta">' + esc(app.id) + '</span>'
              + '</button>';
          });
        }
      }
    } else {
      if (state.sourceFoci) {
        var title = state.fociClient
          ? 'FOCI · ' + (state.fociClient.name || state.fociClient.id)
          : 'Access Token';
        html += redeemBackBarHtml(title);
      }
      html += redeemCustomBarHtml();
      if (state.loading) {
        state.matches = [];
        html += '<div class="redeem-note">Loading resources...</div>';
      } else {
        if (state.error) {
          html += '<div class="redeem-note error">' + esc(state.error) + '</div>';
        }
        if (state.customError) {
          html += '<div class="redeem-note error redeem-custom-error">'
            + esc(state.customError) + '</div>';
        }
        if (state.note) {
          html += '<div class="redeem-note">' + esc(state.note) + '</div>';
        }
        var query = state.query.trim();
        var matches = redeemMatches();
        var limit = 80;
        var visible = matches.slice(0, limit);
        state.matches = visible;
        var normalizedQuery = normalizeRedeemQuery(query);
        var exactMatch = matches.some(function(item) {
          var values = [item.id, item.resource, item.display]
            .concat(item.aliases || []);
          return values.some(function(value) {
            return normalizeRedeemQuery(value) === normalizedQuery;
          });
        });
        var customAvailable = looksLikeResource(query) && !exactMatch;
        if (!matches.length && !customAvailable) {
          html += '<div class="redeem-note">'
            + (query
              ? 'No matching resources for this client.'
              : 'No resources are listed for this client.')
            + '</div>';
        } else if (matches.length) {
          if (matches.length > limit) {
            var clientLabel = state.clientName
              ? ' for ' + state.clientName : '';
            html += '<div class="redeem-note subtle">Showing ' + limit
              + ' of ' + matches.length + ' resources' + esc(clientLabel)
              + '. Keep typing to narrow the list.</div>';
          }
          visible.forEach(function(item, idx) {
            var meta = item.resource || item.display || item.id || '';
            var metaLower = meta.toLowerCase();
            if (item.display && item.display.toLowerCase() !== metaLower) {
              meta += ' · ' + item.display;
              metaLower = meta.toLowerCase();
            }
            if (item.id && item.id.toLowerCase() !== metaLower
                && meta.indexOf(item.id) < 0) {
              meta += ' · ' + item.id;
            }
            html += '<button type="button" class="redeem-option"'
              + ' id="redeem-option-' + idx + '"'
              + ' data-redeem-index="' + idx + '" role="option">'
              + '<span class="redeem-option-name">'
              + esc(item.name || item.id || item.resource) + '</span>'
              + '<span class="redeem-option-meta">' + esc(meta) + '</span>'
              + '</button>';
          });
        }
        if (customAvailable) {
          state.custom = query;
          html += '<button type="button" class="redeem-option"'
            + ' id="redeem-option-custom" data-redeem-custom="1" role="option">'
            + '<span class="redeem-option-name">Use custom resource</span>'
            + '<span class="redeem-option-meta">' + esc(query) + '</span>'
            + '</button>';
        }
      }
    }
    redeemMenu.innerHTML = html;
    state.active = -1;
    state.input.removeAttribute('aria-activedescendant');
    positionRedeemMenu(state.input);
  }

  function redeemResourceKey(tokenId, clientId) {
    return String(tokenId || '') + '|'
      + String(clientId || '').toLowerCase();
  }

  function loadTokenResources(tokenId, clientId) {
    var key = redeemResourceKey(tokenId, clientId);
    if (resourceCache[key]) {
      return Promise.resolve(resourceCache[key]);
    }
    if (resourcePromises[key]) return resourcePromises[key];
    var url = '/api/tokens/resources?id=' + encodeURIComponent(tokenId);
    if (clientId) url += '&client_id=' + encodeURIComponent(clientId);
    resourcePromises[key] = fetch(url)
      .then(function(r) {
        return r.json().then(function(data) {
          if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
          return data;
        });
      })
      .then(function(data) {
        resourceCache[key] = data;
        delete resourcePromises[key];
        return data;
      })
      .catch(function(err) {
        delete resourcePromises[key];
        throw err;
      });
    return resourcePromises[key];
  }

  function openRedeem(input) {
    var tokenId = input.getAttribute('data-redeem-id');
    if (!tokenId) return;
    if (redeemState && redeemState.input === input) return;
    closeRedeemMenu();
    redeemState = {
      input: input,
      tokenId: tokenId,
      query: input.value || '',
      items: [],
      matches: [],
      active: -1,
      loading: true,
      error: '',
      note: '',
      clientName: '',
      sourceClientId: '',
      sourceClientName: '',
      sourceFoci: false,
      sourceResources: [],
      sourceError: '',
      sourceNote: '',
      view: 'access',
      fociClients: null,
      fociLoading: false,
      fociError: '',
      fociClient: null,
      customOpen: false,
      customValue: '',
      customError: '',
      custom: ''
    };
    input.classList.add('redeem-open');
    input.setAttribute('aria-expanded', 'true');
    redeemMenu.classList.remove('hidden');
    redeemMenu.innerHTML = '<div class="redeem-note">Loading resources...</div>';
    positionRedeemMenu(input);
    loadTokenResources(tokenId).then(function(data) {
      if (!redeemState || redeemState.input !== input) return;
      var state = redeemState;
      state.loading = false;
      state.items = data.resources || [];
      state.sourceResources = data.resources || [];
      state.clientName = data.client_name || '';
      state.sourceClientName = data.client_name || '';
      state.sourceClientId = data.client_id || '';
      state.sourceFoci = !!data.foci;
      var status = redeemStatusFor(data);
      state.error = status.error;
      state.note = status.note;
      state.sourceError = status.error;
      state.sourceNote = status.note;
      if (state.sourceFoci) state.view = 'root';
      renderRedeemMenu();
    }).catch(function(err) {
      if (!redeemState || redeemState.input !== input) return;
      redeemState.loading = false;
      redeemState.error = err.message || 'Could not load resources.';
      renderRedeemMenu();
    });
  }

  function redeemFor(tokenId, input, resource, label, clientId, clientName) {
    closeRedeemMenu();
    if (input) {
      input.value = '';
      input.disabled = true;
    }
    var via = clientName ? ' via ' + clientName : '';
    flash('Redeeming for ' + label + via + '...', false);
    var body = { id: tokenId, resource: resource };
    if (clientId) body.client_id = clientId;
    fetch('/api/tokens/redeem', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }).then(function(r) {
      return r.json().then(function(data) {
        if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
        return data;
      });
    }).then(function(data) {
      renderTokens(data);
      flash('Token redeemed for ' + label + via + '.', false);
    }).catch(function(err) {
      if (input) input.disabled = false;
      flash(err.message || 'Could not redeem token.', true);
    });
  }

  function chooseRedeem(index) {
    if (!redeemState) return;
    var state = redeemState;
    if (state.view === 'root') {
      var entry = state.matches[index];
      if (!entry) return;
      if (entry.kind === 'foci') showRedeemFoci();
      else showRedeemAccess();
      return;
    }
    if (state.view === 'foci') {
      chooseFociClient(index);
      return;
    }
    var client = state.fociClient;
    var clientId = client ? client.id : '';
    var clientName = client ? (client.name || client.id) : '';
    if (index >= state.matches.length) {
      if (!state.custom) return;
      redeemFor(state.tokenId, state.input, state.custom, state.custom,
                clientId, clientName);
      return;
    }
    var item = state.matches[index];
    if (!item) return;
    redeemFor(state.tokenId, state.input, item.resource || item.id,
              item.name || item.resource || item.id,
              clientId, clientName);
  }

  listEl.addEventListener('focusin', function(event) {
    var input = event.target.closest('.redeem-input');
    if (input) openRedeem(input);
  });

  listEl.addEventListener('click', function(event) {
    var input = event.target.closest('.redeem-input');
    if (input) openRedeem(input);
  });

  listEl.addEventListener('input', function(event) {
    var input = event.target.closest('.redeem-input');
    if (!input) return;
    if (!redeemState || redeemState.input !== input) openRedeem(input);
    if (!redeemState) return;
    redeemState.query = input.value;
    redeemState.customOpen = false;
    redeemState.customError = '';
    if (redeemState.view === 'root' && input.value.trim()) {
      redeemState.view = 'access';
      redeemState.fociClient = null;
      redeemState.items = redeemState.sourceResources || [];
      redeemState.clientName = redeemState.sourceClientName || '';
      redeemState.error = redeemState.sourceError || '';
      redeemState.note = redeemState.sourceNote || '';
    }
    renderRedeemMenu();
  });

  listEl.addEventListener('keydown', function(event) {
    var input = event.target.closest('.redeem-input');
    if (!input || !redeemState || redeemState.input !== input) return;
    var count = redeemMenu.querySelectorAll('.redeem-option').length;
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setRedeemActive(redeemState.active + 1);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      setRedeemActive(redeemState.active - 1);
    } else if (event.key === 'Enter') {
      if (count) {
        event.preventDefault();
        chooseRedeem(redeemState.active >= 0 ? redeemState.active : 0);
      }
    } else if (event.key === 'Escape') {
      event.preventDefault();
      closeRedeemMenu();
      input.blur();
    } else if (event.key === 'Tab') {
      closeRedeemMenu();
    }
  });

  redeemMenu.addEventListener('mousedown', function(event) {
    if (event.target.closest('.redeem-option')) event.preventDefault();
  });

  redeemMenu.addEventListener('click', function(event) {
    event.stopPropagation();
    if (!redeemState) return;
    var back = event.target.closest('[data-redeem-back]');
    if (back) {
      event.stopPropagation();
      backRedeem();
      return;
    }
    var toggle = event.target.closest('[data-redeem-custom-toggle]');
    if (toggle) {
      event.stopPropagation();
      redeemState.customOpen = !redeemState.customOpen;
      redeemState.customError = '';
      if (redeemState.customOpen) {
        if (!redeemState.customValue && looksLikeResource(redeemState.query)) {
          redeemState.customValue = redeemState.query.trim();
        }
        renderRedeemMenu();
        focusCustomInput();
      } else {
        renderRedeemMenu();
      }
      return;
    }
    var go = event.target.closest('[data-redeem-custom-go]');
    if (go) {
      event.stopPropagation();
      submitCustomRedeem();
      return;
    }
    var option = event.target.closest('.redeem-option');
    if (!option) return;
    if (option.hasAttribute('data-redeem-custom')) {
      chooseRedeem(redeemState.matches.length);
      return;
    }
    var index = parseInt(option.getAttribute('data-redeem-index'), 10);
    if (!isNaN(index)) chooseRedeem(index);
  });

  redeemMenu.addEventListener('input', function(event) {
    if (!redeemState) return;
    var customInput = event.target.closest('.redeem-custom-input');
    if (!customInput) return;
    redeemState.customValue = customInput.value;
    if (redeemState.customError) {
      redeemState.customError = '';
      var errorEl = redeemMenu.querySelector('.redeem-custom-error');
      if (errorEl) errorEl.remove();
    }
  });

  redeemMenu.addEventListener('keydown', function(event) {
    if (!redeemState) return;
    if (!event.target.closest('.redeem-custom-input')) return;
    if (event.key === 'Enter') {
      event.preventDefault();
      submitCustomRedeem();
    } else if (event.key === 'Escape') {
      event.preventDefault();
      var mainInput = redeemState.input;
      closeRedeemMenu();
      if (mainInput) mainInput.blur();
    }
  });

  document.addEventListener('click', function(event) {
    if (!redeemState) return;
    if (redeemMenu.contains(event.target)) return;
    if (event.target.closest && event.target.closest('.redeem-input')) return;
    closeRedeemMenu();
  });

  window.addEventListener('resize', function() {
    if (redeemState) positionRedeemMenu(redeemState.input);
  });
  window.addEventListener('scroll', function() {
    if (redeemState) positionRedeemMenu(redeemState.input);
  }, true);

  function refresh() {
    return fetch('/api/tokens')
      .then(function(r) { return r.json(); })
      .then(renderTokens)
      .catch(function() {});
  }

  [filterText, filterType, filterStatus, filterAudience].forEach(function(el) {
    if (!el) return;
    el.addEventListener('input', function() { renderTokens(lastTokenData); });
    el.addEventListener('change', function() { renderTokens(lastTokenData); });
  });
  setInterval(updateHealthLabels, 30000);

  saveBtn.addEventListener('click', function() {
    var access = typeEl.value === 'access';
    var token = tokenEl.value.trim();
    var client = clientEl.value.trim();
    var accessToken = accessEl.value.trim();
    if (access && !accessToken) {
      setNote('Access token is required.');
      accessEl.focus();
      return;
    }
    if (!access && !token) {
      setNote('Refresh token is required.');
      tokenEl.focus();
      return;
    }
    if (!access && !client) {
      setNote('Client ID is required when a refresh token is provided.');
      clientEl.focus();
      return;
    }
    if (!access && !looksLikeClientId(client)) {
      setNote('Select a client application or enter a valid client ID.');
      clientEl.focus();
      return;
    }
    saveBtn.disabled = true;
    setNote('Saving token...');
    var body = access
      ? { access_token: accessToken }
      : { refresh_token: token, client_id: client };
    fetch('/api/tokens', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }).then(function(r) {
      return r.json().then(function(data) {
        if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
        return data;
      });
    }).then(function(data) {
      tokenEl.value = '';
      clientEl.value = '';
      accessEl.value = '';
      saveBtn.disabled = false;
      closeClientMenu();
      updateClientHint();
      setNote('');
      renderTokens(data);
      showPane('collected');
      flash('Token saved.', false);
    }).catch(function(err) {
      saveBtn.disabled = false;
      setNote(err.message);
      flash(err.message, true);
    });
  });

  listEl.addEventListener('click', function(event) {
    var decodeBtn = event.target.closest('button[data-decode-secret]');
    if (decodeBtn) {
      var kind = decodeBtn.getAttribute('data-decode-secret');
      var secretPanel = decodeBtn.closest('.token-secret');
      var field = secretPanel
        ? secretPanel.querySelector('[data-secret="' + kind + '"]') : null;
      openDecode(kind, field ? field.value : '', decodeBtn);
      return;
    }
    var btn = event.target.closest('button[data-action]');
    if (!btn) return;
    var id = btn.getAttribute('data-id');
    var action = btn.getAttribute('data-action');
    if (action === 'view') {
      var panel = listEl.querySelector('.token-secret[data-secret-for="' + id + '"]');
      if (!panel) return;
      if (!panel.classList.contains('hidden')) {
        panel.classList.add('hidden');
        btn.textContent = 'View tokens';
        return;
      }
      btn.disabled = true;
      fetch('/api/tokens/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: id })
      }).then(function(r) {
        return r.json().then(function(data) {
          if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
          return data;
        });
      }).then(function(data) {
        var accessField = panel.querySelector('[data-secret="access"]');
        var refreshField = panel.querySelector('[data-secret="refresh"]');
        if (accessField) accessField.value = data.access_token || '';
        if (refreshField) refreshField.value = data.refresh_token || '';
        panel.classList.remove('hidden');
        btn.textContent = 'Hide tokens';
        btn.disabled = false;
      }).catch(function(err) {
        btn.disabled = false;
        flash(err.message || 'Could not load tokens.', true);
      });
    } else if (action === 'use') {
      fetch('/api/tokens/select', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: id })
      }).then(function(r) { return r.json(); })
        .then(function(data) {
          renderTokens(data);
          flash('Active token changed.', false);
        }).catch(function() { flash('Could not select token.', true); });
    } else if (action === 'delete') {
      if (!confirm('Delete this saved token?')) return;
      fetch('/api/tokens/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: id })
      }).then(function(r) { return r.json(); })
        .then(function(data) {
          renderTokens(data);
          flash('Token deleted.', false);
        }).catch(function() { flash('Could not delete token.', true); });
    }
  });

  tabs.forEach(function(tab) {
    tab.addEventListener('click', function() {
      closeRedeemMenu();
      closeClientMenu();
      showPane(tab.getAttribute('data-token-view'));
      flash('', false);
    });
  });

  if (decodeClose) decodeClose.addEventListener('click', closeDecode);
  if (decodeOverlay) {
    decodeOverlay.addEventListener('click', function(event) {
      if (event.target === decodeOverlay) closeDecode();
    });
  }
  document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape' && decodeOverlay
        && !decodeOverlay.classList.contains('hidden')) {
      event.preventDefault();
      closeDecode();
    }
  });

  document.addEventListener('app:view', function(e) {
    if (e.detail === 'tokens') {
      refresh();
    } else {
      closeRedeemMenu();
      closeClientMenu();
      closeDecode();
    }
  });

  refresh();
})();
</script>
""".replace("__AUTH_FILE__", html.escape(str(AUTH_FILE)))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-rt", "--refresh-token", default="",
                    help="MS auth broker refresh token")
    ap.add_argument("-at", "--access-token", default="",
                    help="saved access token (Graph or AAD Graph audience)")
    ap.add_argument("-c", "--client-id", default="",
                    help="public client id used to redeem the token")
    ap.add_argument("-o", "--out", default=None,
                    help="output database (default: data/databases/collected.db "
                         "or data/databases/aadgraph.db)")
    ap.add_argument("-ua", "--user-agent", default="",
                    help="custom User-Agent for HTTP requests")
    ap.add_argument("--backend", choices=("graph", "aadgraph"), default="graph",
                    help="collection backend")
    ap.add_argument("--autotoken", action="store_true",
                    help="redeem the refresh token for an AAD Graph token")
    ap.add_argument("--evade", action="store_true",
                    help="batch relationship requests and use the evade user agent")
    ap.add_argument("--gather-all", action="store_true",
                    help="also collect IG, PIM, and Azure data")
    ap.add_argument("--mfa", action="store_true",
                    help="include MFA details (requires privileged access)")
    ap.add_argument("--collector-dir", default=None,
                    help="collector checkout (default: bundled entra_surface/collector)")
    args = ap.parse_args(argv)

    if args.collector_dir:
        os.environ["ENTRA_COLLECTOR_DIR"] = args.collector_dir
    default_out = (DEFAULT_AADGRAPH_OUTPUT if args.backend == "aadgraph"
                   else DEFAULT_OUTPUT)
    out_path = Path(args.out or default_out).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if args.backend == "aadgraph":
            if not args.refresh_token and not args.access_token:
                raise ValueError("a refresh or access token is required")
            cmd = _worker_command(
                "run-aadgraph", args.refresh_token, args.client_id,
                out_path=out_path, user_agent=args.user_agent,
                access_token=args.access_token, evade=args.evade,
                gather_all=args.gather_all, autotoken=args.autotoken,
                mfa=args.mfa)
        elif args.access_token and not args.refresh_token:
            cmd = _worker_command("run-access", args.access_token, "",
                                  out_path=out_path,
                                  user_agent=args.user_agent,
                                  evade=args.evade)
        else:
            if not args.refresh_token or not args.client_id:
                raise ValueError(
                    "refresh token and client id are required for Graph")
            cmd = _worker_command("run", args.refresh_token, args.client_id,
                                  out_path=out_path,
                                  user_agent=args.user_agent,
                                  evade=args.evade)
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return subprocess.call(cmd, cwd=str(BASE_DIR), env=_worker_env())


if __name__ == "__main__":
    raise SystemExit(main())

"""Persistent local settings for entra-surface.

Only non-token preferences live here (currently the collection proxy).  The
file is separate from ``.entra-surface-auth.json`` so proxy settings can be
edited without touching saved credentials.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

SETTINGS_FILE = Path(
    os.environ.get("ENTRA_SURFACE_SETTINGS")
    or (Path.cwd() / ".entra-surface-settings.json")
).expanduser().resolve()
PROXY_SCHEMES = {"http", "https", "socks4", "socks4a", "socks5", "socks5h"}
DEFAULT_PROXY = {
    "enabled": False,
    "url": "",
    "username": "",
    "password": "",
    "no_proxy": "",
    "insecure_tls": False,
}


def _as_bool(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _proxy_from(data) -> dict:
    proxy = dict(DEFAULT_PROXY)
    if isinstance(data, dict):
        for key in DEFAULT_PROXY:
            if key in data and data[key] is not None:
                proxy[key] = data[key]
    proxy["enabled"] = _as_bool(proxy["enabled"])
    proxy["insecure_tls"] = _as_bool(proxy["insecure_tls"])
    for key in ("url", "username", "password", "no_proxy"):
        proxy[key] = str(proxy.get(key) or "")
    return proxy


def load_settings() -> dict:
    try:
        data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    return {"proxy": _proxy_from(data.get("proxy") if isinstance(data, dict) else {})}


def validate_proxy(proxy: dict) -> dict:
    proxy = _proxy_from(proxy)
    if not proxy["enabled"]:
        return proxy
    raw = proxy["url"].strip()
    if not raw:
        raise ValueError("proxy URL is required")
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise ValueError(f"invalid proxy URL: {exc}") from exc
    if parts.scheme.lower() not in PROXY_SCHEMES:
        raise ValueError(
            "proxy scheme must be http, https, socks4, socks4a, socks5, "
            "or socks5h")
    if not parts.hostname:
        raise ValueError("proxy URL must include a host")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"invalid proxy port: {exc}") from exc
    if not port:
        raise ValueError("proxy URL must include a port")
    return proxy


def save_settings(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError("settings payload must be an object")
    proxy = validate_proxy(data.get("proxy") or {})
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(
        prefix=".entra-surface-settings-", dir=str(SETTINGS_FILE.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"proxy": proxy}, handle, indent=2)
            handle.write("\n")
        try:
            os.chmod(name, 0o600)
        except OSError:
            pass
        os.replace(name, SETTINGS_FILE)
    finally:
        try:
            os.unlink(name)
        except OSError:
            pass
    return {"proxy": proxy}


def _proxy_url(proxy: dict) -> str:
    raw = str(proxy.get("url") or "").strip()
    username = str(proxy.get("username") or "")
    if not username:
        return raw
    password = str(proxy.get("password") or "")
    parts = urlsplit(raw)
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    userinfo = quote(username, safe="")
    if password:
        userinfo += ":" + quote(password, safe="")
    netloc = userinfo + "@" + host
    if parts.port:
        netloc += f":{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path,
                       parts.query, parts.fragment))


def proxy_dict(proxy: dict | None = None) -> dict | None:
    """Return a requests-compatible proxies dict, or None when disabled."""
    if proxy is None:
        proxy = load_settings()["proxy"]
    proxy = _proxy_from(proxy)
    if not proxy["enabled"]:
        return None
    url = _proxy_url(proxy)
    if not url:
        return None
    return {"http": url, "https": url}


def is_socks(proxy: dict | None) -> bool:
    if not proxy:
        return False
    url = str(proxy.get("url") or "").lower()
    return url.startswith(("socks4", "socks5"))

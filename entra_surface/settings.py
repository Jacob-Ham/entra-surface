"""Persistent local settings for entra-surface.

Only non-token preferences live here (the collection proxy and user agents).
The file is separate from ``.entra-surface-auth.json`` so preferences can be
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
DEFAULT_USER_AGENTS = {
    "global": "",
    "collect": "",
    "tokens": "",
}
USER_AGENT_MAX_LENGTH = 512


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


def _user_agent_value(value, label: str = "user agent") -> str:
    text = str(value or "").strip()
    if len(text) > USER_AGENT_MAX_LENGTH:
        raise ValueError(
            f"{label} is too long (max {USER_AGENT_MAX_LENGTH} characters)")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise ValueError(f"{label} contains control characters")
    try:
        text.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} must contain Latin-1 characters") from exc
    return text


def _user_agents_from(data, strict: bool = False) -> dict:
    agents = dict(DEFAULT_USER_AGENTS)
    if not isinstance(data, dict):
        return agents
    for key in DEFAULT_USER_AGENTS:
        if key not in data or data[key] is None:
            continue
        try:
            agents[key] = _user_agent_value(data[key], f"{key} user agent")
        except ValueError:
            if strict:
                raise
            agents[key] = ""
    return agents


def load_settings() -> dict:
    try:
        data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    return {
        "proxy": _proxy_from(data.get("proxy") or {}),
        "user_agents": _user_agents_from(data.get("user_agents") or {}),
    }


def effective_user_agent(area: str = "", override: str = "") -> str:
    """Return the configured user agent for an area.

    A non-empty per-run override wins.  Otherwise the area-specific setting is
    used, falling back to the global setting and finally an empty string so the
    caller can apply its built-in default.
    """
    override = _user_agent_value(override, "user agent")
    if override:
        return override
    agents = load_settings()["user_agents"]
    key = str(area or "").strip().lower()
    if key in agents and agents[key]:
        return agents[key]
    return agents.get("global") or ""


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
    raw_agents = data.get("user_agents")
    if raw_agents is None:
        user_agents = load_settings()["user_agents"]
    elif not isinstance(raw_agents, dict):
        raise ValueError("user_agents must be an object")
    else:
        merged = dict(load_settings()["user_agents"])
        merged.update(raw_agents)
        user_agents = _user_agents_from(merged, strict=True)
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(
        prefix=".entra-surface-settings-", dir=str(SETTINGS_FILE.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"proxy": proxy, "user_agents": user_agents}, handle,
                      indent=2)
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
    return {"proxy": proxy, "user_agents": user_agents}


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

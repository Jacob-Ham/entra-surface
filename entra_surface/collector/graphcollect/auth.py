"""Redeem one MS auth broker refresh token for every API the collector needs.

The collector talks to two APIs:
  * https://graph.microsoft.com      - all Entra directory / role / policy data
  * https://management.azure.com     - Azure subscription / RBAC data

Broker refresh tokens rotate on every redemption, so the provider always
reuses the newest refresh token for subsequent exchanges.
"""
from __future__ import annotations

import base64
import json
import threading
import time

import msal
import requests

from .tls import InsecureTLSAdapter

# MSAL adds these to every request. They are telemetry/client metadata, not
# part of the OAuth protocol, so drop them before the request leaves the process.
_MSAL_HEADERS = frozenset({
    "client-request-id",
    "x-ms-lib-capability",
})
_MSAL_HEADER_PREFIXES = ("x-client-", "x-app-")


class _TokenSession(requests.Session):
    """requests session that removes MSAL's telemetry/client headers."""

    def request(self, method, url, *args, **kwargs):
        headers = kwargs.get("headers")
        if headers:
            kwargs["headers"] = {
                key: value for key, value in headers.items()
                if key.lower() not in _MSAL_HEADERS
                and not key.lower().startswith(_MSAL_HEADER_PREFIXES)
            }
        return super().request(method, url, *args, **kwargs)

    def get(self, url, **kwargs):
        # MSAL fetches the OIDC discovery document during Authority setup.
        # The public-cloud endpoints are fixed, so serve them locally instead
        # of making an extra round trip before every token redemption.
        tenant = _well_known_tenant(url)
        if tenant:
            return _oidc_response(tenant)
        return super().get(url, **kwargs)


_OIDC_PREFIX = "https://login.microsoftonline.com/"


def _well_known_tenant(url: str) -> str:
    if not url.startswith(_OIDC_PREFIX):
        return ""
    rest = url[len(_OIDC_PREFIX):]
    if "/v2.0/.well-known/openid-configuration" not in rest:
        return ""
    tenant = rest.split("/", 1)[0].strip()
    return tenant or "common"


def _oidc_response(tenant: str) -> requests.Response:
    base = f"https://login.microsoftonline.com/{tenant}"
    payload = {
        "issuer": f"{base}/v2.0",
        "authorization_endpoint": f"{base}/oauth2/v2.0/authorize",
        "token_endpoint": f"{base}/oauth2/v2.0/token",
        "device_authorization_endpoint": f"{base}/oauth2/v2.0/devicecode",
    }
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps(payload).encode("utf-8")
    response.encoding = "utf-8"
    response.headers["Content-Type"] = "application/json"
    response.url = f"{base}/v2.0/.well-known/openid-configuration"
    return response


def _token_http_client(proxies: dict | None, verify: bool,
                       user_agent: str = "") -> requests.Session:
    session = _TokenSession()
    session.verify = bool(verify)
    if proxies:
        session.proxies = proxies
    if user_agent:
        session.headers["User-Agent"] = user_agent
    adapter_cls = (requests.adapters.HTTPAdapter if verify
                   else InsecureTLSAdapter)
    adapter = adapter_cls(pool_connections=4, pool_maxsize=8, max_retries=1)
    session.mount("https://", adapter)
    if not verify:
        session.mount("http://", adapter)
    return session


GRAPH_RES = "https://graph.microsoft.com"
ARM_RES = "https://management.azure.com"
BROKER_CLIENT_ID = "29d9ed98-a469-4536-ade2-f981bc1d605e"


class AuthError(Exception):
    pass


def _decode_jwt(token: str) -> dict:
    p = token.split(".")[1]
    p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))


class TokenProvider:
    def __init__(self, refresh_token: str, client_id: str | None = None,
                 proxies: dict | None = None, verify: bool = True,
                 user_agent: str = ""):
        self._rt = refresh_token
        self._client_id = client_id or BROKER_CLIENT_ID
        app_kwargs = {
            "authority": "https://login.microsoftonline.com/common",
            # The authority is the public cloud endpoint; skip MSAL's extra
            # instance-discovery request before every worker redemption.
            "instance_discovery": False,
            # MSAL ignores its verify/proxies options when a caller supplies an
            # http_client, so configure the custom session instead.
            "http_client": _token_http_client(proxies, verify, user_agent),
        }
        self._app = msal.PublicClientApplication(self._client_id, **app_kwargs)
        self._tokens: dict[str, tuple[str, float]] = {}
        self._claims: dict | None = None
        self._lock = threading.Lock()

    def get_token(self, resource: str) -> str:
        """Return an access token for `resource`, redeeming/refreshing as needed."""
        resource = resource.rstrip("/")
        now = time.time()
        cached = self._tokens.get(resource)
        if cached and cached[1] > now + 60:
            return cached[0]

        with self._lock:
            # another thread may have refreshed while we waited
            cached = self._tokens.get(resource)
            if cached and cached[1] > time.time() + 60:
                return cached[0]
            res = self._app.acquire_token_by_refresh_token(
                self._rt, scopes=[resource + "/.default"])
            if "access_token" not in res:
                raise AuthError(
                    f"{resource}: {res.get('error')}: "
                    f"{(res.get('error_description') or '')[:250]}")
            # broker RTs rotate - keep the newest one for the next exchange
            if res.get("refresh_token"):
                self._rt = res["refresh_token"]
            self._tokens[resource] = (
                res["access_token"], time.time() + int(res.get("expires_in", 3600)))
            return res["access_token"]

    @property
    def claims(self) -> dict:
        if self._claims is None:
            self._claims = _decode_jwt(self.get_token(GRAPH_RES))
        return self._claims

    @property
    def identity(self) -> str:
        c = self.claims
        return c.get("upn") or c.get("unique_name") or c.get("oid", "?")

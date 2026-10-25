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
                 proxies: dict | None = None):
        self._rt = refresh_token
        self._client_id = client_id or BROKER_CLIENT_ID
        app_kwargs = {"authority": "https://login.microsoftonline.com/common"}
        if proxies:
            app_kwargs["proxies"] = proxies
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

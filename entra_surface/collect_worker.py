#!/usr/bin/env python3
"""Runs inside the collector virtualenv.

The GUI's ``entra_surface/collect.py`` wrapper is stdlib-only.  This worker
imports graphcollect from the bundled ``entra_surface/collector`` checkout,
redeems a broker refresh token, and either prints principal claims for a
requested resource (``probe``) or runs a full collection (``run``).
``run-access`` collects with a Microsoft Graph access token and skips ARM.
``run-aadgraph`` collects legacy AAD Graph (and optionally IG/PIM/ARM) using
either a refresh token or an AAD Graph access token.
The newest rotated refresh token is written to --token-out so the parent can
persist it back into .entra-surface-auth.json.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import time
from pathlib import Path

COLLECTOR_DIR = Path(os.environ.get(
    "ENTRA_COLLECTOR_DIR",
    Path(__file__).resolve().parent / "collector")).expanduser().resolve()
sys.path.insert(0, str(COLLECTOR_DIR))

from graphcollect.auth import (  # noqa: E402
    ARM_RES, GRAPH_RES, AuthError, TokenProvider, _decode_jwt)
from graphcollect.aadgraph import (  # noqa: E402
    AAD_GRAPH_AUDIENCES, AAD_GRAPH_RES, AadGraphClient, collect_aadgraph,
    collect_gatherall)
from graphcollect.client import ArmClient, GraphClient  # noqa: E402
from graphcollect.collectors import Runner, collect_all  # noqa: E402
from graphcollect.store import Store  # noqa: E402


class SavingProvider(TokenProvider):
    """TokenProvider that persists the newest rotated refresh token."""

    def __init__(self, refresh_token: str, client_id: str, token_out: str,
                 access_out: str = ""):
        super().__init__(refresh_token, client_id=client_id)
        self._token_out = token_out
        self._access_out = access_out
        self._save()

    def _write(self, value: str, path_name: str) -> None:
        if not path_name:
            return
        path = Path(path_name)
        path.write_text(value)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def _save(self) -> None:
        self._write(self._rt, self._token_out)

    def get_token(self, resource: str) -> str:
        token = super().get_token(resource)
        self._save()
        if resource.rstrip("/") == GRAPH_RES:
            self._write(token, self._access_out)
        return token


def _claims(token: str) -> dict:
    try:
        return _decode_jwt(token)
    except Exception:
        return {}


GRAPH_AUDIENCES = {
    "https://graph.microsoft.com",
    "00000003-0000-0000-c000-000000000000",
}
# Legacy aliases; the GUI passes an arbitrary --resource-uri instead.
PROBE_RESOURCES = {"graph": GRAPH_RES, "aadgraph": AAD_GRAPH_RES}


def _is_graph_access_token(claims: dict) -> bool:
    aud = claims.get("aud") or ""
    values = aud if isinstance(aud, list) else [aud]
    return any(str(a).rstrip("/").lower() in GRAPH_AUDIENCES for a in values)


def _graph_get(token: str, url: str) -> dict:
    try:
        import requests
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=20)
        if r.ok:
            data = r.json()
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _principal(provider: SavingProvider,
               resource: str = GRAPH_RES) -> tuple[dict, str]:
    token = provider.get_token(resource)
    claims = _claims(token)
    me = {}
    org = {}
    if resource.rstrip("/") == GRAPH_RES:
        me = _graph_get(token, "https://graph.microsoft.com/v1.0/me"
                               "?$select=displayName,userPrincipalName,id,mail")
        orgs = _graph_get(token, "https://graph.microsoft.com/v1.0/organization"
                                 "?$select=displayName,id").get("value") or []
        org = orgs[0] if orgs else {}
    scopes = (claims.get("scp") or "").split()
    roles = claims.get("roles") or []
    audience = claims.get("aud") or ""
    if isinstance(audience, list):
        audience = ", ".join(str(a) for a in audience)
    audience = str(audience).rstrip("/")
    expires = claims.get("exp")
    identity = (claims.get("upn") or claims.get("unique_name")
                or claims.get("oid") or claims.get("sub") or "?")
    return {
        "upn": me.get("userPrincipalName") or claims.get("upn") or claims.get("unique_name") or "",
        "name": me.get("displayName") or claims.get("name") or "",
        "object_id": me.get("id") or claims.get("oid") or "",
        "mail": me.get("mail") or claims.get("email") or "",
        "tenant_id": claims.get("tid") or org.get("id") or "",
        "tenant_name": org.get("displayName") or "",
        "client_id": claims.get("appid") or "",
        "audience": str(audience),
        "scopes": scopes,
        "roles": roles,
        "access_expires_at": (
            dt.datetime.fromtimestamp(expires, dt.UTC).isoformat(timespec="seconds")
            if expires else ""),
        "identity": identity,
    }, token


def probe(args) -> int:
    try:
        provider = SavingProvider(args.refresh_token, args.client_id, args.token_out)
        resource = (getattr(args, "resource_uri", "") or "").strip()
        if not resource:
            resource = PROBE_RESOURCES.get(args.resource, GRAPH_RES)
        principal, access_token = _principal(provider, resource)
    except AuthError as exc:
        print(f"[auth] failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[auth] failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"principal": principal, "access_token": access_token}))
    return 0


def run(args) -> int:
    try:
        provider = SavingProvider(args.refresh_token, args.client_id,
                                  args.token_out, args.access_out)
        claims = provider.claims
    except AuthError as exc:
        print(f"[auth] failed: {exc}")
        return 1
    print(f"[auth] {provider.identity} (tid: {claims.get('tid')})")

    graph = GraphClient(lambda: provider.get_token(GRAPH_RES), verbose=args.verbose,
                        user_agent=args.user_agent)
    arm = None
    try:
        provider.get_token(ARM_RES)
        arm = ArmClient(lambda: provider.get_token(ARM_RES), verbose=args.verbose,
                        user_agent=args.user_agent)
    except AuthError as exc:
        print(f"[arm] no Azure Resource Manager token ({exc}); "
              f"Azure tables will be skipped")

    return _run_collection(graph, arm, args, provider.identity,
                           claims.get("tid") or "")


def _run_collection(graph: GraphClient, arm, args, identity: str,
                    tenant_id: str) -> int:
    Path(args.out).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    store = Store(args.out)
    store.set_meta("started_at", dt.datetime.now(dt.UTC).isoformat())
    store.set_meta("identity", identity)
    store.set_meta("tenant_id", tenant_id)

    runner = collect_all(graph, arm, store, verbose=args.verbose)

    print("\n=== collection summary ===")
    for sec in runner.sections:
        flag = {"ok": "+", "partial": "~", "degraded": "!", "skipped": "-",
                "error": "X"}.get(sec.status, "?")
        print(f"  {flag} {sec.name:52s} {sec.status:8s} {sec.count or ''}"
              + (f"  [{sec.note}]" if sec.note else ""))
    print(f"\n{graph.requests_made} Graph requests"
          + (f", {arm.requests_made} ARM requests" if arm else ""))
    slow = sorted(runner.sections, key=lambda s: s.seconds, reverse=True)[:5]
    print("slowest sections: " + ", ".join(
        f"{s.name} {s.seconds:.1f}s" for s in slow))
    if getattr(graph, "throttled", 0):
        print(f"throttled (429) responses: {graph.throttled}")

    store.close()
    print(f"\nwrote {args.out}")
    return 0


def run_access(args) -> int:
    token = args.access_token.strip()
    claims = _claims(token)
    if not claims:
        print("[auth] failed: access token is not a valid JWT", file=sys.stderr)
        return 1
    if not _is_graph_access_token(claims):
        print("[auth] failed: access token audience is not Microsoft Graph",
              file=sys.stderr)
        return 1
    expires = claims.get("exp")
    if expires and int(expires) <= int(time.time()):
        print("[auth] failed: access token is expired", file=sys.stderr)
        return 1

    identity = claims.get("upn") or claims.get("unique_name") or claims.get("oid") or "?"
    print(f"[auth] {identity} (tid: {claims.get('tid')})")
    graph = GraphClient(lambda: token, verbose=args.verbose,
                        user_agent=args.user_agent)
    return _run_collection(graph, None, args, identity, claims.get("tid") or "")


def _is_aadgraph_access_token(claims: dict) -> bool:
    aud = claims.get("aud") or ""
    values = aud if isinstance(aud, list) else [aud]
    return any(str(a).rstrip("/").lower() in AAD_GRAPH_AUDIENCES for a in values)


def run_aadgraph(args) -> int:
    refresh = (args.refresh_token or "").strip()
    access = (args.access_token or "").strip()
    client_id = (args.client_id or "").strip()
    provider = None
    if refresh:
        if not client_id:
            print("[auth] failed: client id is required when a refresh token "
                  "is provided", file=sys.stderr)
            return 1
        provider = SavingProvider(refresh, client_id, args.token_out)

    use_autotoken = bool((args.autotoken and provider is not None)
                         or (refresh and not access))
    if use_autotoken:
        if provider is None:
            print("[auth] failed: --autotoken requires a refresh token",
                  file=sys.stderr)
            return 1
        try:
            token = provider.get_token(AAD_GRAPH_RES)
        except AuthError as exc:
            print(f"[auth] failed: {exc}", file=sys.stderr)
            return 1
    else:
        token = access
    claims = _claims(token)
    if not claims:
        print("[auth] failed: access token is not a valid JWT", file=sys.stderr)
        return 1
    if not _is_aadgraph_access_token(claims):
        print("[auth] failed: access token audience is not AAD Graph "
              "(https://graph.windows.net)", file=sys.stderr)
        return 1
    expires = claims.get("exp")
    if expires and int(expires) <= int(time.time()):
        print("[auth] failed: access token is expired", file=sys.stderr)
        return 1

    identity = (claims.get("upn") or claims.get("unique_name")
                or claims.get("oid") or "?")
    tenant_id = claims.get("tid") or (args.tenant or "") or "myorganization"
    user_agent = (args.user_agent or "").strip()
    if args.evade and not user_agent:
        user_agent = "Microsoft ADO.NET Data Services"
    print(f"[auth] {identity} (tid: {tenant_id})")
    if use_autotoken:
        def token_getter():
            return provider.get_token(AAD_GRAPH_RES)
    else:
        def token_getter():
            return token

    out_path = Path(args.out).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    store = Store(str(out_path))
    store.reset()
    store.set_meta("backend", "aadgraph")
    store.set_meta("started_at", dt.datetime.now(dt.UTC).isoformat())
    store.set_meta("identity", identity)
    store.set_meta("tenant_id", tenant_id)
    store.set_meta("evade", "1" if args.evade else "0")
    store.set_meta("gather_all", "1" if args.gather_all else "0")

    client = AadGraphClient(
        token_getter, tenant_id, user_agent=user_agent,
        evade=args.evade, verbose=args.verbose)
    runner = Runner(client, store, verbose=args.verbose)
    info = collect_aadgraph(runner, mfa=args.mfa)

    extra_sections = []
    if args.gather_all:
        if provider is None:
            print("[gatherall] skipped: a refresh token is required for "
                  "Microsoft Graph and ARM")
        else:
            graph = GraphClient(
                lambda: provider.get_token(GRAPH_RES),
                verbose=args.verbose, user_agent=user_agent)
            arm = None
            try:
                provider.get_token(ARM_RES)
                arm = ArmClient(
                    lambda: provider.get_token(ARM_RES),
                    verbose=args.verbose, user_agent=user_agent)
            except AuthError as exc:
                print(f"[arm] no Azure Resource Manager token ({exc}); "
                      "Azure tables will be skipped")
            try:
                extra_sections = collect_gatherall(
                    graph, arm, store, info.get("groups") or [],
                    verbose=args.verbose)
            except Exception as exc:
                print(f"[gatherall] failed: {str(exc)[:250]}")

    store.set_meta("finished_at", dt.datetime.now(dt.UTC).isoformat())
    store.commit()
    counts = {
        name: store.count(name)
        for name in ("Users", "Groups", "ServicePrincipals", "Applications",
                     "Devices", "RoleAssignments", "AppRoleAssignments",
                     "Policys", "TenantDetails")
    }
    store.close()

    print("\n=== AAD Graph collection summary ===")
    for sec in list(runner.sections) + list(extra_sections):
        flag = {"ok": "+", "partial": "~", "degraded": "!", "skipped": "-",
                "error": "X"}.get(sec.status, "?")
        print(f"  {flag} {sec.name:52s} {sec.status:8s} {sec.count or ''}"
              + (f"  [{sec.note}]" if sec.note else ""))
    print("\ntables: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    print(f"{client.requests_made} AAD Graph requests")
    if getattr(client, "throttled", 0):
        print(f"throttled (429) responses: {client.throttled}")
    print(f"\nwrote {out_path}")
    if not any(counts[name] for name in
               ("Users", "Groups", "ServicePrincipals", "TenantDetails")):
        print("[error] no directory data was collected; check the token's "
              "AAD Graph permissions", file=sys.stderr)
        return 1
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)

    p = sub.add_parser("probe")
    p.add_argument("-rt", "--refresh-token", required=True)
    p.add_argument("-c", "--client-id", required=True)
    p.add_argument("--token-out", default="")
    p.add_argument("--resource", choices=sorted(PROBE_RESOURCES), default="graph")
    p.add_argument("--resource-uri", default="",
                   help="arbitrary resource URI or application ID")
    p.set_defaults(func=probe)

    r = sub.add_parser("run")
    r.add_argument("-rt", "--refresh-token", required=True)
    r.add_argument("-c", "--client-id", required=True)
    r.add_argument("-o", "--out", required=True)
    r.add_argument("-ua", "--user-agent", default="")
    r.add_argument("-v", "--verbose", action="count", default=0)
    r.add_argument("--token-out", default="")
    r.add_argument("--access-out", default="")
    r.set_defaults(func=run)

    a = sub.add_parser("run-access")
    a.add_argument("-at", "--access-token", required=True)
    a.add_argument("-o", "--out", required=True)
    a.add_argument("-ua", "--user-agent", default="")
    a.add_argument("-v", "--verbose", action="count", default=0)
    a.set_defaults(func=run_access)

    g = sub.add_parser("run-aadgraph")
    g.add_argument("-rt", "--refresh-token", default="")
    g.add_argument("-c", "--client-id", default="")
    g.add_argument("-at", "--access-token", default="")
    g.add_argument("-o", "--out", required=True)
    g.add_argument("-ua", "--user-agent", default="")
    g.add_argument("-t", "--tenant", default="")
    g.add_argument("--autotoken", action="store_true")
    g.add_argument("--evade", action="store_true")
    g.add_argument("--gather-all", action="store_true")
    g.add_argument("--mfa", action="store_true")
    g.add_argument("--token-out", default="")
    g.add_argument("-v", "--verbose", action="count", default=0)
    g.set_defaults(func=run_aadgraph)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

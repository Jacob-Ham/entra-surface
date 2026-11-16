#!/usr/bin/env python3
"""Runs inside the collector virtualenv.

The GUI's ``entra_surface/collect.py`` wrapper is stdlib-only.  This worker
imports graphcollect from the bundled ``entra_surface/collector`` checkout,
redeems a broker refresh token, and either prints principal claims for a
requested resource (``probe``) or runs a full collection (``run``).
``run-access`` collects with a Microsoft Graph access token and skips ARM.
Graph collection supports ``--evade`` JSON batching for relationship requests.
``run-aadgraph`` collects legacy AAD Graph (and optionally IG/PIM/ARM) using
either a refresh token or an AAD Graph access token.
The newest rotated refresh token is written to --token-out so the parent can
persist it back into .entra-surface-auth.json.
The ``proxy-test`` mode checks the configured collection proxy end to end.
"""
from __future__ import annotations

import argparse
import datetime as dt
import inspect
import json
import os
import sys
import tempfile
import time
from pathlib import Path

COLLECTOR_DIR = Path(os.environ.get(
    "ENTRA_COLLECTOR_DIR",
    Path(__file__).resolve().parent / "collector")).expanduser().resolve()
REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(COLLECTOR_DIR))
sys.path.insert(0, str(REPO_DIR))

from entra_surface import settings as surface_settings  # noqa: E402
from graphcollect.auth import (  # noqa: E402
    ARM_RES, GRAPH_RES, AuthError, TokenProvider, _decode_jwt)
from graphcollect.aadgraph import (  # noqa: E402
    AAD_GRAPH_AUDIENCES, AAD_GRAPH_RES, AadGraphClient, collect_aadgraph,
    collect_gatherall)
from graphcollect.client import ArmClient, GraphClient  # noqa: E402
from graphcollect.collectors import Runner, Section, collect_all  # noqa: E402
from graphcollect.store import Store  # noqa: E402
from graphcollect.tls import InsecureTLSAdapter  # noqa: E402


EXIT_NO_CORE = 2
EXIT_PARTIAL = 3
CORE_TABLES = ("Users", "Groups", "ServicePrincipals", "TenantDetails")


try:
    _TOKEN_PROVIDER_HAS_UA = "user_agent" in inspect.signature(
        TokenProvider.__init__).parameters
except (TypeError, ValueError):
    _TOKEN_PROVIDER_HAS_UA = False
try:
    _TOKEN_PROVIDER_HAS_TENANT = "tenant" in inspect.signature(
        TokenProvider.__init__).parameters
except (TypeError, ValueError):
    _TOKEN_PROVIDER_HAS_TENANT = False


class SavingProvider(TokenProvider):
    """TokenProvider that persists the newest rotated refresh token."""

    def __init__(self, refresh_token: str, client_id: str, token_out: str,
                 access_out: str = "", proxies: dict | None = None,
                 verify: bool = True, user_agent: str = "",
                 tenant: str = ""):
        kwargs = {}
        if _TOKEN_PROVIDER_HAS_UA:
            kwargs["user_agent"] = user_agent
        if _TOKEN_PROVIDER_HAS_TENANT:
            kwargs["tenant"] = tenant
        super().__init__(refresh_token, client_id=client_id, proxies=proxies,
                         verify=verify, **kwargs)
        self._token_out = token_out
        self._access_out = access_out
        self._saved_rt = ""
        self._saved_access = ""
        self._save()

    def _write(self, value: str, path_name: str) -> None:
        if not path_name:
            return
        path = Path(path_name)
        fd, tmp_name = tempfile.mkstemp(
            prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(value)
            try:
                os.chmod(tmp_name, 0o600)
            except OSError:
                pass
            os.replace(tmp_name, path)
        finally:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass

    def _write_changed(self, value: str, path_name: str, attr: str) -> bool:
        if not path_name or value == getattr(self, attr):
            return False
        self._write(value, path_name)
        setattr(self, attr, value)
        return True

    def _save(self) -> None:
        if not self._token_out:
            return
        with self._lock:
            # Broker refresh tokens rotate on every redemption.  Persist the
            # new value immediately, but do not rewrite the file for cached
            # token lookups.
            self._write_changed(self._rt, self._token_out, "_saved_rt")

    def get_token(self, resource: str) -> str:
        token = super().get_token(resource)
        self._save()
        if resource.rstrip("/") == GRAPH_RES:
            with self._lock:
                self._write_changed(token, self._access_out, "_saved_access")
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


def _load_proxy_config() -> tuple[dict | None, str, bool]:
    try:
        settings = surface_settings.load_settings()
    except Exception as exc:
        raise RuntimeError(f"could not load settings: {exc}") from exc
    proxy = settings.get("proxy") or {}
    if not proxy.get("enabled"):
        return None, "", True
    if surface_settings.is_socks(proxy):
        try:
            import socks  # noqa: F401 - requests imports it for SOCKS support
        except ImportError as exc:
            raise RuntimeError(
                "SOCKS proxies require PySocks; install requirements.txt "
                "in the collector virtualenv") from exc
    proxies = surface_settings.proxy_dict(proxy)
    if not proxies:
        raise RuntimeError("proxy is enabled but no proxy URL is configured")
    verify = not bool(proxy.get("insecure_tls"))
    if not verify:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
    return proxies, str(proxy.get("no_proxy") or "").strip(), verify


def _http_session(verify: bool, user_agent: str = ""):
    import requests
    session = requests.Session()
    if user_agent:
        session.headers["User-Agent"] = user_agent
    if not verify:
        adapter = InsecureTLSAdapter(
            pool_connections=4, pool_maxsize=8, max_retries=0)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
    return session


def _principal(provider: SavingProvider,
               resource: str = GRAPH_RES) -> tuple[dict, str]:
    """Derive principal metadata from the access token itself.

    The token carries the user/service identity (``upn``/``name``/``oid``/
    ``tid``), so no ``/me`` or ``/organization`` calls are needed.  The tenant
    display name is not a claim; callers can reuse a known name from the local
    token store or display the tenant ID instead.
    """
    token = provider.get_token(resource)
    claims = _claims(token)
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
        "upn": claims.get("upn") or claims.get("unique_name") or "",
        "name": claims.get("name") or claims.get("app_displayname") or "",
        "object_id": claims.get("oid") or "",
        "mail": claims.get("email") or claims.get("mail") or "",
        "tenant_id": claims.get("tid") or "",
        "tenant_name": claims.get("tenant_name") or "",
        "client_id": claims.get("appid") or "",
        "audience": str(audience),
        "scopes": scopes,
        "roles": roles,
        "access_expires_at": (
            dt.datetime.fromtimestamp(expires, dt.timezone.utc).isoformat(timespec="seconds")
            if expires else ""),
        "identity": identity,
    }, token


def proxy_test(args) -> int:
    """Check that the configured proxy can reach Microsoft Graph."""
    try:
        proxies, no_proxy, verify = _load_proxy_config()
    except RuntimeError as exc:
        print(f"[proxy] {exc}", file=sys.stderr)
        return 1
    try:
        user_agent = surface_settings.effective_user_agent("global")
    except ValueError as exc:
        print(f"[settings] {exc}", file=sys.stderr)
        return 1
    if not proxies:
        print("[proxy] no proxy is enabled", file=sys.stderr)
        return 1
    url = (args.url or "https://graph.microsoft.com/v1.0/$metadata").strip()
    if no_proxy:
        from requests.utils import should_bypass_proxies
        if should_bypass_proxies(url, no_proxy):
            print(f"[proxy] {url} matches the no-proxy list; the connection "
                  "would bypass the proxy", file=sys.stderr)
            return 1
    session = _http_session(verify, user_agent)
    session.trust_env = False
    started = time.monotonic()
    try:
        response = session.get(url, proxies=proxies, timeout=args.timeout,
                               verify=verify)
    except Exception as exc:
        print(f"[proxy] failed: {exc}", file=sys.stderr)
        return 1
    elapsed_ms = int((time.monotonic() - started) * 1000)
    ok = response.status_code < 500 and response.status_code != 407
    print(json.dumps({
        "ok": ok,
        "status": response.status_code,
        "url": url,
        "elapsed_ms": elapsed_ms,
        "tls_verify": verify,
    }))
    if not ok:
        print(f"[proxy] proxy returned HTTP {response.status_code}",
              file=sys.stderr)
        return 1
    return 0


def probe(args) -> int:
    try:
        proxies, _, verify = _load_proxy_config()
        user_agent = surface_settings.effective_user_agent("tokens")
        provider = SavingProvider(args.refresh_token, args.client_id,
                                  args.token_out, proxies=proxies,
                                  verify=verify, user_agent=user_agent,
                                  tenant=getattr(args, "tenant", "") or "")
        resource = (getattr(args, "resource_uri", "") or "").strip()
        if not resource:
            resource = PROBE_RESOURCES.get(args.resource, GRAPH_RES)
        principal, access_token = _principal(provider, resource)
    except AuthError as exc:
        print(f"[auth] failed: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"[settings] {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"[proxy] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[auth] failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"principal": principal, "access_token": access_token}))
    return 0


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _remove_db_files(path: Path) -> None:
    for suffix in ("-wal", "-shm"):
        try:
            Path(str(path) + suffix).unlink()
        except OSError:
            pass


def _replace_database(tmp_path: Path, out_path: Path) -> None:
    """Atomically swap a completed collection into the destination path."""
    _remove_db_files(tmp_path)
    # A stale WAL/SHM from the previous database must not be paired with the
    # new main file.
    _remove_db_files(out_path)
    os.replace(tmp_path, out_path)


def _discard_database(path: Path) -> None:
    _remove_db_files(path)
    try:
        path.unlink()
    except OSError:
        pass


class NoCoreData(Exception):
    pass


class _AtomicDatabase:
    """Collect into a temporary database and replace the destination on success.

    The previous snapshot remains untouched on failure, early exit or a
    process kill; only a completed run with core directory data is swapped in.
    """

    def __init__(self, out_path: Path, meta: dict | None = None):
        self.out_path = Path(out_path).expanduser().resolve()
        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(
            prefix=f".{self.out_path.name}.",
            suffix=".tmp", dir=str(self.out_path.parent))
        os.close(fd)
        self.tmp_path = Path(name)
        self.store = Store(str(self.tmp_path))
        self.store.reset()
        for key, value in (meta or {}).items():
            self.store.set_meta(key, value)

    def __enter__(self) -> Store:
        return self.store

    def __exit__(self, exc_type, exc, tb) -> bool:
        sidecar = self.out_path.with_name(self.out_path.name + ".failed.json")
        if exc_type is None:
            self.store.set_meta("finished_at", _now())
            self.store.commit()
            self.store.checkpoint()
            self.store.close()
            _replace_database(self.tmp_path, self.out_path)
            try:
                sidecar.unlink()
            except OSError:
                pass
            return False
        # Record the failure in the disposable copy and in a small sidecar;
        # the previous database itself is never modified.
        failed_at = _now()
        message = str(exc)[:500] if exc is not None else "cancelled"
        try:
            self.store.set_meta("failed_at", failed_at)
            self.store.set_meta("failure", message)
            self.store.commit()
        except Exception:
            pass
        try:
            sidecar.write_text(json.dumps({
                "failed_at": failed_at,
                "error": message,
                "destination": str(self.out_path),
                "temporary_database": str(self.tmp_path),
            }, indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass
        try:
            self.store.close()
        except Exception:
            pass
        _discard_database(self.tmp_path)
        return False


def _print_summary(runner, graph, arm) -> None:
    print("\n=== collection summary ===")
    for sec in runner.sections:
        flag = {"ok": "+", "partial": "~", "degraded": "!", "skipped": "-",
                "error": "X"}.get(sec.status, "?")
        print(f"  {flag} {sec.name:52s} {sec.status:8s} {sec.count or ''}"
              + (f"  [{sec.note}]" if sec.note else ""))
    print(f"\n{graph.requests_made} Graph requests"
          + (f", {getattr(graph, 'subrequests_made', 0)} batched subrequests"
             if getattr(graph, "batch", False) else "")
          + (f", {arm.requests_made} ARM requests" if arm else ""))
    slow = sorted(runner.sections, key=lambda s: s.seconds, reverse=True)[:5]
    print("slowest sections: " + ", ".join(
        f"{s.name} {s.seconds:.1f}s" for s in slow))
    if getattr(graph, "throttled", 0):
        print(f"throttled (429) responses: {graph.throttled}")


def run(args) -> int:
    try:
        proxies, no_proxy, verify = _load_proxy_config()
    except RuntimeError as exc:
        print(f"[proxy] {exc}")
        return 1
    try:
        user_agent = surface_settings.effective_user_agent(
            "collect", args.user_agent)
        token_user_agent = user_agent
        evade = bool(getattr(args, "evade", False))
        if evade and not user_agent:
            user_agent = "Microsoft ADO.NET Data Services"
    except ValueError as exc:
        print(f"[settings] {exc}")
        return 1

    tenant = str(getattr(args, "tenant", "") or "").strip()
    access_fallback = str(getattr(args, "access_token", "") or "").strip()
    provider = None
    claims = {}
    try:
        provider = SavingProvider(args.refresh_token, args.client_id,
                                  args.token_out, args.access_out,
                                  proxies=proxies, verify=verify,
                                  user_agent=token_user_agent,
                                  tenant=tenant)
        claims = provider.claims
        identity = provider.identity
    except AuthError as exc:
        # A stale/revoked refresh token should not block a collection when the
        # saved record still has a valid access token for Graph.
        fallback_claims = _claims(access_fallback)
        expires = fallback_claims.get("exp")
        if (not access_fallback or not fallback_claims
                or not _is_graph_access_token(fallback_claims)
                or (expires and int(expires) <= int(time.time()))):
            print(f"[auth] failed: {exc}")
            return 1
        claims = fallback_claims
        identity = (claims.get("upn") or claims.get("unique_name")
                    or claims.get("oid") or "?")
        provider = None
        print(f"[auth] refresh failed ({exc}); using the saved access token")
    except (ValueError, RuntimeError) as exc:
        print(f"[settings] {exc}")
        return 1
    print(f"[auth] {identity} (tid: {claims.get('tid')})")

    def get_graph_token() -> str:
        if provider is not None:
            return provider.get_token(GRAPH_RES)
        return access_fallback

    graph = GraphClient(get_graph_token, verbose=args.verbose,
                        user_agent=user_agent, batch=evade,
                        proxies=proxies, no_proxy=no_proxy, verify=verify)
    arm = None
    if provider is not None:
        try:
            provider.get_token(ARM_RES)
            arm = ArmClient(lambda: provider.get_token(ARM_RES),
                            verbose=args.verbose, user_agent=user_agent,
                            proxies=proxies, no_proxy=no_proxy, verify=verify)
        except Exception as exc:
            print(f"[arm] no Azure Resource Manager token ({exc}); "
                  f"Azure tables will be skipped")

    return _run_collection(graph, arm, args, identity,
                           claims.get("tid") or tenant or "")


def _run_collection(graph: GraphClient, arm, args, identity: str,
                    tenant_id: str) -> int:
    out_path = Path(args.out).expanduser().resolve()
    meta = {
        "started_at": _now(),
        "identity": identity,
        "tenant_id": tenant_id,
        "backend": "graph",
    }
    try:
        with _AtomicDatabase(out_path, meta) as store:
            runner = collect_all(graph, arm, store, verbose=args.verbose)
            _print_summary(runner, graph, arm)
            counts = {
                name: store.count(name)
                for name in ("Users", "Groups", "ServicePrincipals",
                             "Applications", "Devices", "RoleAssignments",
                             "AppRoleAssignments", "Policys", "TenantDetails")
            }
            if not any(counts[name] for name in CORE_TABLES):
                raise NoCoreData(
                    "no directory data was collected; check the token's "
                    "Microsoft Graph permissions")
            print("\ntables: " + ", ".join(
                f"{key}={value}" for key, value in counts.items()))
    except NoCoreData as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return EXIT_NO_CORE
    except Exception as exc:
        print(f"[error] collection failed: {exc}", file=sys.stderr)
        return 1
    print(f"\nwrote {out_path}")
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
    try:
        proxies, no_proxy, verify = _load_proxy_config()
    except RuntimeError as exc:
        print(f"[proxy] {exc}", file=sys.stderr)
        return 1
    try:
        user_agent = surface_settings.effective_user_agent(
            "collect", args.user_agent)
    except ValueError as exc:
        print(f"[settings] {exc}", file=sys.stderr)
        return 1
    evade = bool(getattr(args, "evade", False))
    if evade and not user_agent:
        user_agent = "Microsoft ADO.NET Data Services"
    graph = GraphClient(lambda: token, verbose=args.verbose,
                        user_agent=user_agent, batch=evade,
                        proxies=proxies, no_proxy=no_proxy, verify=verify)
    return _run_collection(graph, None, args, identity, claims.get("tid") or "")


def _is_aadgraph_access_token(claims: dict) -> bool:
    aud = claims.get("aud") or ""
    values = aud if isinstance(aud, list) else [aud]
    return any(str(a).rstrip("/").lower() in AAD_GRAPH_AUDIENCES for a in values)


def run_aadgraph(args) -> int:
    refresh = (args.refresh_token or "").strip()
    access = (args.access_token or "").strip()
    client_id = (args.client_id or "").strip()
    try:
        proxies, no_proxy, verify = _load_proxy_config()
    except RuntimeError as exc:
        print(f"[proxy] {exc}", file=sys.stderr)
        return 1
    try:
        user_agent = surface_settings.effective_user_agent(
            "collect", args.user_agent)
    except ValueError as exc:
        print(f"[settings] {exc}", file=sys.stderr)
        return 1
    token_user_agent = user_agent
    if args.evade and not user_agent:
        user_agent = "Microsoft ADO.NET Data Services"
    access_claims = _claims(access) if access else {}
    tenant_hint = (args.tenant or "").strip() or access_claims.get("tid") or ""
    provider = None
    refresh_failed = False
    if refresh:
        if not client_id:
            print("[auth] failed: client id is required when a refresh token "
                  "is provided", file=sys.stderr)
            return 1
        provider = SavingProvider(refresh, client_id, args.token_out,
                                  proxies=proxies, verify=verify,
                                  user_agent=token_user_agent,
                                  tenant=tenant_hint)

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
            # Fall back to a valid saved AAD Graph access token rather than
            # failing the whole collection on a stale refresh token.
            fallback = _claims(access)
            expires = fallback.get("exp")
            if (access and fallback and _is_aadgraph_access_token(fallback)
                    and not (expires and int(expires) <= int(time.time()))):
                print(f"[auth] refresh failed ({exc}); using the saved "
                      "AAD Graph access token")
                token = access
                use_autotoken = False
                refresh_failed = True
            else:
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
    print(f"[auth] {identity} (tid: {tenant_id})")
    if use_autotoken:
        def token_getter():
            return provider.get_token(AAD_GRAPH_RES)
    else:
        def token_getter():
            return token

    out_path = Path(args.out).expanduser().resolve()
    meta = {
        "backend": "aadgraph",
        "started_at": _now(),
        "identity": identity,
        "tenant_id": tenant_id,
        "evade": "1" if args.evade else "0",
        "gather_all": "1" if args.gather_all else "0",
    }
    gatherall_failed = False
    try:
        with _AtomicDatabase(out_path, meta) as store:
            client = AadGraphClient(
                token_getter, tenant_id, user_agent=user_agent,
                evade=args.evade, verbose=args.verbose, proxies=proxies,
                no_proxy=no_proxy, verify=verify)
            runner = Runner(client, store, verbose=args.verbose)
            info = collect_aadgraph(runner, mfa=args.mfa)

            extra_sections = []
            if args.gather_all:
                if provider is None or refresh_failed:
                    print("[gatherall] skipped: a working refresh token is "
                          "required for Microsoft Graph and ARM")
                    gatherall_failed = True
                else:
                    graph = GraphClient(
                        lambda: provider.get_token(GRAPH_RES),
                        verbose=args.verbose, user_agent=user_agent,
                        proxies=proxies, no_proxy=no_proxy, verify=verify)
                    arm = None
                    try:
                        provider.get_token(ARM_RES)
                        arm = ArmClient(
                            lambda: provider.get_token(ARM_RES),
                            verbose=args.verbose, user_agent=user_agent,
                            proxies=proxies, no_proxy=no_proxy, verify=verify)
                    except Exception as exc:
                        print(f"[arm] no Azure Resource Manager token ({exc}); "
                              "Azure tables will be skipped")
                    try:
                        extra_sections = collect_gatherall(
                            graph, arm, store, info.get("groups") or [],
                            verbose=args.verbose)
                    except Exception as exc:
                        print(f"[gatherall] failed: {str(exc)[:250]}")
                        failed = Section("gatherall")
                        failed.status = "error"
                        failed.note = str(exc)[:200]
                        extra_sections = [failed]
                        gatherall_failed = True
                    if any(sec.status in ("error", "degraded")
                           or (sec.name == "AZ (ARM)"
                               and sec.status == "skipped")
                           for sec in extra_sections):
                        gatherall_failed = True

            counts = {
                name: store.count(name)
                for name in ("Users", "Groups", "ServicePrincipals",
                             "Applications", "Devices", "RoleAssignments",
                             "AppRoleAssignments", "Policys", "TenantDetails")
            }
            if not any(counts[name] for name in CORE_TABLES):
                raise NoCoreData(
                    "no directory data was collected; check the token's "
                    "AAD Graph permissions")

            print("\n=== AAD Graph collection summary ===")
            for sec in list(runner.sections) + list(extra_sections):
                flag = {"ok": "+", "partial": "~", "degraded": "!",
                        "skipped": "-", "error": "X"}.get(sec.status, "?")
                print(f"  {flag} {sec.name:52s} {sec.status:8s} "
                      f"{sec.count or ''}"
                      + (f"  [{sec.note}]" if sec.note else ""))
            print("\ntables: " + ", ".join(
                f"{key}={value}" for key, value in counts.items()))
            print(f"{client.requests_made} AAD Graph requests")
            if getattr(client, "throttled", 0):
                print(f"throttled (429) responses: {client.throttled}")
    except NoCoreData as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return EXIT_NO_CORE
    except Exception as exc:
        print(f"[error] collection failed: {exc}", file=sys.stderr)
        return 1
    print(f"\nwrote {out_path}")
    if gatherall_failed:
        print("[partial] gather-all did not complete every requested "
              "section; the core AAD Graph snapshot was saved",
              file=sys.stderr)
        return EXIT_PARTIAL
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
    p.add_argument("--tenant", default="",
                   help="tenant ID/domain for the token authority")
    p.set_defaults(func=probe)

    t = sub.add_parser("proxy-test")
    t.add_argument("--url",
                   default="https://graph.microsoft.com/v1.0/$metadata")
    t.add_argument("--timeout", type=float, default=20.0)
    t.set_defaults(func=proxy_test)

    r = sub.add_parser("run")
    r.add_argument("-rt", "--refresh-token", required=True)
    r.add_argument("-c", "--client-id", required=True)
    r.add_argument("-o", "--out", required=True)
    r.add_argument("-ua", "--user-agent", default="")
    r.add_argument("-v", "--verbose", action="count", default=0)
    r.add_argument("--token-out", default="")
    r.add_argument("--access-out", default="")
    r.add_argument("-at", "--access-token", default="",
                   help="fallback access token when the refresh token fails")
    r.add_argument("-t", "--tenant", default="",
                   help="tenant ID/domain for the token authority")
    r.add_argument("--evade", action="store_true",
                   help="batch relationship requests and use the evade UA")
    r.set_defaults(func=run)

    a = sub.add_parser("run-access")
    a.add_argument("-at", "--access-token", required=True)
    a.add_argument("-o", "--out", required=True)
    a.add_argument("-ua", "--user-agent", default="")
    a.add_argument("-v", "--verbose", action="count", default=0)
    a.add_argument("--evade", action="store_true",
                   help="batch relationship requests and use the evade UA")
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

"""Analysis cache persistence and run-to-run diffing."""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import sqlite3
import tempfile
from collections import Counter
from pathlib import Path

CACHE_DIR = Path(__file__).resolve().parents[1] / "data" / "databases" / ".cache"


CACHE_VERSION = 20

CACHE_FINGERPRINT_TABLES = (
    "Users", "ServicePrincipals", "Applications", "Groups", "Devices",
    "RoleAssignments", "AppRoleAssignments", "AZroleAssignments", "Policys",
)


def compute_config_fingerprint(config_resources, check_cfg):
    """Deterministic digest of the *effective* analysis config.

    Includes the resource/role mapping, check config (directory roles,
    severities, suppression, enabled checks, labels) and Azure role mapping.
    Any config edit therefore invalidates cached findings.
    """
    payload = {"resources": config_resources or {},
               "checks": check_cfg or {}}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def cache_payload_valid(payload):
    """A cache payload is only useful when the analysis result shape is intact."""
    if not isinstance(payload, dict):
        return False
    results = payload.get("results")
    if not isinstance(results, list):
        return False
    for res in results:
        if not isinstance(res, dict) or not isinstance(res.get("findings"), list):
            return False
    return True


def cache_fresh(cached, fingerprint):
    return bool(
        cache_payload_valid(cached)
        and cached.get("version") == CACHE_VERSION
        and cached.get("fingerprint") == fingerprint)


def cache_paths(db_path):
    """Per-database cache and sidecar metadata paths."""
    db = Path(db_path).resolve()
    digest = hashlib.sha1(str(db).encode("utf-8")).hexdigest()[:16]
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", db.stem).strip("-")[:60] or "db"
    return (CACHE_DIR / f"{safe}-{digest}.cache.gz",
            CACHE_DIR / f"{safe}-{digest}.meta.json")


def save_cache_sidecar(path, db_path, fingerprint, generated_at,
                       config_fingerprint=None):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "version": CACHE_VERSION,
            "db": str(Path(db_path).resolve()),
            "fingerprint": fingerprint,
            "config_fingerprint": config_fingerprint or "",
            "generated_at": generated_at,
        }, indent=2), encoding="utf-8")
    except OSError as exc:
        print(f"warning: could not write cache metadata: {exc}", file=sys.stderr)


def load_cache_sidecar(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_analysis_cache(cache_path, meta_path, db_path, fingerprint,
                         generated_at, results, tenant_summary,
                         group_roles, group_eligible_roles,
                         config_fingerprint=None):
    wrote = save_cache(cache_path, {
        "version": CACHE_VERSION,
        "fingerprint": fingerprint,
        "config_fingerprint": config_fingerprint or "",
        "generated_at": generated_at,
        "results": results,
        "tenant_summary": tenant_summary,
        "group_roles": group_roles,
        "group_eligible_roles": group_eligible_roles,
    })
    if wrote:
        save_cache_sidecar(meta_path, db_path, fingerprint, generated_at,
                           config_fingerprint)


def compute_db_fingerprint(db_path, cur, config_fingerprint=None):
    """Cheap fingerprint of the audited database plus the effective config:
    file metadata, core-table row counts and a deterministic config hash. Any
    change to the database or to severity/suppression/role mappings triggers a
    reanalysis instead of reusing stale findings."""
    parts = [db_path.stat().st_mtime_ns, db_path.stat().st_size]
    for table in CACHE_FINGERPRINT_TABLES:
        try:
            cur.execute(f'SELECT COUNT(*) FROM "{table}"')
            parts.append(cur.fetchone()[0])
        except sqlite3.OperationalError:
            parts.append(-1)
    parts.append(config_fingerprint or "")
    return parts


def _json_default(obj):
    if isinstance(obj, set):
        return sorted(obj, key=str)
    return str(obj)


def _restore_object_ids(results):
    """JSON has no sets: turn object_ids list values back into sets in place
    (the only set-bearing field in findings)."""
    for res in results or []:
        for f in res.get("findings") or []:
            o = f.get("object_ids")
            if isinstance(o, dict):
                f["object_ids"] = {k: set(v) for k, v in o.items()}


def save_cache(path, payload):
    """Stream the payload to the cache file in small chunks (no full deep
    copy or monolithic string) and gzip it — findings JSON compresses very
    well, keeping the save-time memory spike flat and the file small."""
    path = Path(path)
    tmp_path = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
        os.close(fd)
        tmp_path = Path(tmp_name)
        with gzip.open(tmp_path, "wt", encoding="utf-8") as fh:
            for chunk in json.JSONEncoder(default=_json_default,
                                          separators=(",", ":")).iterencode(payload):
                fh.write(chunk)
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        os.replace(tmp_path, path)
        return True
    except OSError as exc:
        print(f"warning: could not write cache: {exc}", file=sys.stderr)
        return False
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except OSError:
                pass


def load_cache(path):
    """Load and validate a cache payload.

    A truncated gzip stream, corrupt JSON, wrong top-level type or missing
    result list is treated as a cache miss (None) instead of crashing startup
    or a runtime analysis. Legacy uncompressed caches remain supported.
    """
    payload = None
    try:
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, EOFError, gzip.BadGzipFile, ValueError, UnicodeError,
            TypeError):
        # older caches were written uncompressed
        try:
            with open(path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, ValueError, UnicodeError, TypeError):
            return None
    if not cache_payload_valid(payload):
        return None
    _restore_object_ids(payload.get("results"))
    return payload


def _finding_identity(f):
    """Stable diff identity for one finding.

    (check_id, primary_id) alone collapses checks like priv_app_ownership that
    emit one finding per grant/principal. Include the target, permission,
    resource and policy/user/group identity fields when present, then let the
    index add an ordinal for genuinely identical duplicates.
    """
    target = f.get("target") or {}
    parts = [str(f.get("check_id") or ""), str(f.get("primary_id") or "")]
    for key in ("permission", "resource_name", "resource", "policy_id",
                "user_id", "group_id", "sp_id", "device_id", "role_id",
                "app_role_id", "principal_id", "policyIds"):
        value = f.get(key)
        if value not in (None, "", [], {}, ()):
            parts.append(f"{key}={value}")
    if isinstance(target, dict):
        for key in ("type", "id"):
            value = target.get(key)
            if value not in (None, ""):
                parts.append(f"target.{key}={value}")
    return tuple(parts)


def _index_findings(results):
    """Map stable identity (+ duplicate ordinal) to findings."""
    indexed = {}
    seen = Counter()
    for res in results or []:
        if not isinstance(res, dict):
            continue
        for f in res.get("findings") or []:
            if not isinstance(f, dict):
                continue
            key = _finding_identity(f)
            ordinal = seen[key]
            seen[key] += 1
            indexed[(key, ordinal)] = f
    return indexed


def compute_diff(old_results, new_results):
    """Compare two analysis runs by stable finding identity: added and removed
    findings, plus changed severity/title/evidence for survivors."""
    old_map = _index_findings(old_results)
    new_map = _index_findings(new_results)
    added = [new_map[k] for k in sorted(new_map) if k not in old_map]
    removed = [old_map[k] for k in sorted(old_map) if k not in new_map]
    changed = []
    for k in sorted(new_map):
        if k not in old_map:
            continue
        old, new = old_map[k], new_map[k]
        if (old.get("severity") != new.get("severity")
                or old.get("title") != new.get("title")
                or old.get("evidence") != new.get("evidence")):
            changed.append((old, new))
    return {"added": added, "removed": removed, "changed": changed}

"""Server-side profile, detail and LRU endpoints."""
from __future__ import annotations

import sqlite3

from ..profiles import fetch_full_details, make_profile_builder
from ..state import SERVE_STATE, SERVE_STATE_LOCK, serve_generation

PROFILE_LRU_MAX = 4000
DETAIL_LRU_MAX = 4000


def _lru_get(cache, key):
    with SERVE_STATE_LOCK:
        if key in cache:
            value = cache[key]
            del cache[key]
            cache[key] = value  # move to most-recently-used end
            return value
    return None


def _lru_put(cache, key, value, max_size):
    with SERVE_STATE_LOCK:
        cache[key] = value
        while len(cache) > max_size and cache:
            cache.pop(next(iter(cache)))


def _profile_builder():
    """Return the current profile builder, never publishing one built from a
    replaced analysis generation (database reload can race a slow request)."""
    for _attempt in range(3):
        with SERVE_STATE_LOCK:
            builder = SERVE_STATE.get("profile_builder")
            if (builder is not None
                    and SERVE_STATE.get("profile_builder_generation")
                    == SERVE_STATE.get("generation", 0)):
                return builder
            generation = SERVE_STATE.get("generation", 0)
            graph = SERVE_STATE.get("graph") or {}
            check_cfg = SERVE_STATE.get("check_cfg") or {}
            group_roles = SERVE_STATE.get("group_roles") or {}
            group_eligible_roles = SERVE_STATE.get("group_eligible_roles") or {}
        builder = make_profile_builder(graph, check_cfg, group_roles,
                                       group_eligible_roles)
        with SERVE_STATE_LOCK:
            if SERVE_STATE.get("generation", 0) == generation:
                SERVE_STATE["profile_builder"] = builder
                SERVE_STATE["profile_builder_generation"] = generation
                return builder
        # The database was reloaded while building: rebuild against the new
        # graph instead of publishing stale tenant data.
    raise RuntimeError("analysis state changed repeatedly while building profile")


def _fetch_one_detail(kind, oid):
    """One raw record (with Arc enrichment) read from the collected database.
    The DB is opened read-only per request; results are LRU-cached."""
    db_path = SERVE_STATE.get("db_path")
    if not db_path:
        return None
    con = None
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = con.cursor()
        recs = fetch_full_details(cur,
                                  {oid} if kind == "sp" else set(),
                                  {oid} if kind == "app" else set(),
                                  {oid} if kind == "user" else set(),
                                  {oid} if kind == "device" else set())
        return (recs.get(kind) or {}).get(oid)
    except sqlite3.Error:
        return None
    finally:
        if con is not None:
            con.close()


def serve_profile_response(kind, oid):
    generation = serve_generation()
    if kind == "user":
        with SERVE_STATE_LOCK:
            prof = next((f for f in SERVE_STATE["user_findings"]
                         if f.get("user_id") == oid), None)
    elif kind in ("sp", "app"):
        cache = SERVE_STATE["profiles_lru"]
        prof = _lru_get(cache, (kind, oid))
        if prof is None:
            builder = _profile_builder()
            prof = builder[kind](oid)
            if prof is not None and serve_generation() == generation:
                _lru_put(cache, (kind, oid), prof, PROFILE_LRU_MAX)
    elif kind == "group":
        with SERVE_STATE_LOCK:
            prof = SERVE_STATE["group_profiles"].get(oid)
    elif kind == "policy":
        with SERVE_STATE_LOCK:
            prof = SERVE_STATE["policy_profiles"].get(oid)
    else:
        return {"error": f"unknown profile kind: {kind}"}, 400
    if prof is None:
        return {"error": "not found"}, 404
    return prof, 200


def serve_details_response(kind, oid):
    if kind not in ("sp", "app", "user", "device"):
        return {"error": f"unknown detail kind: {kind}"}, 400
    generation = serve_generation()
    cache = SERVE_STATE["details_lru"]
    rec = _lru_get(cache, (kind, oid))
    if rec is None:
        rec = _fetch_one_detail(kind, oid)
        if rec is not None and serve_generation() == generation:
            _lru_put(cache, (kind, oid), rec, DETAIL_LRU_MAX)
    if rec is None:
        return {"error": "not found"}, 404
    return rec, 200



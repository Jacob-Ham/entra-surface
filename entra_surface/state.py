"""Shared live-serving state and lock."""
from __future__ import annotations

import threading


SERVE_STATE = {"shell": "", "user_findings": [], "tables": {},
               "profiles2": {"sp": {}, "app": {}}, "group_profiles": {},
               "policy_profiles": {}, "details": {"sp": {}, "app": {}, "device": {}},
               "records": [], "db_path": None, "ca_analysis": None,
               "graph": {}, "check_cfg": {}, "group_roles": {},
               "group_eligible_roles": {}, "profile_builder": None,
               "profiles_lru": {}, "details_lru": {}, "generation": 0}

# Guards the mutable serve state (analysis swap, profile builder, LRUs and CA
# job state). ThreadingHTTPServer serves requests concurrently.
SERVE_STATE_LOCK = threading.RLock()
CA_LOCK = SERVE_STATE_LOCK


def serve_generation():
    with SERVE_STATE_LOCK:
        return SERVE_STATE.get("generation", 0)

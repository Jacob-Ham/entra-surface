"""Configuration loading and Azure RBAC severity mapping.

Pure module: reads JSON config files and maps role severities. It does not
import the report, graph, checks, or serving layers.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .findings import SEVERITY_ORDER

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = REPO_ROOT / "privileged_roles.json"
DEFAULT_AZURE_CONFIG = REPO_ROOT / "azure_roles.json"

DEFAULT_CHECK_CFG = {
    "enabled": {},                 # {check_id: bool} - empty means all enabled
    "min_severity": "Info",        # drop findings below this
    "suppress": [],                # ["check_id:primary_id"] keys to silence
    "include_disabled": True,      # include disabled/deleted principals
}


class ConfigError(ValueError):
    """A configuration file is missing, malformed, or has an invalid shape."""


def _load_json_config(path, label):
    path = Path(path)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise ConfigError(f"cannot read {label} config {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"invalid JSON in {label} config {path} "
            f"(line {exc.lineno}, column {exc.colno}): {exc.msg}") from exc
    except UnicodeError as exc:
        raise ConfigError(
            f"invalid text encoding in {label} config {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{label} config {path} must contain a JSON object")
    return data


def load_config(config_path):
    data = _load_json_config(config_path, "privileged roles")
    resources = {}
    raw_resources = data.get("resources")
    if raw_resources is None:
        raw_resources = {}
    if not isinstance(raw_resources, dict):
        raise ConfigError(
            f"privileged roles config {config_path}: 'resources' must be an object")
    for resource_app_id, entry in raw_resources.items():
        if not isinstance(entry, dict):
            raise ConfigError(
                f"privileged roles config {config_path}: "
                f"resources[{resource_app_id!r}] must be an object")
        roles = {}
        raw_roles = entry.get("roles") or []
        if not isinstance(raw_roles, list):
            raise ConfigError(
                f"privileged roles config {config_path}: "
                f"resources[{resource_app_id!r}].roles must be a list")
        for index, role in enumerate(raw_roles):
            if not isinstance(role, dict) or not isinstance(role.get("value"), str):
                raise ConfigError(
                    f"privileged roles config {config_path}: "
                    f"resources[{resource_app_id!r}].roles[{index}] is missing "
                    f"a string 'value'")
            roles[role["value"]] = {
                "severity": role.get("severity", "High"),
                "reason": role.get("reason", ""),
            }
        resources[resource_app_id] = {"name": entry.get("name", resource_app_id), "roles": roles}

    check_cfg = dict(DEFAULT_CHECK_CFG)
    cfg = data.get("checks")
    if cfg is None:
        cfg = {}
    if not isinstance(cfg, dict):
        raise ConfigError(
            f"privileged roles config {config_path}: 'checks' must be an object")
    for key in ("enabled", "suppress"):
        if isinstance(cfg.get(key), dict if key == "enabled" else list):
            check_cfg[key] = cfg[key]
    if isinstance(cfg.get("min_severity"), str) and cfg["min_severity"] in SEVERITY_ORDER:
        check_cfg["min_severity"] = cfg["min_severity"]
    if isinstance(cfg.get("include_disabled"), bool):
        check_cfg["include_disabled"] = cfg["include_disabled"]

    directory_roles = {}
    raw_directory_roles = data.get("directory_roles")
    if raw_directory_roles is None:
        raw_directory_roles = {}
    if not isinstance(raw_directory_roles, dict):
        raise ConfigError(
            f"privileged roles config {config_path}: 'directory_roles' must be an object")
    for name, sev in raw_directory_roles.items():
        if isinstance(name, str) and name.startswith("_"):
            continue  # comment keys
        if isinstance(sev, str) and sev in SEVERITY_ORDER:
            directory_roles[name] = sev
        else:
            directory_roles[name] = "Info"
    check_cfg["directory_roles"] = directory_roles

    role_labels = {}
    raw_labels = data.get("role_labels")
    if raw_labels is None:
        raw_labels = {}
    if not isinstance(raw_labels, dict):
        raise ConfigError(
            f"privileged roles config {config_path}: 'role_labels' must be an object")
    for value, label in raw_labels.items():
        if isinstance(value, str) and isinstance(label, str) and not value.startswith("_"):
            role_labels[value] = label
    check_cfg["role_labels"] = role_labels

    directory_role_descriptions = {}
    raw_descriptions = data.get("directory_role_descriptions")
    if raw_descriptions is None:
        raw_descriptions = {}
    if not isinstance(raw_descriptions, dict):
        raise ConfigError(
            f"privileged roles config {config_path}: "
            "'directory_role_descriptions' must be an object")
    for name, desc in raw_descriptions.items():
        if isinstance(name, str) and isinstance(desc, str) and not name.startswith("_"):
            directory_role_descriptions[name] = desc
    check_cfg["directory_role_descriptions"] = directory_role_descriptions
    return resources, check_cfg


AZ_SCOPE_TYPES = {"Subscription", "Resource group", "Resource", "Management group", "Root", "Scope"}


def load_azure_roles(config_path):
    """Azure RBAC role -> severity mapping (role name, optionally 'Role@ScopeType').

    Same conventions as directory_roles: '_'-prefixed keys are comments, invalid
    severities fall back to Info. A missing file degrades to an empty mapping
    (everything renders Info) with a warning.
    """
    azure_roles = {}
    if config_path is None or not Path(config_path).exists():
        print(f"warning: azure roles config not found: {config_path} "
              "(all Azure roles will render as Info)", file=sys.stderr)
        return azure_roles
    data = _load_json_config(config_path, "Azure roles")
    for key, sev in data.items():
        if not isinstance(key, str) or key.startswith("_") or not isinstance(sev, str):
            continue
        if sev not in SEVERITY_ORDER:
            azure_roles[key] = "Info"
            continue
        if "@" in key:
            role, _, scope = key.rpartition("@")
            if role and scope in AZ_SCOPE_TYPES:
                azure_roles[key] = sev
                continue
        azure_roles[key] = sev
    return azure_roles


def azure_severity_for(mapping, role, scope_type):
    """'Role@ScopeType' exact match, then plain 'Role', then Info (unrated)."""
    if scope_type:
        scoped = mapping.get(f"{role}@{scope_type}")
        if scoped:
            return scoped
    return mapping.get(role, "Info")


def apply_azure_severity(graph, mapping):
    """Stamp every collected ARM assignment with its configured severity."""
    for key in ("az_roles", "az_sp_roles", "az_user_roles"):
        for entries in graph[key].values():
            for a in entries:
                a["severity"] = azure_severity_for(mapping, a.get("role", ""), a.get("scope_type", ""))

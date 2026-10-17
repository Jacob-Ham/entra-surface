# Entra Surface

Entra ID attack-surface report from a [ROADrecon](https://github.com/dirkjanm/ROADtools) database. Runs a registry of checks over the tenant data and serves a sortable, filterable HTML report with drilldowns.

## Requirements

- Python 3 (stdlib only)
- A roadrecon database (`roadrecon.db`) for the tenant you want to audit

## Usage

```sh
python3 entra-surface.py --db roadrecon.db
```

Opens `http://127.0.0.1:8787`. Startup takes a few minutes on large tenants.

### Options

| Option | Description |
| --- | --- |
| `--db` | Roadrecon SQLite database (default: `roadrecon.db`) |
| `--config` | Privileged-roles config (default: `privileged_roles.json`) |
| `--azure-config` | Azure RBAC role config (default: `azure_roles.json`) |
| `--port` | Port to serve on (default: `8787`) |
| `--timing` | Print per-phase timings and peak memory |

## Report

- **Tabs:** Apps / Service principals, Users, Active Directory / On-prem, Groups, Conditional Access, Azure Arc.
- **Column manager:** add, remove, and reorder columns per table (persisted in the browser).
- **Filters:** free-text, plus an advanced query language — `field:value`, `contains:`, `AND`/`OR`/`NOT`, and `uniq:column` to deduplicate by any column.
- **Drawers:** per-row detail with roles, owners, Azure RBAC assignments, and a Raw tab with the full captured record.
- **Sync summary:** engine, password writeback, authentication mode (PHS / PTA / federated), and Desktop SSO.
- **Azure Arc:** onboarded machines, Arc role holders, onboarding service principals, and resource providers — detected by tenant-independent identifiers (resource-provider namespaces, role-definition GUIDs, first-party appIds).

Checks are enabled/disabled via the `checks` block in `privileged_roles.json`; the tool always serves the full report.

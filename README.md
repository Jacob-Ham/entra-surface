# Entra Surface

Entra ID (Azure AD) attack surface parser. Reads a [roadrecon](https://github.com/dirkjanm/ROADtools) SQLite database and produces a report of dangerous users, applications, service principals, groups, Conditional Access policies, and AD sync configuration.

## Requirements

- Python 3 (stdlib only, no dependencies)
- A roadrecon database from the tenant you want to audit

## Usage

```sh
python3 entra-surface.py --db roadrecon.db
```

Writes `entra-surface-report.html` (open it in a browser). Optionally serve it instead, which is preferable for large tenants, fetches the users table on demand.

```sh
python3 entra-surface.py --db roadrecon.db --serve --port 8787
```

> **_NOTE:_** Server will take 0 - 5 minutes to spin up depending on the size of the tenant.

### Options

| Option | Description |
| --- | --- |
| `--db` | Path to the roadrecon SQLite database (default: `roadrecon.db`) |
| `--config` | Privileged-roles config JSON (default: `privileged_roles.json`) |
| `--azure-config` | Azure RBAC role severity config (default: `azure_roles.json`) |
| `--output` | HTML report path (default: `entra-surface-report.html`) |
| `--check` | Only run the given checks (comma-separated) |
| `--exclude-check` | Skip the given checks (comma-separated) |
| `--min-severity` | Drop findings below this severity (Critical/High/Medium/Low/Info) |
| `--include-disabled` | Include disabled/soft-deleted service principals |
| `--serve` | Serve the report over HTTP on 127.0.0.1 instead of writing a file |
| `--port` | Port for `--serve` (default: 8787) |
| `--timing` | Print per-phase timings and peak memory |

## Config

- `privileged_roles.json` — which app permissions and directory roles count as privileged, with severities and reasoning. Edit freely per tenant.
- `azure_roles.json` — Azure RBAC role names (optionally `Role@ScopeType`) to severities.

## Checks

Runs a registry of checks and emits structured findings (check id, category, severity, evidence, object ids). See the module docstring in `entra-surface.py` for the full list, including:

- privileged app (app-only) permissions resolved to human owners
- credential-bearing service principals holding role assignments
- apps with `appRoleAssignmentRequired` disabled, implicit flow, or public clients with privileged roles
- foreign (cross-tenant) privileged service principals
- privileged users and role-capable groups
- Conditional Access exposure (policy scopes, MFA exclusions)
- AD sync summary and attack surface (ADSync groups, sync SPs, hybrid auth, Windows devices)

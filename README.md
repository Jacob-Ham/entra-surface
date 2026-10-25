# Entra Surface

Entra ID attack-surface report from a [ROADrecon](https://github.com/dirkjanm/ROADtools) database. Serves a sortable, filterable HTML report with drilldowns.

<img width="1384" height="808" alt="image" src="https://github.com/user-attachments/assets/18f39b77-cd95-468b-9bcb-989b336af9c9" />

## Requirements

- Python 3
- A ROADrecon SQLite database (optional)
- Collection: `msal`, `requests`, and `PySocks` (SOCKS) from `requirements.txt`

## Collection

```sh
roadrecon gatherall --evade
```

Or collect from the in-app **Collect** tab.

## Usage

```sh
python3 entra-surface.py --db roadrecon.db
```

Opens `http://127.0.0.1:8787`. Omit `--db` to open the GUI shell and load or analyze a database from `data/databases` (or a custom path). Analysis is cached; use `--refresh` to force a re-run or `--no-cache` to disable caching.

### Options

| Option | Description |
| --- | --- |
| `--db` | ROADrecon SQLite database (omit to serve the GUI shell) |
| `--config` | Privileged-roles config (default: `privileged_roles.json`) |
| `--azure-config` | Azure RBAC role config (default: `azure_roles.json`) |
| `--port` | Port to serve on (default: `8787`) |
| `--refresh` | Re-run the full analysis, ignoring the cache |
| `--no-cache` | Disable the analysis cache |
| `--timing` | Print per-phase timings and peak memory |

## Collect tab

- **Graph:** bundled collector under `entra_surface/collector`. Output defaults to `data/databases/collected.db`. Uses the active token; refresh tokens require a client ID. Access-token runs skip ARM.
- **Evade Graph detections:** batches up to 20 relationship GETs per Microsoft Graph `$batch` request and uses an ADO.NET User-Agent when none is supplied.
- **AAD Graph:** legacy collector based on ROADrecon 2.0. Output defaults to `data/databases/aadgraph.db` and is recreated each run. Accepts a refresh or AAD Graph access token.
- **AAD Graph options:** autotoken, evade, gather-all (requires a refresh token), and MFA details.
- Collector deps: `msal`, `requests`, and `PySocks`; no ROADRecon package. Override the backend with `ENTRA_COLLECTOR_DIR`.

Headless AAD Graph collection:

```sh
python3 -m entra_surface.collect --backend aadgraph \
  -rt <refresh-token> -c <client-id> --evade --gather-all \
  -o data/databases/aadgraph.db
```

## Tokens

- Add a refresh token with its client ID, or a bare access token.
- Redeem refresh tokens for any listed resource or a custom client/resource.
- FOCI tokens expose **Access Token** and **FOCI** client options.
- Access tokens are nested under their source refresh; FOCI sibling redemption creates a separate refresh entry.
- **Decode** shows JWT header and payload.
- Resource and client lists use the cached entrascopes dataset.
- Tokens are stored in `.entra-surface-auth.json` (mode `0600`, gitignored).

## Settings

- The sidebar gear opens Settings.
- **Proxy:** HTTP, HTTPS, SOCKS4, and SOCKS5 for collection and token refresh; optional auth and no-proxy hosts for Graph, ARM, and AAD Graph requests.
- **Test proxy** checks the current form values against Microsoft Graph.
- Settings are stored in `.entra-surface-settings.json` (mode `0600`, gitignored).
- SOCKS requires `PySocks` in the collector virtualenv.

## Report

- **Tabs:** Apps / Service principals, Users, Active Directory / On-prem, Groups, Conditional Access, Azure Arc.
- **Column manager:** add, remove, and reorder columns per table.
- **Filters:** free text plus advanced queries (`field:value`, `contains:`, `AND`/`OR`/`NOT`, `uniq:column`).
- **Drawers:** details, roles, owners, Azure RBAC, and raw records; PIM-eligible roles open a PIM detail table.
- **Azure Arc:** Arc machines, role holders, onboarding service principals, and resource providers.

Checks are configured in `privileged_roles.json`; the full report is always served.

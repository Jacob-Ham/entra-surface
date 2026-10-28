# Entra Surface

Entra ID attack-surface report from a [ROADrecon](https://github.com/dirkjanm/ROADtools) database. It runs the configured checks and serves a sortable, filterable HTML report with drilldowns. The sidebar switches between **Analysis**, **Collect**, and **Tokens**.

<img width="1384" height="808" alt="image" src="https://github.com/user-attachments/assets/18f39b77-cd95-468b-9bcb-989b336af9c9" />

## Requirements

- Python 3
- A ROADrecon SQLite database (optional)
- For collection: `msal`, `requests`, and `PySocks` from `requirements.txt`

## Collection

```sh
roadrecon gatherall --evade
```

Or collect from the in-app **Collect** tab.

## Usage

```sh
python3 entra-surface.py --db roadrecon.db
```

Open `http://127.0.0.1:8787`.

Omit `--db` to start with an empty GUI shell; use **Analysis** to load a database from `data/databases` or a custom path. Analysis is cached: `--refresh` re-runs it, `--no-cache` disables caching.

## Options

| Option | Description |
| --- | --- |
| `--db` | ROADrecon SQLite database (omit to serve the GUI shell) |
| `--config` | Privileged-roles config (default: `privileged_roles.json`) |
| `--azure-config` | Azure RBAC role config (default: `azure_roles.json`) |
| `--port` | Port to serve on (default: `8787`) |
| `--refresh` | Re-run the full analysis, ignoring the cache |
| `--no-cache` | Disable the analysis cache |
| `--timing` | Print per-phase timings and peak memory |

## Collect

- **Graph:** bundled collector under `entra_surface/collector`. Output defaults to `data/databases/entra-graph.db`. Uses the active token.
- **AAD Graph:** legacy collector based on ROADrecon 2.0. Output defaults to `data/databases/entra-aad.db`. Uses the active token.
- **Dependencies:** `msal`, `requests`, and `PySocks`; no ROADRecon package. Override the backend with `ENTRA_COLLECTOR_DIR`.
- **Throttling:** 429 backoffs appear in the log with the wait time and running count.

Headless AAD Graph collection:

```sh
python3 -m entra_surface.collect --backend aadgraph -rt <refresh-token> -c <client-id> --evade --gather-all -o data/databases/entra-aad.db
```

## Tokens

- **Collected tokens** lists saved tokens; **Add token** accepts a refresh token with its client ID or a bare access token.
- Redeem refresh tokens for any listed resource or a custom client/resource.
- FOCI tokens expose **Access Token** and **FOCI** client options.
- **Decode** shows JWT header and payload.
- Refresh-token rows link to the client in entrascopes.
- Resource and client lists use the cached entrascopes dataset.
- Tokens are stored in `.entra-surface-auth.json` (mode `0600`, gitignored).

## Settings

- **User agents:** **Global** applies to all outbound requests; **Collect** covers Graph/AAD Graph/ARM collection including token acquisition, and **Tokens** covers Tokens-tab exchanges and token-resource metadata. Area settings override Global.
- **Proxy:** HTTP, HTTPS, SOCKS4, and SOCKS5 for collection and token refresh, with optional auth and no-proxy hosts for Graph, ARM, and AAD Graph.

## Analysis

- **Tabs:** Apps / Service principals, Users, Active Directory / On-prem, Groups, Conditional Access Policies, Azure Arc.
- **Column manager:** add, remove, and reorder columns per table.
- **Filters:** free text plus advanced queries (`field:value`, `contains:`, `AND`/`OR`/`NOT`, `uniq:column`).
- **Drawers:** details, roles, owners, Azure RBAC, and raw records; PIM-eligible roles open a PIM detail table.
- **Azure Arc:** Arc machines, role holders, onboarding service principals, and resource providers.

Credits:

- https://github.com/dirkjanm/ROADtools
- https://github.com/f-bader/entrascopes.com
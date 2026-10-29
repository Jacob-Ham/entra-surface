# Entra Surface

Entra ID attack-surface report from a [ROADrecon](https://github.com/dirkjanm/ROADtools) database. It runs the configured checks and serves a sortable, filterable HTML report with drilldowns. The sidebar switches between **Analysis**, **Collect**, and **Tokens**.

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

## Analysis


- **Tabs:** Apps / Service principals, Users, Active Directory / On-prem, Groups, Conditional Access Policies, Azure Arc.
- **Column manager:** add, remove, and reorder columns per table.
- **Filters:** free text plus advanced queries (`field:value`, `contains:`, `AND`/`OR`/`NOT`, `uniq:column`).
- **Drawers:** details, roles, owners, Azure RBAC, and raw records; PIM-eligible roles open a PIM detail table.
- **Azure Arc:** Arc machines, role holders, onboarding service principals, and resource providers.


<img width="1675" height="922" alt="image" src="https://github.com/user-attachments/assets/463f1a8c-8826-411b-82b5-7d8541f5909b" />


## Tokens

- **Collected tokens** lists saved tokens; **Add token** accepts a refresh token with its client ID or a bare access token.
- Redeem refresh tokens for any listed resource or a custom client/resource.
- FOCI tokens expose **Access Token** and **FOCI** client options.
- **Decode** shows JWT header and payload.
- Refresh-token rows link to the client in entrascopes.
- Resource and client lists use the cached entrascopes dataset.
- Tokens are stored in `.entra-surface-auth.json` (mode `0600`, gitignored).

<img width="1660" height="827" alt="image" src="https://github.com/user-attachments/assets/ac080aed-8d93-48a3-b0b5-06598a3b6577" />



## Settings

- **User agents:** **Global** applies to all outbound requests; **Collect** covers Graph/AAD Graph/ARM collection including token acquisition, and **Tokens** covers Tokens-tab exchanges and token-resource metadata. Area settings override Global.
- **Proxy:** HTTP, HTTPS, SOCKS4, and SOCKS5 for collection and token refresh, with optional auth and no-proxy hosts for Graph, ARM, and AAD Graph.



Credits:

- https://github.com/dirkjanm/ROADtools
- https://github.com/f-bader/entrascopes.com

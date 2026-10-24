# Entra Surface

Entra ID attack-surface report from a [ROADrecon](https://github.com/dirkjanm/ROADtools) database. Runs a registry of checks over the tenant data and serves a sortable, filterable HTML report with drilldowns.

<img width="1384" height="808" alt="image" src="https://github.com/user-attachments/assets/18f39b77-cd95-468b-9bcb-989b336af9c9" />

## Requirements

- Python 3 (stdlib only)
- A roadrecon database (`roadrecon.db`) for the tenant you want to audit (optional; without one the GUI opens with no data)

## Collection

```sh
roadrecon gatherall --evade
```

## Usage

```sh
python3 entra-surface.py --db roadrecon.db
```

Opens `http://127.0.0.1:8787`. Startup takes a few minutes on large tenants.

Run without `--db` to open the GUI shell with no data:

```sh
python3 entra-surface.py
```

In that mode the Analysis view shows a dropdown of databases from
`data/databases` (plus a custom-path option) and a **Begin analysis** button;
the analysis runs in the background and reloads the report when ready. Once a
report is loaded, **Re-analyze** at the end of the category tabs opens the same
database selector without restarting the server. Analyses are cached per
database under `data/databases/.cache`: unchanged re-runs skip analysis
entirely, and changed databases are diffed against the previous run. The
**Cache analysis** checkbox controls runtime caching (checked by default), and
cached databases are marked `[cached]` in the selector. `--refresh` forces a
full reanalysis at startup.

### Options

| Option | Description |
| --- | --- |
| `--db` | Roadrecon SQLite database (omit to serve the GUI shell with no data) |
| `--config` | Privileged-roles config (default: `privileged_roles.json`) |
| `--azure-config` | Azure RBAC role config (default: `azure_roles.json`) |
| `--port` | Port to serve on (default: `8787`) |
| `--refresh` | Ignore the cache and re-run the full analysis |
| `--no-cache` | Disable the analysis cache entirely |
| `--timing` | Print per-phase timings and peak memory |

## Collect tab

The sidebar's **Collect** view has **Graph** and **AAD Graph** tabs; AAD Graph
is a placeholder for now. The Graph tab runs the separate graphcollect backend
from the sibling `collector/` checkout (default `../collector`, override with
`ENTRA_COLLECTOR_DIR`). The adapter is `collect.py`; it uses the collector's
`.venv` when present. Choose an output database in **Collect** (defaults to
`data/databases/collected.db`); collection uses the active token from **Tokens**.
A client ID is required whenever a refresh
token is provided. Collection can also use an active Microsoft Graph access
token directly; access-token runs skip the Azure Resource Manager tables.
**Send for analysis once complete** is checked by default and automatically
starts analysis on the collected database; uncheck it to use the **Send to
analysis** button manually. The collector requires `msal` and `requests` from
`collector/requirements.txt`.

### Tokens

**Tokens** has **Add token** and **Collected tokens** tabs. **Add token** only
saves: enter either a refresh token (with its client ID) or a bare access token.
The **Client ID** field is a searchable picker over the same app dataset; select
a client by name or ID, or type a custom GUID. The resolved name and FOCI status
appear below the field.
Bare access tokens are decoded from their JWT claims immediately; refresh tokens
stay unidentified until you redeem them from their collected token row. The
**Redeem for** field on a refresh token is a searchable resource picker: it
suggests every resource that the token's client application can request, based
on the [entrascopes.com](https://github.com/f-bader/entrascopes.com) first-party
scope dataset. Select any listed resource to redeem the token for it (not just
Microsoft Graph or AAD Graph). A **Custom client ID...** option accepts any
application/client ID or resource URI when the target is not in the mapped list.
The dataset is downloaded on demand and cached under `data/token-resources/`;
clients that are not in the dataset fall back to common resources. The refresh
entry stays refresh-only, and the resulting access token is stored as a separate
access-only entry tied to that refresh and indented beneath it, with its audience
and expiry.
Secrets are stored in `.entra-surface-auth.json` (mode `0600`, gitignored), and
rotated refresh tokens are persisted after each collection. Collected tokens are
grouped by principal, and each token is labelled **Refresh Token**,
**Access Token**, or **Refresh + Access Token**. Access tokens redeemed from a
refresh stay under that refresh, so redeeming the same audience from a different
refresh adds a new child instead of overwriting the first. Manually added access
tokens are kept separately by principal and audience. Token rows resolve the
client ID to its application name from the same dataset (the raw ID is in the
tooltip); bare-GUID audiences are resolved to their mapped resource names as
well. Nested access-token rows show their audience in place of the client, since
the parent refresh row already identifies it. Refresh-token rows show a **FOCI**
tag for Family of Client IDs members. Expand a principal to view
its tokens, redeem an individual refresh token, select the active token, or
delete entries. Access-token health badges show valid/expiring/expired status;
the collected list can be filtered by text, type, access state, and audience.
Each token records when it was last used and which output DB it was used for.
**View tokens** reveals only the stored token(s) for that entry: access-only
rows show the access token, refresh-only rows show the refresh token, and legacy
combined rows show both. The bottom of the sidebar shows the principal and
audience behind the currently active token.

## Report

- **Tabs:** Apps / Service principals, Users, Active Directory / On-prem, Groups, Conditional Access, Azure Arc.
- **Column manager:** add, remove, and reorder columns per table (persisted in the browser).
- **Filters:** free-text, plus an advanced query language — `field:value`, `contains:`, `AND`/`OR`/`NOT`, and `uniq:column` to deduplicate by any column.
- **Drawers:** per-row detail with roles, owners, Azure RBAC assignments, and a Raw tab with the full captured record. PIM-eligible roles are rated one notch below the same role held actively (an eligible Global Administrator is High, not Critical), and the user/group drawers render PIM-eligible role tags as clickable underlined links that open the full PIM detail table (scope, group path, schedule, permanence).
- **Sync summary:** engine, password writeback, authentication mode (PHS / PTA / federated), and Desktop SSO.
- **Azure Arc:** onboarded machines, Arc role holders, onboarding service principals, and resource providers — detected by tenant-independent identifiers (resource-provider namespaces, role-definition GUIDs, first-party appIds).

Checks are enabled/disabled via the `checks` block in `privileged_roles.json`; the tool always serves the full report.

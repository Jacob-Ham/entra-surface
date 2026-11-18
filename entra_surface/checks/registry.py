"""Check registry and categories. The report always serves every enabled check."""
from __future__ import annotations

from .ad import (
    check_ad_sync_infra, check_ad_sync_summary, check_ad_sync_users,
)
from .apps import (
    check_app_directory_roles, check_app_inventory, check_enterprise_apps,
    check_foreign_principal, check_no_role_approval,
    check_priv_app_ownership, check_public_client_privileged,
)
from .arc import (
    check_azure_arc_machines, check_azure_arc_providers, check_azure_arc_sps,
)
from .auth import check_authentication_methods
from .ca import check_ca_exposure
from .groups import check_groups
from .users import check_privileged_users


CHECK_SPECS = [
    {
        "id": "priv_app_ownership",
        "category": "apps",
        "title": "Privileged application ownership",
        "description": ("Application (app-only) role assignments matched against the "
                        "privileged permission list, resolved to the human owners of the "
                        "Application / Service Principal."),
        "run": check_priv_app_ownership,
    },
    {
        "id": "enterprise_apps",
        "category": "apps",
        "title": "Enterprise apps",
        "description": "",
        "run": check_enterprise_apps,
    },
    {
        "id": "no_role_approval",
        "category": "apps",
        "title": "Apps without role-assignment requirement",
        "description": ("Service principals with appRoleAssignmentRequired=false: Azure AD does "
                        "not require explicit role assignments. Whether a default user gains "
                        "access depends on the app's own authorization logic, so treat these as "
                        "candidates to test rather than proven exposures (rated Info)."),
        "run": check_no_role_approval,
    },
    {
        "id": "public_client_privileged",
        "category": "apps",
        "title": "Public clients with privileged roles",
        "description": ("Public (installed or browser-based) clients whose service principal "
                        "holds privileged app-role assignments — the client cannot keep "
                        "secrets, so its identity inherits the privilege."),
        "run": check_public_client_privileged,
    },
    {
        "id": "foreign_principal",
        "category": "apps",
        "title": "Foreign principals with privileged roles",
        "description": ("Service principals owned by another tenant (appOwnerTenantId mismatch "
                        "and no local Application registration) that hold privileged application "
                        "roles — cross-tenant trust relationships to validate."),
        "run": check_foreign_principal,
    },
    {
        "id": "app_dir_roles",
        "category": "apps",
        "title": "Directory roles assigned to applications",
        "description": ("One row per service principal holding directory roles, "
                        "assigned directly or inherited through group membership "
                        "(incl. nesting). Rated by the most critical directory role."),
        "run": check_app_directory_roles,
    },
    {
        "id": "app_inventory",
        "category": "apps",
        "title": "All applications / service principals",
        "description": "",
        "run": check_app_inventory,
    },
    {
        "id": "privileged_users",
        "category": "users",
        "title": "Users",
        "description": ("One row per user. Privileged users are rated by their aggregate "
                        "signal: directory roles (assigned or eligible — eligible is "
                        "rated one notch below the same role held actively), ownership of "
                        "apps/service principals that hold privileged grants or directory "
                        "roles, and membership or ownership of role-capable groups. Users "
                        "with no observed signals are listed at Info for completeness. "
                        "On-prem sync is context and never raises the rating. Directory "
                        "role severities come from the 'directory_roles' config block; "
                        "unrated roles stay Info."),
        "run": check_privileged_users,
    },
    {
        "id": "groups",
        "category": "groups",
        "title": "Groups",
        "description": ("One row per group: directory roles carried by the group (members "
                        "inherit them), role-capability (assignable / role-bearing / nested), "
                        "dynamic membership rules, owners, and privileged or service-principal "
                        "members."),
        "run": check_groups,
    },
    {
        "id": "authentication_methods",
        "category": "auth",
        "title": "Authentication methods",
        "description": "",
        "run": check_authentication_methods,
    },
    {
        "id": "ca_exposure",
        "category": "configs",
        "title": "Conditional Access policy exposure",
        "description": ("Per-policy posture (state, scope, exclusions, conditions) "
                        "with a full policy profile in the drawer. Group-targeted "
                        "scope cannot be resolved from the captured links."),
        "run": check_ca_exposure,
    },
    {
        "id": "ad_sync_summary",
        "category": "ad",
        "title": "Sync summary",
        "description": "One-line picture of the sync setup: engine in use (Entra Connect on-prem vs likely Cloud Sync), connector host, password-writeback channel, authentication mode (PHS / PTA / federated), Desktop SSO, and sync coverage.",
        "run": check_ad_sync_summary,
    },
    {
        "id": "ad_sync_users",
        "category": "ad",
        "title": "Interesting On-Prem Synced Users",
        "description": ("Synchronized user accounts carrying at least one targeting flag: "
                        "synced-plus-privileged, service accounts, or missing SID. CA policy "
                        "exclusions are listed per user. Targeting metadata — never scored."),
        "run": check_ad_sync_users,
    },
    {
        "id": "ad_sync_infra",
        "category": "ad",
        "title": "AD sync infrastructure",
        "description": ("ADSync groups, synchronization service principals, hybrid/legacy "
                        "authentication policies, and registered Windows devices — the "
                        "on-prem attack surface visible from the cloud side."),
        "run": check_ad_sync_infra,
    },
    {
        "id": "azure_arc_machines",
        "category": "arc",
        "title": "Azure Arc machines",
        "description": (""),
        "run": check_azure_arc_machines,
    },
    {
        "id": "azure_arc_sps",
        "category": "arc",
        "title": "Azure Arc access",
        "description": "Principals holding Azure Arc ARM roles",
        "run": check_azure_arc_sps,
    },
    {
        "id": "azure_arc_providers",
        "category": "arc",
        "title": "Azure Arc resource providers",
        "description": "First-party Microsoft Arc service principals present in the tenant",
        "run": check_azure_arc_providers,
    },
]



CHECK_ID_CATEGORY = {spec["id"]: spec["category"] for spec in CHECK_SPECS}

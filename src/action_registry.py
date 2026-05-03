# FILE: src/action_registry.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Single source of truth for the approved action vocabulary, field schemas, and classification.
#   SCOPE: Action names, field definitions, required fields, destructive action set, boolean fields, decision values.
#   DEPENDS: none
#   LINKS: M-ACTION-REGISTRY
#   ROLE: TYPES
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   ALLOWED_ACTIONS - Complete set of actions the system accepts.
#   EXPOSED_PUBLIC_TOOLS - Ordered tuple of actions exposed through the MCP tool surface.
#   DESTRUCTIVE_ACTIONS - Actions requiring explicit confirmation before execution.
#   ACTION_FIELDS - Allowed payload fields per action.
#   REQUIRED_ACTION_FIELDS - Mandatory payload fields per action.
#   BOOLEAN_FIELDS - Fields that accept boolean values.
#   DECISION_VALUES - Valid confirmation decision strings.
# END_MODULE_MAP

from __future__ import annotations

ALLOWED_ACTIONS: set[str] = {
    "list_users",
    "list_sessions",
    "list_groups",
    "show_user_ips",
    "disconnect_session",
    "create_user",
    "update_user_ip",
    "disable_user",
    "disable_group_users",
    "delete_user",
    "assign_group",
    "create_group",
    "delete_group",
    "reload_service",
    "rollback_last_change",
    "validate_config",
    "confirm_action",
}

EXPOSED_PUBLIC_TOOLS: tuple[str, ...] = (
    "list_users",
    "list_sessions",
    "list_groups",
    "show_user_ips",
    "disconnect_session",
    "create_user",
    "update_user_ip",
    "disable_user",
    "disable_group_users",
    "delete_user",
    "assign_group",
    "create_group",
    "delete_group",
    "reload_service",
    "rollback_last_change",
    "confirm_action",
)

DESTRUCTIVE_ACTIONS: set[str] = {
    "disable_user",
    "disable_group_users",
    "delete_user",
    "delete_group",
    "assign_group",
    "disconnect_session",
    "rollback_last_change",
}

ACTION_FIELDS: dict[str, tuple[str, ...]] = {
    "list_users": (),
    "list_sessions": (),
    "list_groups": (),
    "show_user_ips": (),
    "disconnect_session": ("username",),
    "create_user": ("username", "group", "ipv4_address"),
    "update_user_ip": ("username", "ipv4_address"),
    "disable_user": ("username",),
    "disable_group_users": ("group",),
    "delete_user": ("username", "force"),
    "assign_group": ("username", "group"),
    "create_group": ("group", "ipv4_network", "ipv4_netmask", "routes"),
    "delete_group": ("group",),
    "reload_service": (),
    "rollback_last_change": (),
    "validate_config": (),
    "confirm_action": ("token", "decision", "expected_action", "expected_username", "expected_group"),
}

REQUIRED_ACTION_FIELDS: dict[str, tuple[str, ...]] = {
    "disconnect_session": ("username",),
    "create_user": ("username", "group"),
    "update_user_ip": ("username", "ipv4_address"),
    "disable_user": ("username",),
    "disable_group_users": ("group",),
    "delete_user": ("username",),
    "assign_group": ("username", "group"),
    "create_group": ("group",),
    "delete_group": ("group",),
    "rollback_last_change": (),
    "confirm_action": ("token", "decision"),
}

BOOLEAN_FIELDS: set[str] = {"force"}

DECISION_VALUES: set[str] = {"confirm", "cancel"}

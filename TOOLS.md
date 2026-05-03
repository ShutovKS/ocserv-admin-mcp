# ocserv Admin Tool Policy

This workspace exposes a constrained MCP tool surface for `ocserv` administration.

## Mandatory behavior

- Never edit `ocserv` config files directly.
- Never use shell commands for `ocserv` administrative operations.
- Always call the approved backend tool surface exposed by the local MCP server.
- Do not rely on free-text intent parsing inside this repository; clients must invoke schema-valid tools directly.
- Treat destructive actions (`disable_user`, `disable_group_users`, `delete_user`, `delete_group`, `assign_group`, `disconnect_session`, `rollback_last_change`) as requiring explicit confirmation.

## Approved tool surface

Use only these public tools for VPN administration:

- `list_users` — list managed VPN users
- `list_sessions` — list active VPN sessions
- `list_groups` — list allowed policy groups with membership details
- `show_user_ips` — show assigned static IP addresses for users
- `disconnect_session` — disconnect an active VPN session (destructive, requires confirmation)
- `create_user` — create a new VPN user with group and optional static IP
- `update_user_ip` — update a user's static IPv4 address
- `disable_user` — disable a VPN user without deleting (destructive, requires confirmation)
- `disable_group_users` — disable all users in a policy group (destructive, requires confirmation)
- `delete_user` — permanently remove a VPN user (destructive, requires confirmation)
- `assign_group` — assign a user to a policy group (destructive, requires confirmation)
- `create_group` — create a new policy group with optional network settings
- `delete_group` — delete a policy group (destructive, requires confirmation)
- `reload_service` — reload the ocserv service configuration
- `rollback_last_change` — restore previous config state from snapshot (destructive, requires confirmation)
- `confirm_action` — confirm or cancel a pending destructive action

Do not invent new public admin actions. If the requested operation is outside this list, say it is not allowed.

## Response contract

When reporting a tool result, preserve these fields from the backend-normalized response:

- `result`: brief status and action
- `entities`: changed or returned entities
- `reload`: reload or activation status when present
- `actionable_error`: concrete recovery guidance when a call fails

## Group handling

When a tool schema exposes an enum for `group`, use one of the provided values exactly.
If no valid group is available for the requested operation, ask for an allowed policy group instead of guessing.

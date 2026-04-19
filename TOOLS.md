# ocserv Admin Tool Policy

This workspace exposes a constrained MCP tool surface for `ocserv` administration.

## Mandatory behavior

- Never edit `ocserv` config files directly.
- Never use shell commands for `ocserv` administrative operations.
- Always call the approved backend tool surface exposed by the local MCP server.
- Do not rely on free-text intent parsing inside this repository; clients must invoke schema-valid tools directly.
- Treat `disable_user` and `delete_user` as destructive actions that require explicit confirmation.

## Approved tool surface

Use only these public tools for VPN administration:

- `list_users`
- `list_sessions`
- `disconnect_session`
- `create_user`
- `disable_user`
- `delete_user`
- `assign_group`
- `reload_service`
- `rollback_last_change`
- `confirm_action`

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

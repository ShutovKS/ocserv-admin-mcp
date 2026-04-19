# ocserv-admin-mcp

`ocserv-admin-mcp` is a safe administrative package for `ocserv`.

It is **not** a bot, chat runtime, or general agent framework. It provides a constrained localhost backend plus an MCP server that expose a small audited tool surface for VPN administration. Any MCP-capable agent can integrate with it, including NanoBot.

## What it is

- A localhost-only admin API for approved `ocserv` operations
- A strict MCP tool surface for agents
- Safety controls for confirmations, allowlists, and rate limits
- Deterministic audit logging, rollback, reload safety, and verification artifacts
- Deployment artifacts for `systemd`, `sudo -n`, and VPS installation

## What it is not

- Telegram integration
- Chat UX or conversation orchestration
- Free-text intent parsing
- Arbitrary shell access
- A replacement for NanoBot or any other agent runtime

## Public tool surface

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

`validate_config` remains an internal backend capability and is not part of the default public MCP tool set.

## Supported clients

- NanoBot via `deploy/examples/nanobot-config.example.json`
- Generic MCP clients via `deploy/examples/generic-mcp-client.example.json`

## Security boundary

- Backend binds to loopback only
- Clients authenticate with a shared bearer token
- Actors must be explicitly allowlisted with `OCSERV_ADMIN_ALLOWED_ACTORS`
- Privileged operations execute only through `sudo -n` allowlisted commands
- Destructive actions require explicit confirmation and are audited

## Repository layout

- `src/` — backend, adapter, safety, audit, and MCP transport layers
- `deploy/` — `systemd`, `sudoers`, env examples, and client config examples
- `docs/` — requirements, development plan, verification plan, knowledge graph
- `tests/` — unit and integration coverage for the approved admin surface

## Operational guidance

Start with `deploy/README.md` for host setup, runtime expectations, and recovery behavior.

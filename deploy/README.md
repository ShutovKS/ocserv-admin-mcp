# ocserv-admin deployment artifacts

These files are the host-side deployment boundary for the localhost backend and public MCP tool surface.

- `ocserv-admin.service`: run the backend as a dedicated `ocserv-admin` system user bound to `127.0.0.1`.
- `ocserv-admin.sudoers`: allow only the approved `sudo -n` mediated `occtl`, `ocpasswd`, validation, and service-control commands with no general shell access.

Suggested host setup:

1. Create the service user: `useradd --system --home /var/lib/ocserv-admin --shell /usr/sbin/nologin ocserv-admin`
2. Install the repository into `/opt/ocserv-admin`
3. Install Python runtime dependencies with `python3 -m pip install --requirement /opt/ocserv-admin/requirements.txt`
4. Install `deploy/ocserv-admin.service` into `/etc/systemd/system/`
5. Install `deploy/ocserv-admin.sudoers` into `/etc/sudoers.d/ocserv-admin`
6. Create `/etc/ocserv-admin/ocserv-admin.env` with `OCSERV_ADMIN_AUTH_TOKEN=<shared-secret>`, `OCSERV_ADMIN_RATE_LIMIT_MAX_REQUESTS=<integer>`, and `OCSERV_ADMIN_RATE_LIMIT_WINDOW_SECONDS=<integer>`. `OCSERV_ADMIN_AUTH_TOKEN` is required and the backend fails closed if it is missing. The packaged backend targets the real ocserv deployment boundary by default: `/etc/ocserv/passwd` for the auth store, `/etc/ocserv/ocserv.conf` for the main config, `/etc/ocserv/config-per-group` for rendered group policy files, `/var/lib/ocserv-admin/user-groups.json` for the managed user-to-group map, `/var/lib/ocserv-admin/groups.json` for allowed-group discovery, and `/var/log/ocserv-admin/audit.log` for the audit sink. Override those env vars only if your host layout differs intentionally.
7. Set `OCSERV_ADMIN_ALLOWED_ACTORS=<comma-separated approved client actor ids>` and include `nanobot` only if you use the Nanobot example integration.
8. Enable and start the backend with `systemctl enable --now ocserv-admin.service`

If you use the shipped `deploy/examples/nanobot-config.example.json`, keep `OCSERV_ADMIN_GROUPS_FILE=/var/lib/ocserv-admin/groups.json` so the example MCP client discovers the same packaged group inventory as the backend.

The backend expects `OCSERV_ADMIN_COMMAND_PREFIX="sudo -n"`, so the adapter always executes approved privileged commands through the sudoers boundary rather than directly. Because the service intentionally relies on sudo-mediated escalation for a tightly allowlisted command set, `NoNewPrivileges=true` is not enabled in the systemd unit. The allowlist must cover the exact `ocpasswd` mutation shapes used for `create_user`, `disable_user`, and `delete_user` against `/etc/ocserv/passwd`, `/usr/sbin/ocserv --test-config --config /etc/ocserv/ocserv.conf` for validation, and the approved `occtl disconnect user <username>` shape used by MCP-backed active-session termination.

When the passwd-file backend is active, a successful `create_user` tool response includes a one-time password for the newly created VPN identity. That credential is intentionally visible only in the successful operator response, is not persisted in audit/shared artifacts, must be shared with the VPN user over a secure channel, and should be rotated after first use.

Operational minimum runbook:

- Supported public MCP tools: `list_users`, `list_sessions`, `disconnect_session`, `create_user`, `disable_user`, `delete_user`, `assign_group`, `reload_service`, `rollback_last_change`, `confirm_action`.
- Logs: `/var/log/ocserv-admin/audit.log` keeps the full audit trail, `/var/log/ocserv-admin/error.log` captures failures and rejections, and `/var/log/ocserv-admin/admin-changes.log` records successful administrative changes.
- Recovery: every config-affecting change records backup evidence before mutation and keeps only the last rollback state at `/var/lib/ocserv-admin/last-rollback.json`. Use `rollback_last_change`, then `confirm_action`, to restore the last config-affecting change batch.
- Health: `GET /health` reports backend liveness plus `ocserv` health-check output, and config-affecting actions also include post-activation health evidence.
- Manual emergency path: stop issuing new tool calls, confirm `GET /health`, inspect `error.log` and `admin-changes.log`, run `rollback_last_change` if the last change caused the fault, then verify `systemctl status ocserv` and a fresh `list_sessions` call.

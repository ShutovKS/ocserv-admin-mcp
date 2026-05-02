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

VPN policy and host firewall notes:

- `ocserv-admin-mcp` manages users, groups, per-user fixed IPv4 assignments, and rendered `ocserv` policy files, but it does not replace host firewall policy. `ocserv` gives VPN clients addresses and routes; inter-client traffic still depends on Linux routing and firewall rules on the VPN host.
- If VPN clients can `ping` each other but cannot open TCP sessions such as SSH, check the host `FORWARD` path before changing `ocserv` policy files. A common host posture is `UFW Default: deny (routed)` with ICMP explicitly allowed in `ufw-before-forward`, which permits ping while dropping new TCP flows between VPN clients.
- For personal device meshes where all VPN clients in `10.10.0.0/24` should reach each other, a narrow and durable UFW rule can be added in `/etc/ufw/before.rules`:

  ```bash
  -A ufw-before-forward -i vpns+ -o vpns+ -s 10.10.0.0/24 -d 10.10.0.0/24 -j ACCEPT
  ```

  Reload with `ufw reload` after editing. This matches `vpns0`, `vpns1`, and later `ocserv` point-to-point interfaces.
- If you want only SSH between VPN clients, use the narrower rule instead:

  ```bash
  -A ufw-before-forward -i vpns+ -o vpns+ -s 10.10.0.0/24 -d 10.10.0.0/24 -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
  ```

- Ensure `net.ipv4.ip_forward = 1` on the VPN host. `ocserv` client-to-client routing will not work if the host is not forwarding IPv4 packets.

Static per-user IPv4 notes:

- The backend can assign fixed user IPv4 addresses through `ocserv` `config-per-user` files. On the live host layout, those files are rendered under `/etc/ocserv/config-per-user/<username>` with directives such as `explicit-ipv4 = 10.10.0.30`.
- Fixed IPv4 assignments should belong to the target user's group pool. For example, users in the `personal` group use the `10.10.0.0/24` pool, so fixed addresses such as `10.10.0.10` and `10.10.0.30` are valid there.
- The backend validates fixed IPv4 requests before applying them: the IP must be syntactically valid, unique across managed users, and inside the assigned group's IPv4 pool.

MCP and Telegram control surface:

- Current public MCP tools: `list_users`, `list_sessions`, `list_groups`, `show_user_ips`, `disconnect_session`, `create_user`, `update_user_ip`, `disable_user`, `disable_group_users`, `delete_user`, `assign_group`, `create_group`, `delete_group`, `reload_service`, `rollback_last_change`, `confirm_action`.
- Use `create_user` with `ipv4_address` when creating a device that should always keep the same VPN IP.
- Use `update_user_ip` when the user already exists and only the fixed IP assignment should change.

Operational minimum runbook:

- Supported public MCP tools: `list_users`, `list_sessions`, `list_groups`, `show_user_ips`, `disconnect_session`, `create_user`, `update_user_ip`, `disable_user`, `disable_group_users`, `delete_user`, `assign_group`, `create_group`, `delete_group`, `reload_service`, `rollback_last_change`, `confirm_action`.
- Logs: `/var/log/ocserv-admin/audit.log` keeps the full audit trail, `/var/log/ocserv-admin/error.log` captures failures and rejections, and `/var/log/ocserv-admin/admin-changes.log` records successful administrative changes.
- Recovery: every config-affecting change records backup evidence before mutation and keeps only the last rollback state at `/var/lib/ocserv-admin/last-rollback.json`. Use `rollback_last_change`, then `confirm_action`, to restore the last config-affecting change batch.
- Health: `GET /health` reports backend liveness plus `ocserv` health-check output, and config-affecting actions also include post-activation health evidence.
- Manual emergency path: stop issuing new tool calls, confirm `GET /health`, inspect `error.log` and `admin-changes.log`, run `rollback_last_change` if the last change caused the fault, then verify `systemctl status ocserv` and a fresh `list_sessions` call.

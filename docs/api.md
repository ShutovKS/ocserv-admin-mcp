# ocserv-admin API Reference

## Overview

The ocserv-admin backend API runs as a localhost WSGI server on `127.0.0.1:8080` by default. All mutation endpoints require Bearer token authentication and loopback-only access.

## Authentication

All `POST /actions/*` endpoints require:
- **Bearer token**: `Authorization: Bearer <token>` header matching `OCSERV_ADMIN_AUTH_TOKEN`
- **Actor ID**: `X-Actor-Id: <actor_id>` header identifying the operator
- **Loopback access**: Requests must originate from `127.0.0.1` or `::1`

## Endpoints

### GET /health

Health check endpoint. No authentication required.

**Response:**
```json
{
  "ok": true,
  "service": "ocserv-admin",
  "ocserv": {
    "ok": true,
    "stdout": "active",
    "stderr": "",
    "returncode": 0
  }
}
```

### GET /readiness

Readiness probe. Checks file accessibility and occtl availability.

**Response:**
```json
{
  "ready": true,
  "checks": {
    "users_file": true,
    "groups_file": true,
    "ocserv_service": true
  },
  "version": "0.1.0"
}
```

---

## Actions

All actions are invoked via `POST /actions/<action_name>` with a JSON body.

### list_users

List all managed VPN users.

```bash
curl -X POST http://127.0.0.1:8080/actions/list_users \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Actor-Id: admin" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Response:**
```json
{
  "ok": true,
  "users": [
    {"username": "alice", "group": "default", "disabled": false}
  ]
}
```

### list_sessions

List active VPN sessions.

```bash
curl -X POST http://127.0.0.1:8080/actions/list_sessions \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Actor-Id: admin" \
  -d '{}'
```

### list_groups

List allowed policy groups.

```bash
curl -X POST http://127.0.0.1:8080/actions/list_groups \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Actor-Id: admin" \
  -d '{}'
```

**Response:**
```json
{"ok": true, "groups": ["default", "admins"]}
```

### show_user_ips

Show user-to-IP mapping from active sessions.

```bash
curl -X POST http://127.0.0.1:8080/actions/show_user_ips \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Actor-Id: admin" \
  -d '{}'
```

### create_user

Create a new VPN user. Optionally assign a static IP.

```bash
curl -X POST http://127.0.0.1:8080/actions/create_user \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Actor-Id: admin" \
  -d '{"username": "alice", "group": "default", "ipv4_address": "10.10.0.10"}'
```

**Response:**
```json
{
  "ok": true,
  "user": {"username": "alice", "group": "default", "ipv4_address": "10.10.0.10"},
  "changed_files": [...],
  "planned_files": [...],
  "verification": {"ok": true},
  "activation": {"ok": true, "activation_mode": "restart"},
  "provisioning": null
}
```

### update_user_ip

Update a user's static IP address.

```bash
curl -X POST http://127.0.0.1:8080/actions/update_user_ip \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Actor-Id: admin" \
  -d '{"username": "alice", "ipv4_address": "10.10.0.20"}'
```

### create_group

Create a new policy group with optional network configuration.

```bash
curl -X POST http://127.0.0.1:8080/actions/create_group \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Actor-Id: admin" \
  -d '{"group": "vpn-users", "ipv4_network": "10.10.0.0/24", "ipv4_netmask": "255.255.255.0", "routes": ["10.0.0.0/8"]}'
```

### assign_group

Reassign a user to a different policy group.

```bash
curl -X POST http://127.0.0.1:8080/actions/assign_group \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Actor-Id: admin" \
  -d '{"username": "alice", "group": "admins"}'
```

### reload_service

Validate config and reload ocserv.

```bash
curl -X POST http://127.0.0.1:8080/actions/reload_service \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Actor-Id: admin" \
  -d '{}'
```

---

## Destructive Actions (Require Confirmation)

The following actions require a two-phase confirmation flow. The first call returns a `pending_confirmation` with a `token`. Use `confirm_action` to execute.

### delete_user

```bash
# Step 1: Request deletion
curl -X POST http://127.0.0.1:8080/actions/delete_user \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Actor-Id: admin" \
  -d '{"username": "alice"}'

# Response: {"status": "pending_confirmation", "token": "<token>", ...}

# Step 2: Confirm
curl -X POST http://127.0.0.1:8080/actions/confirm_action \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Actor-Id: admin" \
  -d '{"token": "<token>", "decision": "confirm"}'
```

### disable_user

Disable a user (lock their password).

```bash
curl -X POST http://127.0.0.1:8080/actions/disable_user \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Actor-Id: admin" \
  -d '{"username": "alice"}'
```

### disable_group_users

Disable all users in a policy group. Requires confirmation.

```bash
curl -X POST http://127.0.0.1:8080/actions/disable_group_users \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Actor-Id: admin" \
  -d '{"group": "default"}'
```

### delete_group

Delete a policy group. Protected groups (`default`, `admins`) cannot be deleted.

```bash
curl -X POST http://127.0.0.1:8080/actions/delete_group \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Actor-Id: admin" \
  -d '{"group": "vpn-users"}'
```

### disconnect_session

Disconnect an active VPN session.

```bash
curl -X POST http://127.0.0.1:8080/actions/disconnect_session \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Actor-Id: admin" \
  -d '{"username": "alice"}'
```

### rollback_last_change

Rollback the last mutation to its pre-change state. Requires confirmation.

```bash
curl -X POST http://127.0.0.1:8080/actions/rollback_last_change \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Actor-Id: admin" \
  -d '{}'
```

### confirm_action

Confirm or cancel a pending destructive action.

```bash
curl -X POST http://127.0.0.1:8080/actions/confirm_action \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Actor-Id: admin" \
  -d '{"token": "<token>", "decision": "confirm"}'
```

**Decision values:** `confirm` or `cancel`

**Optional validation fields:**
- `expected_action` — verify the pending action type
- `expected_username` — verify the target user
- `expected_group` — verify the target group

---

## Confirmation Flow

```
Client                          Server
  |                               |
  |  POST /actions/delete_user    |
  |  {"username": "alice"}        |
  |------------------------------>|
  |                               |
  |  200 OK                       |
  |  {"status": "pending_confirmation",
  |   "token": "abc123...",       |
  |   "confirmation": {...}}      |
  |<------------------------------|
  |                               |
  |  POST /actions/confirm_action |
  |  {"token": "abc123...",       |
  |   "decision": "confirm"}      |
  |------------------------------>|
  |                               |
  |  200 OK                       |
  |  {"ok": true,                 |
  |   "executed": {...}}          |
  |<------------------------------|
```

Confirmations expire after 300 seconds (5 minutes) by default.

---

## Error Codes

| Code | Description |
|------|-------------|
| `UNAUTHORIZED_CLIENT` | Invalid or missing Bearer token |
| `REMOTE_ACCESS_FORBIDDEN` | Request from non-loopback address |
| `UNKNOWN_ACTOR` | Actor not in allowed actors list |
| `RATE_LIMIT_EXCEEDED` | Too many requests in window |
| `ACTION_NOT_ALLOWED` | Action not in allowlist |
| `INVALID_REQUEST:<field>` | Missing or invalid required field |
| `USER_ALREADY_EXISTS` | User already exists |
| `USER_NOT_FOUND` | User does not exist |
| `GROUP_NOT_FOUND` | Group does not exist |
| `GROUP_ALREADY_EXISTS` | Group already exists |
| `GROUP_IN_USE` | Group has assigned users |
| `PROTECTED_GROUP` | Cannot delete `default` or `admins` |
| `CONFIRMATION_NOT_FOUND` | Invalid confirmation token |
| `CONFIRMATION_EXPIRED` | Token expired (>300s) |
| `CONFIRMATION_REPLAYED` | Token already used |
| `ROLLBACK_NOT_AVAILABLE` | No rollback state available |
| `CONFIG_VALIDATION_FAILED` | ocserv config validation failed |
| `MUTATION_LOCK_FAILED` | Concurrent mutation in progress |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OCSERV_ADMIN_AUTH_TOKEN` | *(required)* | Bearer token for API authentication |
| `OCSERV_ADMIN_ALLOWED_ACTORS` | `operator-1` | Comma-separated allowed actor IDs |
| `OCSERV_ADMIN_HOST` | `127.0.0.1` | Bind address |
| `OCSERV_ADMIN_PORT` | `8080` | Bind port |
| `OCSERV_ADMIN_LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `OCSERV_ADMIN_RUNTIME_DIR` | `/var/lib/ocserv-admin` | Runtime state directory |
| `OCSERV_ADMIN_CONFIRMATION_STORE` | `memory` | Confirmation backend (`memory` or `file`) |
| `OCSERV_ADMIN_RATE_LIMIT_MAX_REQUESTS` | `20` | Max requests per window |
| `OCSERV_ADMIN_RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate limit window in seconds |

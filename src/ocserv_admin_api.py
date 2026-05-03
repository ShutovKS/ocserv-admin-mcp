# FILE: src/ocserv_admin_api.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Expose constrained localhost HTTP endpoints for approved user, session, group, reload, and validation actions.
#   SCOPE: Validate request payloads, enforce allowlists, delegate to the approved backend modules, and return structured JSON responses.
#   DEPENDS: M-SAFETY-CONTROLS, M-USER-LIFECYCLE, M-POLICY-GROUP-MANAGER, M-SESSION-MANAGER, M-OCSERV-ADAPTER, M-AUDIT-LOG
#   LINKS: M-OCSERV-ADMIN-API
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   AdminApiConfig - Runtime configuration for the localhost admin API.
#   validateRequest - Validate payloads and invariants for approved actions.
#   executeApprovedAction - Run one approved action through constrained handlers.
#   build_app - Construct the WSGI application callable.
#   serve - Start the localhost admin API server.
# END_MODULE_MAP

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
import shlex
import signal
import time as _time
from pathlib import Path
from typing import Any, Callable, Protocol
from uuid import uuid4
from wsgiref.simple_server import make_server

from src.audit_log import AuditSink, recordAuditEvent
from src.confirmation_state import FileBackedConfirmationStore, InMemoryConfirmationStore, PendingConfirmation, PendingConfirmationRequest, createPendingConfirmation, resolvePendingConfirmation
from src.ocserv_adapter import OcservPaths, healthCheck, loadUsers, rollbackLastChange, safeReload, serializeCommandResult, validateConfig, listGroups, showUserIps
from src.policy_group_manager import assignGroup, createGroup, deleteGroup, disableUsersInGroup
from src.safety_controls import InMemoryRateLimiter, OperatorIdentity, ProposedAdminAction, checkRateLimit, guardAction
from src.session_manager import disconnectSessionForUser, listSessions
from src.logging_config import get_logger, setup_logging
from src.metrics import MetricsCollector, format_prometheus
from src.user_lifecycle_manager import createUser, disableUser, removeUser, updateUserIp

_logger = get_logger("api")

DEFAULT_RUNTIME_DIR = Path("/var/lib/ocserv-admin")
DEFAULT_AUDIT_LOG_FILE = Path("/var/log/ocserv-admin/audit.log")
DEFAULT_USERS_FILE = Path("/etc/ocserv/passwd")
DEFAULT_MAIN_CONFIG_FILE = Path("/etc/ocserv/ocserv.conf")
DEFAULT_GROUP_CONFIG_DIR = Path("/etc/ocserv/config-per-group")
DEFAULT_MAIN_CONFIG_TEMPLATE = DEFAULT_RUNTIME_DIR / "templates" / "ocserv.conf.tpl"
DEFAULT_GROUP_TEMPLATE_DIR = DEFAULT_RUNTIME_DIR / "group-templates"
DEFAULT_USER_GROUP_MAP_FILE = DEFAULT_RUNTIME_DIR / "user-groups.json"
DEFAULT_VALIDATE_COMMAND = "/usr/sbin/ocserv --test-config --config /etc/ocserv/ocserv.conf"


@dataclass(slots=True)
class AdminApiConfig:
    host: str
    port: int
    allowed_actors: tuple[str, ...]
    auth_token: str
    paths: OcservPaths
    rate_limit_max_requests: int = 20
    rate_limit_window_seconds: int = 60
    rate_limit_read_max_requests: int | None = None


SERVER_VERSION = "0.1.0"


class ConfirmationStore(Protocol):
    def put(self, record: PendingConfirmation) -> None: ...

    def get(self, token: str) -> PendingConfirmation | None: ...


def _json_response(status: str, payload: dict[str, Any]) -> tuple[str, list[tuple[str, str]], bytes]:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    return status, [("Content-Type", "application/json"), ("Content-Length", str(len(body)))], body


def _load_json_body(environ: dict[str, Any]) -> dict[str, Any]:
    content_length = int(environ.get("CONTENT_LENGTH") or 0)
    raw_body = environ["wsgi.input"].read(content_length) if content_length else b"{}"
    if not raw_body:
        return {}
    return json.loads(raw_body.decode("utf-8"))


def _is_loopback_request(environ: dict[str, Any]) -> bool:
    remote_addr = str(environ.get("REMOTE_ADDR", ""))
    return remote_addr in {"127.0.0.1", "::1", "localhost", ""}


def _extract_bearer_token(environ: dict[str, Any]) -> str | None:
    header = str(environ.get("HTTP_AUTHORIZATION", ""))
    if not header.startswith("Bearer "):
        return None
    return header.removeprefix("Bearer ").strip() or None


def validateRequest(action: str, payload: dict[str, Any]) -> dict[str, Any]:
    required_fields = {
        "create_user": ("username",),
        "update_user_ip": ("username", "ipv4_address"),
        "create_group": ("group",),
        "disconnect_session": ("username",),
        "disable_user": ("username",),
        "disable_group_users": ("group",),
        "delete_user": ("username",),
        "delete_group": ("group",),
        "assign_group": ("username", "group"),
        "rollback_last_change": (),
        "confirm_action": ("token", "decision"),
    }
    if action in required_fields:
        missing = [field for field in required_fields[action] if not payload.get(field)]
        if missing:
            raise ValueError(f"INVALID_REQUEST:{','.join(missing)}")
    if action == "delete_user" and "force" in payload and not isinstance(payload["force"], bool):
        raise ValueError("INVALID_REQUEST:force")
    if "routes" in payload and (not isinstance(payload["routes"], list) or any(not isinstance(route, str) or not route for route in payload["routes"])):
        raise ValueError("INVALID_REQUEST:routes")
    if action != "confirm_action" and "confirmed" in payload:
        raise ValueError("INVALID_REQUEST:confirmed")
    if "confirmation_actor_id" in payload and not isinstance(payload["confirmation_actor_id"], str):
        raise ValueError("INVALID_REQUEST:confirmation_actor_id")
    return payload


@dataclass(slots=True)
class _ActionContext:
    config: AdminApiConfig
    paths: OcservPaths
    audit_sink: AuditSink
    request_id: str
    actor: OperatorIdentity
    decision: Any
    validated_payload: dict[str, Any]
    store: ConfirmationStore


def _handle_list_users(ctx: _ActionContext) -> dict[str, Any]:
    users = loadUsers(ctx.paths)
    recordAuditEvent(
        {
            "event": "users_listed",
            "request_id": ctx.request_id,
            "actor_id": ctx.actor.actor_id,
            "command": "list_users",
            "result": "ok",
            "message": "[OcservAdminApi][executeApprovedAction][BLOCK_EXECUTE_APPROVED_ACTION] listed users",
            "details": {"count": len(users)},
        },
        ctx.audit_sink,
    )
    return {"ok": True, "users": users}


def _handle_list_sessions(ctx: _ActionContext) -> dict[str, Any]:
    return {"ok": True, "sessions": listSessions(ctx.paths, ctx.audit_sink, ctx.request_id, ctx.actor.actor_id)}


def _handle_list_groups(ctx: _ActionContext) -> dict[str, Any]:
    return {"ok": True, "groups": listGroups(ctx.paths)}


def _handle_show_user_ips(ctx: _ActionContext) -> dict[str, Any]:
    return {"ok": True, "user_ips": showUserIps(ctx.paths, ctx.audit_sink, ctx.request_id, ctx.actor.actor_id)}


def _handle_disconnect_session(ctx: _ActionContext) -> dict[str, Any]:
    disconnected = disconnectSessionForUser(ctx.paths, str(ctx.validated_payload["username"]), ctx.audit_sink, ctx.request_id, ctx.actor.actor_id)
    return {"ok": True, **disconnected}


def _handle_create_user(ctx: _ActionContext) -> dict[str, Any]:
    created = createUser(
        ctx.paths,
        str(ctx.validated_payload["username"]),
        ctx.validated_payload.get("group"),
        ctx.validated_payload.get("ipv4_address"),
        ctx.decision,
        ctx.audit_sink,
        ctx.request_id,
        ctx.actor.actor_id,
    )
    return {"ok": True, **created}


def _handle_update_user_ip(ctx: _ActionContext) -> dict[str, Any]:
    updated = updateUserIp(
        ctx.paths,
        str(ctx.validated_payload["username"]),
        str(ctx.validated_payload["ipv4_address"]),
        ctx.decision,
        ctx.audit_sink,
        ctx.request_id,
        ctx.actor.actor_id,
    )
    return {"ok": True, **updated}


def _handle_create_group(ctx: _ActionContext) -> dict[str, Any]:
    created_group = createGroup(
        ctx.paths,
        str(ctx.validated_payload["group"]),
        ctx.validated_payload.get("ipv4_network"),
        ctx.validated_payload.get("ipv4_netmask"),
        ctx.validated_payload.get("routes") or [],
        ctx.audit_sink,
        ctx.request_id,
        ctx.actor.actor_id,
    )
    return {"ok": True, **created_group}


def _handle_disable_user(ctx: _ActionContext) -> dict[str, Any]:
    disabled = disableUser(ctx.paths, str(ctx.validated_payload["username"]), ctx.decision, ctx.audit_sink, ctx.request_id, ctx.actor.actor_id)
    return {"ok": True, **disabled}


def _handle_disable_group_users(ctx: _ActionContext) -> dict[str, Any]:
    disabled_group_users = disableUsersInGroup(ctx.paths, str(ctx.validated_payload["group"]), ctx.decision, ctx.audit_sink, ctx.request_id, ctx.actor.actor_id)
    return {"ok": True, **disabled_group_users}


def _handle_delete_user(ctx: _ActionContext) -> dict[str, Any]:
    removed = removeUser(
        ctx.paths,
        str(ctx.validated_payload["username"]),
        ctx.decision,
        ctx.audit_sink,
        ctx.request_id,
        ctx.actor.actor_id,
        force=bool(ctx.validated_payload.get("force", False)),
    )
    return {"ok": True, **removed}


def _handle_delete_group(ctx: _ActionContext) -> dict[str, Any]:
    deleted_group = deleteGroup(ctx.paths, str(ctx.validated_payload["group"]), ctx.decision, ctx.audit_sink, ctx.request_id, ctx.actor.actor_id)
    return {"ok": True, **deleted_group}


def _handle_assign_group(ctx: _ActionContext) -> dict[str, Any]:
    updated = assignGroup(ctx.paths, str(ctx.validated_payload["username"]), str(ctx.validated_payload["group"]), ctx.audit_sink, ctx.request_id, ctx.actor.actor_id)
    return {"ok": True, **updated}


def _handle_reload_service(ctx: _ActionContext) -> dict[str, Any]:
    return {"ok": True, "reload": _serialize_reload_result(safeReload(ctx.paths, ctx.audit_sink, ctx.request_id, ctx.actor.actor_id))}


def _handle_rollback_last_change(ctx: _ActionContext) -> dict[str, Any]:
    return {"ok": True, "rollback": rollbackLastChange(ctx.paths, ctx.audit_sink, ctx.request_id, ctx.actor.actor_id)}


def _handle_validate_config(ctx: _ActionContext) -> dict[str, Any]:
    validation = validateConfig(ctx.paths, ctx.audit_sink, ctx.request_id, ctx.actor.actor_id)
    return {"ok": validation.ok, "validation": _serialize_command_result(validation)}


def _handle_confirm_action(ctx: _ActionContext) -> dict[str, Any]:
    token = str(ctx.validated_payload["token"])
    pending = ctx.store.get(token)
    if pending is not None:
        expected_action = _normalize_expected_confirmation_value(ctx.validated_payload.get("expected_action"))
        expected_username = _normalize_expected_confirmation_value(ctx.validated_payload.get("expected_username"))
        expected_group = _normalize_expected_confirmation_value(ctx.validated_payload.get("expected_group"))
        if expected_action is not None and expected_action != pending.action:
            return {"ok": False, "error_code": "INVALID_CONFIRMATION_CONTEXT", "confirmation": _serialize_pending_confirmation(pending)}
        if expected_username is not None and expected_username != pending.target_user:
            return {"ok": False, "error_code": "INVALID_CONFIRMATION_CONTEXT", "confirmation": _serialize_pending_confirmation(pending)}
        if pending.target_group is not None and expected_group is not None and expected_group != pending.target_group:
            return {"ok": False, "error_code": "INVALID_CONFIRMATION_CONTEXT", "confirmation": _serialize_pending_confirmation(pending)}
    resolution = resolvePendingConfirmation(
        ctx.store,
        token,
        str(ctx.validated_payload["decision"]),
        ctx.audit_sink,
        requested_actor_id=str(ctx.validated_payload.get("confirmation_actor_id") or ctx.actor.actor_id),
    )
    if resolution.execute_allowed and pending is not None:
        resumed_payload = dict(pending.payload)
        resumed_payload["request_id"] = pending.request_id
        executed = executeApprovedAction(pending.action, resumed_payload, ctx.actor, ctx.config, ctx.store, confirmed_from_token=True)
        return {"ok": True, "resolution": asdict(resolution), "confirmation": _serialize_pending_confirmation(pending), "executed": executed}
    return {
        "ok": resolution.execute_allowed,
        "error_code": resolution.error_code,
        "resolution": asdict(resolution),
        "confirmation": _serialize_pending_confirmation(pending) if pending is not None else None,
    }


_ACTION_HANDLERS: dict[str, Callable[[_ActionContext], dict[str, Any]]] = {
    "list_users": _handle_list_users,
    "list_sessions": _handle_list_sessions,
    "list_groups": _handle_list_groups,
    "show_user_ips": _handle_show_user_ips,
    "disconnect_session": _handle_disconnect_session,
    "create_user": _handle_create_user,
    "update_user_ip": _handle_update_user_ip,
    "create_group": _handle_create_group,
    "disable_user": _handle_disable_user,
    "disable_group_users": _handle_disable_group_users,
    "delete_user": _handle_delete_user,
    "delete_group": _handle_delete_group,
    "assign_group": _handle_assign_group,
    "reload_service": _handle_reload_service,
    "rollback_last_change": _handle_rollback_last_change,
    "validate_config": _handle_validate_config,
    "confirm_action": _handle_confirm_action,
}


def executeApprovedAction(
    action: str,
    payload: dict[str, Any],
    actor: OperatorIdentity,
    config: AdminApiConfig,
    store: ConfirmationStore,
    *,
    confirmed_from_token: bool = False,
) -> dict[str, Any]:
    # START_BLOCK_EXECUTE_APPROVED_ACTION
    request_id = payload.get("request_id") or uuid4().hex
    audit_sink = AuditSink(config.paths.audit_log_file)
    validated_payload = validateRequest(action, payload)
    target_username = validated_payload.get("username")
    target_group = validated_payload.get("group")

    proposed = ProposedAdminAction(
        action=action,
        username=target_username if isinstance(target_username, str) else None,
        group=target_group,
        confirmed=confirmed_from_token,
        request_id=request_id,
    )
    decision = guardAction(proposed, actor, config.allowed_actors, audit_sink)
    if not decision.allowed:
        if decision.requires_confirmation:
            confirmation_summary = _build_confirmation_summary(action, validated_payload)
            pending = createPendingConfirmation(
                store,
                PendingConfirmationRequest(
                    action=action,
                    actor_id=str(validated_payload.get("confirmation_actor_id") or actor.actor_id),
                    target_user=proposed.username or (proposed.group if proposed.group is not None else action),
                    target_group=proposed.group,
                    summary=confirmation_summary,
                    request_id=request_id,
                    payload=dict(validated_payload),
                ),
                audit_sink,
            )
            return {
                "ok": False,
                "error_code": decision.error_code,
                "token": pending.token,
                "status": "pending_confirmation",
                "confirmation": {
                    "token": pending.token,
                    "action": pending.action,
                    "target_user": pending.target_user,
                    "target_group": pending.target_group,
                    "summary": pending.summary,
                    "expires_at": pending.expires_at.isoformat(),
                },
            }
        return {"ok": False, "error_code": decision.error_code, "status": "rejected"}

    ctx = _ActionContext(config=config, paths=config.paths, audit_sink=audit_sink, request_id=request_id, actor=actor, decision=decision, validated_payload=validated_payload, store=store)
    handler = _ACTION_HANDLERS.get(action)
    if handler is None:
        raise ValueError("ACTION_NOT_ALLOWED")
    return handler(ctx)
    # END_BLOCK_EXECUTE_APPROVED_ACTION


def _serialize_command_result(result: Any) -> dict[str, Any]:
    return {
        "ok": result.ok,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }


def _serialize_reload_result(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": result["ok"],
        "error_code": result["error_code"],
        "validation": _serialize_command_result(result["validation"]),
        "reload": _serialize_command_result(result["reload"]) if result["reload"] is not None else None,
        "health": _serialize_command_result(result.get("health")) if result.get("health") is not None else None,
        "activation_mode": result.get("activation_mode"),
        "restart_required": result.get("restart_required"),
    }


def _serialize_pending_confirmation(pending: PendingConfirmation) -> dict[str, Any]:
    return {
        "token": pending.token,
        "action": pending.action,
        "target_user": pending.target_user,
        "target_group": pending.target_group,
        "summary": pending.summary,
        "expires_at": pending.expires_at.isoformat(),
    }


def _build_confirmation_summary(action: str, payload: dict[str, Any]) -> str:
    username = payload.get("username")
    group = payload.get("group")
    if action == "disable_group_users" and group:
        return f"Disable all users in group {group}"
    if action == "delete_group" and group:
        return f"Delete group {group}"
    if action == "create_group" and group:
        return f"Create group {group}"
    if username and group:
        return f"{action} for user {username} in group {group}"
    if username:
        return f"{action} for user {username}"
    if group:
        return f"{action} for group {group}"
    return action


def _normalize_expected_confirmation_value(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return str(value)
    normalized = value.strip()
    if normalized.lower() in {"", "-", "null", "none"}:
        return None
    return normalized


def _build_confirmation_store(config: AdminApiConfig) -> ConfirmationStore:
    store_type = os.environ.get("OCSERV_ADMIN_CONFIRMATION_STORE", "memory")
    if store_type == "file":
        rollback_state_file = config.paths.rollback_state_file
        if rollback_state_file is None:
            raise RuntimeError("OCSERV_ADMIN_ROLLBACK_STATE_FILE_MISSING")
        store_path = rollback_state_file.parent / "confirmations.json"
        return FileBackedConfirmationStore(store_path)
    return InMemoryConfirmationStore()


def build_app(config: AdminApiConfig, metrics: MetricsCollector | None = None) -> Callable[[dict[str, Any], Callable[..., Any]], list[bytes]]:
    store = _build_confirmation_store(config)
    rate_limiter = InMemoryRateLimiter(config.rate_limit_max_requests, config.rate_limit_window_seconds, read_max_requests=config.rate_limit_read_max_requests)
    _metrics = metrics or MetricsCollector()

    def app(environ: dict[str, Any], start_response: Callable[..., Any]) -> list[bytes]:
        path = environ.get("PATH_INFO", "")
        method = environ.get("REQUEST_METHOD", "GET")
        actor_id = environ.get("HTTP_X_ACTOR_ID", "unknown-actor")
        actor = OperatorIdentity(actor_id=actor_id, authorized=False)
        try:
            if method == "GET" and path == "/metrics":
                metrics_body = format_prometheus(_metrics).encode("utf-8")
                start_response("200 OK", [("Content-Type", "text/plain; version=0.0.4; charset=utf-8"), ("Content-Length", str(len(metrics_body)))])
                return [metrics_body]
            elif method == "GET" and path == "/health":
                health = healthCheck(config.paths, AuditSink(config.paths.audit_log_file), uuid4().hex, "health-probe")
                status_code = "200 OK" if health.ok else "503 Service Unavailable"
                status, headers, body = _json_response(status_code, {
                    "ok": health.ok,
                    "service": "ocserv-admin",
                    "version": SERVER_VERSION,
                    "ocserv": _serialize_command_result(health),
                })
            elif method == "GET" and path == "/readiness":
                checks: dict[str, bool] = {
                    "users_file": config.paths.users_file.parent.exists(),
                    "groups_file": config.paths.groups_file.exists(),
                    "ocserv_service": healthCheck(config.paths).ok,
                }
                ready = all(checks.values())
                status_code = "200 OK" if ready else "503 Service Unavailable"
                status, headers, body = _json_response(status_code, {
                    "ready": ready,
                    "checks": checks,
                    "version": SERVER_VERSION,
                })
            elif method == "POST" and path.startswith("/actions/"):
                if not _is_loopback_request(environ):
                    raise PermissionError("REMOTE_ACCESS_FORBIDDEN")
                token = _extract_bearer_token(environ)
                if token != config.auth_token:
                    raise PermissionError("UNAUTHORIZED_CLIENT")
                actor = OperatorIdentity(actor_id=actor_id, authorized=True)
                action = path.removeprefix("/actions/")
                if not checkRateLimit(rate_limiter, f"backend-actor:{actor.actor_id}", action=action):
                    raise ValueError("RATE_LIMITED")
                t0 = _time.monotonic()
                payload = _load_json_body(environ)
                result = executeApprovedAction(action, payload, actor, config, store)
                _metrics.record_request(action, _time.monotonic() - t0, error=not result.get("ok", False))
                status_code = "200 OK" if result.get("ok") or result.get("status") == "pending_confirmation" else "400 Bad Request"
                status, headers, body = _json_response(status_code, result)
            else:
                status, headers, body = _json_response("404 Not Found", {"ok": False, "error_code": "NOT_FOUND"})
        except (ValueError, PermissionError) as error:
            recordAuditEvent(
                {
                    "event": "api_error",
                    "request_id": uuid4().hex,
                    "actor_id": actor.actor_id,
                    "command": path,
                    "result": "failed",
                    "error_code": str(error),
                    "message": "[OcservAdminApi][executeApprovedAction][BLOCK_EXECUTE_APPROVED_ACTION] rejected request",
                },
                AuditSink(config.paths.audit_log_file),
            )
            status, headers, body = _json_response("400 Bad Request", {"ok": False, "error_code": str(error)})
        start_response(status, headers)
        return [body]

    return app


def serve(config: AdminApiConfig) -> None:
    setup_logging(level=os.environ.get("OCSERV_ADMIN_LOG_LEVEL", "INFO"))
    ensure_runtime_dirs(config)
    app = build_app(config)
    audit_sink = AuditSink(config.paths.audit_log_file)
    _logger.info("[OcservAdminApi][serve] starting server on %s:%d", config.host, config.port)
    with make_server(config.host, config.port, app) as server:

        def _shutdown_handler(signum: int, frame: object) -> None:
            sig_name = signal.Signals(signum).name
            _logger.info("[OcservAdminApi][serve] received %s, shutting down", sig_name)
            recordAuditEvent(
                {
                    "event": "server_shutdown",
                    "message": f"[OcservAdminApi][serve] graceful shutdown on {sig_name}",
                    "details": {"signal": sig_name},
                },
                audit_sink,
            )
            server.shutdown()

        signal.signal(signal.SIGTERM, _shutdown_handler)
        signal.signal(signal.SIGINT, _shutdown_handler)
        server.serve_forever()
    _logger.info("[OcservAdminApi][serve] server stopped")


def ensure_runtime_dirs(config: AdminApiConfig) -> None:
    rollback_state_file = config.paths.rollback_state_file
    if rollback_state_file is None:
        raise RuntimeError("OCSERV_ADMIN_ROLLBACK_STATE_FILE_MISSING")
    runtime = rollback_state_file.parent
    runtime.mkdir(parents=True, exist_ok=True)
    if not config.paths.groups_file.exists() and config.paths.groups_file.suffix == ".json":
        config.paths.groups_file.parent.mkdir(parents=True, exist_ok=True)
        config.paths.groups_file.write_text(json.dumps({"groups": ["default", "admins"]}, indent=2) + "\n", encoding="utf-8")


def _parse_command(value: str) -> tuple[str, ...]:
    return tuple(shlex.split(value))


def build_config_from_env(runtime_root: Path | None = None) -> AdminApiConfig:
    runtime = runtime_root or Path(os.environ.get("OCSERV_ADMIN_RUNTIME_DIR", str(DEFAULT_RUNTIME_DIR)))
    read_limit_raw = os.environ.get("OCSERV_ADMIN_RATE_LIMIT_READ_MAX_REQUESTS")
    paths = OcservPaths(
        users_file=Path(os.environ.get("OCSERV_ADMIN_USERS_FILE", str(DEFAULT_USERS_FILE if runtime_root is None else runtime / "users.json"))),
        groups_file=Path(os.environ.get("OCSERV_ADMIN_GROUPS_FILE", str(runtime / "groups.json"))),
        audit_log_file=Path(os.environ.get("OCSERV_ADMIN_AUDIT_LOG_FILE", str(DEFAULT_AUDIT_LOG_FILE))),
        command_prefix=_parse_command(os.environ.get("OCSERV_ADMIN_COMMAND_PREFIX", "sudo -n")) if os.environ.get("OCSERV_ADMIN_COMMAND_PREFIX", "sudo -n") else (),
        ocpasswd_bin=os.environ.get("OCSERV_ADMIN_OCPASSWD_BIN", "/usr/bin/ocpasswd"),
        occtl_bin=os.environ.get("OCSERV_ADMIN_OCCTL_BIN", "/usr/bin/occtl"),
        validate_command=_parse_command(os.environ.get("OCSERV_ADMIN_VALIDATE_COMMAND", DEFAULT_VALIDATE_COMMAND)),
        reload_command=_parse_command(os.environ.get("OCSERV_ADMIN_RELOAD_COMMAND", "systemctl reload ocserv")),
        restart_command=_parse_command(os.environ.get("OCSERV_ADMIN_RESTART_COMMAND", "systemctl restart ocserv")),
        healthcheck_command=_parse_command(os.environ.get("OCSERV_ADMIN_HEALTHCHECK_COMMAND", "systemctl is-active ocserv")),
        main_config_file=Path(os.environ.get("OCSERV_ADMIN_MAIN_CONFIG_FILE", str(DEFAULT_MAIN_CONFIG_FILE if runtime_root is None else runtime / "ocserv.conf"))),
        main_config_template=Path(os.environ.get("OCSERV_ADMIN_MAIN_CONFIG_TEMPLATE", str(DEFAULT_MAIN_CONFIG_TEMPLATE if runtime_root is None else runtime / "templates" / "ocserv.conf.tpl"))),
        group_config_dir=Path(os.environ.get("OCSERV_ADMIN_GROUP_CONFIG_DIR", str(DEFAULT_GROUP_CONFIG_DIR if runtime_root is None else runtime / "groups.d"))),
        group_template_dir=Path(os.environ.get("OCSERV_ADMIN_GROUP_TEMPLATE_DIR", str(DEFAULT_GROUP_TEMPLATE_DIR if runtime_root is None else runtime / "group-templates"))),
        user_group_map_file=Path(os.environ.get("OCSERV_ADMIN_USER_GROUP_MAP_FILE", str(DEFAULT_USER_GROUP_MAP_FILE if runtime_root is None else runtime / "user-groups.json"))),
        rollback_state_file=Path(os.environ.get("OCSERV_ADMIN_ROLLBACK_STATE_FILE", str(runtime / "last-rollback.json"))),
    )
    auth_token = os.environ.get("OCSERV_ADMIN_AUTH_TOKEN")
    if not auth_token:
        raise RuntimeError("OCSERV_ADMIN_AUTH_TOKEN_MISSING")
    allowed_actor_env = os.environ.get("OCSERV_ADMIN_ALLOWED_ACTORS", "operator-1")
    allowed_actors = tuple(actor for actor in allowed_actor_env.split(",") if actor)
    host = os.environ.get("OCSERV_ADMIN_HOST", "127.0.0.1")
    port = int(os.environ.get("OCSERV_ADMIN_PORT", "8080"))
    return AdminApiConfig(
        host=host,
        port=port,
        allowed_actors=allowed_actors,
        auth_token=auth_token,
        paths=paths,
        rate_limit_max_requests=int(os.environ.get("OCSERV_ADMIN_RATE_LIMIT_MAX_REQUESTS", "20")),
        rate_limit_window_seconds=int(os.environ.get("OCSERV_ADMIN_RATE_LIMIT_WINDOW_SECONDS", "60")),
        rate_limit_read_max_requests=int(read_limit_raw) if read_limit_raw else None,
    )


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ocserv-admin-api",
        description="ocserv-admin backend API server",
    )
    parser.add_argument("--host", default=None, help="Bind address (default: $OCSERV_ADMIN_HOST or 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="Bind port (default: $OCSERV_ADMIN_PORT or 8080)")
    parser.add_argument("--log-level", default=None, choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Log level (default: INFO)")
    parser.add_argument("--validate-config", action="store_true", help="Validate configuration and exit")
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")
    return parser


def main() -> None:
    parser = _build_cli_parser()
    args = parser.parse_args()

    if args.log_level:
        os.environ["OCSERV_ADMIN_LOG_LEVEL"] = args.log_level
    if args.host:
        os.environ["OCSERV_ADMIN_HOST"] = args.host
    if args.port is not None:
        os.environ["OCSERV_ADMIN_PORT"] = str(args.port)

    config = build_config_from_env()

    if args.validate_config:
        _logger.info("[OcservAdminApi][main] configuration valid")
        return

    serve(config)


if __name__ == "__main__":
    main()

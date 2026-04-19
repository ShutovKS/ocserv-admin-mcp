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

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4
from wsgiref.simple_server import make_server

from src.audit_log import AuditSink, recordAuditEvent
from src.confirmation_state import InMemoryConfirmationStore, PendingConfirmationRequest, createPendingConfirmation, resolvePendingConfirmation
from src.ocserv_adapter import OcservPaths, healthCheck, loadUsers, rollbackLastChange, safeReload, serializeCommandResult, validateConfig
from src.policy_group_manager import assignGroup
from src.safety_controls import InMemoryRateLimiter, OperatorIdentity, ProposedAdminAction, checkRateLimit, guardAction
from src.session_manager import disconnectSessionForUser, listSessions
from src.user_lifecycle_manager import createUser, disableUser, removeUser


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
        "disconnect_session": ("username",),
        "disable_user": ("username",),
        "delete_user": ("username",),
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
    if action != "confirm_action" and "confirmed" in payload:
        raise ValueError("INVALID_REQUEST:confirmed")
    if "confirmation_actor_id" in payload and not isinstance(payload["confirmation_actor_id"], str):
        raise ValueError("INVALID_REQUEST:confirmation_actor_id")
    return payload


def executeApprovedAction(
    action: str,
    payload: dict[str, Any],
    actor: OperatorIdentity,
    config: AdminApiConfig,
    store: InMemoryConfirmationStore,
    *,
    confirmed_from_token: bool = False,
) -> dict[str, Any]:
    # START_BLOCK_EXECUTE_APPROVED_ACTION
    request_id = payload.get("request_id") or uuid4().hex
    audit_sink = AuditSink(config.paths.audit_log_file)
    validated_payload = validateRequest(action, payload)
    proposed = ProposedAdminAction(
        action=action,
        username=validated_payload.get("username"),
        group=validated_payload.get("group"),
        confirmed=confirmed_from_token,
        request_id=request_id,
    )
    decision = guardAction(proposed, actor, config.allowed_actors, audit_sink)
    if not decision.allowed:
        if decision.requires_confirmation:
            pending = createPendingConfirmation(
                store,
                PendingConfirmationRequest(
                    action=action,
                    actor_id=str(validated_payload.get("confirmation_actor_id") or actor.actor_id),
                    target_user=proposed.username or action,
                    request_id=request_id,
                    payload=dict(validated_payload),
                ),
                audit_sink,
            )
            return {"ok": False, "error_code": decision.error_code, "token": pending.token, "status": "pending_confirmation"}
        return {"ok": False, "error_code": decision.error_code, "status": "rejected"}

    if action == "list_users":
        users = loadUsers(config.paths)
        recordAuditEvent(
            {
                "event": "users_listed",
                "request_id": request_id,
                "actor_id": actor.actor_id,
                "command": "list_users",
                "result": "ok",
                "message": "[OcservAdminApi][executeApprovedAction][BLOCK_EXECUTE_APPROVED_ACTION] listed users",
                "details": {"count": len(users)},
            },
            audit_sink,
        )
        return {"ok": True, "users": users}
    if action == "list_sessions":
        return {"ok": True, "sessions": listSessions(config.paths, audit_sink, request_id, actor.actor_id)}
    if action == "disconnect_session":
        disconnected = disconnectSessionForUser(config.paths, str(validated_payload["username"]), audit_sink, request_id, actor.actor_id)
        return {"ok": True, **disconnected}
    if action == "create_user":
        created = createUser(config.paths, str(validated_payload["username"]), validated_payload.get("group"), decision, audit_sink, request_id, actor.actor_id)
        return {"ok": True, **created}
    if action == "disable_user":
        disabled = disableUser(config.paths, str(validated_payload["username"]), decision, audit_sink, request_id, actor.actor_id)
        return {"ok": True, **disabled}
    if action == "delete_user":
        removed = removeUser(
            config.paths,
            str(validated_payload["username"]),
            decision,
            audit_sink,
            request_id,
            actor.actor_id,
            force=bool(validated_payload.get("force", False)),
        )
        return {"ok": True, **removed}
    if action == "assign_group":
        updated = assignGroup(config.paths, str(validated_payload["username"]), str(validated_payload["group"]), audit_sink, request_id, actor.actor_id)
        return {"ok": True, **updated}
    if action == "reload_service":
        return {"ok": True, "reload": _serialize_reload_result(safeReload(config.paths, audit_sink, request_id, actor.actor_id))}
    if action == "rollback_last_change":
        return {"ok": True, "rollback": rollbackLastChange(config.paths, audit_sink, request_id, actor.actor_id)}
    if action == "validate_config":
        validation = validateConfig(config.paths, audit_sink, request_id, actor.actor_id)
        return {"ok": validation.ok, "validation": _serialize_command_result(validation)}
    if action == "confirm_action":
        token = str(validated_payload["token"])
        pending = store.get(token)
        resolution = resolvePendingConfirmation(
            store,
            token,
            str(validated_payload["decision"]),
            audit_sink,
            requested_actor_id=str(validated_payload.get("confirmation_actor_id") or actor.actor_id),
        )
        if resolution.execute_allowed and pending is not None:
            resumed_payload = dict(pending.payload)
            resumed_payload["request_id"] = pending.request_id
            executed = executeApprovedAction(pending.action, resumed_payload, actor, config, store, confirmed_from_token=True)
            return {"ok": True, "resolution": asdict(resolution), "executed": executed}
        return {
            "ok": resolution.execute_allowed,
            "error_code": resolution.error_code,
            "resolution": asdict(resolution),
        }
    raise ValueError("ACTION_NOT_ALLOWED")
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


def build_app(config: AdminApiConfig) -> Callable[[dict[str, Any], Callable[..., Any]], list[bytes]]:
    store = InMemoryConfirmationStore()
    rate_limiter = InMemoryRateLimiter(config.rate_limit_max_requests, config.rate_limit_window_seconds)

    def app(environ: dict[str, Any], start_response: Callable[..., Any]) -> list[bytes]:
        path = environ.get("PATH_INFO", "")
        method = environ.get("REQUEST_METHOD", "GET")
        actor_id = environ.get("HTTP_X_ACTOR_ID", "unknown-actor")
        actor = OperatorIdentity(actor_id=actor_id, authorized=False)
        try:
            if method == "GET" and path == "/health":
                health = healthCheck(config.paths, AuditSink(config.paths.audit_log_file), uuid4().hex, "health-probe")
                status_code = "200 OK" if health.ok else "503 Service Unavailable"
                status, headers, body = _json_response(status_code, {"ok": health.ok, "service": "ocserv-admin", "ocserv": _serialize_command_result(health)})
            elif method == "POST" and path.startswith("/actions/"):
                if not _is_loopback_request(environ):
                    raise PermissionError("REMOTE_ACCESS_FORBIDDEN")
                token = _extract_bearer_token(environ)
                if token != config.auth_token:
                    raise PermissionError("UNAUTHORIZED_CLIENT")
                actor = OperatorIdentity(actor_id=actor_id, authorized=True)
                if not checkRateLimit(rate_limiter, f"backend-actor:{actor.actor_id}"):
                    raise ValueError("RATE_LIMITED")
                action = path.removeprefix("/actions/")
                payload = _load_json_body(environ)
                result = executeApprovedAction(action, payload, actor, config, store)
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
    app = build_app(config)
    with make_server(config.host, config.port, app) as server:
        server.serve_forever()


def build_config_from_env(runtime_root: Path | None = None) -> AdminApiConfig:
    runtime = runtime_root or Path(os.environ.get("OCSERV_ADMIN_RUNTIME_DIR", str(DEFAULT_RUNTIME_DIR)))
    runtime.mkdir(parents=True, exist_ok=True)
    paths = OcservPaths(
        users_file=Path(os.environ.get("OCSERV_ADMIN_USERS_FILE", str(DEFAULT_USERS_FILE if runtime_root is None else runtime / "users.json"))),
        groups_file=Path(os.environ.get("OCSERV_ADMIN_GROUPS_FILE", str(runtime / "groups.json"))),
        audit_log_file=Path(os.environ.get("OCSERV_ADMIN_AUDIT_LOG_FILE", str(DEFAULT_AUDIT_LOG_FILE))),
        command_prefix=tuple(os.environ.get("OCSERV_ADMIN_COMMAND_PREFIX", "sudo -n").split()) if os.environ.get("OCSERV_ADMIN_COMMAND_PREFIX", "sudo -n") else (),
        ocpasswd_bin=os.environ.get("OCSERV_ADMIN_OCPASSWD_BIN", "/usr/bin/ocpasswd"),
        occtl_bin=os.environ.get("OCSERV_ADMIN_OCCTL_BIN", "/usr/bin/occtl"),
        validate_command=tuple(os.environ.get("OCSERV_ADMIN_VALIDATE_COMMAND", DEFAULT_VALIDATE_COMMAND).split()),
        reload_command=tuple(os.environ.get("OCSERV_ADMIN_RELOAD_COMMAND", "systemctl reload ocserv").split()),
        restart_command=tuple(os.environ.get("OCSERV_ADMIN_RESTART_COMMAND", "systemctl restart ocserv").split()),
        healthcheck_command=tuple(os.environ.get("OCSERV_ADMIN_HEALTHCHECK_COMMAND", "systemctl is-active ocserv").split()),
        main_config_file=Path(os.environ.get("OCSERV_ADMIN_MAIN_CONFIG_FILE", str(DEFAULT_MAIN_CONFIG_FILE if runtime_root is None else runtime / "ocserv.conf"))),
        main_config_template=Path(os.environ.get("OCSERV_ADMIN_MAIN_CONFIG_TEMPLATE", str(DEFAULT_MAIN_CONFIG_TEMPLATE if runtime_root is None else runtime / "templates" / "ocserv.conf.tpl"))),
        group_config_dir=Path(os.environ.get("OCSERV_ADMIN_GROUP_CONFIG_DIR", str(DEFAULT_GROUP_CONFIG_DIR if runtime_root is None else runtime / "groups.d"))),
        group_template_dir=Path(os.environ.get("OCSERV_ADMIN_GROUP_TEMPLATE_DIR", str(DEFAULT_GROUP_TEMPLATE_DIR if runtime_root is None else runtime / "group-templates"))),
        user_group_map_file=Path(os.environ.get("OCSERV_ADMIN_USER_GROUP_MAP_FILE", str(DEFAULT_USER_GROUP_MAP_FILE if runtime_root is None else runtime / "user-groups.json"))),
    )
    if not paths.groups_file.exists() and paths.groups_file.suffix == ".json":
        paths.groups_file.parent.mkdir(parents=True, exist_ok=True)
        paths.groups_file.write_text(json.dumps({"groups": ["default", "admins"]}, indent=2) + "\n", encoding="utf-8")
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
    )


if __name__ == "__main__":
    serve(build_config_from_env())

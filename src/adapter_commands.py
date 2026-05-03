# FILE: src/adapter_commands.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Wrap subprocess calls for occtl, service validation, reload, and health checks.
#   SCOPE: Execute approved system commands through constrained wrappers with structured results and audit logging.
#   DEPENDS: M-OCSERV-ADAPTER, M-AUDIT-LOG
#   LINKS: M-ADAPTER-COMMANDS
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   runOcctl - Execute approved occtl reads and normalize their output.
#   disconnectSession - Disconnect an active ocserv session through the approved occtl surface.
#   healthCheck - Run a health check against the configured ocserv service.
#   validateConfig - Validate ocserv-related config before reload.
#   reloadService - Reload ocserv with structured result reporting.
#   safeReload - Run validation first and reload only on success.
#   serializeCommandResult - Convert a command result into JSON-safe structured data.
# END_MODULE_MAP

from __future__ import annotations

from typing import Any

import src.ocserv_adapter as _oa
from src.audit_log import AuditSink, recordAuditEvent
from src.logging_config import get_logger

_logger = get_logger("commands")


def serializeCommandResult(result: _oa.SystemCommandResult | None) -> dict[str, Any] | None:
    if result is None:
        return None
    return {
        "ok": result.ok,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }


# START_CONTRACT: runOcctl
#   PURPOSE: Run approved occtl read operations and normalize their structured output.
#   INPUTS: { paths: OcservPaths - adapter config, subcommand: str - approved occtl operation, audit_sink: AuditSink | None - audit destination, request_id: str - request id, actor_id: str - actor id }
#   OUTPUTS: { list[dict[str, Any]] - normalized occtl records }
#   SIDE_EFFECTS: [executes occtl and writes an audit record]
#   LINKS: [validateConfig, reloadService]
# END_CONTRACT: runOcctl
def runOcctl(
    paths: _oa.OcservPaths,
    subcommand: str,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> list[dict[str, Any]]:
    commands = {
        "show_users": _oa._with_prefix(paths, (paths.occtl_bin, "show", "users")),
        "show_sessions": _oa._with_prefix(paths, (paths.occtl_bin, "show", "sessions", "all")),
    }
    if subcommand not in commands:
        raise ValueError("OCCTL_EXECUTION_FAILED")
    result = _oa._run_command(commands[subcommand])
    if not result.ok:
        raise ValueError("OCCTL_EXECUTION_FAILED")
    normalized = _oa._normalize_occtl_output(result.stdout)
    recordAuditEvent(
        {
            "event": "occtl_run",
            "request_id": request_id,
            "actor_id": actor_id,
            "command": subcommand,
            "result": "ok",
            "message": "[OcservAdapter][runOcctl][BLOCK_RUN_OCCTL] executed occtl command",
            "details": {"items": len(normalized)},
        },
        audit_sink,
    )
    return normalized


# START_CONTRACT: disconnectSession
#   PURPOSE: Disconnect an active ocserv session through the approved occtl control surface.
#   INPUTS: { paths: OcservPaths - adapter config, username: str - target VPN identity, audit_sink: AuditSink | None - audit destination, request_id: str - request id, actor_id: str - actor id }
#   OUTPUTS: { SystemCommandResult - disconnect command result }
#   SIDE_EFFECTS: [executes occtl disconnect and writes an audit record]
#   LINKS: [runOcctl]
# END_CONTRACT: disconnectSession
def disconnectSession(
    paths: _oa.OcservPaths,
    username: str,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> _oa.SystemCommandResult:
    # START_BLOCK_DISCONNECT_SESSION
    result = _oa._run_command(_oa._with_prefix(paths, (paths.occtl_bin, "disconnect", "user", username)))
    recordAuditEvent(
        {
            "event": "session_disconnected",
            "request_id": request_id,
            "actor_id": actor_id,
            "command": "disconnect_session",
            "target_user": username,
            "result": "ok" if result.ok else "failed",
            "error_code": None if result.ok else "SESSION_DISCONNECT_FAILED",
            "message": "[OcservAdapter][disconnectSession][BLOCK_DISCONNECT_SESSION] disconnected session",
            "details": {"stderr": result.stderr, "stdout": result.stdout},
        },
        audit_sink,
    )
    return result
    # END_BLOCK_DISCONNECT_SESSION


# START_CONTRACT: validateConfig
#   PURPOSE: Validate ocserv configuration before reload.
#   INPUTS: { paths: OcservPaths - adapter config, audit_sink: AuditSink | None - audit destination, request_id: str - request id, actor_id: str - actor id }
#   OUTPUTS: { SystemCommandResult - validation result }
#   SIDE_EFFECTS: [executes validation command and writes an audit record]
#   LINKS: [safeReload]
# END_CONTRACT: validateConfig
def validateConfig(
    paths: _oa.OcservPaths,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> _oa.SystemCommandResult:
    # START_BLOCK_VALIDATE_CONFIG
    _logger.debug("[OcservAdapter][validateConfig] running validation")
    result = _oa._run_command(_oa._with_prefix(paths, paths.validate_command), timeout=_oa.VALIDATION_COMMAND_TIMEOUT)
    if not result.ok:
        _logger.error("[OcservAdapter][validateConfig] validation failed: %s", result.stderr)
    recordAuditEvent(
        {
            "event": "config_validated",
            "request_id": request_id,
            "actor_id": actor_id,
            "command": "validate_config",
            "result": "ok" if result.ok else "failed",
            "error_code": None if result.ok else "CONFIG_VALIDATION_FAILED",
            "message": "[OcservAdapter][validateConfig][BLOCK_VALIDATE_CONFIG] validated configuration",
            "details": {"stderr": result.stderr, "stdout": result.stdout},
        },
        audit_sink,
    )
    return result
    # END_BLOCK_VALIDATE_CONFIG


# START_CONTRACT: reloadService
#   PURPOSE: Reload ocserv through the configured service command.
#   INPUTS: { paths: OcservPaths - adapter config, audit_sink: AuditSink | None - audit destination, request_id: str - request id, actor_id: str - actor id }
#   OUTPUTS: { SystemCommandResult - reload result }
#   SIDE_EFFECTS: [executes reload command and writes an audit record]
#   LINKS: [safeReload]
# END_CONTRACT: reloadService
def reloadService(
    paths: _oa.OcservPaths,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> _oa.SystemCommandResult:
    # START_BLOCK_SAFE_RELOAD
    result = _oa._run_command(_oa._with_prefix(paths, paths.reload_command), timeout=_oa.VALIDATION_COMMAND_TIMEOUT)
    recordAuditEvent(
        {
            "event": "service_reloaded",
            "request_id": request_id,
            "actor_id": actor_id,
            "command": "reload_service",
            "result": "ok" if result.ok else "failed",
            "reload_status": "reloaded" if result.ok else "failed",
            "error_code": None if result.ok else "SERVICE_RELOAD_FAILED",
            "message": "[OcservAdapter][reloadService][BLOCK_SAFE_RELOAD] reloaded service",
            "details": {"stderr": result.stderr, "stdout": result.stdout},
        },
        audit_sink,
    )
    return result
    # END_BLOCK_SAFE_RELOAD


def healthCheck(
    paths: _oa.OcservPaths,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> _oa.SystemCommandResult:
    result = _oa._run_command(_oa._with_prefix(paths, paths.healthcheck_command))
    recordAuditEvent(
        {
            "event": "service_health_checked",
            "request_id": request_id,
            "actor_id": actor_id,
            "command": "health_check",
            "result": "ok" if result.ok else "failed",
            "error_code": None if result.ok else "SERVICE_HEALTHCHECK_FAILED",
            "message": "[OcservAdapter][healthCheck][BLOCK_HEALTH_CHECK] checked ocserv health",
            "details": {"stderr": result.stderr, "stdout": result.stdout},
        },
        audit_sink,
    )
    return result


# START_CONTRACT: safeReload
#   PURPOSE: Validate config before any reload attempt and stop on failure.
#   INPUTS: { paths: OcservPaths - adapter config, audit_sink: AuditSink | None - audit destination, request_id: str - request id, actor_id: str - actor id }
#   OUTPUTS: { dict[str, Any] - combined validation and reload result }
#   SIDE_EFFECTS: [may execute validation and reload commands, writes audit records]
#   LINKS: [validateConfig, reloadService]
# END_CONTRACT: safeReload
def safeReload(
    paths: _oa.OcservPaths,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> dict[str, Any]:
    validation = validateConfig(paths, audit_sink, request_id, actor_id)
    if not validation.ok:
        return {
            "ok": False,
            "validation": validation,
            "reload": None,
            "error_code": "CONFIG_VALIDATION_FAILED",
            "activation_mode": "reload",
            "restart_required": False,
        }
    reload_result = reloadService(paths, audit_sink, request_id, actor_id)
    health = healthCheck(paths, audit_sink, request_id, actor_id) if reload_result.ok else None
    return {
        "ok": reload_result.ok and (health is None or health.ok),
        "validation": validation,
        "reload": reload_result,
        "health": health,
        "error_code": None if reload_result.ok and (health is None or health.ok) else ("SERVICE_RELOAD_FAILED" if not reload_result.ok else "SERVICE_HEALTHCHECK_FAILED"),
        "activation_mode": "reload",
        "restart_required": False,
    }

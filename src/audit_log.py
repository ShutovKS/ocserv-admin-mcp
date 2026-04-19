# FILE: src/audit_log.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Emit structured audit and operational records for approved and rejected ocserv administrative actions.
#   SCOPE: Build stable audit context, redact sensitive data, and append JSON-line audit records to the configured sink.
#   DEPENDS: none
#   LINKS: M-AUDIT-LOG
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   buildAuditContext - Normalize audit metadata into a stable structured record.
#   recordAuditEvent - Redact sensitive fields and append a JSON-line audit record.
# END_MODULE_MAP

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any, Mapping


SENSITIVE_KEYS = {
    "password",
    "secret",
    "token",
    "cookie",
    "certificate",
    "cert",
    "private_key",
    "config_body",
    "full_config",
}


@dataclass(slots=True)
class AuditSink:
    path: Path
    error_path: Path | None = None
    admin_change_path: Path | None = None


ERROR_RESULTS = {"failed", "rejected"}
ADMIN_CHANGE_COMMANDS = {
    "create_user",
    "disable_user",
    "delete_user",
    "assign_group",
    "disconnect_session",
    "reload_service",
    "restart_service",
    "rollback_last_change",
}


def _resolved_error_path(sink: AuditSink) -> Path:
    return sink.error_path or sink.path.with_name("error.log")


def _resolved_admin_change_path(sink: AuditSink) -> Path:
    return sink.admin_change_path or sink.path.with_name("admin-changes.log")


def _append_json_line(path: Path, record: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def _should_write_error_log(record: Mapping[str, Any]) -> bool:
    result = record.get("result")
    level = record.get("level")
    return bool(record.get("error_code")) or level == "error" or result in ERROR_RESULTS


def _should_write_admin_change_log(record: Mapping[str, Any]) -> bool:
    return record.get("result") == "ok" and record.get("command") in ADMIN_CHANGE_COMMANDS


# START_CONTRACT: _redact_value
#   PURPOSE: Remove or mask sensitive values before they enter the audit log.
#   INPUTS: { value: Any - candidate value to redact, key: str | None - field name used to detect sensitive data }
#   OUTPUTS: { Any - redacted safe value }
#   SIDE_EFFECTS: none
#   LINKS: [recordAuditEvent]
# END_CONTRACT: _redact_value
def _redact_value(value: Any, key: str | None = None) -> Any:
    lowered_key = (key or "").lower()
    if lowered_key in SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {item_key: _redact_value(item_value, item_key) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_value(item) for item in value]
    return value


# START_CONTRACT: buildAuditContext
#   PURPOSE: Construct a stable structured audit context for downstream modules.
#   INPUTS: { event: Mapping[str, Any] - partial audit metadata }
#   OUTPUTS: { dict[str, Any] - normalized audit record }
#   SIDE_EFFECTS: none
#   LINKS: [recordAuditEvent]
# END_CONTRACT: buildAuditContext
def buildAuditContext(event: Mapping[str, Any]) -> dict[str, Any]:
    timestamp = event.get("timestamp")
    normalized_timestamp = timestamp or datetime.now(UTC).isoformat()
    context = {
        "timestamp": normalized_timestamp,
        "level": event.get("level", "info"),
        "event": event.get("event", "audit_event"),
        "request_id": event.get("request_id", "unknown-request"),
        "actor_type": event.get("actor_type", "operator"),
        "actor_id": event.get("actor_id", "unknown-actor"),
        "command": event.get("command"),
        "target_user": event.get("target_user"),
        "target_group": event.get("target_group"),
        "result": event.get("result", "unknown"),
        "reload_status": event.get("reload_status"),
        "error_code": event.get("error_code"),
        "changes": event.get("changes", []),
        "message": event.get("message"),
        "details": _redact_value(event.get("details", {}), "details"),
    }
    return context


# START_CONTRACT: recordAuditEvent
#   PURPOSE: Persist a redaction-aware action record to the configured sink.
#   INPUTS: { event: Mapping[str, Any] - audit payload, sink: AuditSink | Path | None - target audit log }
#   OUTPUTS: { dict[str, Any] - persisted audit record }
#   SIDE_EFFECTS: [writes a JSON line to the audit sink when configured]
#   LINKS: [buildAuditContext]
# END_CONTRACT: recordAuditEvent
def recordAuditEvent(event: Mapping[str, Any], sink: AuditSink | Path | None = None) -> dict[str, Any]:
    # START_BLOCK_RECORD_AUDIT_EVENT
    record = buildAuditContext(event)
    sink_path: Path | None = None
    error_path: Path | None = None
    admin_change_path: Path | None = None
    if isinstance(sink, AuditSink):
        sink_path = sink.path
        error_path = _resolved_error_path(sink)
        admin_change_path = _resolved_admin_change_path(sink)
    elif isinstance(sink, Path):
        sink_path = sink
        error_path = sink.with_name("error.log")
        admin_change_path = sink.with_name("admin-changes.log")

    if sink_path is not None:
        _append_json_line(sink_path, record)
        if error_path is not None and _should_write_error_log(record):
            _append_json_line(error_path, record)
        if admin_change_path is not None and _should_write_admin_change_log(record):
            _append_json_line(admin_change_path, record)
    return record
    # END_BLOCK_RECORD_AUDIT_EVENT

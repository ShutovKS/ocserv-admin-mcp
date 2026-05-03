# FILE: src/confirmation_state.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Track pending destructive actions, explicit confirmations, expiry, and replay-safe resolution state.
#   SCOPE: Create pending confirmation records and resolve them exactly once with deterministic expiration handling.
#   DEPENDS: M-AUDIT-LOG, M-SAFETY-CONTROLS
#   LINKS: M-CONFIRMATION-STATE
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   PendingConfirmationRequest - Input required to create a confirmation record.
#   PendingConfirmation - Stored pending confirmation state.
#   ConfirmationResolution - Result of a confirmation resolution attempt.
#   InMemoryConfirmationStore - Deterministic runtime store for pending confirmations.
#   FileBackedConfirmationStore - Persistent file-backed confirmation store with expiry pruning.
#   createPendingConfirmation - Create and record a pending confirmation.
#   resolvePendingConfirmation - Resolve a confirmation token once.
# END_MODULE_MAP

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from src.audit_log import AuditSink, recordAuditEvent


@dataclass(slots=True)
class PendingConfirmationRequest:
    action: str
    actor_id: str
    target_user: str
    request_id: str
    expires_in_seconds: int = 300
    target_group: str | None = None
    summary: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PendingConfirmation:
    token: str
    action: str
    actor_id: str
    target_user: str
    target_group: str | None
    summary: str | None
    request_id: str
    status: str
    expires_at: datetime
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ConfirmationResolution:
    token: str
    status: str
    execute_allowed: bool
    error_code: str | None = None
    action: str | None = None
    target_user: str | None = None
    target_group: str | None = None


class InMemoryConfirmationStore:
    def __init__(self) -> None:
        self._records: dict[str, PendingConfirmation] = {}

    def put(self, record: PendingConfirmation) -> None:
        self._records[record.token] = record

    def get(self, token: str) -> PendingConfirmation | None:
        return self._records.get(token)


class FileBackedConfirmationStore:
    """Persistent confirmation store backed by a JSON file in the runtime directory."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._records: dict[str, PendingConfirmation] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        now = datetime.now(UTC)
        for token, entry in data.items():
            if not isinstance(entry, dict):
                continue
            expires_at = datetime.fromisoformat(entry["expires_at"])
            if expires_at < now:
                continue
            self._records[token] = PendingConfirmation(
                token=entry["token"],
                action=entry["action"],
                actor_id=entry["actor_id"],
                target_user=entry["target_user"],
                target_group=entry.get("target_group"),
                summary=entry.get("summary"),
                request_id=entry["request_id"],
                status=entry["status"],
                expires_at=expires_at,
                payload=entry.get("payload", {}),
            )

    def _flush(self) -> None:
        serialized: dict[str, dict[str, Any]] = {}
        now = datetime.now(UTC)
        for token, record in self._records.items():
            if record.expires_at < now:
                continue
            serialized[token] = {
                "token": record.token,
                "action": record.action,
                "actor_id": record.actor_id,
                "target_user": record.target_user,
                "target_group": record.target_group,
                "summary": record.summary,
                "request_id": record.request_id,
                "status": record.status,
                "expires_at": record.expires_at.isoformat(),
                "payload": record.payload,
            }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(serialized, indent=2) + "\n", encoding="utf-8")

    def put(self, record: PendingConfirmation) -> None:
        self._records[record.token] = record
        self._flush()

    def get(self, token: str) -> PendingConfirmation | None:
        return self._records.get(token)


class ConfirmationStore(Protocol):
    def put(self, record: PendingConfirmation) -> None: ...

    def get(self, token: str) -> PendingConfirmation | None: ...


# START_CONTRACT: createPendingConfirmation
#   PURPOSE: Create a pending confirmation record for a destructive action.
#   INPUTS: { store: InMemoryConfirmationStore - confirmation store, request: PendingConfirmationRequest - pending request, audit_sink: AuditSink | None - audit destination, now: datetime | None - override for deterministic tests }
#   OUTPUTS: { PendingConfirmation - created pending confirmation }
#   SIDE_EFFECTS: [stores a pending confirmation and writes an audit record]
#   LINKS: [resolvePendingConfirmation]
# END_CONTRACT: createPendingConfirmation
def createPendingConfirmation(
    store: ConfirmationStore,
    request: PendingConfirmationRequest,
    audit_sink: AuditSink | None = None,
    now: datetime | None = None,
) -> PendingConfirmation:
    # START_BLOCK_CREATE_PENDING_CONFIRMATION
    current_time = now or datetime.now(UTC)
    pending = PendingConfirmation(
        token=uuid4().hex,
        action=request.action,
        actor_id=request.actor_id,
        target_user=request.target_user,
        target_group=request.target_group,
        summary=request.summary,
        request_id=request.request_id,
        status="pending",
        expires_at=current_time + timedelta(seconds=request.expires_in_seconds),
        payload=dict(request.payload),
    )
    store.put(pending)
    recordAuditEvent(
        {
            "event": "confirmation_created",
            "request_id": request.request_id,
            "actor_id": request.actor_id,
            "command": request.action,
            "target_user": request.target_user,
            "result": "pending",
            "message": "[ConfirmationState][createPendingConfirmation][BLOCK_CREATE_PENDING_CONFIRMATION] created pending confirmation",
            "details": {"expires_at": pending.expires_at.isoformat(), "target_group": pending.target_group, "summary": pending.summary},
        },
        audit_sink,
    )
    return pending
    # END_BLOCK_CREATE_PENDING_CONFIRMATION


# START_CONTRACT: resolvePendingConfirmation
#   PURPOSE: Resolve a pending confirmation as confirmed, cancelled, expired, or replayed.
#   INPUTS: { store: InMemoryConfirmationStore - confirmation store, token: str - confirmation token, decision: str - confirm or cancel, audit_sink: AuditSink | None - audit destination, requested_actor_id: str | None - actor attempting to resolve the token, now: datetime | None - override for deterministic tests }
#   OUTPUTS: { ConfirmationResolution - resolution outcome }
#   SIDE_EFFECTS: [updates confirmation state and writes an audit record]
#   LINKS: [createPendingConfirmation]
# END_CONTRACT: resolvePendingConfirmation
def resolvePendingConfirmation(
    store: ConfirmationStore,
    token: str,
    decision: str,
    audit_sink: AuditSink | None = None,
    requested_actor_id: str | None = None,
    now: datetime | None = None,
) -> ConfirmationResolution:
    # START_BLOCK_RESOLVE_PENDING_CONFIRMATION
    current_time = now or datetime.now(UTC)
    record = store.get(token)
    if record is None:
        resolution = ConfirmationResolution(token, "missing", False, "CONFIRMATION_NOT_FOUND")
    elif record.status != "pending":
        resolution = ConfirmationResolution(token, "replayed", False, "CONFIRMATION_REPLAYED", action=record.action, target_user=record.target_user, target_group=record.target_group)
    elif current_time > record.expires_at:
        record.status = "expired"
        resolution = ConfirmationResolution(token, "expired", False, "CONFIRMATION_EXPIRED", action=record.action, target_user=record.target_user, target_group=record.target_group)
    elif requested_actor_id is not None and record.actor_id != requested_actor_id:
        resolution = ConfirmationResolution(token, "rejected", False, "UNAUTHORIZED_OPERATOR", action=record.action, target_user=record.target_user, target_group=record.target_group)
    elif decision == "cancel":
        record.status = "cancelled"
        resolution = ConfirmationResolution(token, "cancelled", False, action=record.action, target_user=record.target_user, target_group=record.target_group)
    else:
        record.status = "confirmed"
        resolution = ConfirmationResolution(token, "confirmed", True, action=record.action, target_user=record.target_user, target_group=record.target_group)

    recordAuditEvent(
        {
            "event": "confirmation_resolved",
            "request_id": record.request_id if record else "unknown-request",
            "actor_id": record.actor_id if record else "unknown-actor",
            "command": record.action if record else None,
            "target_user": record.target_user if record else None,
            "result": resolution.status,
            "error_code": resolution.error_code,
            "message": "[ConfirmationState][resolvePendingConfirmation][BLOCK_RESOLVE_PENDING_CONFIRMATION] resolved confirmation",
            "details": {"decision": decision, "requested_actor_id": requested_actor_id, "target_group": record.target_group if record else None, "summary": record.summary if record else None},
        },
        audit_sink,
    )
    return resolution
    # END_BLOCK_RESOLVE_PENDING_CONFIRMATION

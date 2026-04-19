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
#   createPendingConfirmation - Create and record a pending confirmation.
#   resolvePendingConfirmation - Resolve a confirmation token once.
# END_MODULE_MAP

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from src.audit_log import AuditSink, recordAuditEvent


@dataclass(slots=True)
class PendingConfirmationRequest:
    action: str
    actor_id: str
    target_user: str
    request_id: str
    expires_in_seconds: int = 300
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PendingConfirmation:
    token: str
    action: str
    actor_id: str
    target_user: str
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


class InMemoryConfirmationStore:
    def __init__(self) -> None:
        self._records: dict[str, PendingConfirmation] = {}

    def put(self, record: PendingConfirmation) -> None:
        self._records[record.token] = record

    def get(self, token: str) -> PendingConfirmation | None:
        return self._records.get(token)


# START_CONTRACT: createPendingConfirmation
#   PURPOSE: Create a pending confirmation record for a destructive action.
#   INPUTS: { store: InMemoryConfirmationStore - confirmation store, request: PendingConfirmationRequest - pending request, audit_sink: AuditSink | None - audit destination, now: datetime | None - override for deterministic tests }
#   OUTPUTS: { PendingConfirmation - created pending confirmation }
#   SIDE_EFFECTS: [stores a pending confirmation and writes an audit record]
#   LINKS: [resolvePendingConfirmation]
# END_CONTRACT: createPendingConfirmation
def createPendingConfirmation(
    store: InMemoryConfirmationStore,
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
            "details": {"expires_at": pending.expires_at.isoformat()},
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
    store: InMemoryConfirmationStore,
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
        resolution = ConfirmationResolution(token, "replayed", False, "CONFIRMATION_REPLAYED")
    elif current_time > record.expires_at:
        record.status = "expired"
        resolution = ConfirmationResolution(token, "expired", False, "CONFIRMATION_EXPIRED")
    elif requested_actor_id is not None and record.actor_id != requested_actor_id:
        resolution = ConfirmationResolution(token, "rejected", False, "UNAUTHORIZED_OPERATOR")
    elif decision == "cancel":
        record.status = "cancelled"
        resolution = ConfirmationResolution(token, "cancelled", False)
    else:
        record.status = "confirmed"
        resolution = ConfirmationResolution(token, "confirmed", True)

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
            "details": {"decision": decision, "requested_actor_id": requested_actor_id},
        },
        audit_sink,
    )
    return resolution
    # END_BLOCK_RESOLVE_PENDING_CONFIRMATION

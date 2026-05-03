# FILE: src/safety_controls.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Enforce allowlists, confirmation rules, and dangerous-action guards before any backend mutation occurs.
#   SCOPE: Validate actor authorization, action allowlists, username/group formats, and destructive-action confirmation requirements.
#   DEPENDS: M-AUDIT-LOG
#   LINKS: M-SAFETY-CONTROLS
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   OperatorIdentity - Structured operator authorization input.
#   ProposedAdminAction - Structured candidate backend action.
#   GuardDecision - Decision outcome for guard evaluation.
#   InMemoryRateLimiter - Minimal fixed-window limiter for operator requests.
#   guardAction - Validate actor, action, and payload safety before execution.
#   checkRateLimit - Enforce a fixed-window request limit for one key.
#   confirmDestructiveAction - Check whether a destructive action is confirmed.
# END_MODULE_MAP

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import re
from typing import Iterable

from src.audit_log import AuditSink, recordAuditEvent


from src.action_registry import ALLOWED_ACTIONS, DESTRUCTIVE_ACTIONS

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,32}$")
GROUP_PATTERN = re.compile(r"^[A-Za-z0-9_-]{2,32}$")


@dataclass(slots=True)
class OperatorIdentity:
    actor_id: str
    authorized: bool = True
    actor_type: str = "operator"


@dataclass(slots=True)
class ProposedAdminAction:
    action: str
    username: str | None = None
    group: str | None = None
    confirmed: bool = False
    request_id: str = "unknown-request"


@dataclass(slots=True)
class GuardDecision:
    allowed: bool
    requires_confirmation: bool
    error_code: str | None = None
    reason: str | None = None


@dataclass(slots=True)
class InMemoryRateLimiter:
    max_requests: int
    window_seconds: int
    _events: dict[str, list[datetime]] = field(default_factory=dict)


def _prune_rate_limit_window(events: list[datetime], *, now: datetime, window_seconds: int) -> list[datetime]:
    threshold = now - timedelta(seconds=window_seconds)
    return [event_time for event_time in events if event_time > threshold]


# START_CONTRACT: checkRateLimit
#   PURPOSE: Enforce a fixed-window request limit for one operator-scoped key.
#   INPUTS: { limiter: InMemoryRateLimiter - limiter policy and state, key: str - scope key, now: datetime | None - optional deterministic clock }
#   OUTPUTS: { bool - true when the request is within the configured limit }
#   SIDE_EFFECTS: [stores accepted timestamps in limiter state]
#   LINKS: [guardAction]
# END_CONTRACT: checkRateLimit
def checkRateLimit(limiter: InMemoryRateLimiter, key: str, now: datetime | None = None) -> bool:
    if limiter.max_requests <= 0 or limiter.window_seconds <= 0:
        return True

    current_time = now or datetime.now(UTC)
    events = _prune_rate_limit_window(
        limiter._events.get(key, []),
        now=current_time,
        window_seconds=limiter.window_seconds,
    )
    if len(events) >= limiter.max_requests:
        limiter._events[key] = events
        return False

    events.append(current_time)
    limiter._events[key] = events
    return True


def _audit_rejection(
    *,
    action: ProposedAdminAction,
    actor: OperatorIdentity,
    audit_sink: AuditSink | None,
    error_code: str,
    reason: str,
) -> None:
    recordAuditEvent(
        {
            "event": "guard_rejected",
            "request_id": action.request_id,
            "actor_type": actor.actor_type,
            "actor_id": actor.actor_id,
            "command": action.action,
            "target_user": action.username,
            "target_group": action.group,
            "result": "rejected",
            "error_code": error_code,
            "message": "[SafetyControls][guardAction][BLOCK_EVALUATE_GUARD] rejected action",
            "details": {"reason": reason},
        },
        audit_sink,
    )


# START_CONTRACT: confirmDestructiveAction
#   PURPOSE: Check whether a destructive operation carries trusted internal confirmation state.
#   INPUTS: { action: ProposedAdminAction - candidate action }
#   OUTPUTS: { bool - true when confirmation requirements are satisfied }
#   SIDE_EFFECTS: none
#   LINKS: [guardAction]
# END_CONTRACT: confirmDestructiveAction
def confirmDestructiveAction(action: ProposedAdminAction) -> bool:
    return action.action not in DESTRUCTIVE_ACTIONS or action.confirmed


# START_CONTRACT: guardAction
#   PURPOSE: Evaluate whether a backend action may proceed safely.
#   INPUTS: { action: ProposedAdminAction - candidate operation, actor: OperatorIdentity - caller identity, allowed_actors: Iterable[str] - allowlisted actor ids, audit_sink: AuditSink | None - audit destination }
#   OUTPUTS: { GuardDecision - guard decision }
#   SIDE_EFFECTS: [writes audit records for rejected decisions]
#   LINKS: [confirmDestructiveAction, recordAuditEvent]
# END_CONTRACT: guardAction
def guardAction(
    action: ProposedAdminAction,
    actor: OperatorIdentity,
    allowed_actors: Iterable[str],
    audit_sink: AuditSink | None = None,
) -> GuardDecision:
    # START_BLOCK_EVALUATE_GUARD
    allowlisted = set(allowed_actors)
    if not actor.authorized or actor.actor_id not in allowlisted:
        _audit_rejection(
            action=action,
            actor=actor,
            audit_sink=audit_sink,
            error_code="UNAUTHORIZED_OPERATOR",
            reason="actor is not allowlisted",
        )
        return GuardDecision(False, False, "UNAUTHORIZED_OPERATOR", "actor is not allowlisted")

    if action.action not in ALLOWED_ACTIONS:
        _audit_rejection(
            action=action,
            actor=actor,
            audit_sink=audit_sink,
            error_code="ACTION_NOT_ALLOWED",
            reason="action is outside the whitelist",
        )
        return GuardDecision(False, False, "ACTION_NOT_ALLOWED", "action is outside the whitelist")

    if action.username and not USERNAME_PATTERN.fullmatch(action.username):
        _audit_rejection(
            action=action,
            actor=actor,
            audit_sink=audit_sink,
            error_code="INVALID_USERNAME",
            reason="username fails validation",
        )
        return GuardDecision(False, False, "INVALID_USERNAME", "username fails validation")

    if action.group and not GROUP_PATTERN.fullmatch(action.group):
        _audit_rejection(
            action=action,
            actor=actor,
            audit_sink=audit_sink,
            error_code="INVALID_GROUP",
            reason="group fails validation",
        )
        return GuardDecision(False, False, "INVALID_GROUP", "group fails validation")

    if action.action in DESTRUCTIVE_ACTIONS and not confirmDestructiveAction(action):
        _audit_rejection(
            action=action,
            actor=actor,
            audit_sink=audit_sink,
            error_code="CONFIRMATION_REQUIRED",
            reason="destructive action requires explicit confirmation",
        )
        return GuardDecision(False, True, "CONFIRMATION_REQUIRED", "destructive action requires explicit confirmation")

    return GuardDecision(True, False)
    # END_BLOCK_EVALUATE_GUARD

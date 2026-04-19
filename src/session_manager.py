# FILE: src/session_manager.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Provide real session listing backed by the approved occtl control surface.
#   SCOPE: Query occtl through the adapter, normalize session records, and emit stable audit markers.
#   DEPENDS: M-OCSERV-ADAPTER, M-AUDIT-LOG
#   LINKS: M-SESSION-MANAGER
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   listSessions - Return normalized session records from occtl.
#   disconnectSessionForUser - Disconnect an active session for a VPN identity.
# END_MODULE_MAP

from __future__ import annotations

from src.audit_log import AuditSink, recordAuditEvent
from src.ocserv_adapter import OcservPaths, disconnectSession, runOcctl, serializeCommandResult


def listSessions(
    paths: OcservPaths,
    audit_sink: AuditSink | None,
    request_id: str,
    actor_id: str,
) -> list[dict[str, object]]:
    # START_BLOCK_LIST_SESSIONS
    sessions = runOcctl(paths, "show_sessions", audit_sink, request_id, actor_id)
    recordAuditEvent(
        {
            "event": "sessions_listed",
            "request_id": request_id,
            "actor_id": actor_id,
            "command": "list_sessions",
            "result": "ok",
            "message": "[SessionManager][listSessions][BLOCK_LIST_SESSIONS] listed sessions",
            "details": {"count": len(sessions)},
        },
        audit_sink,
    )
    return sessions
    # END_BLOCK_LIST_SESSIONS


def disconnectSessionForUser(
    paths: OcservPaths,
    username: str,
    audit_sink: AuditSink | None,
    request_id: str,
    actor_id: str,
) -> dict[str, object]:
    result = disconnectSession(paths, username, audit_sink, request_id, actor_id)
    if not result.ok:
        raise ValueError("SESSION_DISCONNECT_FAILED")
    recordAuditEvent(
        {
            "event": "session_disconnect_requested",
            "request_id": request_id,
            "actor_id": actor_id,
            "command": "disconnect_session",
            "target_user": username,
            "result": "ok",
            "message": "[SessionManager][disconnectSessionForUser][BLOCK_DISCONNECT_SESSION] disconnected session",
        },
        audit_sink,
    )
    return {
        "user": {"username": username},
        "disconnect": serializeCommandResult(result),
    }

# FILE: src/user_lifecycle_manager.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Own VPN identity creation, disablement, removal, and listing against the configured file-backed ocserv auth backend.
#   SCOPE: Apply guarded lifecycle operations through the deterministic adapter pipeline, emit audit markers, and return structured user results for the admin API.
#   DEPENDS: M-OCSERV-ADAPTER, M-AUDIT-LOG, M-SAFETY-CONTROLS
#   LINKS: M-USER-LIFECYCLE
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   listUsers - Return the managed VPN identities from the canonical user store.
#   createUser - Create a new VPN identity through the approved adapter path.
#   disableUser - Disable an existing VPN identity without deleting it.
#   removeUser - Delete a VPN identity through the approved lifecycle path.
# END_MODULE_MAP

from __future__ import annotations

from src.audit_log import AuditSink, recordAuditEvent
from src.ocserv_adapter import OcservPaths, applyManagedMutation, createUserRecord, deleteUserRecord, disableUserRecord, loadUsers, serializeActivationResult, updateUserIpRecord
from src.safety_controls import GuardDecision


def listUsers(paths: OcservPaths) -> list[dict[str, object]]:
    return loadUsers(paths)


def createUser(
    paths: OcservPaths,
    username: str,
    requested_group: str | None,
    ipv4_address: str | None,
    guard_decision: GuardDecision,
    audit_sink: AuditSink | None,
    request_id: str,
    actor_id: str,
) -> dict[str, object]:
    if not guard_decision.allowed:
        raise PermissionError(guard_decision.error_code or "ACTION_NOT_ALLOWED")
    # START_BLOCK_APPLY_USER_CREATE
    applied = applyManagedMutation(
        paths,
        "create_user",
        lambda: createUserRecord(paths, username, requested_group, ipv4_address),
        username=username,
        group=requested_group,
        ipv4_address=ipv4_address,
        audit_sink=audit_sink,
        request_id=request_id,
        actor_id=actor_id,
    )
    if not applied["ok"]:
        raise ValueError(str(applied["error_code"]))
    created_result = applied["result"]
    created_user = created_result["user"]
    provisioning = created_result.get("provisioning")
    recordAuditEvent(
        {
            "event": "user_created",
            "request_id": request_id,
            "actor_id": actor_id,
            "command": "create_user",
            "target_user": username,
            "target_group": requested_group,
            "result": "ok",
            "message": "[UserLifecycleManager][createUser][BLOCK_APPLY_USER_CREATE] created user",
            "changes": applied["changed_files"],
            "details": {
                "ipv4_address": ipv4_address,
                "planned_files": applied["planned_files"],
                "activation": serializeActivationResult(applied["activation"]),
                "verification": applied["verification"],
                "rolled_back": applied["rolled_back"],
            },
        },
        audit_sink,
    )
    return {
        "user": created_user,
        "provisioning": provisioning,
        "changed_files": applied["changed_files"],
        "planned_files": applied["planned_files"],
        "activation": serializeActivationResult(applied["activation"]),
        "verification": applied["verification"],
        "rolled_back": applied["rolled_back"],
    }
    # END_BLOCK_APPLY_USER_CREATE


def updateUserIp(
    paths: OcservPaths,
    username: str,
    ipv4_address: str,
    guard_decision: GuardDecision,
    audit_sink: AuditSink | None,
    request_id: str,
    actor_id: str,
) -> dict[str, object]:
    if not guard_decision.allowed:
        raise PermissionError(guard_decision.error_code or "ACTION_NOT_ALLOWED")
    applied = applyManagedMutation(
        paths,
        "update_user_ip",
        lambda: updateUserIpRecord(paths, username, ipv4_address),
        username=username,
        ipv4_address=ipv4_address,
        audit_sink=audit_sink,
        request_id=request_id,
        actor_id=actor_id,
    )
    if not applied["ok"]:
        raise ValueError(str(applied["error_code"]))
    updated_user = applied["result"]
    recordAuditEvent(
        {
            "event": "user_ip_updated",
            "request_id": request_id,
            "actor_id": actor_id,
            "command": "update_user_ip",
            "target_user": username,
            "result": "ok",
            "message": "[UserLifecycleManager][updateUserIp][BLOCK_APPLY_USER_CREATE] updated user IP",
            "changes": applied["changed_files"],
            "details": {
                "ipv4_address": ipv4_address,
                "planned_files": applied["planned_files"],
                "activation": serializeActivationResult(applied["activation"]),
                "verification": applied["verification"],
                "rolled_back": applied["rolled_back"],
            },
        },
        audit_sink,
    )
    return {
        "user": updated_user,
        "changed_files": applied["changed_files"],
        "planned_files": applied["planned_files"],
        "activation": serializeActivationResult(applied["activation"]),
        "verification": applied["verification"],
        "rolled_back": applied["rolled_back"],
    }


def disableUser(
    paths: OcservPaths,
    username: str,
    guard_decision: GuardDecision,
    audit_sink: AuditSink | None,
    request_id: str,
    actor_id: str,
) -> dict[str, object]:
    if not guard_decision.allowed:
        raise PermissionError(guard_decision.error_code or "ACTION_NOT_ALLOWED")
    applied = applyManagedMutation(
        paths,
        "disable_user",
        lambda: disableUserRecord(paths, username),
        username=username,
        audit_sink=audit_sink,
        request_id=request_id,
        actor_id=actor_id,
    )
    if not applied["ok"]:
        raise ValueError(str(applied["error_code"]))
    disabled = applied["result"]
    recordAuditEvent(
        {
            "event": "user_disabled",
            "request_id": request_id,
            "actor_id": actor_id,
            "command": "disable_user",
            "target_user": username,
            "result": "ok",
            "message": "[UserLifecycleManager][disableUser][BLOCK_APPLY_USER_DISABLE] disabled user",
            "changes": applied["changed_files"],
            "details": {
                "planned_files": applied["planned_files"],
                "activation": serializeActivationResult(applied["activation"]),
                "verification": applied["verification"],
                "rolled_back": applied["rolled_back"],
            },
        },
        audit_sink,
    )
    return {
        "user": disabled,
        "changed_files": applied["changed_files"],
        "planned_files": applied["planned_files"],
        "activation": serializeActivationResult(applied["activation"]),
        "verification": applied["verification"],
        "rolled_back": applied["rolled_back"],
    }


def removeUser(
    paths: OcservPaths,
    username: str,
    guard_decision: GuardDecision,
    audit_sink: AuditSink | None,
    request_id: str,
    actor_id: str,
    *,
    force: bool = False,
) -> dict[str, object]:
    if not guard_decision.allowed:
        raise PermissionError(guard_decision.error_code or "ACTION_NOT_ALLOWED")
    # START_BLOCK_APPLY_USER_REMOVE
    applied = applyManagedMutation(
        paths,
        "delete_user",
        lambda: deleteUserRecord(paths, username),
        username=username,
        force=force,
        audit_sink=audit_sink,
        request_id=request_id,
        actor_id=actor_id,
    )
    if not applied["ok"]:
        raise ValueError(str(applied["error_code"]))
    removed = applied["result"]
    recordAuditEvent(
        {
            "event": "user_removed",
            "request_id": request_id,
            "actor_id": actor_id,
            "command": "delete_user",
            "target_user": username,
            "result": "ok",
            "message": "[UserLifecycleManager][removeUser][BLOCK_APPLY_USER_REMOVE] removed user",
            "changes": applied["changed_files"],
            "details": {
                "force": force,
                "planned_files": applied["planned_files"],
                "activation": serializeActivationResult(applied["activation"]),
                "verification": applied["verification"],
                "rolled_back": applied["rolled_back"],
            },
        },
        audit_sink,
    )
    return {
        "user": removed,
        "changed_files": applied["changed_files"],
        "planned_files": applied["planned_files"],
        "activation": serializeActivationResult(applied["activation"]),
        "verification": applied["verification"],
        "rolled_back": applied["rolled_back"],
    }
    # END_BLOCK_APPLY_USER_REMOVE

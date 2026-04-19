# FILE: src/policy_group_manager.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Apply intended policy-group assignments and scoped policy rendering updates without touching unrelated config.
#   SCOPE: Validate requested groups against the approved store, update only the target user record and mapping file, and emit audit markers.
#   DEPENDS: M-OCSERV-ADAPTER, M-AUDIT-LOG
#   LINKS: M-POLICY-GROUP-MANAGER
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   renderPolicyChanges - Describe the scoped change set for a user-group update.
#   assignGroup - Apply an approved user-group assignment through the deterministic adapter pipeline.
# END_MODULE_MAP

from __future__ import annotations

from src.audit_log import AuditSink, recordAuditEvent
from src.ocserv_adapter import OcservPaths, applyManagedMutation, assignGroupRecord, inventoryConfig, preflightMutation, serializeActivationResult


def renderPolicyChanges(paths: OcservPaths, target_user: str, target_group: str) -> dict[str, object]:
    # START_BLOCK_RENDER_POLICY_CHANGES
    preflight = preflightMutation(paths, "assign_group", username=target_user, group=target_group)
    inventory = inventoryConfig(paths)
    selected_group_config = None
    for file_path in inventory["group_config_files"]:
        if file_path.endswith(f"/{target_group}.conf"):
            selected_group_config = file_path
            break
    return {
        "target_user": target_user,
        "target_group": target_group,
        "changed_files": preflight["planned_files"],
        "selected_group_config": selected_group_config,
        "scope": "single-user-group-update",
    }
    # END_BLOCK_RENDER_POLICY_CHANGES


def assignGroup(
    paths: OcservPaths,
    target_user: str,
    target_group: str,
    audit_sink: AuditSink | None,
    request_id: str,
    actor_id: str,
) -> dict[str, object]:
    change_set = renderPolicyChanges(paths, target_user, target_group)
    applied = applyManagedMutation(
        paths,
        "assign_group",
        lambda: assignGroupRecord(paths, target_user, target_group),
        username=target_user,
        group=target_group,
        audit_sink=audit_sink,
        request_id=request_id,
        actor_id=actor_id,
    )
    if not applied["ok"]:
        raise ValueError(str(applied["error_code"]))
    updated = applied["result"]
    recordAuditEvent(
        {
            "event": "group_assigned",
            "request_id": request_id,
            "actor_id": actor_id,
            "command": "assign_group",
            "target_user": target_user,
            "target_group": target_group,
            "result": "ok",
            "message": "[PolicyGroupManager][renderPolicyChanges][BLOCK_RENDER_POLICY_CHANGES] assigned group",
            "changes": applied["changed_files"],
            "details": {
                **change_set,
                "activation": serializeActivationResult(applied["activation"]),
                "verification": applied["verification"],
                "rolled_back": applied["rolled_back"],
            },
        },
        audit_sink,
    )
    return {
        "user": updated,
        "changed_files": applied["changed_files"],
        "planned_files": applied["planned_files"],
        "activation": serializeActivationResult(applied["activation"]),
        "verification": applied["verification"],
        "rolled_back": applied["rolled_back"],
        "change_set": change_set,
    }

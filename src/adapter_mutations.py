# FILE: src/adapter_mutations.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Deterministic mutation pipeline — preflight validation, snapshot, mutate, validate, activate, verify, rollback.
#   SCOPE: Managed config inventory, mutation preflight checks, file snapshots, service activation, post-mutation verification, and rollback.
#   DEPENDS: M-OCSERV-ADAPTER, M-ADAPTER-COMMANDS, M-ADAPTER-TEMPLATES, M-AUDIT-LOG
#   LINKS: M-ADAPTER-MUTATIONS
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   inventoryConfig - Inventory managed ocserv config, auth, and user-to-group mapping surfaces.
#   preflightMutation - Validate mutation preconditions and declare the deterministic write surface.
#   verifyMutation - Post-mutation verification of expected state.
#   activateService - Validate config, choose reload or restart, and activate ocserv safely.
#   applyManagedMutation - Run a deterministic mutate -> validate -> reload -> verify pipeline with rollback.
#   rollbackLastChange - Restore the previous config state from the last rollback snapshot.
#   serializeActivationResult - Convert activation evidence into JSON-safe structured data.
# END_MODULE_MAP

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import src.ocserv_adapter as _oa
import src.adapter_commands as _cmd
import src.adapter_templates as _tpl
from src.audit_log import AuditSink, recordAuditEvent
from src.file_lock import MutationLock


def _inventory_conflicts(
    paths: _oa.OcservPaths,
    assignments: dict[str, str],
    allowed_groups: list[str],
    users: dict[str, dict[str, Any]],
) -> list[str]:
    conflicts: list[str] = []
    allowed_set = set(allowed_groups)
    for username, group in assignments.items():
        if group not in allowed_set:
            conflicts.append(f"USER_ASSIGNED_TO_UNKNOWN_GROUP:{username}:{group}")
        if username not in users:
            conflicts.append(f"ASSIGNMENT_FOR_MISSING_USER:{username}")
    for username, record in users.items():
        stored_group = record.get("group")
        if isinstance(stored_group, str) and stored_group not in allowed_set:
            conflicts.append(f"USER_STORED_GROUP_UNKNOWN:{username}:{stored_group}")
    return sorted(conflicts)


def inventoryConfig(paths: _oa.OcservPaths) -> dict[str, Any]:
    users = _oa._load_user_payload(paths)
    assignments = _oa._load_user_group_map(paths, users)
    allowed_groups = sorted(_oa.listAllowedGroups(paths))
    rendered_files = _tpl.render_managed_files(paths)
    conflicts = _inventory_conflicts(paths, assignments, allowed_groups, users)

    return {
        "main_config_file": str(_oa._resolved_main_config_file(paths)),
        "main_config_template": str(_oa._resolved_main_template(paths)),
        "group_config_dir": str(_oa._resolved_group_config_dir(paths)),
        "group_template_dir": str(_oa._resolved_group_template_dir(paths)),
        "user_config_dir": str(_oa._resolved_user_config_dir(paths)),
        "group_config_files": sorted(str(path) for path in rendered_files if path.parent == _oa._resolved_group_config_dir(paths)),
        "user_config_files": sorted(str(path) for path in rendered_files if path.parent == _oa._resolved_user_config_dir(paths)),
        "group_template_files": sorted(str(path) for path in _oa._group_template_paths(paths)),
        "auth_store": str(paths.users_file),
        "auth_mechanism": "json" if paths.users_file.suffix == ".json" else "plain",
        "user_group_map_file": str(_oa._resolved_user_group_map_file(paths)),
        "user_group_assignments": assignments,
        "allowed_groups": allowed_groups,
        "managed_files": sorted(str(path) for path in _tpl._managed_paths(paths)),
        "conflicts": sorted(conflicts),
    }


def _determine_activation_mode(paths: _oa.OcservPaths, changed_files: list[str]) -> str:
    main_config_path = _oa._resolved_main_config_file(paths)
    group_config_dir = _oa._resolved_group_config_dir(paths)
    group_template_dir = _oa._resolved_group_template_dir(paths)
    user_config_dir = _oa._resolved_user_config_dir(paths)
    for changed_file in changed_files:
        changed_path = Path(changed_file)
        if changed_path == main_config_path:
            return "restart"
        if changed_path.is_relative_to(group_config_dir) or changed_path.is_relative_to(group_template_dir):
            return "restart"
        if changed_path.is_relative_to(user_config_dir):
            return "restart"
    return "reload"


def _user_has_active_sessions(paths: _oa.OcservPaths, username: str, audit_sink: AuditSink | None, request_id: str, actor_id: str) -> bool:
    try:
        sessions = _cmd.runOcctl(paths, "show_sessions", audit_sink, request_id, actor_id)
    except ValueError:
        return False
    for session in sessions:
        session_user = session.get("username") or session.get("name") or session.get("user")
        if session_user == username:
            return True
    return False


def preflightMutation(
    paths: _oa.OcservPaths,
    action: str,
    *,
    username: str | None = None,
    group: str | None = None,
    ipv4_address: str | None = None,
    force: bool = False,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> dict[str, Any]:
    inventory = inventoryConfig(paths)
    users = _oa._load_user_payload(paths)
    planned_files = [str(path) for path in _tpl._planned_mutation_paths(paths, action, group, username)]
    if inventory["conflicts"]:
        return {
            "ok": False,
            "error_code": "CONFIG_INVENTORY_CONFLICT",
            "details": {"conflicts": inventory["conflicts"]},
            "planned_files": planned_files,
            "data_files": [],
            "activation_mode": _determine_activation_mode(paths, planned_files),
        }

    if action == "create_user":
        if username in users:
            return {
                "ok": False,
                "error_code": "USER_ALREADY_EXISTS",
                "details": {"username": username},
                "planned_files": planned_files,
                "data_files": [str(paths.users_file), str(_oa._resolved_user_group_map_file(paths))],
                "activation_mode": _determine_activation_mode(paths, planned_files),
            }
        if group is not None and group not in set(inventory["allowed_groups"]):
            return {
                "ok": False,
                "error_code": "GROUP_NOT_FOUND",
                "details": {"group": group},
                "planned_files": planned_files,
                "data_files": [str(paths.users_file), str(_oa._resolved_user_group_map_file(paths))],
                "activation_mode": _determine_activation_mode(paths, planned_files),
            }
        try:
            _oa._validate_user_ipv4_address(paths, username=username, group=group, ipv4_address=ipv4_address, users=users)
        except ValueError as error:
            return {
                "ok": False,
                "error_code": str(error),
                "details": {"username": username, "group": group, "ipv4_address": ipv4_address},
                "planned_files": planned_files,
                "data_files": [str(paths.users_file), str(_oa._resolved_user_group_map_file(paths))],
                "activation_mode": _determine_activation_mode(paths, planned_files),
            }
        data_files = [str(paths.users_file), str(_oa._resolved_user_group_map_file(paths))]
    elif action == "assign_group":
        if username not in users:
            return {
                "ok": False,
                "error_code": "USER_NOT_FOUND",
                "details": {"username": username},
                "planned_files": planned_files,
                "data_files": [str(paths.users_file), str(_oa._resolved_user_group_map_file(paths))],
                "activation_mode": _determine_activation_mode(paths, planned_files),
            }
        if group not in set(inventory["allowed_groups"]):
            return {
                "ok": False,
                "error_code": "GROUP_NOT_FOUND",
                "details": {"group": group},
                "planned_files": planned_files,
                "data_files": [str(paths.users_file), str(_oa._resolved_user_group_map_file(paths))],
                "activation_mode": _determine_activation_mode(paths, planned_files),
            }
        data_files = [str(paths.users_file), str(_oa._resolved_user_group_map_file(paths))]
    elif action == "update_user_ip":
        if username not in users:
            return {
                "ok": False,
                "error_code": "USER_NOT_FOUND",
                "details": {"username": username},
                "planned_files": planned_files,
                "data_files": [str(paths.users_file), str(_oa._resolved_user_group_map_file(paths))],
                "activation_mode": _determine_activation_mode(paths, planned_files),
            }
        resolved_group = users[str(username)].get("group")
        try:
            _oa._validate_user_ipv4_address(paths, username=username, group=resolved_group if isinstance(resolved_group, str) else None, ipv4_address=ipv4_address, users=users)
        except ValueError as error:
            return {
                "ok": False,
                "error_code": str(error),
                "details": {"username": username, "group": resolved_group, "ipv4_address": ipv4_address},
                "planned_files": planned_files,
                "data_files": [str(paths.users_file), str(_oa._resolved_user_group_map_file(paths))],
                "activation_mode": _determine_activation_mode(paths, planned_files),
            }
        data_files = [str(paths.users_file), str(_oa._resolved_user_group_map_file(paths))]
    elif action == "disable_user":
        if username not in users:
            return {
                "ok": False,
                "error_code": "USER_NOT_FOUND",
                "details": {"username": username},
                "planned_files": planned_files,
                "data_files": [str(paths.users_file)],
                "activation_mode": _determine_activation_mode(paths, planned_files),
            }
        data_files = [str(paths.users_file)]
    elif action == "delete_user":
        if username not in users:
            return {
                "ok": False,
                "error_code": "USER_NOT_FOUND",
                "details": {"username": username},
                "planned_files": planned_files,
                "data_files": [str(paths.users_file), str(_oa._resolved_user_group_map_file(paths))],
                "activation_mode": "reload",
            }
        if not force and username is not None and _user_has_active_sessions(paths, username, audit_sink, request_id, actor_id):
            return {
                "ok": False,
                "error_code": "ACTIVE_USER_REQUIRES_FORCE",
                "details": {"username": username},
                "planned_files": planned_files,
                "data_files": [str(paths.users_file), str(_oa._resolved_user_group_map_file(paths))],
                "activation_mode": "reload",
            }
        data_files = [str(paths.users_file), str(_oa._resolved_user_group_map_file(paths))]
    else:
        data_files = []

    return {
        "ok": True,
        "error_code": None,
        "details": {"username": username, "group": group, "force": force},
        "planned_files": sorted(set(planned_files) | set(data_files)),
        "data_files": sorted(set(data_files)),
        "activation_mode": _determine_activation_mode(paths, sorted(set(planned_files) | set(data_files))),
    }


def _capture_file_snapshots(paths: list[Path]) -> dict[str, dict[str, Any]]:
    snapshots: dict[str, dict[str, Any]] = {}
    for file_path in paths:
        snapshots[str(file_path)] = {
            "exists": file_path.exists(),
            "content": file_path.read_text(encoding="utf-8") if file_path.exists() else None,
        }
    return snapshots


def _restore_file_snapshots(snapshots: dict[str, dict[str, Any]]) -> None:
    for path_string, snapshot in snapshots.items():
        file_path = Path(path_string)
        if snapshot["exists"]:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(str(snapshot["content"]), encoding="utf-8")
        elif file_path.exists():
            file_path.unlink()


def _detect_changed_files(paths: list[Path], snapshots: dict[str, dict[str, Any]]) -> list[str]:
    changed_files: list[str] = []
    for file_path in paths:
        snapshot = snapshots[str(file_path)]
        exists_now = file_path.exists()
        content_now = file_path.read_text(encoding="utf-8") if exists_now else None
        if snapshot["exists"] != exists_now or snapshot["content"] != content_now:
            changed_files.append(str(file_path))
    return sorted(changed_files)


def _store_rollback_state(
    paths: _oa.OcservPaths,
    *,
    action: str,
    request_id: str,
    actor_id: str,
    snapshots: dict[str, dict[str, Any]],
    changed_files: list[str],
) -> str:
    rollback_state_file = _oa._resolved_rollback_state_file(paths)
    _oa._write_json(
        rollback_state_file,
        {
            "action": action,
            "request_id": request_id,
            "actor_id": actor_id,
            "changed_files": changed_files,
            "snapshots": snapshots,
        },
    )
    return str(rollback_state_file)


def _load_rollback_state(paths: _oa.OcservPaths) -> dict[str, Any] | None:
    rollback_state_file = _oa._resolved_rollback_state_file(paths)
    if not rollback_state_file.exists():
        return None
    payload = _oa._read_json(rollback_state_file, None)
    return payload if isinstance(payload, dict) else None


def _clear_rollback_state(paths: _oa.OcservPaths) -> None:
    rollback_state_file = _oa._resolved_rollback_state_file(paths)
    if rollback_state_file.exists():
        rollback_state_file.unlink()


def _runtime_group_assignment(
    paths: _oa.OcservPaths,
    username: str,
    audit_sink: AuditSink | None,
    request_id: str,
    actor_id: str,
) -> str | None:
    try:
        users = _cmd.runOcctl(paths, "show_users", audit_sink, request_id, actor_id)
    except ValueError:
        return None
    for record in users:
        record_user = record.get("username") or record.get("name") or record.get("user")
        if record_user == username:
            return record.get("group") or record.get("groupname")
    return None


def verifyMutation(
    paths: _oa.OcservPaths,
    action: str,
    *,
    username: str | None = None,
    group: str | None = None,
    ipv4_address: str | None = None,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> dict[str, Any]:
    users = _oa._load_user_payload(paths)
    assignments = _oa._load_user_group_map(paths, users)
    if action == "create_user":
        if username not in users:
            return {"ok": False, "error_code": "VERIFY_CREATE_FAILED", "details": {"username": username}}
        if group is not None and assignments.get(str(username)) != group:
            return {"ok": False, "error_code": "VERIFY_GROUP_MAPPING_FAILED", "details": {"username": username, "group": group}}
        if ipv4_address is not None:
            if users[str(username)].get("ipv4_address") != ipv4_address:
                return {"ok": False, "error_code": "VERIFY_USER_IPV4_FAILED", "details": {"username": username, "ipv4_address": ipv4_address}}
            if not _oa._user_config_path(paths, str(username)).exists():
                return {"ok": False, "error_code": "VERIFY_USER_CONFIG_FAILED", "details": {"username": username}}
    elif action == "assign_group":
        if username not in users or users[str(username)].get("group") != group:
            return {"ok": False, "error_code": "VERIFY_ASSIGNMENT_FAILED", "details": {"username": username, "group": group}}
        if assignments.get(str(username)) != group:
            return {"ok": False, "error_code": "VERIFY_GROUP_MAPPING_FAILED", "details": {"username": username, "group": group}}
        if not _oa._group_config_path(paths, str(group)).exists():
            return {"ok": False, "error_code": "VERIFY_GROUP_CONFIG_FAILED", "details": {"group": group}}
        runtime_group = _runtime_group_assignment(paths, str(username), audit_sink, request_id, actor_id)
        if runtime_group is not None and runtime_group != group:
            return {
                "ok": False,
                "error_code": "VERIFY_RUNTIME_GROUP_FAILED",
                "details": {"username": username, "group": group, "runtime_group": runtime_group},
            }
    elif action == "disable_user":
        if username not in users or not bool(users[str(username)].get("disabled", False)):
            return {"ok": False, "error_code": "VERIFY_DISABLE_FAILED", "details": {"username": username}}
    elif action == "update_user_ip":
        if username not in users or users[str(username)].get("ipv4_address") != ipv4_address:
            return {"ok": False, "error_code": "VERIFY_USER_IPV4_FAILED", "details": {"username": username, "ipv4_address": ipv4_address}}
        if not _oa._user_config_path(paths, str(username)).exists():
            return {"ok": False, "error_code": "VERIFY_USER_CONFIG_FAILED", "details": {"username": username}}
    elif action == "delete_user":
        if username in users or str(username) in assignments:
            return {"ok": False, "error_code": "VERIFY_DELETE_FAILED", "details": {"username": username}}
        if username is not None and _oa._user_config_path(paths, str(username)).exists():
            return {"ok": False, "error_code": "VERIFY_USER_CONFIG_FAILED", "details": {"username": username}}
    return {"ok": True, "error_code": None, "details": {"username": username, "group": group}}


def activateService(
    paths: _oa.OcservPaths,
    changed_files: list[str],
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> dict[str, Any]:
    activation_mode = _determine_activation_mode(paths, changed_files)
    validation = _cmd.validateConfig(paths, audit_sink, request_id, actor_id)
    if not validation.ok:
        return {
            "ok": False,
            "validation": validation,
            "reload": None,
            "error_code": "CONFIG_VALIDATION_FAILED",
            "activation_mode": activation_mode,
            "restart_required": activation_mode == "restart",
        }
    command = paths.restart_command if activation_mode == "restart" else paths.reload_command
    command_result = _oa._run_command(_oa._with_prefix(paths, command))
    event_name = "service_restarted" if activation_mode == "restart" else "service_reloaded"
    command_name = "restart_service" if activation_mode == "restart" else "reload_service"
    failure_code = "SERVICE_RESTART_FAILED" if activation_mode == "restart" else "SERVICE_RELOAD_FAILED"
    recordAuditEvent(
        {
            "event": event_name,
            "request_id": request_id,
            "actor_id": actor_id,
            "command": command_name,
            "result": "ok" if command_result.ok else "failed",
            "reload_status": activation_mode if command_result.ok else "failed",
            "error_code": None if command_result.ok else failure_code,
            "message": "[OcservAdapter][reloadService][BLOCK_SAFE_RELOAD] activated service",
            "details": {"stderr": command_result.stderr, "stdout": command_result.stdout, "activation_mode": activation_mode},
        },
        audit_sink,
    )
    health = _cmd.healthCheck(paths, audit_sink, request_id, actor_id) if command_result.ok else None
    return {
        "ok": command_result.ok and (health is None or health.ok),
        "validation": validation,
        "reload": command_result,
        "health": health,
        "error_code": None if command_result.ok and (health is None or health.ok) else (failure_code if not command_result.ok else "SERVICE_HEALTHCHECK_FAILED"),
        "activation_mode": activation_mode,
        "restart_required": activation_mode == "restart",
    }


def applyManagedMutation(
    paths: _oa.OcservPaths,
    action: str,
    mutate: Callable[[], dict[str, Any]],
    *,
    username: str | None = None,
    group: str | None = None,
    ipv4_address: str | None = None,
    force: bool = False,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> dict[str, Any]:
    lock_dir = _oa._resolved_rollback_state_file(paths).parent
    with MutationLock(lock_dir):
        return _apply_managed_mutation_locked(
            paths, action, mutate,
            username=username, group=group, ipv4_address=ipv4_address,
            force=force, audit_sink=audit_sink,
            request_id=request_id, actor_id=actor_id,
        )


def _apply_managed_mutation_locked(
    paths: _oa.OcservPaths,
    action: str,
    mutate: Callable[[], dict[str, Any]],
    *,
    username: str | None = None,
    group: str | None = None,
    ipv4_address: str | None = None,
    force: bool = False,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> dict[str, Any]:
    preflight = preflightMutation(
        paths,
        action,
        username=username,
        group=group,
        ipv4_address=ipv4_address,
        force=force,
        audit_sink=audit_sink,
        request_id=request_id,
        actor_id=actor_id,
    )
    if not preflight["ok"]:
        return {
            "ok": False,
            "error_code": preflight["error_code"],
            "preflight": preflight,
            "activation": None,
            "verification": None,
            "planned_files": preflight["planned_files"],
            "changed_files": [],
            "rolled_back": False,
        }

    snapshot_paths = [Path(path_string) for path_string in preflight["planned_files"]]
    snapshots = _capture_file_snapshots(snapshot_paths)
    activation: dict[str, Any] | None = None
    try:
        _tpl.sync_managed_files(paths, action, group)
        mutated = mutate()
        changed_files = _detect_changed_files(snapshot_paths, snapshots)
        activation = activateService(paths, changed_files, audit_sink, request_id, actor_id)
        if not activation["ok"]:
            raise ValueError(activation["error_code"] or "SERVICE_RELOAD_FAILED")
        verification = verifyMutation(
            paths,
            action,
            username=username,
            group=group,
            ipv4_address=ipv4_address,
            audit_sink=audit_sink,
            request_id=request_id,
            actor_id=actor_id,
        )
        if not verification["ok"]:
            raise ValueError(verification["error_code"] or "VERIFY_MUTATION_FAILED")
        rollback_state_file = _store_rollback_state(
            paths,
            action=action,
            request_id=request_id,
            actor_id=actor_id,
            snapshots=snapshots,
            changed_files=changed_files,
        )
        return {
            "ok": True,
            "result": mutated,
            "preflight": preflight,
            "activation": activation,
            "verification": verification,
            "planned_files": preflight["planned_files"],
            "changed_files": changed_files,
            "backup": {"files": sorted(snapshots), "rollback_state_file": rollback_state_file},
            "rolled_back": False,
        }
    except ValueError as error:
        _restore_file_snapshots(snapshots)
        return {
            "ok": False,
            "error_code": str(error),
            "preflight": preflight,
            "activation": activation,
            "verification": {"ok": False, "error_code": str(error)},
            "planned_files": preflight["planned_files"],
            "changed_files": [],
            "backup": {"files": sorted(snapshots), "rollback_state_file": str(_oa._resolved_rollback_state_file(paths))},
            "rolled_back": True,
        }


def serializeActivationResult(result: dict[str, Any] | None) -> dict[str, Any] | None:
    if result is None:
        return None
    return {
        "ok": result["ok"],
        "error_code": result["error_code"],
        "validation": _cmd.serializeCommandResult(result["validation"]),
        "reload": _cmd.serializeCommandResult(result["reload"]),
        "health": _cmd.serializeCommandResult(result.get("health")),
        "activation_mode": result.get("activation_mode"),
        "restart_required": result.get("restart_required"),
    }


def rollbackLastChange(
    paths: _oa.OcservPaths,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> dict[str, Any]:
    rollback_state = _load_rollback_state(paths)
    if rollback_state is None:
        raise ValueError("ROLLBACK_NOT_AVAILABLE")

    snapshots = rollback_state.get("snapshots")
    if not isinstance(snapshots, dict):
        raise ValueError("ROLLBACK_STATE_INVALID")

    _restore_file_snapshots(snapshots)
    changed_files = rollback_state.get("changed_files")
    normalized_changed_files = [str(path) for path in changed_files] if isinstance(changed_files, list) else sorted(snapshots)
    activation = activateService(paths, normalized_changed_files, audit_sink, request_id, actor_id)
    if not activation["ok"]:
        raise ValueError(activation["error_code"] or "ROLLBACK_FAILED")

    recordAuditEvent(
        {
            "event": "rollback_applied",
            "request_id": request_id,
            "actor_id": actor_id,
            "command": "rollback_last_change",
            "result": "ok",
            "changes": normalized_changed_files,
            "message": "[OcservAdapter][rollbackLastChange][BLOCK_ROLLBACK_LAST_CHANGE] restored last change backup",
            "details": {
                "rolled_back_action": rollback_state.get("action"),
                "rolled_back_request_id": rollback_state.get("request_id"),
            },
        },
        audit_sink,
    )
    _clear_rollback_state(paths)
    return {
        "rolled_back_action": rollback_state.get("action"),
        "rolled_back_request_id": rollback_state.get("request_id"),
        "changed_files": normalized_changed_files,
        "activation": serializeActivationResult(activation),
    }

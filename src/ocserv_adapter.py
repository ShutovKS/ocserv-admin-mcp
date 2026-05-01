# FILE: src/ocserv_adapter.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Wrap occtl, config validation, reload flows, and canonical auth/policy file operations in a constrained system adapter.
#   SCOPE: Manage deterministic file-backed user state, managed ocserv config templates, allowed policy groups, occtl session inspection, config validation, and service reload commands.
#   DEPENDS: M-AUDIT-LOG, M-SAFETY-CONTROLS
#   LINKS: M-OCSERV-ADAPTER
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   OcservPaths - Filesystem and command configuration for the backend.
#   SystemCommandResult - Structured subprocess result.
#   inventoryConfig - Inventory managed ocserv config, auth, and user-to-group mapping surfaces.
#   listAllowedGroups - Resolve admissible policy groups from managed templates or the legacy group store.
#   preflightMutation - Validate mutation preconditions and declare the deterministic write surface.
#   applyManagedMutation - Run a deterministic mutate -> validate -> reload -> verify pipeline with rollback.
#   serializeCommandResult - Convert a command result into JSON-safe structured data.
#   serializeActivationResult - Convert activation evidence into JSON-safe structured data.
#   activateService - Validate config, choose reload or restart, and activate ocserv safely.
#   runOcctl - Execute approved occtl reads and normalize their output.
#   disconnectSession - Disconnect an active ocserv session through the approved occtl surface.
#   validateConfig - Validate ocserv-related config before reload.
#   reloadService - Reload ocserv with structured result reporting.
#   safeReload - Run validation first and reload only on success.
#   loadUsers - Return canonical file-backed users.
#   createUserRecord - Create a file-backed user.
#   disableUserRecord - Disable an existing user.
#   deleteUserRecord - Delete a file-backed user.
#   assignGroupRecord - Update a user's policy group safely.
# END_MODULE_MAP

from __future__ import annotations

from dataclasses import dataclass
import json
import ipaddress
from pathlib import Path
import secrets
from string import Template
import subprocess
from typing import Any, Callable

from src.audit_log import AuditSink, recordAuditEvent


@dataclass(slots=True)
class OcservPaths:
    users_file: Path
    groups_file: Path
    audit_log_file: Path
    command_prefix: tuple[str, ...] = ()
    ocpasswd_bin: str = "ocpasswd"
    occtl_bin: str = "occtl"
    validate_command: tuple[str, ...] = ("ocserv", "--test-config")
    reload_command: tuple[str, ...] = ("systemctl", "reload", "ocserv")
    restart_command: tuple[str, ...] = ("systemctl", "restart", "ocserv")
    main_config_file: Path | None = None
    main_config_template: Path | None = None
    group_config_dir: Path | None = None
    group_template_dir: Path | None = None
    user_config_dir: Path | None = None
    user_group_map_file: Path | None = None
    healthcheck_command: tuple[str, ...] = ("systemctl", "is-active", "ocserv")
    rollback_state_file: Path | None = None


@dataclass(slots=True)
class SystemCommandResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int


def _managed_root(paths: OcservPaths) -> Path:
    return paths.users_file.parent


def _resolved_main_config_file(paths: OcservPaths) -> Path:
    return paths.main_config_file or (_managed_root(paths) / "ocserv.conf")


def _resolved_main_template(paths: OcservPaths) -> Path:
    return paths.main_config_template or (_managed_root(paths) / "templates" / "ocserv.conf.tpl")


def _resolved_group_config_dir(paths: OcservPaths) -> Path:
    if paths.group_config_dir is not None:
        return paths.group_config_dir
    if paths.groups_file.is_dir():
        return paths.groups_file
    return _managed_root(paths) / "groups.d"


def _resolved_group_template_dir(paths: OcservPaths) -> Path:
    return paths.group_template_dir or (_managed_root(paths) / "group-templates")


def _resolved_user_config_dir(paths: OcservPaths) -> Path:
    return paths.user_config_dir or (_managed_root(paths) / "config-per-user")


def _resolved_user_group_map_file(paths: OcservPaths) -> Path:
    return paths.user_group_map_file or (_managed_root(paths) / "user-groups.json")


def _resolved_rollback_state_file(paths: OcservPaths) -> Path:
    return paths.rollback_state_file or (_managed_root(paths) / "last-rollback.json")


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run_command(command: tuple[str, ...]) -> SystemCommandResult:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError as error:
        return SystemCommandResult(ok=False, stdout="", stderr=str(error), returncode=127)
    return SystemCommandResult(
        ok=completed.returncode == 0,
        stdout=completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
    )


def _with_prefix(paths: OcservPaths, command: tuple[str, ...]) -> tuple[str, ...]:
    return (*paths.command_prefix, *command)


def _uses_json_user_store(path: Path) -> bool:
    return path.suffix == ".json"


def _normalize_occtl_output(raw_output: str) -> list[dict[str, Any]]:
    stripped = raw_output.strip()
    if not stripped:
        return []
    lowered = stripped.lower()
    if lowered in {"session id not found or expired", "no users found", "no sessions found"}:
        return []
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        records: list[dict[str, Any]] = []
        for line in stripped.splitlines():
            parts = [part for part in line.split() if part]
            if not parts:
                continue
            if len(parts) == 1:
                records.append({"name": parts[0]})
            else:
                records.append({"name": parts[0], "status": " ".join(parts[1:])})
        return records
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    if isinstance(parsed, dict) and "items" in parsed and isinstance(parsed["items"], list):
        return [item for item in parsed["items"] if isinstance(item, dict)]
    return []


def _group_name_from_template(path: Path) -> str:
    name = path.name
    if name.endswith(".conf.tpl"):
        return name[: -len(".conf.tpl")]
    if name.endswith(".tpl"):
        return name[: -len(".tpl")]
    return path.stem


def _group_config_path(paths: OcservPaths, group: str) -> Path:
    config_dir = _resolved_group_config_dir(paths)
    legacy_path = config_dir / group
    if legacy_path.exists():
        return legacy_path
    return config_dir / f"{group}.conf"


def _group_template_paths(paths: OcservPaths) -> list[Path]:
    template_dir = _resolved_group_template_dir(paths)
    if not template_dir.exists():
        return []
    return sorted([entry for entry in template_dir.iterdir() if entry.is_file()])


def _configured_group_paths(paths: OcservPaths) -> list[Path]:
    config_dir = _resolved_group_config_dir(paths)
    if not config_dir.exists():
        return []
    return sorted([entry for entry in config_dir.iterdir() if entry.is_file()])


def _legacy_allowed_groups(paths: OcservPaths) -> set[str]:
    if paths.groups_file.is_dir():
        return {entry.stem if entry.suffix == ".conf" else entry.name for entry in paths.groups_file.iterdir() if entry.is_file()}
    payload = _read_json(paths.groups_file, {"groups": []})
    return {item for item in payload.get("groups", []) if isinstance(item, str)}


def _planned_group_names(paths: OcservPaths) -> list[str]:
    template_groups = {_group_name_from_template(path) for path in _group_template_paths(paths)}
    configured_groups = {path.stem for path in _configured_group_paths(paths)}
    legacy_groups = _legacy_allowed_groups(paths)
    return sorted(template_groups | configured_groups | legacy_groups | {"default", "admins"})


def _default_main_template(paths: OcservPaths) -> str:
    return (
        "# managed by ocserv-admin\n"
        "# render actual deployment directives through the template file\n"
        f"# group config dir: {_resolved_group_config_dir(paths)}\n"
    )


def _default_group_template(group: str) -> str:
    return (
        "# managed by ocserv-admin\n"
        f"# group: {group}\n"
        "# provide deployment-specific policy directives in this template\n"
    )


def _ensure_default_templates(paths: OcservPaths, template_paths: list[Path] | None = None) -> list[str]:
    changed_files: list[str] = []
    main_template = _resolved_main_template(paths)
    target_templates = set(template_paths) if template_paths is not None else set(_template_paths(paths))
    if main_template in target_templates:
        main_template.parent.mkdir(parents=True, exist_ok=True)
    if main_template in target_templates and not main_template.exists():
        main_template.write_text(_default_main_template(paths), encoding="utf-8")
        changed_files.append(str(main_template))

    template_dir = _resolved_group_template_dir(paths)
    allowed_groups = _planned_group_names(paths)
    for group in allowed_groups:
        template_path = template_dir / f"{group}.conf.tpl"
        if template_path not in target_templates:
            continue
        template_dir.mkdir(parents=True, exist_ok=True)
        if not template_path.exists():
            template_path.write_text(_default_group_template(group), encoding="utf-8")
            changed_files.append(str(template_path))
    return changed_files


def _load_plain_user_payload(passwd_file: Path) -> dict[str, dict[str, Any]]:
    users: dict[str, dict[str, Any]] = {}
    if not passwd_file.exists():
        return users
    for raw_line in passwd_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        username, group, password_hash = line.split(":", 2)
        normalized_group = None if group in {"", "*"} else group
        users[username] = {
            "username": username,
            "group": normalized_group,
            "disabled": password_hash.startswith("!"),
            "password_hash": password_hash,
        }
    return users


def _save_plain_user_payload(passwd_file: Path, users: dict[str, dict[str, Any]]) -> None:
    passwd_file.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for username in sorted(users):
        record = users[username]
        lines.append(f"{username}:{record.get('group') or ''}:{record['password_hash']}")
    passwd_file.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _load_user_metadata(paths: OcservPaths) -> tuple[dict[str, str], dict[str, str]]:
    map_file = _resolved_user_group_map_file(paths)
    if not map_file.exists():
        return {}, {}
    payload = _read_json(map_file, {"assignments": {}, "ipv4_addresses": {}})
    if not isinstance(payload, dict):
        return {}, {}

    raw_assignments = payload.get("assignments", payload)
    assignments = {
        str(username): str(group)
        for username, group in raw_assignments.items()
        if isinstance(raw_assignments, dict) and isinstance(username, str) and isinstance(group, str)
    }
    raw_ipv4_addresses = payload.get("ipv4_addresses", {})
    ipv4_addresses = {
        str(username): str(address)
        for username, address in raw_ipv4_addresses.items()
        if isinstance(raw_ipv4_addresses, dict) and isinstance(username, str) and isinstance(address, str) and address
    }
    return assignments, ipv4_addresses


def _save_user_metadata(paths: OcservPaths, assignments: dict[str, str], ipv4_addresses: dict[str, str]) -> None:
    payload = {
        "assignments": {username: assignments[username] for username in sorted(assignments)},
        "ipv4_addresses": {username: ipv4_addresses[username] for username in sorted(ipv4_addresses)},
    }
    _write_json(_resolved_user_group_map_file(paths), payload)


def _load_user_payload(paths: OcservPaths) -> dict[str, dict[str, Any]]:
    metadata_assignments, metadata_ipv4_addresses = _load_user_metadata(paths)
    if not _uses_json_user_store(paths.users_file):
        users = _load_plain_user_payload(paths.users_file)
        for username, address in metadata_ipv4_addresses.items():
            if username in users:
                users[username]["ipv4_address"] = address
        return users
    payload = _read_json(paths.users_file, {"users": []})
    users: dict[str, dict[str, Any]] = {}
    for record in payload.get("users", []):
        username = record.get("username")
        if isinstance(username, str):
            ipv4_address = record.get("ipv4_address")
            if not isinstance(ipv4_address, str) or not ipv4_address:
                ipv4_address = metadata_ipv4_addresses.get(username)
            users[username] = {
                "username": username,
                "group": record.get("group") or metadata_assignments.get(username),
                "disabled": bool(record.get("disabled", False)),
                "ipv4_address": ipv4_address,
            }
    return users


def _save_user_payload(paths: OcservPaths, users: dict[str, dict[str, Any]]) -> None:
    if not _uses_json_user_store(paths.users_file):
        _save_plain_user_payload(paths.users_file, users)
        return
    _write_json(paths.users_file, {"users": sorted(users.values(), key=lambda item: item["username"])})


def _load_user_group_map(paths: OcservPaths, users: dict[str, dict[str, Any]] | None = None) -> dict[str, str]:
    assignments, _ = _load_user_metadata(paths)
    if assignments:
        return assignments
    source_users = users or _load_user_payload(paths)
    return {
        username: str(record["group"])
        for username, record in source_users.items()
        if isinstance(record.get("group"), str) and record.get("group")
    }


def _save_user_group_map(paths: OcservPaths, assignments: dict[str, str]) -> None:
    _, ipv4_addresses = _load_user_metadata(paths)
    _save_user_metadata(paths, assignments, ipv4_addresses)


def _load_user_ipv4_map(paths: OcservPaths, users: dict[str, dict[str, Any]] | None = None) -> dict[str, str]:
    _, ipv4_addresses = _load_user_metadata(paths)
    if ipv4_addresses:
        return ipv4_addresses
    source_users = users or _load_user_payload(paths)
    return {
        username: str(record["ipv4_address"])
        for username, record in source_users.items()
        if isinstance(record.get("ipv4_address"), str) and record.get("ipv4_address")
    }


def _save_user_ipv4_map(paths: OcservPaths, ipv4_addresses: dict[str, str]) -> None:
    assignments, _ = _load_user_metadata(paths)
    _save_user_metadata(paths, assignments, ipv4_addresses)


def _sanitize_user_record(record: dict[str, Any]) -> dict[str, Any]:
    sanitized = {
        "username": record["username"],
        "group": record.get("group"),
        "disabled": bool(record.get("disabled", False)),
    }
    if record.get("ipv4_address"):
        sanitized["ipv4_address"] = record["ipv4_address"]
    return sanitized


def _parse_group_config_details(path: Path) -> dict[str, Any]:
    details: dict[str, Any] = {"group": path.stem, "ipv4_network": None, "ipv4_netmask": None, "routes": []}
    if not path.exists():
        return details
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if key == "ipv4-network":
            details["ipv4_network"] = value
        elif key == "ipv4-netmask":
            details["ipv4_netmask"] = value
        elif key == "route":
            details["routes"].append(value)
    return details


def _user_config_path(paths: OcservPaths, username: str) -> Path:
    return _resolved_user_config_dir(paths) / username


def _render_user_config(ipv4_address: str) -> str:
    return f"explicit-ipv4 = {ipv4_address}\n"


def _sync_user_config(paths: OcservPaths, username: str, ipv4_address: str | None) -> None:
    config_path = _user_config_path(paths, username)
    if ipv4_address:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(_render_user_config(ipv4_address), encoding="utf-8")
    elif config_path.exists():
        config_path.unlink()


def loadUsers(paths: OcservPaths) -> list[dict[str, Any]]:
    users = _load_user_payload(paths)
    return [_sanitize_user_record(users[key]) for key in sorted(users)]


def listGroups(paths: OcservPaths) -> list[dict[str, Any]]:
    inventory = inventoryConfig(paths)
    assignments = inventory["user_group_assignments"]
    groups: list[dict[str, Any]] = []
    for group in inventory["allowed_groups"]:
        details = _parse_group_config_details(_group_config_path(paths, group))
        members = sorted(username for username, assigned_group in assignments.items() if assigned_group == group)
        groups.append({
            "group": group,
            "ipv4_network": details["ipv4_network"],
            "ipv4_netmask": details["ipv4_netmask"],
            "routes": details["routes"],
            "member_count": len(members),
            "members": members,
        })
    return groups


def showUserIps(
    paths: OcservPaths,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> list[dict[str, Any]]:
    sessions = runOcctl(paths, "show_sessions", audit_sink, request_id, actor_id)
    if sessions and "ip" not in sessions[0] and "vpn_ip" not in sessions[0] and "status" in sessions[0]:
        parsed_tabular: list[dict[str, Any]] = []
        for session in sessions:
            status = session.get("status")
            if not isinstance(status, str):
                continue
            parts = [part for part in status.split() if part]
            if len(parts) < 4:
                continue
            if parts[0].lower() == "user" and parts[1].lower() == "vhost":
                continue
            parsed_tabular.append(
                {
                    "username": parts[0],
                    "group": parts[1] if len(parts) > 1 else None,
                    "ip": parts[2] if len(parts) > 2 else None,
                    "session": session,
                }
            )
        if parsed_tabular:
            return parsed_tabular
    user_ips: list[dict[str, Any]] = []
    for session in sessions:
        username = session.get("username") or session.get("name") or session.get("user")
        if not isinstance(username, str):
            continue
        user_ips.append(
            {
                "username": username,
                "ip": session.get("ip") or session.get("vpn_ip"),
                "group": session.get("group") or session.get("policy_group") or session.get("profile"),
                "session": session,
            }
        )
    return user_ips


def listAllowedGroups(paths: OcservPaths) -> set[str]:
    return set(_planned_group_names(paths))


def _render_template(template_path: Path, variables: dict[str, str], fallback: str) -> str:
    if template_path.exists():
        template_text = template_path.read_text(encoding="utf-8")
    else:
        template_text = fallback
    return Template(template_text).safe_substitute(variables)


def _render_managed_files(paths: OcservPaths) -> dict[Path, str]:
    rendered: dict[Path, str] = {}
    group_config_dir = _resolved_group_config_dir(paths)
    main_config = _resolved_main_config_file(paths)
    rendered[main_config] = _render_template(
        _resolved_main_template(paths),
        {"GROUP_CONFIG_DIR": str(group_config_dir)},
        _default_main_template(paths),
    )

    for group in _planned_group_names(paths):
        template_path = _resolved_group_template_dir(paths) / f"{group}.conf.tpl"
        rendered[_group_config_path(paths, group)] = _render_template(
            template_path,
            {
                "GROUP_NAME": group,
                "GROUP_CONFIG_FILE": str(_group_config_path(paths, group)),
                "GROUP_CONFIG_DIR": str(group_config_dir),
            },
            _default_group_template(group),
        )
    for user in _load_user_payload(paths).values():
        ipv4_address = user.get("ipv4_address")
        username = user.get("username")
        if isinstance(username, str) and isinstance(ipv4_address, str) and ipv4_address:
            rendered[_user_config_path(paths, username)] = _render_user_config(ipv4_address)
    return rendered


def _template_paths(paths: OcservPaths) -> list[Path]:
    return [_resolved_main_template(paths), *[_resolved_group_template_dir(paths) / f"{group}.conf.tpl" for group in _planned_group_names(paths)]]


def _planned_mutation_paths(paths: OcservPaths, action: str, group: str | None = None, username: str | None = None) -> list[Path]:
    planned: list[Path] = []
    if action in {"create_user", "assign_group"}:
        planned.extend([
            _resolved_main_template(paths),
            _resolved_main_config_file(paths),
        ])
        if group is not None:
            planned.extend([
                _resolved_group_template_dir(paths) / f"{group}.conf.tpl",
                _group_config_path(paths, group),
            ])
    if action in {"create_user", "update_user_ip", "delete_user"} and username is not None:
        planned.append(_user_config_path(paths, username))
    planned.append(paths.users_file)
    if action in {"create_user", "assign_group", "delete_user", "update_user_ip"}:
        planned.append(_resolved_user_group_map_file(paths))
    return sorted(set(planned))


def _managed_paths(paths: OcservPaths) -> list[Path]:
    rendered = _render_managed_files(paths)
    managed = set(rendered)
    managed.add(paths.users_file)
    managed.add(_resolved_user_group_map_file(paths))
    managed.update(_template_paths(paths))
    return sorted(managed)


def _sync_managed_files(paths: OcservPaths, action: str, group: str | None = None) -> dict[str, Any]:
    relevant_paths = set(_planned_mutation_paths(paths, action, group))
    relevant_templates = {path for path in relevant_paths if path.suffix == ".tpl"}
    template_changes = _ensure_default_templates(paths, list(relevant_templates))
    rendered = _render_managed_files(paths)
    changed_files: list[str] = []
    for file_path, content in rendered.items():
        if file_path not in relevant_paths:
            continue
        file_path.parent.mkdir(parents=True, exist_ok=True)
        existing = file_path.read_text(encoding="utf-8") if file_path.exists() else None
        normalized = content if content.endswith("\n") else content + "\n"
        if existing != normalized:
            file_path.write_text(normalized, encoding="utf-8")
            changed_files.append(str(file_path))
    return {
        "changed_files": sorted(set(changed_files) | set(template_changes)),
        "rendered_files": sorted(str(path) for path in rendered if path in relevant_paths),
        "template_files": sorted(str(path) for path in relevant_templates),
    }


def _inventory_conflicts(
    paths: OcservPaths,
    assignments: dict[str, str],
    allowed_groups: list[str],
    users: dict[str, dict[str, Any]],
) -> list[str]:
    conflicts: list[str] = []
    allowed_group_set = set(allowed_groups)
    static_ips: dict[str, str] = {}
    for username, group in assignments.items():
        if username not in users:
            conflicts.append(f"missing_auth_user:{username}")
        if group not in allowed_group_set:
            conflicts.append(f"unknown_group_mapping:{username}:{group}")
    for username, record in users.items():
        ipv4_address = record.get("ipv4_address")
        if not isinstance(ipv4_address, str) or not ipv4_address:
            continue
        if ipv4_address in static_ips.values():
            conflicts.append(f"duplicate_user_ipv4:{ipv4_address}")
        static_ips[username] = ipv4_address

    template_names = [_group_name_from_template(path) for path in _group_template_paths(paths)]
    if len(template_names) != len(set(template_names)):
        conflicts.append("duplicate_group_template_name")

    config_names = [path.stem for path in _configured_group_paths(paths)]
    if len(config_names) != len(set(config_names)):
        conflicts.append("duplicate_group_config_name")

    return sorted(set(conflicts))


def inventoryConfig(paths: OcservPaths) -> dict[str, Any]:
    users = _load_user_payload(paths)
    assignments = _load_user_group_map(paths, users)
    allowed_groups = sorted(listAllowedGroups(paths))
    rendered_files = _render_managed_files(paths)
    conflicts = _inventory_conflicts(paths, assignments, allowed_groups, users)

    return {
        "main_config_file": str(_resolved_main_config_file(paths)),
        "main_config_template": str(_resolved_main_template(paths)),
        "group_config_dir": str(_resolved_group_config_dir(paths)),
        "group_template_dir": str(_resolved_group_template_dir(paths)),
        "user_config_dir": str(_resolved_user_config_dir(paths)),
        "group_config_files": sorted(str(path) for path in rendered_files if path.parent == _resolved_group_config_dir(paths)),
        "user_config_files": sorted(str(path) for path in rendered_files if path.parent == _resolved_user_config_dir(paths)),
        "group_template_files": sorted(str(path) for path in _group_template_paths(paths)),
        "auth_store": str(paths.users_file),
        "auth_mechanism": "json" if _uses_json_user_store(paths.users_file) else "plain",
        "user_group_map_file": str(_resolved_user_group_map_file(paths)),
        "user_group_assignments": assignments,
        "allowed_groups": allowed_groups,
        "managed_files": sorted(str(path) for path in _managed_paths(paths)),
        "conflicts": sorted(conflicts),
    }


def _determine_activation_mode(paths: OcservPaths, changed_files: list[str]) -> str:
    main_config_path = _resolved_main_config_file(paths)
    group_config_dir = _resolved_group_config_dir(paths)
    group_template_dir = _resolved_group_template_dir(paths)
    user_config_dir = _resolved_user_config_dir(paths)
    for changed_file in changed_files:
        changed_path = Path(changed_file)
        if changed_path == main_config_path:
            return "restart"
        if changed_path.is_relative_to(group_config_dir) or changed_path.is_relative_to(group_template_dir):
            return "restart"
        if changed_path.is_relative_to(user_config_dir):
            return "restart"
    return "reload"


def _group_ipv4_network(paths: OcservPaths, group: str | None) -> ipaddress.IPv4Network | None:
    if group is None:
        return None
    group_config_path = _group_config_path(paths, group)
    details = _parse_group_config_details(group_config_path)
    if details.get("ipv4_network") is None:
        template_path = _resolved_group_template_dir(paths) / f"{group}.conf.tpl"
        details = _parse_group_config_details(template_path)
    ipv4_network = details.get("ipv4_network")
    ipv4_netmask = details.get("ipv4_netmask")
    if not isinstance(ipv4_network, str) or not ipv4_network:
        return None
    try:
        if "/" in ipv4_network:
            network = ipaddress.ip_network(ipv4_network, strict=False)
            return network if isinstance(network, ipaddress.IPv4Network) else None
        if isinstance(ipv4_netmask, str) and ipv4_netmask:
            network = ipaddress.ip_network(f"{ipv4_network}/{ipv4_netmask}", strict=False)
            return network if isinstance(network, ipaddress.IPv4Network) else None
    except ValueError:
        return None
    return None


def _validate_user_ipv4_address(
    paths: OcservPaths,
    *,
    username: str | None,
    group: str | None,
    ipv4_address: str | None,
    users: dict[str, dict[str, Any]],
) -> str | None:
    if ipv4_address is None:
        return None
    try:
        address = ipaddress.ip_address(ipv4_address)
    except ValueError as error:
        raise ValueError("INVALID_IPV4_ADDRESS") from error
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("INVALID_IPV4_ADDRESS")

    for existing_username, record in users.items():
        if existing_username == username:
            continue
        if record.get("ipv4_address") == ipv4_address:
            raise ValueError("IP_ADDRESS_IN_USE")

    network = _group_ipv4_network(paths, group)
    if network is None:
        raise ValueError("GROUP_IPV4_POOL_REQUIRED")
    if address not in network:
        raise ValueError("IP_OUTSIDE_GROUP_POOL")
    if address == network.network_address or (network.num_addresses > 2 and address == network.broadcast_address):
        raise ValueError("IP_OUTSIDE_GROUP_POOL")
    return ipv4_address


def _user_visible_in_runtime(paths: OcservPaths, username: str, audit_sink: AuditSink | None, request_id: str, actor_id: str) -> bool | None:
    try:
        users = runOcctl(paths, "show_users", audit_sink, request_id, actor_id)
    except ValueError:
        return None
    for record in users:
        record_user = record.get("username") or record.get("name") or record.get("user")
        if record_user == username:
            return True
    return False


def _runtime_group_assignment(
    paths: OcservPaths,
    username: str,
    audit_sink: AuditSink | None,
    request_id: str,
    actor_id: str,
) -> str | None:
    try:
        users = runOcctl(paths, "show_users", audit_sink, request_id, actor_id)
    except ValueError:
        return None
    for record in users:
        record_user = record.get("username") or record.get("name") or record.get("user")
        if record_user == username:
            runtime_group = record.get("group") or record.get("policy_group") or record.get("profile")
            return str(runtime_group) if isinstance(runtime_group, str) else None
    return None


def _user_has_active_sessions(paths: OcservPaths, username: str, audit_sink: AuditSink | None, request_id: str, actor_id: str) -> bool:
    sessions = runOcctl(paths, "show_sessions", audit_sink, request_id, actor_id)
    for session in sessions:
        session_user = session.get("username") or session.get("name") or session.get("user")
        if session_user == username:
            return True
    return False


def preflightMutation(
    paths: OcservPaths,
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
    users = _load_user_payload(paths)
    planned_files = [str(path) for path in _planned_mutation_paths(paths, action, group, username)]
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
                "data_files": [str(paths.users_file), str(_resolved_user_group_map_file(paths))],
                "activation_mode": _determine_activation_mode(paths, planned_files),
            }
        if group is not None and group not in set(inventory["allowed_groups"]):
            return {
                "ok": False,
                "error_code": "GROUP_NOT_FOUND",
                "details": {"group": group},
                "planned_files": planned_files,
                "data_files": [str(paths.users_file), str(_resolved_user_group_map_file(paths))],
                "activation_mode": _determine_activation_mode(paths, planned_files),
            }
        try:
            _validate_user_ipv4_address(paths, username=username, group=group, ipv4_address=ipv4_address, users=users)
        except ValueError as error:
            return {
                "ok": False,
                "error_code": str(error),
                "details": {"username": username, "group": group, "ipv4_address": ipv4_address},
                "planned_files": planned_files,
                "data_files": [str(paths.users_file), str(_resolved_user_group_map_file(paths))],
                "activation_mode": _determine_activation_mode(paths, planned_files),
            }
        data_files = [str(paths.users_file), str(_resolved_user_group_map_file(paths))]
    elif action == "assign_group":
        if username not in users:
            return {
                "ok": False,
                "error_code": "USER_NOT_FOUND",
                "details": {"username": username},
                "planned_files": planned_files,
                "data_files": [str(paths.users_file), str(_resolved_user_group_map_file(paths))],
                "activation_mode": _determine_activation_mode(paths, planned_files),
            }
        if group not in set(inventory["allowed_groups"]):
            return {
                "ok": False,
                "error_code": "GROUP_NOT_FOUND",
                "details": {"group": group},
                "planned_files": planned_files,
                "data_files": [str(paths.users_file), str(_resolved_user_group_map_file(paths))],
                "activation_mode": _determine_activation_mode(paths, planned_files),
            }
        data_files = [str(paths.users_file), str(_resolved_user_group_map_file(paths))]
    elif action == "update_user_ip":
        if username not in users:
            return {
                "ok": False,
                "error_code": "USER_NOT_FOUND",
                "details": {"username": username},
                "planned_files": planned_files,
                "data_files": [str(paths.users_file), str(_resolved_user_group_map_file(paths))],
                "activation_mode": _determine_activation_mode(paths, planned_files),
            }
        resolved_group = users[str(username)].get("group")
        try:
            _validate_user_ipv4_address(paths, username=username, group=resolved_group if isinstance(resolved_group, str) else None, ipv4_address=ipv4_address, users=users)
        except ValueError as error:
            return {
                "ok": False,
                "error_code": str(error),
                "details": {"username": username, "group": resolved_group, "ipv4_address": ipv4_address},
                "planned_files": planned_files,
                "data_files": [str(paths.users_file), str(_resolved_user_group_map_file(paths))],
                "activation_mode": _determine_activation_mode(paths, planned_files),
            }
        data_files = [str(paths.users_file), str(_resolved_user_group_map_file(paths))]
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
                "data_files": [str(paths.users_file), str(_resolved_user_group_map_file(paths))],
                "activation_mode": "reload",
            }
        if not force and username is not None and _user_has_active_sessions(paths, username, audit_sink, request_id, actor_id):
            return {
                "ok": False,
                "error_code": "ACTIVE_USER_REQUIRES_FORCE",
                "details": {"username": username},
                "planned_files": planned_files,
                "data_files": [str(paths.users_file), str(_resolved_user_group_map_file(paths))],
                "activation_mode": "reload",
            }
        data_files = [str(paths.users_file), str(_resolved_user_group_map_file(paths))]
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
    paths: OcservPaths,
    *,
    action: str,
    request_id: str,
    actor_id: str,
    snapshots: dict[str, dict[str, Any]],
    changed_files: list[str],
) -> str:
    rollback_state_file = _resolved_rollback_state_file(paths)
    _write_json(
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


def _load_rollback_state(paths: OcservPaths) -> dict[str, Any] | None:
    rollback_state_file = _resolved_rollback_state_file(paths)
    if not rollback_state_file.exists():
        return None
    payload = _read_json(rollback_state_file, None)
    return payload if isinstance(payload, dict) else None


def _clear_rollback_state(paths: OcservPaths) -> None:
    rollback_state_file = _resolved_rollback_state_file(paths)
    if rollback_state_file.exists():
        rollback_state_file.unlink()


def verifyMutation(
    paths: OcservPaths,
    action: str,
    *,
    username: str | None = None,
    group: str | None = None,
    ipv4_address: str | None = None,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> dict[str, Any]:
    users = _load_user_payload(paths)
    assignments = _load_user_group_map(paths, users)
    if action == "create_user":
        if username not in users:
            return {"ok": False, "error_code": "VERIFY_CREATE_FAILED", "details": {"username": username}}
        if group is not None and assignments.get(str(username)) != group:
            return {"ok": False, "error_code": "VERIFY_GROUP_MAPPING_FAILED", "details": {"username": username, "group": group}}
        if ipv4_address is not None:
            if users[str(username)].get("ipv4_address") != ipv4_address:
                return {"ok": False, "error_code": "VERIFY_USER_IPV4_FAILED", "details": {"username": username, "ipv4_address": ipv4_address}}
            if not _user_config_path(paths, str(username)).exists():
                return {"ok": False, "error_code": "VERIFY_USER_CONFIG_FAILED", "details": {"username": username}}
    elif action == "assign_group":
        if username not in users or users[str(username)].get("group") != group:
            return {"ok": False, "error_code": "VERIFY_ASSIGNMENT_FAILED", "details": {"username": username, "group": group}}
        if assignments.get(str(username)) != group:
            return {"ok": False, "error_code": "VERIFY_GROUP_MAPPING_FAILED", "details": {"username": username, "group": group}}
        if not _group_config_path(paths, str(group)).exists():
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
        if not _user_config_path(paths, str(username)).exists():
            return {"ok": False, "error_code": "VERIFY_USER_CONFIG_FAILED", "details": {"username": username}}
    elif action == "delete_user":
        if username in users or str(username) in assignments:
            return {"ok": False, "error_code": "VERIFY_DELETE_FAILED", "details": {"username": username}}
        if username is not None and _user_config_path(paths, str(username)).exists():
            return {"ok": False, "error_code": "VERIFY_USER_CONFIG_FAILED", "details": {"username": username}}
    return {"ok": True, "error_code": None, "details": {"username": username, "group": group}}


def activateService(
    paths: OcservPaths,
    changed_files: list[str],
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> dict[str, Any]:
    activation_mode = _determine_activation_mode(paths, changed_files)
    validation = validateConfig(paths, audit_sink, request_id, actor_id)
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
    command_result = _run_command(_with_prefix(paths, command))
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
    health = healthCheck(paths, audit_sink, request_id, actor_id) if command_result.ok else None
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
    paths: OcservPaths,
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
    sync_result = {"changed_files": []}
    try:
        sync_result = _sync_managed_files(paths, action, group)
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
            "backup": {"files": sorted(snapshots), "rollback_state_file": str(_resolved_rollback_state_file(paths))},
            "rolled_back": True,
        }


def serializeCommandResult(result: SystemCommandResult | None) -> dict[str, Any] | None:
    if result is None:
        return None
    return {
        "ok": result.ok,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }


def serializeActivationResult(result: dict[str, Any] | None) -> dict[str, Any] | None:
    if result is None:
        return None
    return {
        "ok": result["ok"],
        "error_code": result["error_code"],
        "validation": serializeCommandResult(result["validation"]),
        "reload": serializeCommandResult(result["reload"]),
        "health": serializeCommandResult(result.get("health")),
        "activation_mode": result.get("activation_mode"),
        "restart_required": result.get("restart_required"),
    }


def healthCheck(
    paths: OcservPaths,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> SystemCommandResult:
    result = _run_command(_with_prefix(paths, paths.healthcheck_command))
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


def rollbackLastChange(
    paths: OcservPaths,
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


def createUserRecord(paths: OcservPaths, username: str, group: str | None, ipv4_address: str | None = None) -> dict[str, Any]:
    users = _load_user_payload(paths)
    assignments = _load_user_group_map(paths, users)
    ipv4_addresses = _load_user_ipv4_map(paths, users)
    if username in users:
        raise ValueError("USER_ALREADY_EXISTS")
    if group is not None and group not in listAllowedGroups(paths):
        raise ValueError("GROUP_NOT_FOUND")
    normalized_ipv4_address = _validate_user_ipv4_address(paths, username=username, group=group, ipv4_address=ipv4_address, users=users)
    if not _uses_json_user_store(paths.users_file):
        generated_password = secrets.token_urlsafe(18)
        command = _with_prefix(paths, (paths.ocpasswd_bin, "-c", str(paths.users_file), *(("-g", group) if group else ()), username))
        result = subprocess.run(command, input=f"{generated_password}\n{generated_password}\n", capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise ValueError("USER_CREATE_FAILED")
        created_users = _load_user_payload(paths)
        if group is not None:
            assignments[username] = group
        if normalized_ipv4_address is not None:
            ipv4_addresses[username] = normalized_ipv4_address
        _save_user_metadata(paths, assignments, ipv4_addresses)
        _sync_user_config(paths, username, normalized_ipv4_address)
        created_users = _load_user_payload(paths)
        return {
            "user": _sanitize_user_record(created_users[username]),
            "provisioning": {"one_time_password": generated_password},
        }

    users[username] = {"username": username, "group": group, "disabled": False, "ipv4_address": normalized_ipv4_address}
    if group is not None:
        assignments[username] = group
    if normalized_ipv4_address is not None:
        ipv4_addresses[username] = normalized_ipv4_address
    _save_user_payload(paths, users)
    _save_user_metadata(paths, assignments, ipv4_addresses)
    _sync_user_config(paths, username, normalized_ipv4_address)
    return {"user": users[username], "provisioning": None}


def disableUserRecord(paths: OcservPaths, username: str) -> dict[str, Any]:
    users = _load_user_payload(paths)
    if username not in users:
        raise ValueError("USER_NOT_FOUND")
    if not _uses_json_user_store(paths.users_file):
        result = _run_command(_with_prefix(paths, (paths.ocpasswd_bin, "-c", str(paths.users_file), "-l", username)))
        if not result.ok:
            raise ValueError("USER_DISABLE_FAILED")
        return _sanitize_user_record(_load_user_payload(paths)[username])
    users[username]["disabled"] = True
    _save_user_payload(paths, users)
    return users[username]


def deleteUserRecord(paths: OcservPaths, username: str) -> dict[str, Any]:
    users = _load_user_payload(paths)
    assignments = _load_user_group_map(paths, users)
    ipv4_addresses = _load_user_ipv4_map(paths, users)
    if username not in users:
        raise ValueError("USER_NOT_FOUND")
    if not _uses_json_user_store(paths.users_file):
        removed = _sanitize_user_record(users[username])
        result = _run_command(_with_prefix(paths, (paths.ocpasswd_bin, "-c", str(paths.users_file), "-d", username)))
        if not result.ok:
            raise ValueError("USER_DELETE_FAILED")
        assignments.pop(username, None)
        ipv4_addresses.pop(username, None)
        _save_user_metadata(paths, assignments, ipv4_addresses)
        _sync_user_config(paths, username, None)
        return removed

    removed = users.pop(username)
    assignments.pop(username, None)
    ipv4_addresses.pop(username, None)
    _save_user_payload(paths, users)
    _save_user_metadata(paths, assignments, ipv4_addresses)
    _sync_user_config(paths, username, None)
    return removed


def assignGroupRecord(paths: OcservPaths, username: str, group: str) -> dict[str, Any]:
    allowed_groups = listAllowedGroups(paths)
    if group not in allowed_groups:
        raise ValueError("GROUP_NOT_FOUND")
    users = _load_user_payload(paths)
    assignments = _load_user_group_map(paths, users)
    if username not in users:
        raise ValueError("USER_NOT_FOUND")
    _validate_user_ipv4_address(paths, username=username, group=group, ipv4_address=users[username].get("ipv4_address"), users=users)
    users[username]["group"] = group
    assignments[username] = group
    _save_user_payload(paths, users)
    _save_user_group_map(paths, assignments)
    _sync_user_config(paths, username, users[username].get("ipv4_address"))
    return _sanitize_user_record(users[username])


def updateUserIpRecord(paths: OcservPaths, username: str, ipv4_address: str) -> dict[str, Any]:
    users = _load_user_payload(paths)
    assignments = _load_user_group_map(paths, users)
    ipv4_addresses = _load_user_ipv4_map(paths, users)
    if username not in users:
        raise ValueError("USER_NOT_FOUND")
    group = users[username].get("group")
    normalized_ipv4_address = _validate_user_ipv4_address(
        paths,
        username=username,
        group=group if isinstance(group, str) else None,
        ipv4_address=ipv4_address,
        users=users,
    )
    if normalized_ipv4_address is None:
        raise ValueError("INVALID_IPV4_ADDRESS")
    users[username]["ipv4_address"] = normalized_ipv4_address
    ipv4_addresses[username] = normalized_ipv4_address
    if _uses_json_user_store(paths.users_file):
        _save_user_payload(paths, users)
    _save_user_metadata(paths, assignments, ipv4_addresses)
    _sync_user_config(paths, username, normalized_ipv4_address)
    return _sanitize_user_record(users[username])


def createGroupRecord(
    paths: OcservPaths,
    group: str,
    ipv4_network: str | None,
    ipv4_netmask: str | None,
    routes: list[str],
) -> dict[str, Any]:
    if group in listAllowedGroups(paths):
        raise ValueError("GROUP_ALREADY_EXISTS")
    payload = _read_json(paths.groups_file, {"groups": []}) if not paths.groups_file.is_dir() else {"groups": []}
    existing_groups = payload.get("groups", []) if isinstance(payload, dict) else []
    if not isinstance(existing_groups, list):
        existing_groups = []
    normalized_groups = sorted(set([item for item in existing_groups if isinstance(item, str)] + [group]))
    if not paths.groups_file.is_dir():
        _write_json(paths.groups_file, {"groups": normalized_groups})

    template_dir = _resolved_group_template_dir(paths)
    template_dir.mkdir(parents=True, exist_ok=True)
    template_path = template_dir / f"{group}.conf.tpl"
    lines = [f"# {group}"]
    if ipv4_network:
        lines.append(f"ipv4-network = {ipv4_network}")
    if ipv4_netmask:
        lines.append(f"ipv4-netmask = {ipv4_netmask}")
    if routes:
        lines.append("restrict-user-to-routes = true")
        for route in routes:
            lines.append(f"route = {route}")
    template_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "group": group,
        "group_details": {
            "group": group,
            "ipv4_network": ipv4_network,
            "ipv4_netmask": ipv4_netmask,
            "routes": list(routes),
        },
    }


def deleteGroupRecord(paths: OcservPaths, group: str) -> dict[str, Any]:
    if group in {"default", "admins"}:
        raise ValueError("PROTECTED_GROUP")
    users = _load_user_payload(paths)
    assignments = _load_user_group_map(paths, users)
    if any(assigned_group == group for assigned_group in assignments.values()):
        raise ValueError("GROUP_IN_USE")
    if group not in listAllowedGroups(paths):
        raise ValueError("GROUP_NOT_FOUND")

    if not paths.groups_file.is_dir() and paths.groups_file.exists():
        payload = _read_json(paths.groups_file, {"groups": []})
        existing_groups = payload.get("groups", []) if isinstance(payload, dict) else []
        remaining = [item for item in existing_groups if item != group]
        _write_json(paths.groups_file, {"groups": remaining})

    group_path = _group_config_path(paths, group)
    if group_path.exists():
        group_path.unlink()
    template_path = _resolved_group_template_dir(paths) / f"{group}.conf.tpl"
    if template_path.exists():
        template_path.unlink()
    return {"group": group, "group_details": {"group": group}}


def disableUsersInGroupRecord(paths: OcservPaths, group: str) -> dict[str, Any]:
    users = _load_user_payload(paths)
    assignments = _load_user_group_map(paths, users)
    target_users = sorted(
        username
        for username, assigned_group in assignments.items()
        if assigned_group == group and username in users and not bool(users[username].get("disabled", False))
    )
    if group not in listAllowedGroups(paths):
        raise ValueError("GROUP_NOT_FOUND")
    if not target_users:
        return {"group": group, "affected_users": []}
    for username in target_users:
        disableUserRecord(paths, username)
    return {
        "group": group,
        "affected_users": [_sanitize_user_record(_load_user_payload(paths)[username]) for username in target_users],
    }


# START_CONTRACT: runOcctl
#   PURPOSE: Run approved occtl read operations and normalize their structured output.
#   INPUTS: { paths: OcservPaths - adapter config, subcommand: str - approved occtl operation, audit_sink: AuditSink | None - audit destination, request_id: str - request id, actor_id: str - actor id }
#   OUTPUTS: { list[dict[str, Any]] - normalized occtl records }
#   SIDE_EFFECTS: [executes occtl and writes an audit record]
#   LINKS: [validateConfig, reloadService]
# END_CONTRACT: runOcctl
def runOcctl(
    paths: OcservPaths,
    subcommand: str,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> list[dict[str, Any]]:
    commands = {
        "show_users": _with_prefix(paths, (paths.occtl_bin, "show", "users")),
        "show_sessions": _with_prefix(paths, (paths.occtl_bin, "show", "sessions", "all")),
    }
    if subcommand not in commands:
        raise ValueError("OCCTL_EXECUTION_FAILED")
    result = _run_command(commands[subcommand])
    if not result.ok:
        raise ValueError("OCCTL_EXECUTION_FAILED")
    normalized = _normalize_occtl_output(result.stdout)
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
    paths: OcservPaths,
    username: str,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> SystemCommandResult:
    # START_BLOCK_DISCONNECT_SESSION
    result = _run_command(_with_prefix(paths, (paths.occtl_bin, "disconnect", "user", username)))
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
    paths: OcservPaths,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> SystemCommandResult:
    # START_BLOCK_VALIDATE_CONFIG
    result = _run_command(_with_prefix(paths, paths.validate_command))
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
    paths: OcservPaths,
    audit_sink: AuditSink | None = None,
    request_id: str = "unknown-request",
    actor_id: str = "unknown-actor",
) -> SystemCommandResult:
    # START_BLOCK_SAFE_RELOAD
    result = _run_command(_with_prefix(paths, paths.reload_command))
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


# START_CONTRACT: safeReload
#   PURPOSE: Validate config before any reload attempt and stop on failure.
#   INPUTS: { paths: OcservPaths - adapter config, audit_sink: AuditSink | None - audit destination, request_id: str - request id, actor_id: str - actor id }
#   OUTPUTS: { dict[str, Any] - combined validation and reload result }
#   SIDE_EFFECTS: [may execute validation and reload commands, writes audit records]
#   LINKS: [validateConfig, reloadService]
# END_CONTRACT: safeReload
def safeReload(
    paths: OcservPaths,
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

# FILE: src/ocserv_adapter.py
# VERSION: 2.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Core types, filesystem helpers, user/group CRUD, and backward-compatible re-exports for the ocserv adapter layer.
#   SCOPE: Data classes, path resolution, file-backed user/group state, CRUD record operations, and re-exports from adapter_commands, adapter_templates, adapter_mutations.
#   DEPENDS: M-AUDIT-LOG
#   LINKS: M-OCSERV-ADAPTER
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   OcservPaths - Filesystem and command configuration for the backend.
#   SystemCommandResult - Structured subprocess result.
#   listAllowedGroups - Resolve admissible policy groups from managed templates or the legacy group store.
#   loadUsers - Return canonical file-backed users.
#   listGroups - List allowed groups with membership details.
#   showUserIps - Show user IP assignments from active sessions.
#   createUserRecord - Create a file-backed user.
#   disableUserRecord - Disable an existing user.
#   deleteUserRecord - Delete a file-backed user.
#   assignGroupRecord - Update a user's policy group safely.
#   updateUserIpRecord - Update a user's static IPv4 address.
#   createGroupRecord - Create a new policy group with template.
#   deleteGroupRecord - Delete a policy group.
#   disableUsersInGroupRecord - Disable all active users in a policy group.
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: [v2.0.0 - Extracted command, template, and mutation logic into adapter_commands, adapter_templates, adapter_mutations. This module retains core types, file I/O, CRUD, and re-exports for backward compatibility.]
# END_CHANGE_SUMMARY

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
import secrets
import subprocess
from typing import Any

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


# --- Path resolution helpers ---

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


# --- File I/O helpers ---

def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# --- Command helpers ---

DEFAULT_COMMAND_TIMEOUT = 30
VALIDATION_COMMAND_TIMEOUT = 60


def _run_command(command: tuple[str, ...], *, timeout: int = DEFAULT_COMMAND_TIMEOUT) -> SystemCommandResult:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        return SystemCommandResult(ok=False, stdout="", stderr="COMMAND_TIMEOUT", returncode=-1)
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


def _uses_json_user_store(path: Path) -> bool:
    return path.suffix == ".json"


# --- Group helpers ---

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


def listAllowedGroups(paths: OcservPaths) -> set[str]:
    return set(_planned_group_names(paths))


# --- User data helpers ---

def _load_plain_user_payload(passwd_file: Path, audit_sink: AuditSink | None = None) -> dict[str, dict[str, Any]]:
    users: dict[str, dict[str, Any]] = {}
    if not passwd_file.exists():
        return users
    for line_number, raw_line in enumerate(passwd_file.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(":", 2)
        if len(parts) < 3:
            recordAuditEvent(
                {
                    "event": "corrupt_user_record",
                    "error_code": "CORRUPT_USER_RECORD",
                    "message": "[OcservAdapter][_load_plain_user_payload] skipped malformed passwd line",
                    "details": {"line_number": line_number, "file": str(passwd_file)},
                },
                audit_sink,
            )
            continue
        username, group, password_hash = parts
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


# --- User config helpers ---

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


# --- IP validation ---

def _group_ipv4_network(paths: OcservPaths, group: str | None) -> ipaddress.IPv4Network | None:
    if group is None:
        return None
    group_config_path_val = _group_config_path(paths, group)
    details = _parse_group_config_details(group_config_path_val)
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


# --- Public query functions ---

def loadUsers(paths: OcservPaths) -> list[dict[str, Any]]:
    users = _load_user_payload(paths)
    return [_sanitize_user_record(users[key]) for key in sorted(users)]


def listGroups(paths: OcservPaths) -> list[dict[str, Any]]:
    from src.adapter_mutations import inventoryConfig
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
    from src.adapter_commands import runOcctl
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


# --- CRUD record operations ---

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
        result = subprocess.run(command, input=f"{generated_password}\n{generated_password}\n", capture_output=True, text=True, check=False, timeout=DEFAULT_COMMAND_TIMEOUT)
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


# --- Backward-compatible re-exports ---
# These imports allow existing code to continue using `from src.ocserv_adapter import X`
# for symbols that have been moved to adapter_commands, adapter_templates, or adapter_mutations.

from src.adapter_commands import (  # noqa: E402, F811
    disconnectSession,
    healthCheck,
    reloadService,
    runOcctl,
    safeReload,
    serializeCommandResult,
    validateConfig,
)
from src.adapter_mutations import (  # noqa: E402, F811
    activateService,
    applyManagedMutation,
    inventoryConfig,
    preflightMutation,
    rollbackLastChange,
    serializeActivationResult,
    verifyMutation,
)

__all__ = [
    "OcservPaths",
    "SystemCommandResult",
    "DEFAULT_COMMAND_TIMEOUT",
    "VALIDATION_COMMAND_TIMEOUT",
    "activateService",
    "applyManagedMutation",
    "assignGroupRecord",
    "createGroupRecord",
    "createUserRecord",
    "deleteGroupRecord",
    "deleteUserRecord",
    "disableUserRecord",
    "disableUsersInGroupRecord",
    "disconnectSession",
    "healthCheck",
    "inventoryConfig",
    "listAllowedGroups",
    "listGroups",
    "loadUsers",
    "preflightMutation",
    "reloadService",
    "rollbackLastChange",
    "runOcctl",
    "safeReload",
    "serializeActivationResult",
    "serializeCommandResult",
    "showUserIps",
    "updateUserIpRecord",
    "validateConfig",
    "verifyMutation",
]

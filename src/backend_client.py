# FILE: src/backend_client.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Provide the client boundary that talks only to the localhost ocserv-admin backend for approved actions.
#   SCOPE: Validate allowed action names, normalize approved tool payloads into backend actions, send authenticated localhost HTTP requests, and normalize backend responses without performing administrative work directly.
#   DEPENDS: M-OCSERV-ADMIN-API
#   LINKS: M-BACKEND-CLIENT
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   BackendClient - Authenticated localhost client for ocserv-admin.
#   buildToolCatalog - Return the strict public tool schema for approved backend actions.
#   discoverGroupChoices - Discover allowed policy groups for tool schema enums.
#   normalizeBackendResponse - Convert backend responses into a stable tool-facing envelope.
#   paginateCollection - Slice list results into a stable MCP-facing pagination window.
#   planAction - Normalize a requested approved action into the backend request vocabulary.
# END_MODULE_MAP

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
import urllib.error
import urllib.request

from src.audit_log import AuditSink, recordAuditEvent


DEFAULT_RUNTIME_DIR = Path("/var/lib/ocserv-admin")
BACKEND_UNAVAILABLE_ERROR = "BACKEND_UNAVAILABLE"


ALLOWED_BACKEND_ACTIONS = {
    "list_users",
    "list_sessions",
    "list_groups",
    "show_user_ips",
    "disconnect_session",
    "create_user",
    "disable_user",
    "disable_group_users",
    "delete_user",
    "assign_group",
    "create_group",
    "delete_group",
    "reload_service",
    "rollback_last_change",
    "validate_config",
    "confirm_action",
}

EXPOSED_PUBLIC_TOOLS = (
    "list_users",
    "list_sessions",
    "list_groups",
    "show_user_ips",
    "disconnect_session",
    "create_user",
    "disable_user",
    "disable_group_users",
    "delete_user",
    "assign_group",
    "create_group",
    "delete_group",
    "reload_service",
    "rollback_last_change",
    "confirm_action",
)

ACTION_FIELDS: dict[str, tuple[str, ...]] = {
    "list_users": (),
    "list_sessions": (),
    "list_groups": (),
    "show_user_ips": (),
    "disconnect_session": ("username",),
    "create_user": ("username", "group"),
    "disable_user": ("username",),
    "disable_group_users": ("group",),
    "delete_user": ("username", "force"),
    "assign_group": ("username", "group"),
    "create_group": ("group", "ipv4_network", "ipv4_netmask", "routes"),
    "delete_group": ("group",),
    "reload_service": (),
    "rollback_last_change": (),
    "validate_config": (),
    "confirm_action": ("token", "decision", "expected_action", "expected_username", "expected_group"),
}

REQUIRED_ACTION_FIELDS: dict[str, tuple[str, ...]] = {
    "disconnect_session": ("username",),
    "create_user": ("username", "group"),
    "disable_user": ("username",),
    "disable_group_users": ("group",),
    "delete_user": ("username",),
    "assign_group": ("username", "group"),
    "create_group": ("group",),
    "delete_group": ("group",),
    "rollback_last_change": (),
    "confirm_action": ("token", "decision"),
}

BOOLEAN_FIELDS = {"force"}
DECISION_VALUES = {"confirm", "cancel"}

RESPONSE_FORMAT_SCHEMA = {
    "type": "string",
    "enum": ["json", "markdown"],
    "default": "json",
}

PAGINATION_PROPERTIES = {
    "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 50},
    "offset": {"type": "integer", "minimum": 0, "default": 0},
}

TOOL_METADATA: dict[str, dict[str, Any]] = {
    "list_users": {
        "description": "List managed VPN users.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **PAGINATION_PROPERTIES,
                "response_format": RESPONSE_FORMAT_SCHEMA,
            },
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    "list_sessions": {
        "description": "List active ocserv sessions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **PAGINATION_PROPERTIES,
                "response_format": RESPONSE_FORMAT_SCHEMA,
            },
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    "list_groups": {
        "description": "List configured ocserv policy groups with network and membership details.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **PAGINATION_PROPERTIES,
                "response_format": RESPONSE_FORMAT_SCHEMA,
            },
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    "show_user_ips": {
        "description": "Show current VPN IP information for active users based on live sessions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "response_format": RESPONSE_FORMAT_SCHEMA,
            },
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    "disconnect_session": {
        "description": "Disconnect an active VPN session through the confirmation-token flow.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "username": {"type": "string", "minLength": 3, "maxLength": 32},
                "response_format": RESPONSE_FORMAT_SCHEMA,
            },
            "required": ["username"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    "create_user": {
        "description": "Create a VPN user in an existing ocserv policy group.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "username": {"type": "string", "minLength": 3, "maxLength": 32},
                "group": {"type": "string", "minLength": 2, "maxLength": 32},
                "response_format": RESPONSE_FORMAT_SCHEMA,
            },
            "required": ["username", "group"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    "disable_user": {
        "description": "Disable a VPN user through the confirmation-token flow.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "username": {"type": "string", "minLength": 3, "maxLength": 32},
                "response_format": RESPONSE_FORMAT_SCHEMA,
            },
            "required": ["username"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    "disable_group_users": {
        "description": "Disable all VPN users assigned to a policy group through the confirmation-token flow.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group": {"type": "string", "minLength": 2, "maxLength": 32},
                "response_format": RESPONSE_FORMAT_SCHEMA,
            },
            "required": ["group"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    "delete_user": {
        "description": "Delete a VPN user. Force removal still requires confirmation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "username": {"type": "string", "minLength": 3, "maxLength": 32},
                "force": {"type": "boolean"},
                "response_format": RESPONSE_FORMAT_SCHEMA,
            },
            "required": ["username"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    "assign_group": {
        "description": "Assign an existing VPN user to an ocserv policy group.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "username": {"type": "string", "minLength": 3, "maxLength": 32},
                "group": {"type": "string", "minLength": 2, "maxLength": 32},
                "response_format": RESPONSE_FORMAT_SCHEMA,
            },
            "required": ["username", "group"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    "create_group": {
        "description": "Create a managed ocserv policy group, optionally with IPv4 pool and routes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group": {"type": "string", "minLength": 2, "maxLength": 32},
                "ipv4_network": {"type": "string", "minLength": 3, "maxLength": 64},
                "ipv4_netmask": {"type": "string", "minLength": 3, "maxLength": 64},
                "routes": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 3, "maxLength": 128},
                },
                "response_format": RESPONSE_FORMAT_SCHEMA,
            },
            "required": ["group"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    "delete_group": {
        "description": "Delete a managed ocserv policy group when no users still belong to it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group": {"type": "string", "minLength": 2, "maxLength": 32},
                "response_format": RESPONSE_FORMAT_SCHEMA,
            },
            "required": ["group"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    "reload_service": {
        "description": "Validate and reload ocserv through the approved backend path.",
        "inputSchema": {
            "type": "object",
            "properties": {"response_format": RESPONSE_FORMAT_SCHEMA},
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    "rollback_last_change": {
        "description": "Rollback the last config-affecting change after explicit confirmation.",
        "inputSchema": {
            "type": "object",
            "properties": {"response_format": RESPONSE_FORMAT_SCHEMA},
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    "confirm_action": {
        "description": "Confirm or cancel a previously staged destructive admin action.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {"type": "string", "minLength": 1},
                "decision": {"type": "string", "enum": ["confirm", "cancel"]},
                "expected_action": {"type": "string", "minLength": 1, "maxLength": 64},
                "expected_username": {"type": "string", "minLength": 1, "maxLength": 64},
                "expected_group": {"type": "string", "minLength": 1, "maxLength": 64},
                "response_format": RESPONSE_FORMAT_SCHEMA,
            },
            "required": ["token", "decision"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
}


@dataclass(slots=True)
class BackendClient:
    base_url: str
    actor_id: str
    auth_token: str

    def __post_init__(self) -> None:
        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("BACKEND_URL_MUST_BE_HTTP")
        if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("BACKEND_MUST_BE_LOOPBACK")

    def _request(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        if action not in ALLOWED_BACKEND_ACTIONS:
            raise ValueError("ACTION_NOT_ALLOWED")
        request = urllib.request.Request(
            f"{self.base_url}/actions/{action}",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Actor-Id": self.actor_id,
                "Authorization": f"Bearer {self.auth_token}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            return json.loads(error.read().decode("utf-8"))
        except urllib.error.URLError as error:
            return {
                "ok": False,
                "status": "failed",
                "error_code": BACKEND_UNAVAILABLE_ERROR,
                "details": {"reason": str(getattr(error, "reason", error))},
            }

    def execute(self, action: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request(action, payload or {})


def buildToolCatalog() -> list[dict[str, Any]]:
    return buildToolCatalogWithGroups(discoverGroupChoices())


def discoverGroupChoices(
    groups_file: Path | None = None,
    env_groups: str | None = None,
) -> tuple[str, ...] | None:
    if env_groups:
        parsed = tuple(group.strip() for group in env_groups.split(",") if group.strip())
        return parsed or None

    path = groups_file
    if path is None:
        configured = Path(
            os.environ.get(
                "OCSERV_ADMIN_GROUPS_FILE",
                str(DEFAULT_RUNTIME_DIR / "groups.json"),
            )
        )
        path = configured

    if not path.exists():
        return None

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    groups = payload.get("groups")
    if not isinstance(groups, list):
        return None
    normalized = tuple(group for group in groups if isinstance(group, str) and group)
    return normalized or None


def buildToolCatalogWithGroups(group_choices: tuple[str, ...] | None) -> list[dict[str, Any]]:
    catalog: list[dict[str, Any]] = []
    for action in EXPOSED_PUBLIC_TOOLS:
        metadata = json.loads(json.dumps(TOOL_METADATA[action]))
        if group_choices and action in {"create_user", "assign_group", "disable_group_users", "create_group", "delete_group"}:
            metadata["inputSchema"]["properties"]["group"] = {
                "type": "string",
                "enum": list(group_choices),
            }
        catalog.append({"name": action, **metadata})
    return catalog


def normalizeBackendResponse(action: str, response: dict[str, Any]) -> dict[str, Any]:
    status = "ok"
    if response.get("status") == "pending_confirmation":
        status = "pending_confirmation"
    elif response.get("status") == "rejected":
        status = "rejected"
    elif not response.get("ok", False):
        status = "failed"

    actionable_error = None
    if status != "ok":
        error_code = response.get("error_code") or response.get("status") or "UNKNOWN_ERROR"
        actionable_error = {
            "code": error_code,
            "message": _actionable_message(error_code),
            "details": _error_details(response),
            "next_step": _next_step_for_status(status, error_code),
        }

    entities = {
        "users": response.get("users"),
        "sessions": response.get("sessions"),
        "groups": response.get("groups"),
        "user_ips": response.get("user_ips"),
        "user": response.get("user"),
        "provisioning": response.get("provisioning") or (response.get("executed") or {}).get("provisioning"),
        "disconnect": response.get("disconnect") or (response.get("executed") or {}).get("disconnect"),
        "group": response.get("group") or (response.get("user") or {}).get("group"),
        "group_details": response.get("group_details") or (response.get("executed") or {}).get("group_details"),
        "affected_users": response.get("affected_users") or (response.get("executed") or {}).get("affected_users"),
        "token": response.get("token"),
        "resolution": response.get("resolution"),
        "confirmation": response.get("confirmation") or (response.get("executed") or {}).get("confirmation"),
        "executed": response.get("executed"),
    }

    return {
        "result": {
            "status": status,
            "action": action,
            "request_id": response.get("request_id"),
            "ok": bool(response.get("ok", False)),
        },
        "entities": entities,
        "reload": response.get("reload") or response.get("activation") or (response.get("executed") or {}).get("reload"),
        "actionable_error": actionable_error,
    }


def paginateCollection(items: list[Any] | None, *, limit: int | None = None, offset: int | None = None) -> tuple[list[Any], dict[str, int | bool | None]]:
    normalized_items = list(items or [])
    normalized_limit = 50 if limit is None else max(1, min(limit, 100))
    normalized_offset = 0 if offset is None else max(offset, 0)
    page = normalized_items[normalized_offset : normalized_offset + normalized_limit]
    total_count = len(normalized_items)
    count = len(page)
    next_offset = normalized_offset + count if normalized_offset + count < total_count else None
    return page, {
        "limit": normalized_limit,
        "offset": normalized_offset,
        "count": count,
        "total_count": total_count,
        "has_more": next_offset is not None,
        "next_offset": next_offset,
    }


def _actionable_message(error_code: str) -> str:
    messages = {
        "CONFIRMATION_REQUIRED": "Repeat the request only after the operator confirms the destructive action.",
        "UNAUTHORIZED_OPERATOR": "Use an allowlisted client actor identity for backend calls.",
        "ACTION_NOT_ALLOWED": "Use one of the approved public admin actions only.",
        "INVALID_USERNAME": "Provide a username that matches the ocserv-safe identifier format.",
        "INVALID_GROUP": "Provide an existing ocserv policy group identifier.",
        "GROUP_NOT_FOUND": "Choose one of the configured ocserv policy groups.",
        "GROUP_ALREADY_EXISTS": "Choose a different group name because that policy group already exists.",
        "GROUP_IN_USE": "Move or disable users in that group before deleting it.",
        "PROTECTED_GROUP": "That built-in group cannot be deleted.",
        "INVALID_REQUEST:force": "The force flag must be a boolean value.",
        "INVALID_REQUEST:routes": "Provide routes as an array of strings.",
        "INVALID_REQUEST:response_format": "Use response_format=json or response_format=markdown.",
        "INVALID_REQUEST:limit": "Provide limit as an integer between 1 and 100.",
        "INVALID_REQUEST:offset": "Provide offset as an integer greater than or equal to 0.",
        "INVALID_CONFIRMATION_CONTEXT": "Retry confirmation with the exact action context or request a fresh destructive action preview.",
        BACKEND_UNAVAILABLE_ERROR: "Ensure the localhost ocserv-admin backend is running and reachable before retrying.",
    }
    return messages.get(error_code, "Review the backend response details and retry with an approved payload.")


def _error_details(response: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in response.items()
        if key in {"error_code", "status", "token", "resolution", "validation"}
    }


def _next_step_for_status(status: str, error_code: str) -> str | None:
    if status == "pending_confirmation":
        return "Call confirm_action with the returned token and a confirm or cancel decision."
    if error_code == "GROUP_NOT_FOUND":
        return "Ask for an existing ocserv policy group before retrying."
    if error_code == "GROUP_IN_USE":
        return "List users in that group, reassign or disable them, and retry the delete request."
    if error_code == "UNAUTHORIZED_OPERATOR":
        return "Configure OCSERV_ADMIN_ALLOWED_ACTORS to include the client actor id."
    return None


def planAction(action: str, *, audit_sink: AuditSink | Path | None = None, actor_id: str = "mcp-client", **payload: Any) -> tuple[str, dict[str, Any]]:
    # START_BLOCK_PLAN_ACTION
    recordAuditEvent(
        {
            "event": "backend_client_plan_action",
            "actor_type": "mcp_client",
            "actor_id": actor_id,
            "command": action,
            "result": "planned",
            "message": "[BackendClient][planAction][BLOCK_PLAN_ACTION] planned backend action",
            "details": {"fields": sorted(payload.keys())},
        },
        audit_sink,
    )
    if action not in ALLOWED_BACKEND_ACTIONS:
        raise ValueError("ACTION_NOT_ALLOWED")
    allowed_fields = set(ACTION_FIELDS[action])
    unexpected_fields = sorted(set(payload) - allowed_fields)
    if unexpected_fields:
        raise ValueError(f"INVALID_REQUEST:{','.join(unexpected_fields)}")

    for field in REQUIRED_ACTION_FIELDS.get(action, ()): 
        if payload.get(field) in {None, ""}:
            raise ValueError(f"INVALID_REQUEST:{field}")

    for field in BOOLEAN_FIELDS:
        if field in payload and not isinstance(payload[field], bool):
            raise ValueError(f"INVALID_REQUEST:{field}")

    if "routes" in payload:
        routes = payload["routes"]
        if not isinstance(routes, list) or any(not isinstance(route, str) or not route for route in routes):
            raise ValueError("INVALID_REQUEST:routes")

    if action == "confirm_action" and payload.get("decision") not in DECISION_VALUES:
        raise ValueError("INVALID_REQUEST:decision")

    return action, dict(payload)
    # END_BLOCK_PLAN_ACTION

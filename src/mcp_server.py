# FILE: src/mcp_server.py
# VERSION: 1.3.0
# START_MODULE_CONTRACT
#   PURPOSE: Expose the approved ocserv admin actions as a strict local MCP stdio server through the official Python MCP SDK.
#   SCOPE: Build the official stdio MCP server, advertise only the approved tools, route approved calls through the backend client, add MCP-layer response formatting and pagination, and return normalized structured responses.
#   DEPENDS: M-BACKEND-CLIENT
#   LINKS: M-MCP-SERVER
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   OcservAdminMcpServer - Official SDK-backed MCP server exposing approved backend actions.
#   buildServerFromEnv - Build a server from environment-configured backend settings.
#   main - Run the stdio MCP server loop.
# END_MODULE_MAP

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from src.backend_client import (
    BackendClient,
    buildToolCatalog,
    normalizeBackendResponse,
    paginateCollection,
    planAction,
)

from src.logging_config import get_logger, setup_logging

_logger = get_logger("mcp")

try:
    from mcp.server.lowlevel.server import Server as _MCPServer  # type: ignore[import-untyped]
    from mcp.server.lowlevel.server import NotificationOptions as _NotificationOptions  # type: ignore[import-untyped]
    from mcp.server.stdio import stdio_server as _stdio_server  # type: ignore[import-untyped]
    from mcp.types import CallToolResult as _CallToolResult  # type: ignore[import-untyped]
    from mcp.types import TextContent as _TextContent  # type: ignore[import-untyped]
    from mcp.types import Tool as _Tool  # type: ignore[import-untyped]
    from mcp.types import ToolAnnotations as _ToolAnnotations  # type: ignore[import-untyped]
except ImportError as error:  # pragma: no cover - exercised in runtime environments without dependency installed
    MCP_IMPORT_ERROR = error
    _MCPServer = None  # type: ignore[assignment]
    _NotificationOptions = None  # type: ignore[assignment]
    _stdio_server = None  # type: ignore[assignment]
    _CallToolResult = None  # type: ignore[assignment]
    _TextContent = None  # type: ignore[assignment]
    _Tool = None  # type: ignore[assignment]
    _ToolAnnotations = None  # type: ignore[assignment]
else:
    MCP_IMPORT_ERROR = None


DEFAULT_RESPONSE_FORMAT = "json"
MARKDOWN_RESPONSE_FORMAT = "markdown"
SERVER_NAME = "ocserv-admin"
SERVER_VERSION = "1.3.0"
MCP_PROTOCOL_VERSION = "2025-11-25"
ALLOWED_RESPONSE_FORMATS = {DEFAULT_RESPONSE_FORMAT, MARKDOWN_RESPONSE_FORMAT}


@dataclass(slots=True)
class OcservAdminMcpServer:
    client: BackendClient
    server_name: str = SERVER_NAME
    server_version: str = SERVER_VERSION

    def __post_init__(self) -> None:
        if _MCPServer is None:
            raise RuntimeError("MCP_SDK_IMPORT_FAILED") from MCP_IMPORT_ERROR

    async def list_tools(self) -> list[Any]:
        return [_catalog_entry_to_tool(entry) for entry in buildToolCatalog()]

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        tool_name = name
        raw_arguments = arguments or {}
        if not isinstance(raw_arguments, dict):
            normalized = _invalid_request_response(tool_name, "INVALID_REQUEST:arguments")
            return _build_call_tool_result(normalized, DEFAULT_RESPONSE_FORMAT)

        try:
            response_format, limit, offset = _validate_mcp_request_options(raw_arguments)
        except ValueError as error:
            normalized = _invalid_request_response(tool_name, str(error))
            return _build_call_tool_result(normalized, DEFAULT_RESPONSE_FORMAT)

        planning_arguments = {
            key: value
            for key, value in raw_arguments.items()
            if key not in {"response_format", "limit", "offset"}
        }

        try:
            action, payload = planAction(tool_name, **planning_arguments)
            backend_response = self.client.execute(action, payload)
            normalized = normalizeBackendResponse(action, backend_response)
            normalized = _apply_list_pagination(normalized, action, limit=limit, offset=offset)
        except ValueError as error:
            normalized = _invalid_request_response(tool_name, str(error))

        return _build_call_tool_result(normalized, response_format)

    async def run_stdio_async(self) -> None:
        if _MCPServer is None or _NotificationOptions is None or _stdio_server is None:
            raise RuntimeError("MCP_SDK_IMPORT_FAILED") from MCP_IMPORT_ERROR

        server = _MCPServer(self.server_name, version=self.server_version)

        @server.list_tools()
        async def _handle_list_tools() -> list[Any]:
            return await self.list_tools()

        @server.call_tool(validate_input=False)
        async def _handle_call_tool(name: str, arguments: dict[str, Any] | None) -> Any:
            return await self.call_tool(name, arguments)

        async with _stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(
                    notification_options=_NotificationOptions(),
                    experimental_capabilities={},
                ),
            )


def _validate_mcp_request_options(arguments: dict[str, Any]) -> tuple[str, int | None, int | None]:
    response_format = arguments.get("response_format", DEFAULT_RESPONSE_FORMAT)
    if response_format not in ALLOWED_RESPONSE_FORMATS:
        raise ValueError("INVALID_REQUEST:response_format")

    limit = arguments.get("limit")
    if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit < 1 or limit > 100):
        raise ValueError("INVALID_REQUEST:limit")

    offset = arguments.get("offset")
    if offset is not None and (not isinstance(offset, int) or isinstance(offset, bool) or offset < 0):
        raise ValueError("INVALID_REQUEST:offset")

    return response_format, limit, offset


def _catalog_entry_to_tool(entry: dict[str, Any]) -> Any:
    if _Tool is None or _ToolAnnotations is None:
        raise RuntimeError("MCP_SDK_IMPORT_FAILED") from MCP_IMPORT_ERROR

    annotation_payload = entry.get("annotations") or {}
    tool_annotations = _ToolAnnotations(
        title=entry.get("name"),
        readOnlyHint=annotation_payload.get("readOnlyHint"),
        destructiveHint=annotation_payload.get("destructiveHint"),
        idempotentHint=annotation_payload.get("idempotentHint"),
        openWorldHint=annotation_payload.get("openWorldHint"),
    )
    tool = _Tool(
        name=entry["name"],
        description=entry.get("description"),
        inputSchema=entry.get("inputSchema") or {"type": "object", "properties": {}, "additionalProperties": False},
        annotations=tool_annotations,
    )
    # SDK compat: some MCP SDK versions expose only camelCase attributes;
    # add snake_case aliases so consumers work regardless of SDK version (mcp>=1.0,<2.0).
    if not hasattr(tool, "input_schema"):
        tool.input_schema = tool.inputSchema  # type: ignore[attr-defined]
    if not hasattr(tool.annotations, "read_only_hint"):
        tool.annotations.read_only_hint = annotation_payload.get("readOnlyHint")  # type: ignore[attr-defined]
        tool.annotations.destructive_hint = annotation_payload.get("destructiveHint")  # type: ignore[attr-defined]
        tool.annotations.idempotent_hint = annotation_payload.get("idempotentHint")  # type: ignore[attr-defined]
        tool.annotations.open_world_hint = annotation_payload.get("openWorldHint")  # type: ignore[attr-defined]
    return tool


def _invalid_request_response(tool_name: str, error_code: str) -> dict[str, Any]:
    return {
        "result": {"status": "failed", "action": tool_name, "request_id": None, "ok": False},
        "entities": {},
        "reload": None,
        "actionable_error": {
            "code": error_code,
            "message": "The requested tool call did not satisfy the strict contract.",
            "details": {"error_code": error_code},
            "next_step": "Retry with one of the approved tools and a schema-valid payload.",
        },
    }


def _apply_list_pagination(
    normalized: dict[str, Any],
    action: str,
    *,
    limit: int | None,
    offset: int | None,
) -> dict[str, Any]:
    collection_key = {"list_users": "users", "list_sessions": "sessions"}.get(action)
    if collection_key is None:
        return normalized

    entities = dict(normalized.get("entities") or {})
    paged_items, pagination = paginateCollection(entities.get(collection_key), limit=limit, offset=offset)
    entities[collection_key] = paged_items
    entities["pagination"] = pagination
    return {**normalized, "entities": entities}


def _build_call_tool_result(normalized: dict[str, Any], response_format: str | None) -> Any:
    if _CallToolResult is None or _TextContent is None:
        raise RuntimeError("MCP_SDK_IMPORT_FAILED") from MCP_IMPORT_ERROR
    text = _render_response_text(normalized, response_format)
    result = _CallToolResult(
        content=[_TextContent(type="text", text=text)],
        structuredContent=normalized,
        isError=normalized["result"]["status"] != "ok",
    )
    # SDK compat: add snake_case aliases for camelCase properties (mcp>=1.0,<2.0).
    if not hasattr(result, "structured_content"):
        result.structured_content = normalized  # type: ignore[attr-defined]
    if not hasattr(result, "is_error"):
        result.is_error = normalized["result"]["status"] != "ok"  # type: ignore[attr-defined]
    return result


def _render_response_text(normalized: dict[str, Any], response_format: str | None) -> str:
    if response_format == MARKDOWN_RESPONSE_FORMAT:
        return _render_markdown(normalized)
    return json.dumps(normalized, sort_keys=True)


def _render_markdown(normalized: dict[str, Any]) -> str:
    result = normalized["result"]
    entities = normalized.get("entities") or {}
    pagination = entities.get("pagination")
    lines = [
        f"# {result['action']}",
        "",
        f"- status: {result['status']}",
        f"- ok: {str(result['ok']).lower()}",
    ]

    if pagination:
        lines.extend(
            [
                f"- count: {pagination['count']}",
                f"- total_count: {pagination['total_count']}",
                f"- limit: {pagination['limit']}",
                f"- offset: {pagination['offset']}",
                f"- has_more: {str(pagination['has_more']).lower()}",
                f"- next_offset: {pagination['next_offset']}",
            ]
        )

    lines.extend(["", "```json", json.dumps(normalized, indent=2, sort_keys=True), "```"])
    return "\n".join(lines)


def buildServerFromEnv() -> OcservAdminMcpServer:
    auth_token = os.environ.get("OCSERV_ADMIN_AUTH_TOKEN")
    if not auth_token:
        raise RuntimeError("OCSERV_ADMIN_AUTH_TOKEN_MISSING")
    client = BackendClient(
        base_url=os.environ.get("OCSERV_ADMIN_BACKEND_URL", "http://127.0.0.1:8080"),
        actor_id=os.environ.get("OCSERV_ADMIN_CLIENT_ACTOR_ID", "mcp-client"),
        auth_token=auth_token,
    )
    return OcservAdminMcpServer(client=client)


def main() -> int:
    setup_logging(level=os.environ.get("OCSERV_ADMIN_LOG_LEVEL", "INFO"))
    _logger.info("[MCP][main] starting ocserv-admin MCP server")
    server = buildServerFromEnv()
    import asyncio

    asyncio.run(server.run_stdio_async())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

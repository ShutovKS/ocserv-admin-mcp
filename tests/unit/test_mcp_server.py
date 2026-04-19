import asyncio
import json
import unittest
from typing import cast
from unittest.mock import patch

from src.backend_client import BackendClient
from src.mcp_server import OcservAdminMcpServer, _apply_list_pagination, _render_response_text


class _FakeTool:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class _FakeTextContent:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class _FakeCallToolResult:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class _FakeMCPServer:
    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version

    def run(self, transport: str = "stdio") -> None:
        self.transport = transport


class OcservAdminMcpServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._patchers = [
            patch("src.mcp_server._MCPServer", _FakeMCPServer),
            patch("src.mcp_server._Tool", _FakeTool),
            patch("src.mcp_server._ToolAnnotations", _FakeToolAnnotations),
            patch("src.mcp_server._TextContent", _FakeTextContent),
            patch("src.mcp_server._CallToolResult", _FakeCallToolResult),
        ]
        for patcher in self._patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def _server(self):
        client = BackendClient("http://127.0.0.1:18082", "mcp-client", "secret-token")
        return OcservAdminMcpServer(client=client)

    def test_list_tools_returns_strict_catalog_with_completed_annotations(self) -> None:
        server = self._server()
        tools = asyncio.run(server.list_tools())
        self.assertEqual(tools[0].name, "list_users")
        self.assertFalse(tools[0].input_schema["additionalProperties"])
        self.assertEqual(tools[0].annotations.read_only_hint, True)
        self.assertEqual(tools[0].annotations.idempotent_hint, True)
        self.assertNotIn("validate_config", [tool.name for tool in tools])
        self.assertIn("rollback_last_change", [tool.name for tool in tools])

    def test_call_tool_routes_to_backend_and_returns_json_structured_content(self) -> None:
        server = self._server()
        with patch.object(
            BackendClient,
            "execute",
            return_value={"ok": True, "users": [{"username": "alice"}]},
        ) as mocked:
            response = asyncio.run(server.call_tool("list_users", {}))
        mocked.assert_called_once_with("list_users", {})
        self.assertEqual(response.is_error, False)
        self.assertEqual(response.structured_content["result"]["status"], "ok")
        self.assertEqual(response.structured_content["entities"]["users"][0]["username"], "alice")
        self.assertEqual(json.loads(response.content[0].text)["result"]["action"], "list_users")

    def test_call_tool_supports_markdown_response_format(self) -> None:
        server = self._server()
        with patch.object(BackendClient, "execute", return_value={"ok": True, "users": [{"username": "alice"}]}) as mocked:
            response = asyncio.run(server.call_tool("list_users", {"response_format": "markdown"}))
        mocked.assert_called_once_with("list_users", {})
        self.assertIn("# list_users", response.content[0].text)
        self.assertIn("```json", response.content[0].text)
        self.assertEqual(response.structured_content["entities"]["users"][0]["username"], "alice")

    def test_call_tool_adds_pagination_for_list_users(self) -> None:
        server = self._server()
        with patch.object(
            BackendClient,
            "execute",
            return_value={
                "ok": True,
                "users": [{"username": "alice"}, {"username": "bob"}, {"username": "carol"}],
            },
        ):
            response = asyncio.run(server.call_tool("list_users", {"limit": 2, "offset": 1}))
        pagination = response.structured_content["entities"]["pagination"]
        self.assertEqual([user["username"] for user in response.structured_content["entities"]["users"]], ["bob", "carol"])
        self.assertEqual(pagination["limit"], 2)
        self.assertEqual(pagination["offset"], 1)
        self.assertEqual(pagination["count"], 2)
        self.assertEqual(pagination["total_count"], 3)
        self.assertEqual(pagination["has_more"], False)
        self.assertIsNone(pagination["next_offset"])

    def test_call_tool_surfaces_pending_confirmation(self) -> None:
        server = self._server()
        with patch.object(
            BackendClient,
            "execute",
            return_value={"ok": False, "status": "pending_confirmation", "token": "tok-1", "error_code": "CONFIRMATION_REQUIRED"},
        ):
            response = asyncio.run(server.call_tool("delete_user", {"username": "alice"}))
        self.assertEqual(response.is_error, True)
        self.assertEqual(response.structured_content["result"]["status"], "pending_confirmation")
        self.assertEqual(response.structured_content["entities"]["token"], "tok-1")

    def test_call_tool_rejects_invalid_payload(self) -> None:
        server = self._server()
        response = asyncio.run(server.call_tool("delete_user", {"username": "alice", "force": "yes"}))
        self.assertEqual(response.is_error, True)
        self.assertEqual(response.structured_content["actionable_error"]["code"], "INVALID_REQUEST:force")

    def test_call_tool_rejects_non_object_arguments(self) -> None:
        server = self._server()
        response = asyncio.run(server.call_tool("list_users", cast(dict[str, object], "bad-args")))
        self.assertEqual(response.is_error, True)
        self.assertEqual(response.structured_content["actionable_error"]["code"], "INVALID_REQUEST:arguments")

    def test_call_tool_rejects_invalid_response_format(self) -> None:
        server = self._server()
        response = asyncio.run(server.call_tool("list_users", {"response_format": "yaml"}))
        self.assertEqual(response.is_error, True)
        self.assertEqual(response.structured_content["actionable_error"]["code"], "INVALID_REQUEST:response_format")

    def test_call_tool_rejects_invalid_limit_type(self) -> None:
        server = self._server()
        response = asyncio.run(server.call_tool("list_users", {"limit": "10"}))
        self.assertEqual(response.is_error, True)
        self.assertEqual(response.structured_content["actionable_error"]["code"], "INVALID_REQUEST:limit")

    def test_call_tool_rejects_invalid_offset_value(self) -> None:
        server = self._server()
        response = asyncio.run(server.call_tool("list_users", {"offset": -1}))
        self.assertEqual(response.is_error, True)
        self.assertEqual(response.structured_content["actionable_error"]["code"], "INVALID_REQUEST:offset")

    def test_call_tool_normalizes_backend_transport_failure(self) -> None:
        server = self._server()
        with patch.object(BackendClient, "execute", return_value={"ok": False, "status": "failed", "error_code": "BACKEND_UNAVAILABLE"}) as mocked:
            response = asyncio.run(server.call_tool("list_users", {}))
        mocked.assert_called_once_with("list_users", {})
        self.assertEqual(response.is_error, True)
        self.assertEqual(response.structured_content["actionable_error"]["code"], "BACKEND_UNAVAILABLE")

    def test_apply_list_pagination_only_touches_list_actions(self) -> None:
        normalized = {"result": {"status": "ok", "action": "reload_service", "request_id": None, "ok": True}, "entities": {}, "reload": None, "actionable_error": None}
        self.assertEqual(_apply_list_pagination(normalized, "reload_service", limit=2, offset=0), normalized)

    def test_render_response_text_defaults_to_json(self) -> None:
        payload = {"result": {"status": "ok", "action": "list_users", "request_id": None, "ok": True}, "entities": {}, "reload": None, "actionable_error": None}
        self.assertEqual(json.loads(_render_response_text(payload, None))["result"]["action"], "list_users")


if __name__ == "__main__":
    unittest.main()

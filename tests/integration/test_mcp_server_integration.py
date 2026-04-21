import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from src.backend_client import BackendClient
from src.mcp_server import OcservAdminMcpServer
from src.ocserv_admin_api import AdminApiConfig, build_app
from src.ocserv_adapter import OcservPaths, SystemCommandResult


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


class _LocalAppClient(BackendClient):
    def __init__(self, app):
        super().__init__("http://127.0.0.1:18082", "mcp-client", "secret-token")
        self._app = app

    def execute(self, action: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        request_payload = payload or {}
        body = json.dumps(request_payload).encode("utf-8")
        status_holder: dict[str, Any] = {}

        def start_response(status, headers):
            status_holder["status"] = status
            status_holder["headers"] = headers

        from io import BytesIO

        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": f"/actions/{action}",
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": BytesIO(body),
            "HTTP_X_ACTOR_ID": "mcp-client",
            "HTTP_AUTHORIZATION": "Bearer secret-token",
            "REMOTE_ADDR": "127.0.0.1",
        }
        response = b"".join(self._app(environ, start_response))
        return json.loads(response.decode("utf-8"))


class OcservAdminMcpServerIntegrationTests(unittest.TestCase):
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

    def _config(self, temp_dir: str) -> AdminApiConfig:
        runtime = Path(temp_dir)
        (runtime / "groups.json").write_text(json.dumps({"groups": ["default", "admins"]}) + "\n", encoding="utf-8")
        return AdminApiConfig(
            host="127.0.0.1",
            port=8080,
            allowed_actors=("mcp-client",),
            auth_token="secret-token",
            paths=OcservPaths(runtime / "users.json", runtime / "groups.json", runtime / "audit.log", validate_command=("validate",), reload_command=("reload",)),
        )

    def _server(self, temp_dir: str) -> OcservAdminMcpServer:
        app = build_app(self._config(temp_dir))
        return OcservAdminMcpServer(client=_LocalAppClient(app))

    def _call(self, server: OcservAdminMcpServer, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        response = asyncio.run(server.call_tool(tool_name, arguments))
        return response.structured_content

    def test_tools_list_uses_group_enum_when_groups_available(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            "os.environ",
            {"OCSERV_ADMIN_GROUPS_FILE": str(Path(temp_dir) / "groups.json")},
            clear=False,
        ):
            server = self._server(temp_dir)
            tools = asyncio.run(server.list_tools())
            create_user = next(tool for tool in tools if tool.name == "create_user")
            self.assertEqual(create_user.input_schema["properties"]["group"]["enum"], ["default", "admins"])
            delete_group = next(tool for tool in tools if tool.name == "delete_group")
            self.assertEqual(delete_group.input_schema["properties"]["group"]["enum"], ["default", "admins"])

    def test_mvp_tools_execute_through_mcp_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            server = self._server(temp_dir)
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, '[{"username":"alice"}]', "", 0),
                    SystemCommandResult(True, '[{"name":"alice","ip":"10.0.0.1"}]', "", 0),
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "reloaded", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                ],
            ):
                created = self._call(server, "create_user", {"username": "alice", "group": "default"})
                listed = self._call(server, "list_users", {})
                sessions = self._call(server, "list_sessions", {})
                groups = self._call(server, "list_groups", {})
                reload_result = self._call(server, "reload_service", {})

            self.assertEqual(created["result"]["status"], "ok")
            self.assertEqual(created["entities"]["user"]["username"], "alice")
            self.assertEqual(listed["result"]["status"], "ok")
            self.assertEqual(listed["entities"]["users"][0]["username"], "alice")
            session_user = sessions["entities"]["sessions"][0].get("name") or sessions["entities"]["sessions"][0].get("username")
            self.assertEqual(session_user, "alice")
            self.assertIsNotNone(groups["entities"]["groups"])
            self.assertTrue(reload_result["reload"]["ok"])

    def test_list_sessions_markdown_and_pagination_are_applied_at_mcp_layer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            server = self._server(temp_dir)
            with patch(
                "src.ocserv_adapter._run_command",
                return_value=SystemCommandResult(
                    True,
                    json.dumps([
                        {"name": "alice", "ip": "10.0.0.1"},
                        {"name": "bob", "ip": "10.0.0.2"},
                        {"name": "carol", "ip": "10.0.0.3"},
                    ]),
                    "",
                    0,
                ),
            ):
                response = asyncio.run(server.call_tool("list_sessions", {"limit": 2, "offset": 1, "response_format": "markdown"}))

            self.assertIn("# list_sessions", response.content[0].text)
            self.assertEqual([item["name"] for item in response.structured_content["entities"]["sessions"]], ["bob", "carol"])
            self.assertEqual(response.structured_content["entities"]["pagination"]["total_count"], 3)
            self.assertEqual(response.structured_content["entities"]["pagination"]["count"], 2)

    def test_destructive_mcp_flow_requires_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            server = self._server(temp_dir)
            pending = self._call(server, "delete_user", {"username": "alice"})
            self.assertEqual(pending["result"]["status"], "pending_confirmation")
            self.assertIsNotNone(pending["entities"]["token"])

    def test_disallowed_payload_is_blocked_from_mcp_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            server = self._server(temp_dir)
            blocked = self._call(server, "delete_user", {"username": "alice", "force": "yes"})
            self.assertEqual(blocked["result"]["status"], "failed")
            self.assertEqual(blocked["actionable_error"]["code"], "INVALID_REQUEST:force")

    def test_invalid_pagination_arguments_are_blocked_at_mcp_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            server = self._server(temp_dir)
            blocked = self._call(server, "list_users", {"limit": "10", "offset": -1})
            self.assertEqual(blocked["result"]["status"], "failed")
            self.assertEqual(blocked["actionable_error"]["code"], "INVALID_REQUEST:limit")

    def test_backend_unavailable_is_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            server = OcservAdminMcpServer(client=BackendClient("http://127.0.0.1:18082", "mcp-client", "secret-token"))
            with patch.object(BackendClient, "execute", return_value={"ok": False, "status": "failed", "error_code": "BACKEND_UNAVAILABLE"}):
                response = asyncio.run(server.call_tool("list_users", {}))
            self.assertEqual(response.structured_content["result"]["status"], "failed")
            self.assertEqual(response.structured_content["actionable_error"]["code"], "BACKEND_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()

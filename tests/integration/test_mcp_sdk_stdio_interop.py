import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast


ROOT = Path(__file__).resolve().parents[2]


def _python_can_import_mcp() -> bool:
    command = [sys.executable, "-c", "import mcp"]
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True).returncode == 0


@unittest.skipUnless(_python_can_import_mcp(), "official mcp SDK is not installed in this environment")
class McpSdkStdioInteropTests(unittest.TestCase):
    def test_official_client_can_initialize_list_and_call(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = Path(temp_dir)
            backend_port = self._reserve_loopback_port()
            env = os.environ.copy()
            env.update(
                {
                    "PYTHONPATH": str(ROOT),
                    "OCSERV_ADMIN_AUTH_TOKEN": "secret-token",
                    "OCSERV_ADMIN_ALLOWED_ACTORS": "mcp-client",
                    "OCSERV_ADMIN_HOST": "127.0.0.1",
                    "OCSERV_ADMIN_PORT": str(backend_port),
                    "OCSERV_ADMIN_BACKEND_URL": f"http://127.0.0.1:{backend_port}",
                    "OCSERV_ADMIN_USERS_FILE": str(runtime / "users.json"),
                    "OCSERV_ADMIN_GROUPS_FILE": str(runtime / "groups.json"),
                    "OCSERV_ADMIN_AUDIT_LOG_FILE": str(runtime / "audit.log"),
                    "OCSERV_ADMIN_MAIN_CONFIG_FILE": str(runtime / "ocserv.conf"),
                    "OCSERV_ADMIN_GROUP_CONFIG_DIR": str(runtime / "groups.d"),
                    "OCSERV_ADMIN_MAIN_CONFIG_TEMPLATE": str(runtime / "templates" / "ocserv.conf.tpl"),
                    "OCSERV_ADMIN_GROUP_TEMPLATE_DIR": str(runtime / "group-templates"),
                    "OCSERV_ADMIN_USER_GROUP_MAP_FILE": str(runtime / "user-groups.json"),
                }
            )
            (runtime / "groups.json").write_text('{"groups": ["default", "admins"]}\n', encoding="utf-8")
            (runtime / "templates").mkdir(parents=True, exist_ok=True)
            (runtime / "groups.d").mkdir(parents=True, exist_ok=True)
            (runtime / "group-templates").mkdir(parents=True, exist_ok=True)

            backend = subprocess.Popen(
                [sys.executable, "-m", "src.ocserv_admin_api"],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self._wait_for_port(backend_port)
                script = """
import asyncio
import json
import os
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def main() -> None:
    server_params = StdioServerParameters(
        command=os.environ['PYTHON_BIN'],
        args=['-m', 'src.mcp_server'],
        env={
            'PYTHONPATH': os.environ['PYTHONPATH'],
            'OCSERV_ADMIN_AUTH_TOKEN': os.environ['OCSERV_ADMIN_AUTH_TOKEN'],
            'OCSERV_ADMIN_BACKEND_URL': os.environ['OCSERV_ADMIN_BACKEND_URL'],
            'OCSERV_ADMIN_CLIENT_ACTOR_ID': 'mcp-client',
            'OCSERV_ADMIN_GROUPS_FILE': os.environ['OCSERV_ADMIN_GROUPS_FILE'],
        },
        cwd=os.environ['PROJECT_ROOT'],
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            init_result = await session.initialize()
            tools = await session.list_tools()
            tool_names = [tool.name for tool in tools.tools]
            list_users = await session.call_tool('list_users', {'response_format': 'markdown', 'limit': 1, 'offset': 0})
            payload = {
                'protocol_version': init_result.protocolVersion,
                'tool_names': tool_names,
                'text': list_users.content[0].text,
                'structured': list_users.structured_content,
            }
            print(json.dumps(payload, sort_keys=True))


asyncio.run(main())
"""
                client_env = env | {"PYTHON_BIN": sys.executable, "PROJECT_ROOT": str(ROOT)}
                result = subprocess.run(
                    [sys.executable, "-c", script],
                    cwd=ROOT,
                    env=client_env,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, msg=result.stderr)
                payload = self._parse_last_json_line(result.stdout)
                tool_names = cast(list[str], payload["tool_names"])
                text = cast(str, payload["text"])
                structured = cast(dict[str, Any], payload["structured"])
                self.assertIn("list_users", tool_names)
                self.assertIn("confirm_action", tool_names)
                self.assertNotIn("validate_config", tool_names)
                self.assertIn("# list_users", text)
                self.assertEqual(structured["result"]["action"], "list_users")
                self.assertIn("pagination", structured["entities"])
            finally:
                backend.terminate()
                try:
                    backend.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    backend.kill()

    def _wait_for_port(self, port: int) -> None:
        import time

        deadline = time.time() + 10
        while time.time() < deadline:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.2)
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    return
            time.sleep(0.1)
        self.fail(f"backend port {port} did not become ready")

    def _reserve_loopback_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            sock.listen(1)
            return cast(int, sock.getsockname()[1])

    def _parse_last_json_line(self, stdout: str) -> dict[str, Any]:
        for line in reversed([item.strip() for item in stdout.splitlines() if item.strip()]):
            if line.startswith("{"):
                import json

                return json.loads(line)
        self.fail(f"no JSON payload found in stdout: {stdout}")


if __name__ == "__main__":
    unittest.main()

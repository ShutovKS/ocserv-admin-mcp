import json
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from typing import Any
from unittest.mock import patch

from src.ocserv_admin_api import DEFAULT_GROUP_CONFIG_DIR, DEFAULT_MAIN_CONFIG_FILE, DEFAULT_USERS_FILE, AdminApiConfig, build_app, build_config_from_env
from src.ocserv_adapter import OcservPaths, SystemCommandResult


class OcservAdminApiTests(unittest.TestCase):
    def test_build_config_from_env_uses_service_writable_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            "os.environ",
            {
                "OCSERV_ADMIN_AUTH_TOKEN": "secret-token",
                "OCSERV_ADMIN_ALLOWED_ACTORS": "mcp-client",
                "OCSERV_ADMIN_RUNTIME_DIR": temp_dir,
                "OCSERV_ADMIN_USERS_FILE": str(Path(temp_dir) / "users.json"),
                "OCSERV_ADMIN_GROUPS_FILE": str(Path(temp_dir) / "groups.json"),
                "OCSERV_ADMIN_AUDIT_LOG_FILE": str(Path(temp_dir) / "audit.log"),
                "OCSERV_ADMIN_MAIN_CONFIG_FILE": str(Path(temp_dir) / "ocserv.conf"),
                "OCSERV_ADMIN_GROUP_CONFIG_DIR": str(Path(temp_dir) / "groups.d"),
                "OCSERV_ADMIN_MAIN_CONFIG_TEMPLATE": str(Path(temp_dir) / "templates" / "ocserv.conf.tpl"),
                "OCSERV_ADMIN_GROUP_TEMPLATE_DIR": str(Path(temp_dir) / "group-templates"),
                "OCSERV_ADMIN_USER_GROUP_MAP_FILE": str(Path(temp_dir) / "user-groups.json"),
            },
            clear=False,
        ):
            config = build_config_from_env()

        self.assertEqual(config.paths.users_file, Path(temp_dir) / "users.json")
        self.assertEqual(config.paths.groups_file, Path(temp_dir) / "groups.json")
        self.assertEqual(config.paths.audit_log_file, Path(temp_dir) / "audit.log")

    def test_build_config_from_env_production_defaults_target_real_ocserv_paths(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "OCSERV_ADMIN_AUTH_TOKEN": "secret-token",
                "OCSERV_ADMIN_ALLOWED_ACTORS": "mcp-client",
                "OCSERV_ADMIN_RUNTIME_DIR": "/var/lib/ocserv-admin",
            },
            clear=True,
        ), patch("pathlib.Path.mkdir"), patch("pathlib.Path.write_text"):
            config = build_config_from_env()

        self.assertEqual(config.paths.users_file, DEFAULT_USERS_FILE)
        self.assertEqual(config.paths.main_config_file, DEFAULT_MAIN_CONFIG_FILE)
        self.assertEqual(config.paths.group_config_dir, DEFAULT_GROUP_CONFIG_DIR)
        self.assertEqual(config.paths.validate_command, ("/usr/sbin/ocserv", "--test-config", "--config", "/etc/ocserv/ocserv.conf"))

    def test_build_config_from_env_requires_auth_token(self) -> None:
        with patch.dict("os.environ", {}, clear=True), patch("pathlib.Path.mkdir"), patch("pathlib.Path.write_text"):
            with self.assertRaisesRegex(RuntimeError, "OCSERV_ADMIN_AUTH_TOKEN_MISSING"):
                build_config_from_env()

    def _config(self, temp_dir: str) -> AdminApiConfig:
        runtime = Path(temp_dir)
        (runtime / "groups.json").write_text(json.dumps({"groups": ["default", "admins"]}) + "\n", encoding="utf-8")
        return AdminApiConfig(
            host="127.0.0.1",
            port=8080,
            allowed_actors=("admin",),
            auth_token="secret-token",
            paths=OcservPaths(runtime / "users.json", runtime / "groups.json", runtime / "audit.log", validate_command=("validate",), reload_command=("reload",)),
        )

    def _request(self, app, path: str, payload: dict[str, object], actor_id: str = "admin", token: str = "secret-token") -> tuple[str, dict[str, Any]]:
        status_holder: dict[str, Any] = {}

        def start_response(status, headers):
            status_holder["status"] = status
            status_holder["headers"] = headers

        body = json.dumps(payload).encode("utf-8")
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": BytesIO(body),
            "HTTP_X_ACTOR_ID": actor_id,
            "HTTP_AUTHORIZATION": f"Bearer {token}",
            "REMOTE_ADDR": "127.0.0.1",
        }
        response = b"".join(app(environ, start_response))
        return status_holder["status"], json.loads(response.decode("utf-8"))

    def test_rejects_bad_client_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = self._config(temp_dir)
            app = build_app(config)
            status, payload = self._request(app, "/actions/list_users", {}, token="wrong-token")
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(payload["error_code"], "UNAUTHORIZED_CLIENT")

    def test_create_user_endpoint_returns_deterministic_activation_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = self._config(temp_dir)
            template_dir = Path(temp_dir) / "group-templates"
            template_dir.mkdir(parents=True, exist_ok=True)
            (template_dir / "default.conf.tpl").write_text(
                "# default\nipv4-network = 10.10.0.0/24\nipv4-netmask = 255.255.255.0\n",
                encoding="utf-8",
            )
            app = build_app(config)
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, '[{"username":"alice"}]', "", 0),
                ],
            ):
                status, payload = self._request(app, "/actions/create_user", {"username": "alice", "group": "default", "ipv4_address": "10.10.0.10"})
            self.assertEqual(status, "200 OK")
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["user"]["username"], "alice")
            self.assertEqual(payload["user"]["ipv4_address"], "10.10.0.10")
            self.assertIn(str(Path(temp_dir) / "user-groups.json"), payload["changed_files"])
            self.assertIn(str(Path(temp_dir) / "config-per-user" / "alice"), payload["changed_files"])
            self.assertIn(str(Path(temp_dir) / "templates" / "ocserv.conf.tpl"), payload["planned_files"])
            self.assertTrue(payload["verification"]["ok"])
            self.assertTrue(payload["activation"]["ok"])
            self.assertEqual(payload["activation"]["activation_mode"], "restart")
            self.assertIsNone(payload["provisioning"])

    def test_create_user_plain_backend_returns_one_time_password(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = Path(temp_dir)
            groups_file = runtime / "groups.json"
            groups_file.write_text(json.dumps({"groups": ["default"]}) + "\n", encoding="utf-8")
            config = AdminApiConfig(
                host="127.0.0.1",
                port=8080,
                allowed_actors=("admin",),
                auth_token="secret-token",
                paths=OcservPaths(runtime / "passwd", groups_file, runtime / "audit.log", command_prefix=(), validate_command=("validate",), reload_command=("reload",)),
            )
            app = build_app(config)

            def fake_run(command, input, capture_output, text, check, **kwargs):
                (runtime / "passwd").write_text("alice:default:hashed-password\n", encoding="utf-8")
                return type("Completed", (), {"returncode": 0})()

            with patch("subprocess.run", side_effect=fake_run), patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, '[{"username":"alice"}]', "", 0),
                ],
            ):
                status, payload = self._request(app, "/actions/create_user", {"username": "alice", "group": "default"})

            self.assertEqual(status, "200 OK")
            self.assertEqual(payload["user"]["username"], "alice")
            self.assertIn("one_time_password", payload["provisioning"])

    def test_delete_user_requires_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = self._config(temp_dir)
            app = build_app(config)
            status, payload = self._request(app, "/actions/delete_user", {"username": "alice"})
            self.assertEqual(status, "200 OK")
            self.assertEqual(payload["status"], "pending_confirmation")
            self.assertIn("token", payload)

    def test_confirm_action_executes_original_delete(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = self._config(temp_dir)
            app = build_app(config)
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, '[{"username":"alice"}]', "", 0),
                    SystemCommandResult(True, "[]", "", 0),
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "reloaded", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, "[]", "", 0),
                ],
            ):
                create_status, _ = self._request(app, "/actions/create_user", {"username": "alice", "group": "default"})
                self.assertEqual(create_status, "200 OK")
                pending_status, pending_payload = self._request(app, "/actions/delete_user", {"username": "alice", "force": True})
                self.assertEqual(pending_status, "200 OK")
                confirm_status, confirm_payload = self._request(app, "/actions/confirm_action", {"token": pending_payload["token"], "decision": "confirm", "expected_action": "delete_user", "expected_username": pending_payload["confirmation"]["target_user"]})
            self.assertEqual(confirm_status, "200 OK")
            self.assertTrue(confirm_payload["ok"])
            users_status, users_payload = self._request(app, "/actions/list_users", {})
            self.assertEqual(users_status, "200 OK")
            self.assertEqual(users_payload["users"], [])

    def test_confirm_action_rejects_context_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = self._config(temp_dir)
            app = build_app(config)
            pending_status, pending_payload = self._request(app, "/actions/delete_user", {"username": "alice"})
            self.assertEqual(pending_status, "200 OK")
            confirm_status, confirm_payload = self._request(app, "/actions/confirm_action", {"token": pending_payload["token"], "decision": "confirm", "expected_action": "disable_user"})
            self.assertEqual(confirm_status, "400 Bad Request")
            self.assertEqual(confirm_payload["error_code"], "INVALID_CONFIRMATION_CONTEXT")

    def test_create_user_rejects_unknown_group(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = self._config(temp_dir)
            app = build_app(config)
            status, payload = self._request(app, "/actions/create_user", {"username": "alice", "group": "unknown"})
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(payload["error_code"], "GROUP_NOT_FOUND")

    def test_assign_group_and_disable_user_require_confirmation_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = self._config(temp_dir)
            app = build_app(config)
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, '[{"username":"alice"}]', "", 0),
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, '[{"username":"alice","group":"admins"}]', "", 0),
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "reloaded", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                ],
            ):
                self._request(app, "/actions/create_user", {"username": "alice", "group": "default"})
                pending_status, pending_payload = self._request(app, "/actions/assign_group", {"username": "alice", "group": "admins"})
                assign_status, assign_payload = self._request(app, "/actions/confirm_action", {"token": pending_payload["token"], "decision": "confirm"})
                disable_pending_status, disable_pending_payload = self._request(app, "/actions/disable_user", {"username": "alice"})
                disable_status, disable_payload = self._request(app, "/actions/confirm_action", {"token": disable_pending_payload["token"], "decision": "confirm"})
            self.assertEqual(pending_status, "200 OK")
            self.assertEqual(pending_payload["status"], "pending_confirmation")
            self.assertEqual(assign_status, "200 OK")
            self.assertEqual(assign_payload["executed"]["user"]["group"], "admins")
            self.assertTrue(assign_payload["executed"]["verification"]["ok"])
            self.assertEqual(disable_pending_status, "200 OK")
            self.assertEqual(disable_pending_payload["status"], "pending_confirmation")
            self.assertEqual(disable_status, "200 OK")
            self.assertEqual(disable_payload["executed"]["user"]["disabled"], True)

    def test_destructive_action_rejects_direct_confirmed_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = self._config(temp_dir)
            app = build_app(config)
            status, payload = self._request(app, "/actions/disable_user", {"username": "alice", "confirmed": True})
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(payload["error_code"], "INVALID_REQUEST:confirmed")

    def test_delete_user_rejects_non_boolean_force(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = self._config(temp_dir)
            app = build_app(config)
            status, payload = self._request(app, "/actions/delete_user", {"username": "alice", "force": "yes"})
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(payload["error_code"], "INVALID_REQUEST:force")

    def test_list_sessions_and_reload_service(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = self._config(temp_dir)
            app = build_app(config)
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, '[{"name":"alice","ip":"10.0.0.1"}]', "", 0),
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "reloaded", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                ],
            ):
                sessions_status, sessions_payload = self._request(app, "/actions/list_sessions", {})
                reload_status, reload_payload = self._request(app, "/actions/reload_service", {})
            self.assertEqual(sessions_status, "200 OK")
            self.assertEqual(sessions_payload["sessions"][0]["name"], "alice")
            self.assertEqual(reload_status, "200 OK")
            self.assertTrue(reload_payload["reload"]["ok"])
            self.assertTrue(reload_payload["reload"]["health"]["ok"])

    def test_list_groups_and_show_user_ips(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = Path(temp_dir)
            (runtime / "groups.json").write_text(json.dumps({"groups": ["default", "admins"]}) + "\n", encoding="utf-8")
            (runtime / "groups.d").mkdir(exist_ok=True)
            (runtime / "groups.d" / "admins.conf").write_text("ipv4-network = 10.66.99.0/24\nipv4-netmask = 255.255.255.0\nroute = 10.66.99.0/255.255.255.0\n", encoding="utf-8")
            config = AdminApiConfig(
                host="127.0.0.1",
                port=8080,
                allowed_actors=("admin",),
                auth_token="secret-token",
                paths=OcservPaths(runtime / "users.json", runtime / "groups.json", runtime / "audit.log", validate_command=("validate",), reload_command=("reload",), group_config_dir=runtime / "groups.d"),
            )
            app = build_app(config)
            with patch("src.ocserv_adapter._run_command", return_value=SystemCommandResult(True, '[{"username":"alice","ip":"10.0.0.1","group":"admins"}]', "", 0)):
                groups_status, groups_payload = self._request(app, "/actions/list_groups", {})
                user_ips_status, user_ips_payload = self._request(app, "/actions/show_user_ips", {})
            self.assertEqual(groups_status, "200 OK")
            admins_group = next(group for group in groups_payload["groups"] if group["group"] == "admins")
            self.assertEqual(admins_group["ipv4_network"], "10.66.99.0/24")
            self.assertEqual(user_ips_status, "200 OK")
            self.assertEqual(user_ips_payload["user_ips"][0]["ip"], "10.0.0.1")

    def test_rollback_last_change_requires_confirmation_then_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = self._config(temp_dir)
            app = build_app(config)
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, '[{"username":"alice"}]', "", 0),
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                ],
            ):
                self._request(app, "/actions/create_user", {"username": "alice", "group": "default"})
                pending_status, pending_payload = self._request(app, "/actions/rollback_last_change", {})
                confirm_status, confirm_payload = self._request(app, "/actions/confirm_action", {"token": pending_payload["token"], "decision": "confirm"})
            self.assertEqual(pending_status, "200 OK")
            self.assertEqual(pending_payload["status"], "pending_confirmation")
            self.assertEqual(confirm_status, "200 OK")
            self.assertTrue(confirm_payload["ok"])
            self.assertEqual(confirm_payload["executed"]["rollback"]["rolled_back_action"], "create_user")

    def test_health_endpoint_reports_ocserv_health(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = self._config(temp_dir)
            app = build_app(config)
            status_holder: dict[str, Any] = {}

            def start_response(status, headers):
                status_holder["status"] = status
                status_holder["headers"] = headers

            environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/health", "REMOTE_ADDR": "127.0.0.1", "wsgi.input": BytesIO(b""), "CONTENT_LENGTH": "0"}
            with patch("src.ocserv_adapter._run_command", return_value=SystemCommandResult(True, "active", "", 0)):
                response = b"".join(app(environ, start_response))

            payload = json.loads(response.decode("utf-8"))
            self.assertEqual(status_holder["status"], "200 OK")
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["ocserv"]["stdout"], "active")

    def test_disconnect_session_requires_confirmation_then_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = self._config(temp_dir)
            app = build_app(config)
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, "disconnected", "", 0),
                ],
            ):
                pending_status, pending_payload = self._request(app, "/actions/disconnect_session", {"username": "alice"})
                confirm_status, confirm_payload = self._request(app, "/actions/confirm_action", {"token": pending_payload["token"], "decision": "confirm"})
            self.assertEqual(pending_status, "200 OK")
            self.assertEqual(pending_payload["status"], "pending_confirmation")
            self.assertEqual(confirm_status, "200 OK")
            self.assertTrue(confirm_payload["ok"])
            self.assertTrue(confirm_payload["executed"]["disconnect"]["ok"])


    def test_create_group_and_delete_group_full_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = self._config(temp_dir)
            app = build_app(config)
            status, payload = self._request(app, "/actions/create_group", {"group": "vpn-users", "ipv4_network": "10.10.0.0/24", "ipv4_netmask": "255.255.255.0", "routes": ["10.0.0.0/8"]})
            self.assertEqual(status, "200 OK")
            self.assertEqual(payload["group"], "vpn-users")
            groups = json.loads(config.paths.groups_file.read_text(encoding="utf-8"))
            self.assertIn("vpn-users", groups["groups"])
            pending_status, pending_payload = self._request(app, "/actions/delete_group", {"group": "vpn-users"})
            self.assertEqual(pending_status, "200 OK")
            self.assertEqual(pending_payload["status"], "pending_confirmation")
            confirm_status, confirm_payload = self._request(app, "/actions/confirm_action", {"token": pending_payload["token"], "decision": "confirm"})
            self.assertEqual(confirm_status, "200 OK")
            self.assertTrue(confirm_payload["ok"])
            groups_after = json.loads(config.paths.groups_file.read_text(encoding="utf-8"))
            self.assertNotIn("vpn-users", groups_after["groups"])

    def test_disable_group_users_full_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = self._config(temp_dir)
            app = build_app(config)
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, '[{"username":"alice"}]', "", 0),
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, '[{"username":"bob"}]', "", 0),
                ],
            ):
                self._request(app, "/actions/create_user", {"username": "alice", "group": "default"})
                self._request(app, "/actions/create_user", {"username": "bob", "group": "default"})
            pending_status, pending_payload = self._request(app, "/actions/disable_group_users", {"group": "default"})
            self.assertEqual(pending_status, "200 OK")
            self.assertEqual(pending_payload["status"], "pending_confirmation")
            confirm_status, confirm_payload = self._request(app, "/actions/confirm_action", {"token": pending_payload["token"], "decision": "confirm"})
            self.assertEqual(confirm_status, "200 OK")
            self.assertTrue(confirm_payload["ok"])
            self.assertEqual(len(confirm_payload["executed"]["affected_users"]), 2)

    def test_update_user_ip_full_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = self._config(temp_dir)
            template_dir = Path(temp_dir) / "group-templates"
            template_dir.mkdir(parents=True, exist_ok=True)
            (template_dir / "default.conf.tpl").write_text(
                "# default\nipv4-network = 10.10.0.0/24\nipv4-netmask = 255.255.255.0\n",
                encoding="utf-8",
            )
            app = build_app(config)
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, '[{"username":"alice"}]', "", 0),
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, '[{"username":"alice"}]', "", 0),
                ],
            ):
                self._request(app, "/actions/create_user", {"username": "alice", "group": "default", "ipv4_address": "10.10.0.10"})
                status, payload = self._request(app, "/actions/update_user_ip", {"username": "alice", "ipv4_address": "10.10.0.20"})
            self.assertEqual(status, "200 OK")
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["user"]["ipv4_address"], "10.10.0.20")
            per_user_config = (Path(temp_dir) / "config-per-user" / "alice").read_text(encoding="utf-8")
            self.assertIn("10.10.0.20", per_user_config)

    def test_rollback_last_change_full_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = self._config(temp_dir)
            app = build_app(config)
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, '[{"username":"alice"}]', "", 0),
                ],
            ):
                self._request(app, "/actions/create_user", {"username": "alice", "group": "default"})
            users_before_rollback = json.loads(config.paths.users_file.read_text(encoding="utf-8"))
            self.assertEqual(len(users_before_rollback["users"]), 1)
            pending_status, pending_payload = self._request(app, "/actions/rollback_last_change", {})
            self.assertEqual(pending_status, "200 OK")
            self.assertEqual(pending_payload["status"], "pending_confirmation")
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                ],
            ):
                confirm_status, confirm_payload = self._request(app, "/actions/confirm_action", {"token": pending_payload["token"], "decision": "confirm"})
            self.assertEqual(confirm_status, "200 OK")
            self.assertTrue(confirm_payload["ok"])
            if config.paths.users_file.exists():
                users_after_rollback = json.loads(config.paths.users_file.read_text(encoding="utf-8"))
                self.assertEqual(len(users_after_rollback["users"]), 0)
            else:
                pass  # file was removed by rollback (pre-creation state)


if __name__ == "__main__":
    unittest.main()

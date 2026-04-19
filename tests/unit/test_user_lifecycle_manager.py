import tempfile
import unittest
from pathlib import Path
from typing import cast
from unittest.mock import patch

from src.audit_log import AuditSink
from src.ocserv_adapter import OcservPaths, SystemCommandResult
from src.safety_controls import GuardDecision
from src.user_lifecycle_manager import createUser, disableUser, listUsers, removeUser


class UserLifecycleManagerTests(unittest.TestCase):
    def _paths(self, temp_dir: str) -> OcservPaths:
        runtime = Path(temp_dir)
        (runtime / "groups.json").write_text('{"groups":["default"]}\n', encoding="utf-8")
        return OcservPaths(runtime / "users.json", runtime / "groups.json", runtime / "audit.log")

    def test_create_disable_remove_user(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._paths(temp_dir)
            sink = AuditSink(paths.audit_log_file)
            allowed = GuardDecision(True, False)
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, '[{"username":"alice"}]', "", 0),
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "reloaded", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "reloaded", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, "[]", "", 0),
                ],
            ):
                created = createUser(paths, "alice", "default", allowed, sink, "req-1", "admin")
                disabled = disableUser(paths, "alice", allowed, sink, "req-2", "admin")
                removed = removeUser(paths, "alice", allowed, sink, "req-3", "admin", force=True)
            created_user = cast(dict[str, object], created["user"])
            disabled_user = cast(dict[str, object], disabled["user"])
            removed_user = cast(dict[str, object], removed["user"])
            created_activation = cast(dict[str, object], created["activation"])
            self.assertEqual(created_user["username"], "alice")
            self.assertIsNone(created["provisioning"])
            self.assertTrue(disabled_user["disabled"])
            self.assertEqual(removed_user["username"], "alice")
            self.assertEqual(created_activation["activation_mode"], "restart")
            self.assertEqual(listUsers(paths), [])

    def test_create_user_returns_one_time_password_for_plain_backend(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = Path(temp_dir)
            groups_file = runtime / "groups.json"
            groups_file.write_text('{"groups":["default"]}\n', encoding="utf-8")
            passwd_file = runtime / "passwd"
            paths = OcservPaths(passwd_file, groups_file, runtime / "audit.log", command_prefix=())
            sink = AuditSink(paths.audit_log_file)
            allowed = GuardDecision(True, False)

            def fake_run(command, input, capture_output, text, check):
                passwd_file.write_text("alice:default:hashed-password\n", encoding="utf-8")
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
                created = createUser(paths, "alice", "default", allowed, sink, "req-1", "admin")

            provisioning = cast(dict[str, str], created["provisioning"])
            self.assertEqual(cast(dict[str, object], created["user"])["username"], "alice")
            self.assertIn("one_time_password", provisioning)

    def test_remove_user_requires_force_when_active(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._paths(temp_dir)
            sink = AuditSink(paths.audit_log_file)
            allowed = GuardDecision(True, False)
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, '[{"username":"alice"}]', "", 0),
                    SystemCommandResult(True, '[{"username":"alice"}]', "", 0),
                ],
            ):
                createUser(paths, "alice", "default", allowed, sink, "req-1", "admin")
                with self.assertRaisesRegex(ValueError, "ACTIVE_USER_REQUIRES_FORCE"):
                    removeUser(paths, "alice", allowed, sink, "req-2", "admin")


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.ocserv_adapter import OcservPaths, SystemCommandResult
from src.session_manager import disconnectSessionForUser, listSessions


class SessionManagerTests(unittest.TestCase):
    def test_list_sessions_returns_structured_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = Path(temp_dir)
            (runtime / "groups.json").write_text('{"groups":["default"]}\n', encoding="utf-8")
            paths = OcservPaths(runtime / "users.json", runtime / "groups.json", runtime / "audit.log")
            with patch("src.session_manager.runOcctl", return_value=[{"name": "alice", "ip": "10.0.0.1"}]):
                sessions = listSessions(paths, None, "req-1", "admin")
            self.assertEqual(sessions[0]["name"], "alice")

    def test_disconnect_session_returns_structured_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = Path(temp_dir)
            (runtime / "groups.json").write_text('{"groups":["default"]}\n', encoding="utf-8")
            paths = OcservPaths(runtime / "users.json", runtime / "groups.json", runtime / "audit.log")
            with patch("src.session_manager.disconnectSession", return_value=SystemCommandResult(True, "disconnected", "", 0)):
                result = disconnectSessionForUser(paths, "alice", None, "req-2", "admin")
            user = result["user"]
            disconnect = result["disconnect"]
            self.assertIsInstance(user, dict)
            self.assertIsInstance(disconnect, dict)
            if not isinstance(user, dict) or not isinstance(disconnect, dict):
                self.fail("disconnectSessionForUser should return structured dictionaries")
            self.assertEqual(user["username"], "alice")
            self.assertTrue(disconnect["ok"])


    def test_disconnect_session_raises_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = Path(temp_dir)
            (runtime / "groups.json").write_text('{"groups":["default"]}\n', encoding="utf-8")
            paths = OcservPaths(runtime / "users.json", runtime / "groups.json", runtime / "audit.log")
            with patch("src.session_manager.disconnectSession", return_value=SystemCommandResult(False, "", "disconnect failed", 1)):
                with self.assertRaisesRegex(ValueError, "SESSION_DISCONNECT_FAILED"):
                    disconnectSessionForUser(paths, "alice", None, "req-2", "admin")

    def test_list_sessions_handles_empty_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = Path(temp_dir)
            (runtime / "groups.json").write_text('{"groups":["default"]}\n', encoding="utf-8")
            paths = OcservPaths(runtime / "users.json", runtime / "groups.json", runtime / "audit.log")
            with patch("src.session_manager.runOcctl", return_value=[]):
                sessions = listSessions(paths, None, "req-1", "admin")
            self.assertEqual(sessions, [])


if __name__ == "__main__":
    unittest.main()

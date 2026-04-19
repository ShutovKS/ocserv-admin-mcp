import json
import tempfile
import unittest
from pathlib import Path
from typing import cast
from unittest.mock import patch

from src.ocserv_adapter import OcservPaths, SystemCommandResult, createUserRecord
from src.policy_group_manager import assignGroup, renderPolicyChanges


class PolicyGroupManagerTests(unittest.TestCase):
    def test_render_and_assign_group(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = Path(temp_dir)
            (runtime / "groups.json").write_text(json.dumps({"groups": ["default", "admins"]}) + "\n", encoding="utf-8")
            paths = OcservPaths(runtime / "users.json", runtime / "groups.json", runtime / "audit.log")
            createUserRecord(paths, "alice", "default")
            preview = renderPolicyChanges(paths, "alice", "admins")
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                    SystemCommandResult(True, '[{"username":"alice","group":"admins"}]', "", 0),
                ],
            ):
                updated = assignGroup(paths, "alice", "admins", None, "req-1", "admin")
            updated_user = cast(dict[str, object], updated["user"])
            changed_files = cast(list[str], updated["changed_files"])
            verification = cast(dict[str, object], updated["verification"])
            self.assertEqual(preview["scope"], "single-user-group-update")
            self.assertEqual(updated_user["group"], "admins")
            self.assertIn(str(runtime / "user-groups.json"), changed_files)
            self.assertTrue(verification["ok"])


if __name__ == "__main__":
    unittest.main()

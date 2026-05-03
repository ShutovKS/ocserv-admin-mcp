import json
import tempfile
import unittest
from pathlib import Path
from typing import cast
from unittest.mock import patch

from src.ocserv_adapter import OcservPaths, SystemCommandResult, createUserRecord, disableUserRecord
from src.policy_group_manager import assignGroup, createGroup, deleteGroup, disableUsersInGroup, renderPolicyChanges
from src.safety_controls import GuardDecision


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


    def test_create_group_persists_template_and_registry(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = Path(temp_dir)
            (runtime / "groups.json").write_text(json.dumps({"groups": ["default"]}) + "\n", encoding="utf-8")
            paths = OcservPaths(runtime / "users.json", runtime / "groups.json", runtime / "audit.log")
            result = createGroup(paths, "vpn-users", "10.10.0.0/24", "255.255.255.0", ["10.0.0.0/8"], None, "req-1", "admin")
            self.assertEqual(result["group"], "vpn-users")
            groups = json.loads(paths.groups_file.read_text(encoding="utf-8"))
            self.assertIn("vpn-users", groups["groups"])
            template = (runtime / "group-templates" / "vpn-users.conf.tpl").read_text(encoding="utf-8")
            self.assertIn("ipv4-network = 10.10.0.0/24", template)

    def test_delete_group_rejects_protected_groups(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = Path(temp_dir)
            (runtime / "groups.json").write_text(json.dumps({"groups": ["default", "admins"]}) + "\n", encoding="utf-8")
            paths = OcservPaths(runtime / "users.json", runtime / "groups.json", runtime / "audit.log")
            allowed = GuardDecision(allowed=True, requires_confirmation=False)
            with self.assertRaisesRegex(ValueError, "PROTECTED_GROUP"):
                deleteGroup(paths, "default", allowed, None, "req-1", "admin")

    def test_delete_group_rejects_group_in_use(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = Path(temp_dir)
            (runtime / "groups.json").write_text(json.dumps({"groups": ["default", "test-group"]}) + "\n", encoding="utf-8")
            paths = OcservPaths(runtime / "users.json", runtime / "groups.json", runtime / "audit.log")
            createUserRecord(paths, "alice", "test-group")
            allowed = GuardDecision(allowed=True, requires_confirmation=False)
            with self.assertRaisesRegex(ValueError, "GROUP_IN_USE"):
                deleteGroup(paths, "test-group", allowed, None, "req-1", "admin")

    def test_disable_users_in_group_disables_only_target_group(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = Path(temp_dir)
            (runtime / "groups.json").write_text(json.dumps({"groups": ["default", "admins"]}) + "\n", encoding="utf-8")
            paths = OcservPaths(runtime / "users.json", runtime / "groups.json", runtime / "audit.log")
            createUserRecord(paths, "alice", "default")
            createUserRecord(paths, "bob", "admins")
            createUserRecord(paths, "charlie", "default")
            allowed = GuardDecision(allowed=True, requires_confirmation=False)
            result = disableUsersInGroup(paths, "default", allowed, None, "req-1", "admin")
            self.assertEqual(len(result["affected_users"]), 2)
            affected_names = {u["username"] for u in result["affected_users"]}
            self.assertIn("alice", affected_names)
            self.assertIn("charlie", affected_names)
            self.assertNotIn("bob", affected_names)

    def test_disable_users_in_group_skips_already_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = Path(temp_dir)
            (runtime / "groups.json").write_text(json.dumps({"groups": ["default"]}) + "\n", encoding="utf-8")
            paths = OcservPaths(runtime / "users.json", runtime / "groups.json", runtime / "audit.log")
            createUserRecord(paths, "alice", "default")
            createUserRecord(paths, "bob", "default")
            disableUserRecord(paths, "alice")
            allowed = GuardDecision(allowed=True, requires_confirmation=False)
            result = disableUsersInGroup(paths, "default", allowed, None, "req-1", "admin")
            self.assertEqual(len(result["affected_users"]), 1)
            self.assertEqual(result["affected_users"][0]["username"], "bob")


if __name__ == "__main__":
    unittest.main()

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.ocserv_adapter import (
    OcservPaths,
    SystemCommandResult,
    activateService,
    applyManagedMutation,
    assignGroupRecord,
    createUserRecord,
    disconnectSession,
    disableUserRecord,
    healthCheck,
    inventoryConfig,
    preflightMutation,
    rollbackLastChange,
    runOcctl,
    safeReload,
)


class OcservAdapterTests(unittest.TestCase):
    def _make_paths(self, temp_dir: str) -> OcservPaths:
        runtime = Path(temp_dir)
        groups_file = runtime / "groups.json"
        groups_file.write_text(json.dumps({"groups": ["default", "admins"]}) + "\n", encoding="utf-8")
        return OcservPaths(
            users_file=runtime / "users.json",
            groups_file=groups_file,
            audit_log_file=runtime / "audit.log",
            command_prefix=("sudo", "-n"),
            validate_command=("validate",),
            reload_command=("reload",),
        )

    def test_inventory_reports_managed_files_and_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            createUserRecord(paths, "alice", "default")
            inventory = inventoryConfig(paths)
            self.assertIn(str(paths.users_file), inventory["managed_files"])
            self.assertIn(str(Path(temp_dir) / "user-groups.json"), inventory["managed_files"])
            self.assertIn(str(Path(temp_dir) / "templates" / "ocserv.conf.tpl"), inventory["managed_files"])
            self.assertIn(str(Path(temp_dir) / "group-templates" / "default.conf.tpl"), inventory["managed_files"])
            self.assertIn("default", inventory["allowed_groups"])
            self.assertEqual(inventory["user_group_assignments"]["alice"], "default")

    def test_preflight_declares_template_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            result = preflightMutation(paths, "create_user", username="alice", group="default")
            self.assertTrue(result["ok"])
            self.assertIn(str(Path(temp_dir) / "templates" / "ocserv.conf.tpl"), result["planned_files"])
            self.assertIn(str(Path(temp_dir) / "group-templates" / "default.conf.tpl"), result["planned_files"])
            self.assertFalse((Path(temp_dir) / "groups.d").exists())

    def test_assign_group_updates_user_store_and_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            createUserRecord(paths, "alice", "default")
            assignGroupRecord(paths, "alice", "admins")
            payload = json.loads(paths.users_file.read_text(encoding="utf-8"))
            assignments = json.loads((Path(temp_dir) / "user-groups.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["users"][0]["group"], "admins")
            self.assertEqual(assignments["assignments"]["alice"], "admins")

    def test_create_user_rejects_unknown_group(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            with self.assertRaisesRegex(ValueError, "GROUP_NOT_FOUND"):
                createUserRecord(paths, "alice", "unknown")

    def test_create_user_plain_backend_returns_one_time_password(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = Path(temp_dir)
            groups_file = runtime / "groups.json"
            groups_file.write_text(json.dumps({"groups": ["default"]}) + "\n", encoding="utf-8")
            passwd_file = runtime / "passwd"
            paths = OcservPaths(passwd_file, groups_file, runtime / "audit.log", command_prefix=())

            def fake_run(command, input, capture_output, text, check):
                passwd_file.write_text("alice:default:hashed-password\n", encoding="utf-8")
                return type("Completed", (), {"returncode": 0})()

            with patch("subprocess.run", side_effect=fake_run):
                created = createUserRecord(paths, "alice", "default")

            self.assertEqual(created["user"]["username"], "alice")
            self.assertEqual(created["user"]["group"], "default")
            self.assertIn("one_time_password", created["provisioning"])

    def test_preflight_rejects_active_delete_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            createUserRecord(paths, "alice", "default")
            with patch("src.ocserv_adapter._run_command", return_value=SystemCommandResult(True, '[{"username":"alice"}]', "", 0)):
                result = preflightMutation(paths, "delete_user", username="alice")
            self.assertFalse(result["ok"])
            self.assertEqual(result["error_code"], "ACTIVE_USER_REQUIRES_FORCE")

    def test_apply_managed_mutation_rolls_back_on_failed_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(False, "", "bad config", 1),
                ],
            ):
                result = applyManagedMutation(
                    paths,
                    "create_user",
                    lambda: createUserRecord(paths, "alice", "default"),
                    username="alice",
                    group="default",
                )
            self.assertFalse(result["ok"])
            self.assertTrue(result["rolled_back"])
            self.assertEqual(result["error_code"], "CONFIG_VALIDATION_FAILED")
            self.assertEqual(json.loads(paths.users_file.read_text(encoding="utf-8"))["users"], []) if paths.users_file.exists() else self.assertFalse(paths.users_file.exists())
            self.assertFalse((Path(temp_dir) / "templates" / "ocserv.conf.tpl").exists())
            self.assertFalse((Path(temp_dir) / "group-templates" / "default.conf.tpl").exists())

    def test_disable_user_does_not_create_undeclared_templates(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            createUserRecord(paths, "alice", "default")
            before_templates = {
                str(Path(temp_dir) / "templates" / "ocserv.conf.tpl"): (Path(temp_dir) / "templates" / "ocserv.conf.tpl").exists(),
                str(Path(temp_dir) / "group-templates" / "default.conf.tpl"): (Path(temp_dir) / "group-templates" / "default.conf.tpl").exists(),
            }
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "reloaded", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                ],
            ):
                result = applyManagedMutation(
                    paths,
                    "disable_user",
                    lambda: disableUserRecord(paths, "alice"),
                    username="alice",
                )
            self.assertEqual((Path(temp_dir) / "templates" / "ocserv.conf.tpl").exists(), before_templates[str(Path(temp_dir) / "templates" / "ocserv.conf.tpl")])
            self.assertEqual((Path(temp_dir) / "group-templates" / "default.conf.tpl").exists(), before_templates[str(Path(temp_dir) / "group-templates" / "default.conf.tpl")])
            self.assertEqual(result["planned_files"], [str(paths.users_file)])
            self.assertEqual(result["changed_files"], [str(paths.users_file)])

    def test_activate_service_uses_restart_for_managed_config_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            changed_files = [str(Path(temp_dir) / "ocserv.conf")]
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(True, "restarted", "", 0),
                    SystemCommandResult(True, "active", "", 0),
                ],
            ):
                result = activateService(paths, changed_files)
            self.assertTrue(result["ok"])
            self.assertEqual(result["activation_mode"], "restart")
            self.assertTrue(result["restart_required"])
            self.assertTrue(result["health"].ok)

    def test_run_occtl_normalizes_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            with patch("src.ocserv_adapter._run_command", return_value=SystemCommandResult(True, '[{"name":"alice","ip":"10.0.0.1"}]', "", 0)) as runner:
                records = runOcctl(paths, "show_sessions")
            self.assertEqual(records[0]["name"], "alice")
            self.assertEqual(runner.call_args.args[0][:2], ("sudo", "-n"))

    def test_disconnect_session_uses_approved_occtl_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            with patch("src.ocserv_adapter._run_command", return_value=SystemCommandResult(True, "disconnected", "", 0)) as runner:
                result = disconnectSession(paths, "alice")
            self.assertTrue(result.ok)
            self.assertEqual(runner.call_args.args[0], ("sudo", "-n", "occtl", "disconnect", "user", "alice"))

    def test_safe_reload_stops_after_failed_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(False, "", "bad config", 1),
                    SystemCommandResult(True, "reloaded", "", 0),
                ],
            ) as runner:
                result = safeReload(paths)
            self.assertFalse(result["ok"])
            self.assertEqual(result["error_code"], "CONFIG_VALIDATION_FAILED")
            self.assertEqual(runner.call_count, 1)

    def test_missing_command_returns_structured_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            paths = OcservPaths(
                users_file=paths.users_file,
                groups_file=paths.groups_file,
                audit_log_file=paths.audit_log_file,
                validate_command=("definitely-missing-command",),
                reload_command=("reload",),
            )
            result = safeReload(paths)
            self.assertFalse(result["ok"])
            self.assertEqual(result["validation"].returncode, 127)

    def test_health_check_returns_structured_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            with patch("src.ocserv_adapter._run_command", return_value=SystemCommandResult(True, "active", "", 0)):
                result = healthCheck(paths)
            self.assertTrue(result.ok)
            self.assertEqual(result.stdout, "active")

    def test_apply_managed_mutation_persists_backup_and_rollback_restores_previous_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
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
                applied = applyManagedMutation(
                    paths,
                    "create_user",
                    lambda: createUserRecord(paths, "alice", "default"),
                    username="alice",
                    group="default",
                )
                rolled_back = rollbackLastChange(paths)

            self.assertTrue(applied["ok"])
            self.assertIn("rollback_state_file", applied["backup"])
            users_payload = json.loads(paths.users_file.read_text(encoding="utf-8")) if paths.users_file.exists() else {"users": []}
            self.assertEqual(users_payload["users"], [])
            self.assertEqual(rolled_back["rolled_back_action"], "create_user")


if __name__ == "__main__":
    unittest.main()

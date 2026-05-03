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
    createGroupRecord,
    createUserRecord,
    deleteGroupRecord,
    disableUserRecord,
    disableUsersInGroupRecord,
    disconnectSession,
    healthCheck,
    inventoryConfig,
    preflightMutation,
    rollbackLastChange,
    runOcctl,
    safeReload,
    showUserIps,
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

    def test_create_user_with_static_ip_persists_and_renders_per_user_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            (Path(temp_dir) / "group-templates" / "default.conf.tpl").parent.mkdir(parents=True, exist_ok=True)
            (Path(temp_dir) / "group-templates" / "default.conf.tpl").write_text(
                "# default\nipv4-network = 10.10.0.0/24\nipv4-netmask = 255.255.255.0\n",
                encoding="utf-8",
            )
            created = createUserRecord(paths, "alice", "default", "10.10.0.10")

            self.assertEqual(created["user"]["ipv4_address"], "10.10.0.10")
            payload = json.loads(paths.users_file.read_text(encoding="utf-8"))
            self.assertEqual(payload["users"][0]["ipv4_address"], "10.10.0.10")
            metadata = json.loads((Path(temp_dir) / "user-groups.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["ipv4_addresses"]["alice"], "10.10.0.10")
            self.assertEqual(
                (Path(temp_dir) / "config-per-user" / "alice").read_text(encoding="utf-8"),
                "explicit-ipv4 = 10.10.0.10\n",
            )

    def test_preflight_declares_template_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            result = preflightMutation(paths, "create_user", username="alice", group="default")
            self.assertTrue(result["ok"])
            self.assertIn(str(Path(temp_dir) / "templates" / "ocserv.conf.tpl"), result["planned_files"])
            self.assertIn(str(Path(temp_dir) / "group-templates" / "default.conf.tpl"), result["planned_files"])
            self.assertFalse((Path(temp_dir) / "groups.d").exists())

    def test_preflight_declares_user_config_write_for_static_ip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            (Path(temp_dir) / "group-templates" / "default.conf.tpl").parent.mkdir(parents=True, exist_ok=True)
            (Path(temp_dir) / "group-templates" / "default.conf.tpl").write_text(
                "# default\nipv4-network = 10.10.0.0/24\nipv4-netmask = 255.255.255.0\n",
                encoding="utf-8",
            )
            result = preflightMutation(paths, "create_user", username="alice", group="default", ipv4_address="10.10.0.10")
            self.assertTrue(result["ok"])
            self.assertIn(str(Path(temp_dir) / "config-per-user" / "alice"), result["planned_files"])

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

    def test_create_user_rejects_static_ip_outside_group_pool(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            (Path(temp_dir) / "group-templates" / "default.conf.tpl").parent.mkdir(parents=True, exist_ok=True)
            (Path(temp_dir) / "group-templates" / "default.conf.tpl").write_text(
                "# default\nipv4-network = 10.10.0.0/24\nipv4-netmask = 255.255.255.0\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "IP_OUTSIDE_GROUP_POOL"):
                createUserRecord(paths, "alice", "default", "10.20.0.10")

    def test_update_user_ip_rejects_duplicate_address(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            template_dir = Path(temp_dir) / "group-templates"
            template_dir.mkdir(parents=True, exist_ok=True)
            (template_dir / "default.conf.tpl").write_text(
                "# default\nipv4-network = 10.10.0.0/24\nipv4-netmask = 255.255.255.0\n",
                encoding="utf-8",
            )
            createUserRecord(paths, "alice", "default", "10.10.0.10")
            with self.assertRaisesRegex(ValueError, "IP_ADDRESS_IN_USE"):
                createUserRecord(paths, "bob", "default", "10.10.0.10")

    def test_create_user_plain_backend_returns_one_time_password(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = Path(temp_dir)
            groups_file = runtime / "groups.json"
            groups_file.write_text(json.dumps({"groups": ["default"]}) + "\n", encoding="utf-8")
            passwd_file = runtime / "passwd"
            paths = OcservPaths(passwd_file, groups_file, runtime / "audit.log", command_prefix=())

            def fake_run(command, input, capture_output, text, check, **kwargs):
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

    def test_apply_managed_mutation_rolls_back_static_ip_user_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            template_dir = Path(temp_dir) / "group-templates"
            template_dir.mkdir(parents=True, exist_ok=True)
            (template_dir / "default.conf.tpl").write_text(
                "# default\nipv4-network = 10.10.0.0/24\nipv4-netmask = 255.255.255.0\n",
                encoding="utf-8",
            )
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(False, "", "bad config", 1),
                ],
            ):
                result = applyManagedMutation(
                    paths,
                    "create_user",
                    lambda: createUserRecord(paths, "alice", "default", "10.10.0.10"),
                    username="alice",
                    group="default",
                    ipv4_address="10.10.0.10",
                )
            self.assertFalse(result["ok"])
            self.assertFalse((Path(temp_dir) / "config-per-user" / "alice").exists())

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


    def test_rollback_fails_when_no_snapshot_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            with self.assertRaisesRegex(ValueError, "ROLLBACK_NOT_AVAILABLE"):
                rollbackLastChange(paths)

    def test_show_user_ips_parses_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            with patch(
                "src.ocserv_adapter._run_command",
                return_value=SystemCommandResult(
                    True,
                    json.dumps([
                        {"username": "alice", "ip": "10.0.0.1", "group": "default"},
                        {"username": "bob", "ip": "10.0.0.2", "group": "admins"},
                    ]),
                    "",
                    0,
                ),
            ):
                result = showUserIps(paths)
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["username"], "alice")
            self.assertEqual(result[0]["ip"], "10.0.0.1")
            self.assertEqual(result[1]["username"], "bob")

    def test_show_user_ips_parses_tabular_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            with patch(
                "src.ocserv_adapter._run_command",
                return_value=SystemCommandResult(
                    True,
                    json.dumps([
                        {"status": "alice default 10.0.0.1 connected"},
                        {"status": "bob admins 10.0.0.2 connected"},
                    ]),
                    "",
                    0,
                ),
            ):
                result = showUserIps(paths)
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["username"], "alice")
            self.assertEqual(result[0]["ip"], "10.0.0.1")

    def test_apply_managed_mutation_rolls_back_on_activation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            with patch(
                "src.ocserv_adapter._run_command",
                side_effect=[
                    SystemCommandResult(True, "ok", "", 0),
                    SystemCommandResult(False, "", "restart failed", 1),
                    SystemCommandResult(False, "", "not active", 1),
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

    def test_create_group_record_generates_correct_template(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            result = createGroupRecord(paths, "vpn-users", "192.168.1.0/24", "255.255.255.0", ["10.0.0.0/8"])
            self.assertEqual(result["group"], "vpn-users")
            self.assertEqual(result["group_details"]["ipv4_network"], "192.168.1.0/24")
            template_path = Path(temp_dir) / "group-templates" / "vpn-users.conf.tpl"
            self.assertTrue(template_path.exists())
            content = template_path.read_text(encoding="utf-8")
            self.assertIn("ipv4-network = 192.168.1.0/24", content)
            self.assertIn("ipv4-netmask = 255.255.255.0", content)
            self.assertIn("route = 10.0.0.0/8", content)
            self.assertIn("restrict-user-to-routes = true", content)

    def test_delete_group_record_rejects_protected_groups(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            with self.assertRaisesRegex(ValueError, "PROTECTED_GROUP"):
                deleteGroupRecord(paths, "default")
            with self.assertRaisesRegex(ValueError, "PROTECTED_GROUP"):
                deleteGroupRecord(paths, "admins")

    def test_delete_group_record_rejects_group_in_use(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            createGroupRecord(paths, "vpn-users", None, None, [])
            createUserRecord(paths, "alice", "vpn-users")
            with self.assertRaisesRegex(ValueError, "GROUP_IN_USE"):
                deleteGroupRecord(paths, "vpn-users")

    def test_delete_group_record_cleans_template_and_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            createGroupRecord(paths, "vpn-users", "192.168.1.0/24", "255.255.255.0", [])
            template_path = Path(temp_dir) / "group-templates" / "vpn-users.conf.tpl"
            self.assertTrue(template_path.exists())
            deleteGroupRecord(paths, "vpn-users")
            self.assertFalse(template_path.exists())
            groups = json.loads(paths.groups_file.read_text(encoding="utf-8"))
            self.assertNotIn("vpn-users", groups["groups"])

    def test_disable_users_in_group_disables_only_target_group(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            createUserRecord(paths, "alice", "default")
            createUserRecord(paths, "bob", "admins")
            createUserRecord(paths, "charlie", "default")
            result = disableUsersInGroupRecord(paths, "default")
            self.assertEqual(result["group"], "default")
            self.assertEqual(len(result["affected_users"]), 2)
            affected_names = {u["username"] for u in result["affected_users"]}
            self.assertIn("alice", affected_names)
            self.assertIn("charlie", affected_names)
            self.assertNotIn("bob", affected_names)

    def test_disable_users_in_group_skips_already_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._make_paths(temp_dir)
            createUserRecord(paths, "alice", "default")
            createUserRecord(paths, "bob", "default")
            disableUserRecord(paths, "alice")
            result = disableUsersInGroupRecord(paths, "default")
            self.assertEqual(len(result["affected_users"]), 1)
            self.assertEqual(result["affected_users"][0]["username"], "bob")

    def test_disable_users_in_group_plain_backend_uses_ocpasswd(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = Path(temp_dir)
            groups_file = runtime / "groups.json"
            groups_file.write_text(json.dumps({"groups": ["default"]}) + "\n", encoding="utf-8")
            passwd_file = runtime / "passwd"
            passwd_file.write_text("alice:default:hash1\nbob:default:hash2\n", encoding="utf-8")
            paths = OcservPaths(passwd_file, groups_file, runtime / "audit.log", command_prefix=())

            def fake_lock(command, *args, **kwargs):
                username = command[-1] if isinstance(command, (list, tuple)) else "unknown"
                content = passwd_file.read_text(encoding="utf-8")
                new_lines = []
                for line in content.splitlines():
                    parts = line.split(":", 2)
                    if len(parts) == 3 and parts[0] == username and not parts[2].startswith("!"):
                        new_lines.append(f"{parts[0]}:{parts[1]}:!{parts[2]}")
                    else:
                        new_lines.append(line)
                passwd_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
                return SystemCommandResult(True, "ok", "", 0)

            with patch("src.ocserv_adapter._run_command", side_effect=fake_lock):
                result = disableUsersInGroupRecord(paths, "default")
            self.assertEqual(len(result["affected_users"]), 2)
            content = passwd_file.read_text(encoding="utf-8")
            for line in content.strip().splitlines():
                parts = line.split(":", 2)
                self.assertTrue(parts[2].startswith("!"), f"Expected disabled hash for {parts[0]}")


if __name__ == "__main__":
    unittest.main()

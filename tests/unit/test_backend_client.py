from pathlib import Path
import urllib.error
import unittest
from unittest.mock import patch

from src.backend_client import (
    DEFAULT_RUNTIME_DIR,
    BackendClient,
    buildToolCatalog,
    discoverGroupChoices,
    normalizeBackendResponse,
    paginateCollection,
    planAction,
)


class BackendClientTests(unittest.TestCase):
    def test_build_tool_catalog_exposes_only_mvp_tools(self) -> None:
        catalog = buildToolCatalog()
        self.assertEqual(
            [tool["name"] for tool in catalog],
            [
                "list_users",
                "list_sessions",
                "list_groups",
                "show_user_ips",
                "disconnect_session",
                "create_user",
                "disable_user",
                "disable_group_users",
                "delete_user",
                "assign_group",
                "create_group",
                "delete_group",
                "reload_service",
                "rollback_last_change",
                "confirm_action",
            ],
        )
        delete_tool = next(tool for tool in catalog if tool["name"] == "delete_user")
        self.assertEqual(delete_tool["inputSchema"]["additionalProperties"], False)
        self.assertEqual(delete_tool["annotations"]["destructiveHint"], True)
        self.assertEqual(delete_tool["annotations"]["readOnlyHint"], False)
        disable_tool = next(tool for tool in catalog if tool["name"] == "disable_user")
        self.assertNotIn("confirmed", disable_tool["inputSchema"]["properties"])
        self.assertEqual(disable_tool["inputSchema"]["properties"]["response_format"]["enum"], ["json", "markdown"])
        list_users_tool = next(tool for tool in catalog if tool["name"] == "list_users")
        self.assertEqual(list_users_tool["annotations"]["idempotentHint"], True)
        self.assertEqual(list_users_tool["annotations"]["openWorldHint"], False)
        self.assertIn("limit", list_users_tool["inputSchema"]["properties"])
        self.assertIn("offset", list_users_tool["inputSchema"]["properties"])

    def test_client_rejects_non_loopback_backend(self) -> None:
        with self.assertRaisesRegex(ValueError, "BACKEND_MUST_BE_LOOPBACK"):
            BackendClient("http://10.0.0.5:8080", "mcp-client", "secret-token")

    def test_plan_action_rejects_unknown_action(self) -> None:
        with self.assertRaisesRegex(ValueError, "ACTION_NOT_ALLOWED"):
            planAction("rm_rf")

    def test_plan_action_rejects_unexpected_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "INVALID_REQUEST:raw_command"):
            planAction("list_users", raw_command="whoami")

    def test_plan_action_rejects_non_boolean_force(self) -> None:
        with self.assertRaisesRegex(ValueError, "INVALID_REQUEST:force"):
            planAction("delete_user", username="alice", force="yes")

    def test_plan_action_rejects_confirmed_flag_for_destructive_actions(self) -> None:
        with self.assertRaisesRegex(ValueError, "INVALID_REQUEST:confirmed"):
            planAction("disable_user", username="alice", confirmed=True)

    def test_plan_action_emits_required_marker(self) -> None:
        with patch("src.backend_client.recordAuditEvent") as recorder:
            action, payload = planAction("create_user", username="alice", group="admins")
        self.assertEqual(action, "create_user")
        self.assertEqual(payload, {"username": "alice", "group": "admins"})
        self.assertIn("[BackendClient][planAction][BLOCK_PLAN_ACTION] planned backend action", recorder.call_args.args[0]["message"])

    def test_normalize_backend_response_marks_pending_confirmation(self) -> None:
        normalized = normalizeBackendResponse(
            "delete_user",
            {"ok": False, "status": "pending_confirmation", "token": "tok-1", "error_code": "CONFIRMATION_REQUIRED", "confirmation": {"action": "delete_user"}},
        )
        self.assertEqual(normalized["result"]["status"], "pending_confirmation")
        self.assertEqual(normalized["entities"]["token"], "tok-1")
        self.assertEqual(normalized["entities"]["confirmation"]["action"], "delete_user")
        self.assertEqual(
            normalized["actionable_error"]["next_step"],
            "Call confirm_action with the returned token and a confirm or cancel decision.",
        )

    def test_plan_action_accepts_group_bulk_and_group_crud_fields(self) -> None:
        action, payload = planAction("disable_group_users", group="admins")
        self.assertEqual(action, "disable_group_users")
        self.assertEqual(payload, {"group": "admins"})

        action, payload = planAction("create_group", group="vpn-a", ipv4_network="10.10.10.0/24", ipv4_netmask="255.255.255.0", routes=["10.10.10.0/255.255.255.0"])
        self.assertEqual(action, "create_group")
        self.assertEqual(payload["group"], "vpn-a")
        self.assertEqual(payload["routes"], ["10.10.10.0/255.255.255.0"])

    def test_plan_action_rejects_invalid_routes(self) -> None:
        with self.assertRaisesRegex(ValueError, "INVALID_REQUEST:routes"):
            planAction("create_group", group="vpn-a", routes="10.0.0.0/8")

    def test_normalize_backend_response_preserves_reload_evidence(self) -> None:
        normalized = normalizeBackendResponse(
            "reload_service",
            {"ok": True, "reload": {"ok": True, "activation_mode": "restart"}},
        )
        self.assertEqual(normalized["result"]["status"], "ok")
        self.assertEqual(normalized["reload"]["activation_mode"], "restart")

    def test_paginate_collection_returns_stable_counts(self) -> None:
        items, pagination = paginateCollection(["alice", "bob", "carol"], limit=2, offset=1)
        self.assertEqual(items, ["bob", "carol"])
        self.assertEqual(
            pagination,
            {
                "limit": 2,
                "offset": 1,
                "count": 2,
                "total_count": 3,
                "has_more": False,
                "next_offset": None,
            },
        )

    def test_paginate_collection_defaults_and_clamps(self) -> None:
        items, pagination = paginateCollection(["alice", "bob"], limit=500, offset=-5)
        self.assertEqual(items, ["alice", "bob"])
        self.assertEqual(pagination["limit"], 100)
        self.assertEqual(pagination["offset"], 0)
        self.assertEqual(pagination["count"], 2)

    def test_client_calls_backend_only(self) -> None:
        client = BackendClient("http://127.0.0.1:18082", "mcp-client", "secret-token")
        with patch("urllib.request.urlopen") as mocked:
            mocked.return_value.__enter__.return_value.read.return_value = b'{"ok": true}'
            response = client.execute("list_users")
        self.assertEqual(response["ok"], True)
        request = mocked.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:18082/actions/list_users")
        self.assertEqual(request.get_header("Authorization"), "Bearer secret-token")

    def test_client_normalizes_backend_transport_failure(self) -> None:
        client = BackendClient("http://127.0.0.1:18082", "mcp-client", "secret-token")
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")):
            response = client.execute("list_users")
        self.assertEqual(response["ok"], False)
        self.assertEqual(response["error_code"], "BACKEND_UNAVAILABLE")
        self.assertIn("connection refused", response["details"]["reason"])

    def test_discover_group_choices_uses_packaged_runtime_default(self) -> None:
        self.assertEqual(DEFAULT_RUNTIME_DIR, Path("/var/lib/ocserv-admin"))
        with patch.dict("os.environ", {}, clear=True):
            with patch.object(Path, "exists", return_value=False):
                groups = discoverGroupChoices()
        self.assertIsNone(groups)

    def test_shipped_nanobot_config_uses_groups_file_contract(self) -> None:
        config_path = Path(__file__).resolve().parents[2] / "deploy" / "examples" / "nanobot-config.example.json"
        contents = config_path.read_text(encoding="utf-8")
        self.assertIn('"OCSERV_ADMIN_GROUPS_FILE": "/var/lib/ocserv-admin/groups.json"', contents)
        self.assertNotIn("OCSERV_ADMIN_ALLOWED_GROUPS", contents)


if __name__ == "__main__":
    unittest.main()

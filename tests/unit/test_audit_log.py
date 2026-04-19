import json
import tempfile
import unittest
from pathlib import Path

from src.audit_log import buildAuditContext, recordAuditEvent


class AuditLogTests(unittest.TestCase):
    def test_build_context_redacts_sensitive_fields(self) -> None:
        record = buildAuditContext(
            {
                "actor_id": "alice",
                "details": {"password": "secret", "safe": "value"},
            }
        )
        self.assertEqual(record["details"]["password"], "[REDACTED]")
        self.assertEqual(record["details"]["safe"], "value")

    def test_record_writes_json_line(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_path = Path(temp_dir) / "audit.log"
            record = recordAuditEvent({"actor_id": "alice", "event": "user_created"}, audit_path)
            persisted = json.loads(audit_path.read_text(encoding="utf-8").strip())
            self.assertEqual(record["event"], "user_created")
            self.assertEqual(persisted["actor_id"], "alice")

    def test_record_routes_failures_and_admin_changes_to_separate_logs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_path = Path(temp_dir) / "audit.log"
            recordAuditEvent({"actor_id": "alice", "event": "reload_failed", "command": "reload_service", "result": "failed", "error_code": "SERVICE_RELOAD_FAILED"}, audit_path)
            recordAuditEvent({"actor_id": "alice", "event": "user_created", "command": "create_user", "result": "ok"}, audit_path)

            error_log = json.loads((Path(temp_dir) / "error.log").read_text(encoding="utf-8").strip())
            admin_change_log = json.loads((Path(temp_dir) / "admin-changes.log").read_text(encoding="utf-8").strip())

            self.assertEqual(error_log["error_code"], "SERVICE_RELOAD_FAILED")
            self.assertEqual(admin_change_log["command"], "create_user")


if __name__ == "__main__":
    unittest.main()

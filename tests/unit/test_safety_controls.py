import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from src.audit_log import AuditSink
from src.safety_controls import InMemoryRateLimiter, OperatorIdentity, ProposedAdminAction, checkRateLimit, guardAction


class SafetyControlsTests(unittest.TestCase):
    def test_allows_safe_whitelisted_action(self) -> None:
        decision = guardAction(
            ProposedAdminAction(action="list_users", request_id="req-1"),
            OperatorIdentity(actor_id="admin"),
            ["admin"],
        )
        self.assertTrue(decision.allowed)
        self.assertFalse(decision.requires_confirmation)

    def test_requires_confirmation_for_destructive_action(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sink = AuditSink(Path(temp_dir) / "audit.log")
            decision = guardAction(
                ProposedAdminAction(action="delete_user", username="alice", request_id="req-2"),
                OperatorIdentity(actor_id="admin"),
                ["admin"],
                sink,
            )
            self.assertFalse(decision.allowed)
            self.assertTrue(decision.requires_confirmation)

    def test_requires_confirmation_for_group_change(self) -> None:
        decision = guardAction(
            ProposedAdminAction(action="assign_group", username="alice", group="admins", request_id="req-4"),
            OperatorIdentity(actor_id="admin"),
            ["admin"],
        )
        self.assertFalse(decision.allowed)
        self.assertTrue(decision.requires_confirmation)

    def test_requires_confirmation_for_session_disconnect(self) -> None:
        decision = guardAction(
            ProposedAdminAction(action="disconnect_session", username="alice", request_id="req-5"),
            OperatorIdentity(actor_id="admin"),
            ["admin"],
        )
        self.assertFalse(decision.allowed)
        self.assertTrue(decision.requires_confirmation)

    def test_rejects_invalid_username(self) -> None:
        decision = guardAction(
            ProposedAdminAction(action="create_user", username="bad name", request_id="req-3"),
            OperatorIdentity(actor_id="admin"),
            ["admin"],
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error_code, "INVALID_USERNAME")

    def test_requires_confirmation_for_rollback(self) -> None:
        decision = guardAction(
            ProposedAdminAction(action="rollback_last_change", request_id="req-6"),
            OperatorIdentity(actor_id="admin"),
            ["admin"],
        )
        self.assertFalse(decision.allowed)
        self.assertTrue(decision.requires_confirmation)

    def test_allows_destructive_action_after_internal_confirmation(self) -> None:
        decision = guardAction(
            ProposedAdminAction(action="delete_user", username="alice", confirmed=True, request_id="req-7"),
            OperatorIdentity(actor_id="admin"),
            ["admin"],
        )
        self.assertTrue(decision.allowed)
        self.assertFalse(decision.requires_confirmation)

    def test_rate_limiter_rejects_requests_over_limit(self) -> None:
        limiter = InMemoryRateLimiter(max_requests=2, window_seconds=60)
        now = datetime(2026, 4, 19, tzinfo=UTC)

        self.assertTrue(checkRateLimit(limiter, "actor:admin", now))
        self.assertTrue(checkRateLimit(limiter, "actor:admin", now + timedelta(seconds=1)))
        self.assertFalse(checkRateLimit(limiter, "actor:admin", now + timedelta(seconds=2)))


if __name__ == "__main__":
    unittest.main()

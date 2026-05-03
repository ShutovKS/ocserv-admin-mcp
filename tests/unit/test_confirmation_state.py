from datetime import UTC, datetime, timedelta
import tempfile
import unittest
from pathlib import Path

from src.audit_log import AuditSink
from src.confirmation_state import FileBackedConfirmationStore, InMemoryConfirmationStore, PendingConfirmationRequest, createPendingConfirmation, resolvePendingConfirmation


class ConfirmationStateTests(unittest.TestCase):
    def test_create_and_confirm_once(self) -> None:
        store = InMemoryConfirmationStore()
        pending = createPendingConfirmation(
            store,
            PendingConfirmationRequest(action="delete_user", actor_id="admin", target_user="alice", request_id="req-1"),
        )
        resolution = resolvePendingConfirmation(store, pending.token, "confirm")
        replay = resolvePendingConfirmation(store, pending.token, "confirm")
        self.assertTrue(resolution.execute_allowed)
        self.assertEqual(replay.error_code, "CONFIRMATION_REPLAYED")

    def test_expired_confirmation_never_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sink = AuditSink(Path(temp_dir) / "audit.log")
            store = InMemoryConfirmationStore()
            now = datetime.now(UTC)
            pending = createPendingConfirmation(
                store,
                PendingConfirmationRequest(action="delete_user", actor_id="admin", target_user="alice", request_id="req-2", expires_in_seconds=1),
                sink,
                now,
            )
            resolution = resolvePendingConfirmation(
                store,
                pending.token,
                "confirm",
                sink,
                now=now + timedelta(seconds=5),
            )
            self.assertFalse(resolution.execute_allowed)
            self.assertEqual(resolution.error_code, "CONFIRMATION_EXPIRED")

    def test_confirmation_rejects_different_actor(self) -> None:
        store = InMemoryConfirmationStore()
        pending = createPendingConfirmation(
            store,
            PendingConfirmationRequest(action="delete_user", actor_id="admin-a", target_user="alice", request_id="req-3"),
        )
        resolution = resolvePendingConfirmation(
            store,
            pending.token,
            "confirm",
            requested_actor_id="admin-b",
        )
        self.assertFalse(resolution.execute_allowed)
        self.assertEqual(resolution.error_code, "UNAUTHORIZED_OPERATOR")
        stored = store.get(pending.token)
        if stored is None:
            self.fail("pending confirmation record should remain available")
        self.assertEqual(stored.status, "pending")

    def test_file_backed_store_persists_confirmed_status_after_reload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "confirmations.json"
            store = FileBackedConfirmationStore(path)
            pending = createPendingConfirmation(
                store,
                PendingConfirmationRequest(action="delete_user", actor_id="admin", target_user="alice", request_id="req-4"),
            )

            resolution = resolvePendingConfirmation(store, pending.token, "confirm")
            self.assertTrue(resolution.execute_allowed)

            reloaded_store = FileBackedConfirmationStore(path)
            reloaded_record = reloaded_store.get(pending.token)
            if reloaded_record is None:
                self.fail("confirmed record should persist in file-backed store")
            self.assertEqual(reloaded_record.status, "confirmed")

            replay = resolvePendingConfirmation(reloaded_store, pending.token, "confirm")
            self.assertFalse(replay.execute_allowed)
            self.assertEqual(replay.error_code, "CONFIRMATION_REPLAYED")


if __name__ == "__main__":
    unittest.main()

# FILE: src/file_lock.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Provide file-level exclusive locking for mutation pipelines to prevent concurrent writes.
#   SCOPE: Exclusive advisory file lock acquisition and release using fcntl.flock.
#   DEPENDS: none
#   LINKS: M-FILE-LOCK
#   ROLE: UTILITY
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   MutationLock - Context manager for exclusive mutation lock on a directory.
# END_MODULE_MAP

from __future__ import annotations

import fcntl
import io
from pathlib import Path
from types import TracebackType


class MutationLock:
    """Exclusive advisory lock on a .mutation.lock file inside the given directory."""

    def __init__(self, lock_dir: Path, timeout_message: str = "MUTATION_LOCK_FAILED") -> None:
        self._lock_path = lock_dir / ".mutation.lock"
        self._timeout_message = timeout_message
        self._file: io.TextIOWrapper | None = None

    def __enter__(self) -> MutationLock:
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self._lock_path.open("w")
        try:
            fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._file.close()
            self._file = None
            raise ValueError(self._timeout_message)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._file is not None:
            try:
                fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            self._file.close()
            self._file = None

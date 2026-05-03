# FILE: src/logging_config.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Centralized logging configuration with JSON formatter for structured operational logs.
#   SCOPE: Logger setup, JSON formatting, log level configuration.
#   DEPENDS: none
#   LINKS: M-LOGGING-CONFIG
#   ROLE: UTILITY
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   setup_logging - Configure the root ocserv_admin logger with JSON formatter.
#   get_logger - Get a child logger under the ocserv_admin namespace.
#   JsonFormatter - JSON log formatter for structured output.
# END_MODULE_MAP

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any


class JsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1] is not None:
            entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "context") and isinstance(record.context, dict):  # type: ignore[attr-defined]
            entry["context"] = record.context  # type: ignore[attr-defined]
        return json.dumps(entry, ensure_ascii=False, default=str)


_ROOT_LOGGER_NAME = "ocserv_admin"


def setup_logging(level: str = "INFO", json_output: bool = True) -> logging.Logger:
    """Configure the ocserv_admin logger hierarchy.

    Args:
        level: Log level name (DEBUG, INFO, WARNING, ERROR).
        json_output: If True, use JSON formatter; otherwise use standard text format.

    Returns:
        The configured root logger for the application.
    """
    logger = logging.getLogger(_ROOT_LOGGER_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        if json_output:
            handler.setFormatter(JsonFormatter())
        else:
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        logger.addHandler(handler)
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a child logger under the ocserv_admin namespace."""
    return logging.getLogger(f"{_ROOT_LOGGER_NAME}.{name}")

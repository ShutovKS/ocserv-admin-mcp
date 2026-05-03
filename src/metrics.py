# FILE: src/metrics.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Collect and expose Prometheus-compatible metrics for monitoring.
#   SCOPE: Request counting, duration tracking, error counting by action.
#   DEPENDS: none
#   LINKS: M-METRICS
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   MetricsCollector - Collects request_count, request_duration, error_count per action.
#   format_prometheus - Render metrics in Prometheus text exposition format.
# END_MODULE_MAP

from __future__ import annotations

import time
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class MetricsCollector:
    """Thread-safe metrics collector for the admin API."""

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _request_count: dict[str, int] = field(default_factory=dict)
    _error_count: dict[str, int] = field(default_factory=dict)
    _request_duration_sum: dict[str, float] = field(default_factory=dict)
    _request_duration_count: dict[str, int] = field(default_factory=dict)
    _start_time: float = field(default_factory=time.monotonic)
    _pending_confirmations: int = 0

    def record_request(self, action: str, duration_seconds: float, error: bool = False) -> None:
        with self._lock:
            self._request_count[action] = self._request_count.get(action, 0) + 1
            self._request_duration_sum[action] = self._request_duration_sum.get(action, 0.0) + duration_seconds
            self._request_duration_count[action] = self._request_duration_count.get(action, 0) + 1
            if error:
                self._error_count[action] = self._error_count.get(action, 0) + 1

    def set_pending_confirmations(self, count: int) -> None:
        with self._lock:
            self._pending_confirmations = count

    @property
    def uptime_seconds(self) -> float:
        return time.monotonic() - self._start_time


def format_prometheus(collector: MetricsCollector) -> str:
    """Render metrics in Prometheus text exposition format."""
    lines: list[str] = []

    lines.append("# HELP ocserv_admin_uptime_seconds Time since server started")
    lines.append("# TYPE ocserv_admin_uptime_seconds gauge")
    lines.append(f"ocserv_admin_uptime_seconds {collector.uptime_seconds:.1f}")

    lines.append("# HELP ocserv_admin_requests_total Total number of requests by action")
    lines.append("# TYPE ocserv_admin_requests_total counter")
    with collector._lock:
        for action, count in sorted(collector._request_count.items()):
            lines.append(f'ocserv_admin_requests_total{{action="{action}"}} {count}')

    lines.append("# HELP ocserv_admin_errors_total Total number of errors by action")
    lines.append("# TYPE ocserv_admin_errors_total counter")
    with collector._lock:
        for action, count in sorted(collector._error_count.items()):
            lines.append(f'ocserv_admin_errors_total{{action="{action}"}} {count}')

    lines.append("# HELP ocserv_admin_request_duration_seconds_sum Total request duration by action")
    lines.append("# TYPE ocserv_admin_request_duration_seconds_sum counter")
    with collector._lock:
        for action, total in sorted(collector._request_duration_sum.items()):
            lines.append(f'ocserv_admin_request_duration_seconds_sum{{action="{action}"}} {total:.4f}')

    lines.append("# HELP ocserv_admin_request_duration_seconds_count Total request count for duration by action")
    lines.append("# TYPE ocserv_admin_request_duration_seconds_count counter")
    with collector._lock:
        for action, count in sorted(collector._request_duration_count.items()):
            lines.append(f'ocserv_admin_request_duration_seconds_count{{action="{action}"}} {count}')

    lines.append("# HELP ocserv_admin_pending_confirmations Number of pending confirmations")
    lines.append("# TYPE ocserv_admin_pending_confirmations gauge")
    lines.append(f"ocserv_admin_pending_confirmations {collector._pending_confirmations}")

    lines.append("")
    return "\n".join(lines)

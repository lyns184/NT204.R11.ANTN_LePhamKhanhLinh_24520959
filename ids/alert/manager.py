"""Điều phối chuyển đổi, lọc, gom nhóm và xuất Alert theo từng lần chạy."""

import json
import sqlite3
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TextIO
from uuid import uuid4

from ids.alert.config import AlertConfig
from ids.alert.conversion import convert_detection
from ids.alert.filtering import AlertFilter
from ids.alert.models import Alert
from ids.alert.repository import AlertRepository
from ids.detection.models import DetectionEvent
from ids.output.paths import validate_output_paths


@dataclass(frozen=True)
class AlertProcessingResult:
    status: Literal["rejected", "filtered", "created", "aggregated"]
    reason: str | None = None
    alert: Alert | None = None


def _write_alerts(alerts: list[Alert], stream: TextIO) -> None:
    for alert in alerts:
        message = json.dumps(alert.msg, ensure_ascii=False)
        source = alert.src_ip if alert.src_port is None else f"{alert.src_ip}:{alert.src_port}"
        destination = alert.dst_ip if alert.dst_port is None else f"{alert.dst_ip}:{alert.dst_port}"
        stream.write(
            f"[ALERT] id={alert.alert_id} severity={alert.severity.value} sid={alert.sid} "
            f"{alert.protocol or 'UNKNOWN'} {source} -> {destination} count={alert.count} "
            f"first_seen={alert.first_seen} last_seen={alert.last_seen} msg={message}\n"
        )


class AlertManager:
    """Một manager cho một lần chạy. Caller gọi process tuần tự."""

    def __init__(self, config: AlertConfig, repository: AlertRepository) -> None:
        self.run_id = str(uuid4())
        self._config = config
        self._repository = repository
        self._filter = AlertFilter(config)
        self._window_seconds = config.aggregation_window_seconds if config.aggregation_enabled else None
        self._counts: Counter[str] = Counter()

    @property
    def counts(self) -> dict[str, int | dict[str, int]]:
        return {
            **{name: self._counts[name] for name in (
                "received", "rejected", "filtered", "created", "aggregated", "storage_errors",
            )},
            "filtered_by_reason": self._filter.filtered_counts,
        }

    def process(self, detection: DetectionEvent | Mapping[str, Any]) -> AlertProcessingResult:
        self._counts["received"] += 1
        converted = convert_detection(detection, self._config)
        if converted.alert is None:
            self._counts["rejected"] += 1
            return AlertProcessingResult("rejected", reason=converted.reason)

        reason = self._filter.evaluate(converted.alert)
        if reason is not None:
            self._counts["filtered"] += 1
            return AlertProcessingResult("filtered", reason=reason.value)

        try:
            result = self._repository.record(
                converted.alert, run_id=self.run_id, window_seconds=self._window_seconds,
            )
        except sqlite3.Error:
            self._counts["storage_errors"] += 1
            raise
        self._counts[result.status] += 1
        return AlertProcessingResult(result.status, alert=result.alert)

    def export_alerts(self, destination: TextIO | str | Path) -> int:
        """Xuất trạng thái cuối của các nhóm đã lưu trong run hiện tại."""
        alerts = self._repository.query(run_id=self.run_id)
        if isinstance(destination, (str, Path)):
            storage = self._repository.path
            storage_files = [storage, *(storage.with_name(storage.name + suffix)
                                        for suffix in ("-journal", "-wal", "-shm"))]
            validate_output_paths({"alert export": destination}, storage_files)
            path = Path(destination)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="utf-8") as stream:
                _write_alerts(alerts, stream)
        else:
            _write_alerts(alerts, destination)
        return len(alerts)

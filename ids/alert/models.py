"""Alert chuẩn hóa nhận từ Detector và kết quả chuyển đổi."""

from dataclasses import asdict, dataclass
from typing import Any, Literal

from ids.alert.config import Severity


@dataclass(frozen=True)
class Alert:
    alert_id: str
    sid: int
    msg: str
    severity: Severity
    src_ip: str
    dst_ip: str
    first_seen: float
    last_seen: float
    count: int = 1
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    application_protocol: str | None = None
    flow_id: str | None = None
    classtype: str | None = None
    priority: int | None = None
    rev: int | None = None

    @property
    def timestamp(self) -> float:
        """Timestamp đại diện của alert là lúc nhóm bắt đầu."""
        return self.first_seen

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "timestamp": self.timestamp, "severity": self.severity.value}


@dataclass(frozen=True)
class AlertConversionResult:
    alert: Alert | None = None
    reason: str | None = None

    @property
    def status(self) -> Literal["accepted", "rejected"]:
        return "accepted" if self.alert is not None else "rejected"

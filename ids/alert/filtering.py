"""Lọc Alert đã chuẩn hóa trước khi gom nhóm hoặc lưu."""

from collections import Counter
from enum import Enum

from ids.alert.config import AlertConfig, Severity
from ids.alert.models import Alert


_SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class AlertFilterReason(str, Enum):
    SID_SUPPRESSED = "sid_suppressed"
    BELOW_MIN_SEVERITY = "below_min_severity"


class AlertFilter:
    """Một bộ lọc và bộ đếm theo lý do cho mỗi lần chạy."""

    def __init__(self, config: AlertConfig) -> None:
        self._suppressed_sids = config.suppressed_sids
        self._minimum_rank = _SEVERITY_RANK[config.min_severity]
        self._filtered: Counter[AlertFilterReason] = Counter()

    @property
    def filtered_counts(self) -> dict[str, int]:
        return {reason.value: self._filtered[reason] for reason in AlertFilterReason}

    def evaluate(self, alert: Alert) -> AlertFilterReason | None:
        """Trả lý do loại hoặc None nếu giữ lại. SID suppression được xét trước."""
        if alert.sid in self._suppressed_sids:
            reason = AlertFilterReason.SID_SUPPRESSED
        elif _SEVERITY_RANK[alert.severity] < self._minimum_rank:
            reason = AlertFilterReason.BELOW_MIN_SEVERITY
        else:
            return None

        self._filtered[reason] += 1
        return reason

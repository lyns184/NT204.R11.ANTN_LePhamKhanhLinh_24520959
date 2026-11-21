"""Tổng hợp báo cáo theo nhóm Alert đã lưu trong SQLite."""

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Literal, TypedDict, TypeVar

from ids.alert.config import Severity
from ids.alert.repository import AlertRepository


class ReportPeriod(TypedDict):
    from_utc: str
    to_utc: str


class RankedCount(TypedDict):
    value: int | str
    alerts: int


class AlertReport(TypedDict):
    period: ReportPeriod
    run_id: str | None
    time_basis: Literal["first_seen"]
    top_n: int
    total_alerts: int
    total_occurrences: int
    severity_counts: dict[str, int]
    sid_counts: dict[str, int]
    classtype_counts: dict[str, int]
    top_sids: list[RankedCount]
    top_classtypes: list[RankedCount]
    top_src_ips: list[RankedCount]
    top_dst_ips: list[RankedCount]
    protocol_counts: dict[str, int]
    application_protocol_counts: dict[str, int]
    alerts_by_hour_utc: dict[str, int]


_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)
_SECONDS_PER_HOUR = 3600
_UNKNOWN = "UNKNOWN"
_Key = TypeVar("_Key", int, str)


def _utc_text(timestamp: float, field: str) -> str:
    if type(timestamp) not in (int, float):
        raise ValueError(f"{field} must be a Unix timestamp")
    try:
        date = _EPOCH_UTC + timedelta(seconds=timestamp)
    except (ValueError, OverflowError) as exc:
        raise ValueError(f"{field} must be a Unix timestamp representable in UTC") from exc
    return date.isoformat().replace("+00:00", "Z")


def _top(counts: Counter[_Key], top_n: int) -> list[RankedCount]:
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [{"value": value, "alerts": count} for value, count in ranked[:top_n]]


def generate_report(
    repository: AlertRepository, *, from_time: float, to_time: float,
    top_n: int, run_id: str | None = None,
) -> AlertReport:
    """Đếm nhóm theo first_seen trong [from_time, to_time) UTC.

    total_occurrences là tổng count của các nhóm được chọn. Top-N, phân bố
    và bucket giờ đếm nhóm. Bucket chỉ xuất hiện khi chứa ít nhất một nhóm.
    """
    if type(top_n) is not int or top_n <= 0:
        raise ValueError("top_n must be a positive integer")
    period: ReportPeriod = {
        "from_utc": _utc_text(from_time, "from_time"),
        "to_utc": _utc_text(to_time, "to_time"),
    }
    alerts = repository.query(from_time=from_time, to_time=to_time, run_id=run_id)

    severity: Counter[str] = Counter()
    sids: Counter[int] = Counter()
    classtypes: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    applications: Counter[str] = Counter()
    hours: Counter[int] = Counter()
    occurrences = 0

    for alert in alerts:
        occurrences += alert.count
        severity[alert.severity.value] += 1
        sids[alert.sid] += 1
        classtypes[alert.classtype or _UNKNOWN] += 1
        sources[alert.src_ip] += 1
        destinations[alert.dst_ip] += 1
        protocols[alert.protocol or _UNKNOWN] += 1
        applications[alert.application_protocol or _UNKNOWN] += 1
        # Dùng Unix timestamp để phép chia theo giờ không bị làm tròn lên
        # giờ tiếp theo khi timestamp có độ chính xác dưới microsecond.
        hour = int(alert.first_seen // _SECONDS_PER_HOUR)
        hours[hour] += 1

    return {
        "period": period,
        "run_id": run_id,
        "time_basis": "first_seen",
        "top_n": top_n,
        "total_alerts": len(alerts),
        "total_occurrences": occurrences,
        "severity_counts": {level.value: severity[level.value] for level in Severity},
        "sid_counts": {str(sid): count for sid, count in sorted(sids.items())},
        "classtype_counts": dict(sorted(classtypes.items())),
        "top_sids": _top(sids, top_n),
        "top_classtypes": _top(classtypes, top_n),
        "top_src_ips": _top(sources, top_n),
        "top_dst_ips": _top(destinations, top_n),
        "protocol_counts": dict(sorted(protocols.items())),
        "application_protocol_counts": dict(sorted(applications.items())),
        "alerts_by_hour_utc": {
            _utc_text(hour * _SECONDS_PER_HOUR, "hour"): count
            for hour, count in sorted(hours.items())
        },
    }

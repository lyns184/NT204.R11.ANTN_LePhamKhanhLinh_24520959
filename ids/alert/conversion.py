"""Chuyển Detection Event thành Alert ban đầu, trước filter và aggregation."""

import math
from collections.abc import Mapping
from ipaddress import IPv4Address
from typing import Any
from uuid import uuid4

from ids.alert.config import AlertConfig
from ids.alert.models import Alert, AlertConversionResult
from ids.detection.models import MAX_RULE_NUMBER, DetectionEvent


def _timestamp(value: object) -> float:
    try:
        if type(value) in (int, float) and math.isfinite(value):
            return float(value)
    except OverflowError:
        pass
    raise ValueError("timestamp must be a finite number")


def _integer(value: object, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must contain valid Unicode text") from exc
    return value.strip()


def _ip(value: object, name: str) -> str:
    try:
        return str(IPv4Address(_text(value, name)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an IPv4 address") from exc


def _optional_int(record: Mapping[str, Any], name: str, low: int, high: int) -> int | None:
    value = record.get(name)
    return None if value is None else _integer(value, name, low, high)


def _optional_text(record: Mapping[str, Any], name: str) -> str | None:
    value = record.get(name)
    return None if value is None else _text(value, name)


def _protocol(record: Mapping[str, Any], name: str) -> str | None:
    value = _optional_text(record, name)
    if value is None or value.upper() == "UNKNOWN":
        return None
    return value.upper()


def convert_detection(
    detection: DetectionEvent | Mapping[str, Any], config: AlertConfig
) -> AlertConversionResult:
    """Nhận DetectionEvent hoặc dict từ callback Bài 3, không sửa input."""
    record = detection.to_dict() if isinstance(detection, DetectionEvent) else detection
    if not isinstance(record, Mapping):
        return AlertConversionResult(reason="detection must be a DetectionEvent or mapping")

    try:
        timestamp = _timestamp(record.get("timestamp"))
        sid = _integer(record.get("sid"), "sid", 1, MAX_RULE_NUMBER)
        msg = _text(record.get("msg"), "msg")
        src_ip = _ip(record.get("src_ip"), "src_ip")
        dst_ip = _ip(record.get("dst_ip"), "dst_ip")
        src_port = _optional_int(record, "src_port", 0, 65535)
        dst_port = _optional_int(record, "dst_port", 0, 65535)
        protocol = _protocol(record, "protocol")
        if protocol is not None and protocol not in ("TCP", "UDP"):
            raise ValueError("protocol must be TCP, UDP or unknown")
        application_protocol = _protocol(record, "application_protocol")
        flow_id = _optional_text(record, "flow_id")
        classtype = _optional_text(record, "classtype")
        priority = _optional_int(record, "priority", 1, MAX_RULE_NUMBER)
        rev = _optional_int(record, "rev", 1, MAX_RULE_NUMBER)
    except ValueError as exc:
        return AlertConversionResult(reason=str(exc))

    alert = Alert(
        alert_id=str(uuid4()),
        sid=sid,
        msg=msg,
        severity=config.severity_for(priority),
        src_ip=src_ip,
        dst_ip=dst_ip,
        first_seen=timestamp,
        last_seen=timestamp,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        application_protocol=application_protocol,
        flow_id=flow_id,
        classtype=classtype,
        priority=priority,
        rev=rev,
    )
    return AlertConversionResult(alert=alert)

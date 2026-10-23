"""Chọn raw TCP/UDP payload trong ranh giới IPv4; không decode/reassembly."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ids.core.event import IDSEvent
from ids.detection.models import Diagnostic, JSONModel, PayloadStatus, _choice, _integer, _items


@dataclass(frozen=True)
class PayloadResult(JSONModel):
    status: PayloadStatus
    payload: bytes | None = field(default=None, repr=False, metadata={"export": False})
    expected_length: int | None = None
    captured_length: int | None = None
    diagnostics: tuple[Diagnostic, ...] = ()

    def __post_init__(self) -> None:
        _choice(self.status, "payload.status", tuple(item.value for item in PayloadStatus))
        object.__setattr__(self, "status", PayloadStatus(self.status))
        object.__setattr__(self, "diagnostics", _items(self.diagnostics, "payload.diagnostics", Diagnostic))
        for name in ("expected_length", "captured_length"):
            value = getattr(self, name)
            if value is not None:
                _integer(value, name, 0)
        if self.payload is not None and not isinstance(self.payload, bytes):
            raise ValueError("payload must be bytes or None")
        if self.status == PayloadStatus.AVAILABLE:
            if (self.payload is None or self.expected_length != len(self.payload)
                    or self.captured_length is None or self.captured_length < len(self.payload)):
                raise ValueError("available payload requires complete bytes and consistent lengths")
        elif not self.diagnostics:
            raise ValueError("unavailable payload requires diagnostics")
        if self.status in (PayloadStatus.MISSING, PayloadStatus.ERROR) and self.payload is not None:
            raise ValueError("missing/error payload must be None")

    @property
    def payload_length(self) -> int | None:
        return len(self.payload) if self.status == PayloadStatus.AVAILABLE else None

    def to_dict(self) -> dict[str, Any]:
        return {**super().to_dict(), "payload_length": self.payload_length}


class _PayloadIssue(Exception):
    def __init__(self, status: PayloadStatus, code: str, reason: str, keyword: str | None = None):
        super().__init__(reason)
        self.status, self.code, self.keyword = status, code, keyword


def _length(data: Mapping, key: str, low: int, high: int, name: str,
            multiple: int = 1) -> int | None:
    value = data.get(key)
    if value is not None and (type(value) is not int or not low <= value <= high or value % multiple):
        raise _PayloadIssue(PayloadStatus.ERROR, "invalid_payload_field",
                            f"{name} must be an integer in {low}..{high}, multiple of {multiple}", name)
    return value


def _fragment(network: Mapping) -> bool:
    offset = _length(network, "fragment_offset", 0, 8191, "network.fragment_offset")
    flags = network.get("flags")
    if flags is not None:
        parts = flags.split("+") if isinstance(flags, str) and flags else []
        if (not isinstance(flags, str) or len(parts) != len(set(parts))
                or any(part not in ("MF", "DF", "evil") for part in parts)):
            raise _PayloadIssue(PayloadStatus.ERROR, "invalid_payload_field",
                                "network.flags must use canonical IPv4 flag names", "network.flags")
        if "MF" in parts:
            return True
    if offset is not None and offset > 0:
        return True
    if offset is None or flags is None:
        raise _PayloadIssue(PayloadStatus.MISSING, "missing_fragment_metadata",
                            "Cannot establish an unfragmented IPv4 packet without flags/fragment_offset")
    return False


def _prepare(event: IDSEvent) -> PayloadResult:
    raw = event.raw_payload
    provenance = event.payload_extraction_succeeded
    if provenance is False or not isinstance(raw, bytes) or (provenance is not None and type(provenance) is not bool):
        raise _PayloadIssue(PayloadStatus.ERROR, "payload_extraction_error",
                            "Payload extraction failed or raw payload/provenance has invalid type")
    if provenance is None:
        raise _PayloadIssue(PayloadStatus.MISSING, "missing_payload_provenance",
                            "Payload extraction success has not been recorded")
    normalized = event.normalized
    network = normalized.get("network") if isinstance(normalized, Mapping) else None
    transport = normalized.get("transport") if isinstance(normalized, Mapping) else None
    if (not isinstance(network, Mapping) or network.get("protocol") != "IPv4"
            or not isinstance(transport, Mapping) or transport.get("protocol") not in ("TCP", "UDP")):
        raise _PayloadIssue(PayloadStatus.MISSING, "missing_payload_source",
                            "Payload adapter requires normalized IPv4 and TCP/UDP metadata")
    captured = len(raw)
    if _fragment(network):
        return PayloadResult(PayloadStatus.INCOMPLETE, raw, captured_length=captured, diagnostics=(Diagnostic(
            "fragmented_payload", "IPv4 fragment is not a complete application payload; no reassembly",
            category="input"),))
    protocol = transport["protocol"]
    total = _length(network, "total_length", 20, 65535, "network.total_length")
    ip_header = _length(network, "header_length", 20, 60, "network.header_length", 4)
    next_protocol = _length(network, "next_protocol", 0, 255, "network.next_protocol")
    if next_protocol is not None and next_protocol != (6 if protocol == "TCP" else 17):
        raise _PayloadIssue(PayloadStatus.ERROR, "inconsistent_payload_length", "IP and transport protocols disagree")
    transport_length = (_length(transport, "header_length", 20, 60, "transport.header_length", 4)
                        if protocol == "TCP" else _length(transport, "length", 8, 65535, "transport.length"))
    reported = [_length(normalized, "payload_length", 0, 65535, "normalized.payload_length"),
                _length(transport, "payload_length", 0, 65535, "transport.payload_length")]
    if total is None or ip_header is None or transport_length is None:
        raise _PayloadIssue(PayloadStatus.MISSING, "missing_payload_length",
                            "IP total/header length and TCP header length or UDP length are required")
    if total < ip_header or (protocol == "TCP" and total < ip_header + transport_length
                            or protocol == "UDP" and transport_length > total - ip_header):
        raise _PayloadIssue(PayloadStatus.ERROR, "inconsistent_payload_length",
                            "Declared IP/transport lengths cannot contain the payload")
    expected = total - ip_header - transport_length if protocol == "TCP" else transport_length - 8
    known_reported = [value for value in reported if value is not None]
    if (len(set(known_reported)) > 1
            or any(value not in (captured, min(captured, expected)) for value in known_reported)):
        raise _PayloadIssue(PayloadStatus.ERROR, "inconsistent_payload_length",
                            "Reported payload lengths disagree with captured bytes/packet boundaries")
    if captured < expected:
        return PayloadResult(PayloadStatus.INCOMPLETE, raw, expected, captured, (Diagnostic(
            "truncated_payload", f"Captured {captured} payload bytes; expected {expected}", category="input"),))
    diagnostics = () if captured == expected else (Diagnostic(
        "payload_padding_removed", f"Removed {captured - expected} bytes beyond the application payload boundary",
        category="input"),)
    return PayloadResult(PayloadStatus.AVAILABLE, raw[:expected], expected, captured, diagnostics)


def prepare_payload(event: IDSEvent) -> PayloadResult:
    """Dùng provenance được pipeline ghi khi extraction, không dò parse_errors.

    Event tạo trực tiếp phải ghi payload_extraction_succeeded tường minh.
    Không đổi event, không cứu processing_action=skip. Caller giữ nguyên action
    khi chuyển result.payload/status/diagnostics sang InspectionContext.
    """
    if not isinstance(event, IDSEvent):
        raise TypeError("event must be IDSEvent")
    try:
        return _prepare(event)
    except _PayloadIssue as exc:
        return PayloadResult(exc.status, diagnostics=(Diagnostic(
            exc.code, str(exc), category="input", keyword=exc.keyword),))
    except Exception as exc:
        return PayloadResult(PayloadStatus.ERROR, diagnostics=(Diagnostic(
            "payload_preparation_error", f"Payload preparation failed ({type(exc).__name__}): {exc}",
            category="evaluation"),))

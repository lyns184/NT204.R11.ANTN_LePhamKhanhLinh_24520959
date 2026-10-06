"""Kiểm tra IDSEvent, không sửa dữ liệu và không áp dụng chính sách skip."""

import math
from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import Any, Literal

from ids.core.event import IDSEvent


@dataclass(frozen=True)
class ValidationIssue:
    field: str
    code: str
    message: str


@dataclass(frozen=True)
class ValidationResult:
    errors: tuple[ValidationIssue, ...] = ()
    warnings: tuple[ValidationIssue, ...] = ()
    unsupported: bool = False

    @property
    def status(self) -> Literal["valid", "partial", "invalid"]:
        if self.errors:
            return "invalid"
        if self.warnings or self.unsupported:
            return "partial"
        return "valid"


def validate_event(event: IDSEvent) -> ValidationResult:
    """Validation trước normalization; chấp nhận case/whitespace của tên protocol.

    Field tùy chọn có thể thiếu/None. Field bắt buộc thiếu hoặc giá trị
    có kiểu/range sai là lỗi. Unsupported và lỗi Parser/Decoder là cảnh báo.
    Không kiểm tra checksum, không truy cập Scapy và không mutate event.
    """
    errors: list[ValidationIssue] = []
    warnings: list[ValidationIssue] = []
    unsupported = False

    def error(field: str, code: str, message: str) -> None:
        errors.append(ValidationIssue(field, code, message))

    def warning(field: str, code: str, message: str) -> None:
        warnings.append(ValidationIssue(field, code, message))

    def integer(value: Any, field: str, minimum: int, maximum: int | None = None,
                required: bool = False) -> bool:
        if value is None:
            if required:
                error(field, "missing_field", "Required integer is missing")
            return False
        if type(value) is not int:
            error(field, "invalid_type", "Expected an integer, not bool or numeric text")
            return False
        if value < minimum or (maximum is not None and value > maximum):
            error(field, "out_of_range", f"Integer outside {minimum}..{maximum}")
            return False
        return True

    def text(value: Any, field: str, required: bool = False) -> bool:
        if value is None:
            if required:
                error(field, "missing_field", "Required string is missing")
            return False
        if not isinstance(value, str):
            error(field, "invalid_type", "Expected a string")
            return False
        if not value.strip():
            error(field, "missing_field", "String must not be empty")
            return False
        return True

    def section(value: Any, field: str, required: bool = False) -> dict[str, Any]:
        if value is None:
            if required:
                error(field, "missing_field", "Required section is missing")
            else:
                warning(field, "missing_field", "Section is unavailable")
            return {}
        if not isinstance(value, dict):
            error(field, "invalid_type", "Expected a dictionary")
            return {}
        return value

    def protocol(data: dict[str, Any], field: str) -> str | None:
        value = data.get("protocol")
        if not text(value, field, required=True):
            return None
        return value.strip().upper()

    def header_length(data: dict[str, Any], field: str) -> None:
        value = data.get("header_length")
        if integer(value, field, 20, 60) and value % 4:
            error(field, "invalid_value", "Header length must be a multiple of 4 bytes")

    if not isinstance(event, IDSEvent):
        return ValidationResult(errors=(ValidationIssue(
            "event", "invalid_type", "Expected IDSEvent"
        ),))

    integer(getattr(event, "packet_id", None), "packet_id", 1, required=True)
    text(getattr(event, "capture_source", None), "capture_source", required=True)
    timestamp = getattr(event, "timestamp", None)
    if timestamp is None:
        error("timestamp", "missing_field", "Required timestamp is missing")
    elif type(timestamp) not in (int, float):
        error("timestamp", "invalid_type", "Timestamp must be an int or float")
    else:
        try:
            finite = math.isfinite(timestamp)
        except OverflowError:
            finite = False
        if not finite:
            error("timestamp", "invalid_value", "Timestamp must be finite")

    payload_length = getattr(event, "payload_length", None)
    if payload_length is None:
        warning("payload_length", "missing_field", "Payload length is unavailable")
    else:
        integer(payload_length, "payload_length", 0)
    integer(getattr(event, "packet_length", None), "packet_length", 0)

    network = section(getattr(event, "network", None), "network", required=True)
    transport = section(getattr(event, "transport", None), "transport", required=True)
    application = section(getattr(event, "application", None), "application")
    network_protocol = protocol(network, "network.protocol")
    transport_protocol = protocol(transport, "transport.protocol")
    application_protocol = protocol(application, "application.protocol") if application else None
    if not application and getattr(event, "application", None) is not None:
        warning("application", "missing_field", "Application metadata is unavailable")

    if network_protocol == "IPV4":
        for field in ("src_ip", "dst_ip"):
            value = network.get(field)
            if text(value, f"network.{field}", required=True):
                try:
                    IPv4Address(value.strip())
                except ValueError:
                    error(f"network.{field}", "invalid_value", "Expected an IPv4 address")
        for field, low, high in (
            ("version", 4, 4), ("total_length", 20, 65535),
            ("identification", 0, 65535), ("fragment_offset", 0, 8191),
            ("ttl", 0, 255), ("next_protocol", 0, 255), ("checksum", 0, 65535),
        ):
            integer(network.get(field), f"network.{field}", low, high)
        header_length(network, "network.header_length")
        total, header = network.get("total_length"), network.get("header_length")
        if type(total) is int and type(header) is int and total < header:
            error("network.total_length", "inconsistent_value", "IP length is smaller than its header")
    elif network_protocol is not None:
        unsupported = True
        warning("network.protocol", "unsupported_protocol", "Network protocol is outside IPv4 scope")

    if transport_protocol in ("TCP", "UDP"):
        for field in ("src_port", "dst_port"):
            integer(transport.get(field), f"transport.{field}", 0, 65535, required=True)
        length = transport.get("payload_length")
        integer(length, "transport.payload_length", 0)
        if type(length) is int and type(payload_length) is int and length != payload_length:
            error("payload_length", "inconsistent_value", "Event and transport payload lengths differ")
        expected_protocol = 6 if transport_protocol == "TCP" else 17
        if network_protocol == "IPV4" and type(network.get("next_protocol")) is int:
            if network["next_protocol"] != expected_protocol:
                error("network.next_protocol", "inconsistent_value", "IP and transport protocols disagree")
        integer(transport.get("checksum"), "transport.checksum", 0, 65535)
        if transport_protocol == "TCP":
            header_length(transport, "transport.header_length")
            for field, maximum in (
                ("sequence_number", 2**32 - 1), ("acknowledgment_number", 2**32 - 1),
                ("window_size", 65535), ("urgent_pointer", 65535),
            ):
                integer(transport.get(field), f"transport.{field}", 0, maximum)
            if transport.get("flags") is not None:
                text(transport["flags"], "transport.flags")
            flags = transport.get("flags_detail")
            if flags is not None:
                if not isinstance(flags, dict):
                    error("transport.flags_detail", "invalid_type", "Expected a dictionary of booleans")
                elif any(not isinstance(key, str) or type(value) is not bool for key, value in flags.items()):
                    error("transport.flags_detail", "invalid_type", "Flag names must be strings and values booleans")
        else:
            udp_length = transport.get("length")
            integer(udp_length, "transport.length", 8, 65535)
            if type(udp_length) is int and type(length) is int and length > udp_length - 8:
                error("transport.payload_length", "inconsistent_value", "Payload exceeds declared UDP length")
    elif transport_protocol is not None:
        unsupported = True
        warning("transport.protocol", "unsupported_protocol", "Transport protocol is outside TCP/UDP scope")

    if application_protocol not in (None, "HTTP", "DNS", "SMTP", "UNKNOWN"):
        warning("application.protocol", "unsupported_protocol", "Application protocol is outside Parser scope")
    fields = application.get("fields")
    if fields is None:
        if application_protocol not in (None, "UNKNOWN"):
            warning("application.fields", "missing_field", "Application fields are unavailable")
        fields = {}
    elif not isinstance(fields, dict):
        error("application.fields", "invalid_type", "Expected a dictionary")
        fields = {}
    if application_protocol in ("HTTP", "DNS", "SMTP") and not fields:
        warning("application.fields", "incomplete_data", "Recognized protocol has no parsed fields")

    if application_protocol == "HTTP":
        headers = fields.get("headers")
        if headers is not None:
            if not isinstance(headers, dict):
                error("application.fields.headers", "invalid_type", "Expected a dictionary")
            else:
                for key, value in headers.items():
                    if not isinstance(key, str) or not key.strip() or not isinstance(value, str):
                        error("application.fields.headers", "invalid_type", "Header names and values must be strings")
                        break
        message_type = fields.get("message_type")
        if message_type is None and fields:
            warning("application.fields.message_type", "missing_field", "HTTP message type is unavailable")
        elif message_type is not None:
            if not isinstance(message_type, str) or message_type.strip().lower() not in ("request", "response"):
                error("application.fields.message_type", "invalid_value", "Expected request or response")
            elif message_type.strip().lower() == "request":
                text(fields.get("method"), "application.fields.method", required=True)
                text(fields.get("path"), "application.fields.path", required=True)
            else:
                integer(fields.get("status_code"), "application.fields.status_code", 100, 599, required=True)
        integer(fields.get("body_length"), "application.fields.body_length", 0)
        if fields.get("body") is not None and not isinstance(fields["body"], str):
            error("application.fields.body", "invalid_type", "Expected a body string")
    elif application_protocol == "DNS":
        for key, name_field in (("questions", "domain"), ("answers", "name")):
            records = fields.get(key)
            if records is None:
                continue
            if not isinstance(records, list):
                error(f"application.fields.{key}", "invalid_type", "Expected a list")
                continue
            for index, record in enumerate(records):
                path = f"application.fields.{key}[{index}]"
                if not isinstance(record, dict):
                    error(path, "invalid_type", "Expected a record dictionary")
                elif name_field in record:
                    # DNS root is represented by an empty string in the Parser.
                    if not isinstance(record[name_field], str):
                        error(f"{path}.{name_field}", "invalid_type", "Expected a domain string")
    elif application_protocol == "SMTP":
        message_type = fields.get("message_type")
        if message_type is None and fields:
            warning("application.fields.message_type", "missing_field", "SMTP message type is unavailable")
        elif message_type is not None:
            if not isinstance(message_type, str) or message_type.strip().lower() not in ("command", "response"):
                error("application.fields.message_type", "invalid_value", "Expected command or response")
            elif message_type.strip().lower() == "command":
                text(fields.get("command"), "application.fields.command", required=True)
            else:
                integer(fields.get("status_code"), "application.fields.status_code", 200, 599, required=True)

    for key in ("parse_errors", "decode_errors"):
        values = getattr(event, key, None)
        if values is None:
            continue
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            error(key, "invalid_type", "Expected a list of error strings")
        elif values:
            warning(key, "upstream_error", "Parser or Decoder reported errors")
    decode_status = getattr(event, "decode_status", None)
    if decode_status is not None:
        if not isinstance(decode_status, str) or decode_status.strip().lower() not in ("not_processed", "ok", "partial", "error"):
            error("decode_status", "invalid_value", "Unknown Decoder status")
        elif decode_status.strip().lower() in ("partial", "error"):
            warning("decode_status", "upstream_error", "Decoded data is incomplete or invalid")
    decoded = getattr(event, "decoded", None)
    if decoded is not None and not isinstance(decoded, dict):
        error("decoded", "invalid_type", "Expected a dictionary")

    return ValidationResult(tuple(errors), tuple(warnings), unsupported)

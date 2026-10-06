"""Chuẩn hóa biểu diễn trong bản sao riêng, không đổi nội dung payload."""

import json
from copy import deepcopy
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from ids.core.event import IDSEvent, NormalizedEvent
from ids.preprocessor.validation import validate_event


class NormalizationError(ValueError):
    """Dữ liệu không thể chuẩn hóa an toàn; caller điều phối xử lý lỗi này."""


def normalize_protocol(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    name = value.strip().upper()
    return "IPv4" if name == "IPV4" else name


def normalize_domain(value: Any) -> Any:
    """Chuẩn hóa tên DNS, bỏ đúng một dấu chấm biểu diễn root cuối tên."""
    if not isinstance(value, str):
        return value
    return value.strip().lower().removesuffix(".")


def normalize_dns_fields(fields: dict[str, Any]) -> None:
    """Chỉ sửa bản sao fields; TXT và dữ liệu ngoài loại hỗ trợ giữ nguyên."""
    for key in ("questions", "answers"):
        records = fields.get(key)
        if records is None:
            continue
        for record in records:
            name_field = "domain" if key == "questions" else "name"
            if name_field in record:
                record[name_field] = normalize_domain(record[name_field])
            type_field = "query_type" if key == "questions" else "type"
            if isinstance(record.get(type_field), str):
                record[type_field] = record[type_field].strip().upper()
            if key == "questions":
                continue

            data = record.get("data")
            record_type = record.get("type")
            # Dùng type number khi có vì đây là mã loại record trên wire.
            number = record.get("type_number")
            if type(number) is int:
                record_type = {
                    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
                    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
                }.get(number)

            if record_type in ("NS", "CNAME", "PTR") and isinstance(data, str):
                record["data"] = normalize_domain(data)
            elif record_type == "A" and isinstance(data, str):
                record["data"] = str(IPv4Address(data.strip()))
            elif record_type == "AAAA" and isinstance(data, str):
                record["data"] = str(IPv6Address(data.strip()))
            elif isinstance(data, dict):
                domain_key = {"MX": "exchange", "SOA": "mname", "SRV": "target"}.get(record_type)
                if domain_key is not None and domain_key in data:
                    data[domain_key] = normalize_domain(data[domain_key])
                # SOA rname mã hóa mailbox: giữ nguyên để không đổi local-part.


def normalize_event(event: IDSEvent) -> NormalizedEvent:
    """Trả biểu diễn chuẩn hóa; không điền metadata hoặc áp dụng process/skip.

    Validator kiểm tra đầu vào trước khi chuẩn hóa. Invalid input hoặc
    header collision gây NormalizationError, để task điều phối bắt và ghi reason.
    Field thiếu vẫn để nguyên trong section cho module missing-data xử lý sau.
    """
    validation = validate_event(event)
    if validation.errors:
        raise NormalizationError("; ".join(
            f"{issue.field}: {issue.message}" for issue in validation.errors
        ))

    try:
        network = deepcopy(getattr(event, "network", None) or {})
        transport = deepcopy(getattr(event, "transport", None) or {})
        application = deepcopy(getattr(event, "application", None) or {})
        for section in (network, transport, application):
            if "protocol" in section:
                section["protocol"] = normalize_protocol(section["protocol"])

        if network.get("protocol") == "IPv4":
            for key in ("src_ip", "dst_ip"):
                network[key] = str(IPv4Address(network[key].strip()))

        fields = application.get("fields")
        if isinstance(fields, dict):
            if isinstance(fields.get("message_type"), str):
                fields["message_type"] = fields["message_type"].strip().lower()
            if application.get("protocol") == "HTTP":
                headers = fields.get("headers")
                if isinstance(headers, dict):
                    normalized_headers = {}
                    for name, value in headers.items():
                        canonical_name = name.strip().lower()
                        if canonical_name in normalized_headers:
                            raise NormalizationError(
                                f"HTTP headers collide after normalization: {canonical_name}"
                            )
                        normalized_headers[canonical_name] = value
                    fields["headers"] = normalized_headers
                # Giữ nguyên method/path, header values và body; không decode lại.
            elif application.get("protocol") == "DNS":
                normalize_dns_fields(fields)

        normalized: NormalizedEvent = {
            "timestamp": float(event.timestamp),
            "network": network,
            "transport": transport,
            "application": application,
            "payload_length": getattr(event, "payload_length", None),
            "packet_length": getattr(event, "packet_length", None),
        }
        # Không cho bytes, NaN hoặc cyclic data lọt vào vùng xuất JSONL.
        json.dumps(normalized, allow_nan=False)
        return normalized
    except (ValueError, TypeError, OverflowError, RecursionError) as error:
        if isinstance(error, NormalizationError):
            raise
        raise NormalizationError(f"Cannot normalize event safely: {error}") from error

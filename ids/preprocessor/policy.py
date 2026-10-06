"""Biểu diễn missing data và quyết định process/skip; không sửa event gốc."""

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Literal

from ids.core.config import PreprocessorConfig
from ids.core.event import NormalizedEvent, ProcessingAction
from ids.preprocessor.validation import ValidationResult


@dataclass(frozen=True)
class PreprocessDecision:
    status: Literal["valid", "partial", "invalid"]
    action: ProcessingAction
    reason: str | None


def decide_processing(
    validation: ValidationResult,
    config: PreprocessorConfig | None = None,
) -> PreprocessDecision:
    """Invalid có ưu tiên trước unsupported; partial còn dùng được thì process.

    Skip vẫn giữ event để ghi output. Metadata chỉ được trả về ở đây,
    task điều phối sẽ gắn nó lên IDSEvent.
    """
    if not isinstance(validation, ValidationResult):
        raise TypeError("Expected ValidationResult")
    config = config if config is not None else PreprocessorConfig()
    if not isinstance(config, PreprocessorConfig):
        raise TypeError("Expected PreprocessorConfig")

    if validation.status == "invalid":
        action = config.invalid_action
    elif validation.unsupported:
        action = config.unsupported_action
    else:
        action = "process"

    messages = []
    for issue in validation.errors + validation.warnings:
        message = f"{issue.field} [{issue.code}]: {issue.message}"
        if message not in messages:
            messages.append(message)
    if validation.unsupported and not messages:
        messages.append("Unsupported network/transport protocol")
    return PreprocessDecision(validation.status, action, "; ".join(messages) or None)


def fill_missing_data(normalized: NormalizedEvent) -> NormalizedEvent:
    """Bổ sung None/[]/{} trong bản sao; không đổi giá trị đã có hoặc sai kiểu.

    Hàm dùng sau normalization. Không đoán port/IP/length, không tạo dữ liệu
    decoded và không xóa field ngoài schema. Container sai kiểu gây ValueError
    để task điều phối xử lý, thay vì che giấu dữ liệu malformed.
    """
    if not isinstance(normalized, dict):
        raise TypeError("Expected a normalized dictionary")
    result = deepcopy(normalized)

    def scalars(data: dict[str, Any], keys: tuple[str, ...]) -> None:
        for key in keys:
            data.setdefault(key, None)

    def container(data: dict[str, Any], key: str, kind: type) -> Any:
        value = data.get(key)
        if value is None:
            value = kind()
            data[key] = value
        elif not isinstance(value, kind):
            raise ValueError(f"{key} must be a {kind.__name__}")
        return value

    scalars(result, ("timestamp", "payload_length", "packet_length"))
    network = container(result, "network", dict)
    transport = container(result, "transport", dict)
    application = container(result, "application", dict)
    scalars(network, ("protocol", "src_ip", "dst_ip"))
    scalars(transport, ("protocol", "src_port", "dst_port", "payload_length"))
    scalars(application, ("protocol",))
    fields = container(application, "fields", dict)

    def protocol(data: dict[str, Any]) -> str | None:
        value = data.get("protocol")
        return value.strip().upper() if isinstance(value, str) else None

    if protocol(network) == "IPV4":
        scalars(network, (
            "version", "header_length", "total_length", "identification", "flags",
            "fragment_offset", "ttl", "next_protocol", "checksum",
        ))
    if protocol(transport) == "TCP":
        scalars(transport, (
            "sequence_number", "acknowledgment_number", "header_length", "flags",
            "window_size", "checksum", "urgent_pointer",
        ))
        container(transport, "flags_detail", dict)
    elif protocol(transport) == "UDP":
        scalars(transport, ("length", "checksum"))

    application_protocol = protocol(application)
    if application_protocol == "HTTP":
        scalars(fields, (
            "message_type", "version", "method", "path", "status_code", "reason",
            "body", "body_length",
        ))
        container(fields, "headers", dict)
    elif application_protocol == "DNS":
        scalars(fields, (
            "transaction_id", "message_type", "opcode", "authoritative", "truncated",
            "recursion_desired", "recursion_available", "response_code",
            "question_count", "answer_count",
        ))
        for key in ("questions", "answers"):
            records = container(fields, key, list)
            for record in records:
                if not isinstance(record, dict):
                    raise ValueError(f"DNS {key} must contain record dictionaries")
                if key == "questions":
                    scalars(record, ("domain", "query_type", "query_type_number", "query_class"))
                else:
                    scalars(record, ("name", "type", "type_number", "ttl"))
                    record_type = record.get("type")
                    is_txt = record.get("type_number") == 16 or (
                        isinstance(record_type, str) and record_type.strip().upper() == "TXT"
                    )
                    if is_txt:
                        container(record, "data", list)
                    else:
                        scalars(record, ("data",))
    elif application_protocol == "SMTP":
        scalars(fields, (
            "message_type", "command", "argument", "address", "status_code",
            "message", "multiline",
        ))
        container(fields, "lines", list)

    return result

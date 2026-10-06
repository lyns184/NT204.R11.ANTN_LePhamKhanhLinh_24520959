import base64
import math
from dataclasses import dataclass, field, fields
from typing import Any, Literal, TypedDict


PreprocessStatus = Literal["not_processed", "valid", "partial", "invalid"]
ProcessingAction = Literal["process", "skip"]


def _json_safe_copy(value: Any, path: str, errors: list[str],
                    ancestors: set[int], depth: int = 0) -> Any:
    """Sao chép dữ liệu xuất log, không thay đổi dữ liệu trong event."""
    if depth > 64:
        errors.append(f"{path}: nesting exceeds 64 levels; exported null")
        return None
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:
            errors.append(f"{path}: integer exceeds decimal conversion limit; exported hex")
            return {"type": "int", "encoding": "hex", "value": hex(value)}
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            errors.append(f"{path}: non-finite float {value!r}; exported null")
            return None
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        errors.append(f"{path}: binary data exported as Base64")
        return {
            "type": type(value).__name__,
            "encoding": "base64",
            "value": base64.b64encode(bytes(value)).decode("ascii"),
        }
    if isinstance(value, (dict, list, tuple)):
        identity = id(value)
        if identity in ancestors:
            errors.append(f"{path}: circular reference; exported null")
            return None
        ancestors.add(identity)
        try:
            if isinstance(value, dict):
                result = {}
                for key, item in value.items():
                    if not isinstance(key, str):
                        errors.append(f"{path}: non-string key omitted ({type(key).__name__})")
                        continue
                    result[key] = _json_safe_copy(item, f"{path}.{key}", errors, ancestors, depth + 1)
                return result
            return [
                _json_safe_copy(item, f"{path}[{index}]", errors, ancestors, depth + 1)
                for index, item in enumerate(value)
            ]
        finally:
            ancestors.remove(identity)
    errors.append(f"{path}: unsupported type {type(value).__name__}; exported null")
    return None


class NormalizedEvent(TypedDict, total=False):
    """Biểu diễn chuẩn hóa riêng; để rỗng trước khi Preprocessor chạy."""

    timestamp: float | None
    network: dict[str, Any]
    transport: dict[str, Any]
    application: dict[str, Any]
    payload_length: int | None
    packet_length: int | None


@dataclass
class IDSEvent:
    packet_id: int
    timestamp: float
    capture_source: str

    # Dữ liệu do parser Bài 01 tạo ra.
    network: dict[str, Any] = field(default_factory=dict)
    transport: dict[str, Any] = field(default_factory=dict)

    application: dict[str, Any] = field(
        default_factory=lambda: {
            "protocol": "UNKNOWN",
            "fields": {},
        }
    )

    payload_length: int = 0
    parse_errors: list[str] = field(default_factory=list)

    # Dữ liệu nội bộ phục vụ Decoder.
    # Không đưa raw bytes trực tiếp vào JSONL.
    raw_payload: bytes = field(default=b"", repr=False)

    # Chưa thu thập thì để None, không suy ra từ payload_length.
    packet_length: int | None = None

    # Kết quả Decoder: giữ riêng, không ghi đè application.fields.
    decoded: dict[str, Any] = field(default_factory=dict)
    decode_status: str = "not_processed"
    decode_errors: list[str] = field(default_factory=list)

    # Preprocessor giữ kết quả riêng, không sửa dữ liệu Parser/Decoder.
    normalized: NormalizedEvent = field(default_factory=dict)

    # not_processed/None được giữ cho đến khi Preprocessor chạy.
    preprocess_status: PreprocessStatus = "not_processed"
    processing_action: ProcessingAction | None = None
    reason: str | None = None

    # Metadata do Flow Tracker bổ sung.
    flow_id: str | None = None
    direction: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Xuất bản sao JSON-safe, loại raw_payload và giữ nguyên event gốc.

        Bytes ngoài raw_payload được biểu diễn Base64 có nhãn, NaN/Infinity
        thành None. serialization_errors chỉ xuất khi cần chuyển dữ liệu lỗi.
        """
        values = {
            item.name: getattr(self, item.name, None)
            for item in fields(self) if item.name != "raw_payload"
        }
        errors: list[str] = []
        data = _json_safe_copy(values, "event", errors, set())
        if errors:
            data["serialization_errors"] = errors
        return data

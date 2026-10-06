from dataclasses import asdict, dataclass, field
from typing import Any, Literal, TypedDict


PreprocessStatus = Literal["not_processed", "valid", "partial", "invalid"]
ProcessingAction = Literal["process", "skip"]


class NormalizedEvent(TypedDict, total=False):
    """Biểu diễn chuẩn hóa riêng; để rỗng trước khi Preprocessor chạy."""

    timestamp: float
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
        """Xuất event ra dictionary, loại dữ liệu bytes nội bộ."""
        data = asdict(self)
        data.pop("raw_payload", None)
        return data

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class IDSEvent:
    packet_id: int
    timestamp: float
    capture_source: str

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

    def to_dict(self) -> dict[str, Any]:
        """Chuyển IDSEvent sang dictionary để xuất dữ liệu."""
        return asdict(self)
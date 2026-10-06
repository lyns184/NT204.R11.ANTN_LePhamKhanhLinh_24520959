import math
from dataclasses import dataclass

from ids.core.event import ProcessingAction


@dataclass(frozen=True)
class DecoderConfig:
    """Các giới hạn dùng khi giải mã dữ liệu ứng dụng."""

    max_input_bytes: int = 1_048_576
    max_form_fields: int = 1_000

    # Tổng số MIME entities, gồm root và các phần con.
    max_mime_parts: int = 100

    # Root ở depth 0.
    max_mime_depth: int = 8

    def __post_init__(self) -> None:
        limits = {
            "max_input_bytes": self.max_input_bytes,
            "max_form_fields": self.max_form_fields,
            "max_mime_parts": self.max_mime_parts,
            "max_mime_depth": self.max_mime_depth,
        }

        for name, value in limits.items():
            if type(value) is not int or value <= 0:
                raise ValueError(
                    f"{name} phải là số nguyên dương"
                )


@dataclass(frozen=True)
class SMTPDecoderConfig:
    max_sessions: int = 1_000
    idle_timeout_seconds: float = 300.0

    def __post_init__(self) -> None:
        if (
            type(self.max_sessions) is not int
            or self.max_sessions <= 0
        ):
            raise ValueError(
                "max_sessions phải là số nguyên dương"
            )

        timeout = self.idle_timeout_seconds

        if type(timeout) not in (int, float):
            raise ValueError(
                "idle_timeout_seconds phải là số dương hữu hạn"
            )

        try:
            valid_timeout = math.isfinite(timeout) and timeout > 0
        except OverflowError:
            valid_timeout = False

        if not valid_timeout:
            raise ValueError(
                "idle_timeout_seconds phải là số dương hữu hạn"
            )


@dataclass(frozen=True)
class PreprocessorConfig:
    """Chính sách cho event invalid và network/transport không hỗ trợ.

    Application UNKNOWN không tự động thuộc chính sách unsupported:
    event vẫn có thể có IPv4/TCP/UDP đủ để Flow Tracker xử lý.
    """

    invalid_action: ProcessingAction = "skip"
    unsupported_action: ProcessingAction = "skip"

    def __post_init__(self) -> None:
        for name in ("invalid_action", "unsupported_action"):
            value = getattr(self, name)
            if not isinstance(value, str) or value not in ("process", "skip"):
                raise ValueError(
                    f"{name} phải là 'process' hoặc 'skip'"
                )


@dataclass(frozen=True)
class FlowTrackerConfig:
    """Giới hạn bảng flow và lịch kiểm tra timeout của live capture.

    PCAP dùng timestamp event; live cần kiểm tra định kỳ kể cả khi không có
    packet mới. Các giá trị dưới đây là mặc định của project, có thể cấu hình.
    """

    tcp_idle_timeout_seconds: float = 300.0
    udp_idle_timeout_seconds: float = 60.0
    expiration_check_interval_seconds: float = 1.0
    max_active_flows: int = 10_000

    def __post_init__(self) -> None:
        if type(self.max_active_flows) is not int or self.max_active_flows <= 0:
            raise ValueError("max_active_flows phải là số nguyên dương")
        for name in (
            "tcp_idle_timeout_seconds", "udp_idle_timeout_seconds",
            "expiration_check_interval_seconds",
        ):
            value = getattr(self, name)
            try:
                valid = type(value) in (int, float) and math.isfinite(value) and value > 0
            except OverflowError:
                valid = False
            if not valid:
                raise ValueError(f"{name} phải là số dương hữu hạn")

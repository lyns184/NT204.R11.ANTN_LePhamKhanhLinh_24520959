from dataclasses import dataclass
import math


@dataclass(frozen=True)
class DecoderConfig:
    """Các giới hạn dùng khi giải mã dữ liệu ứng dụng."""

    # Giới hạn dữ liệu đầu vào cho mỗi thao tác decode: 1 MiB.
    max_input_bytes: int = 1_048_576

    # Giới hạn số field khi phân tích URL-encoded form.
    max_form_fields: int = 1_000

    def __post_init__(self) -> None:
        limits = {
            "max_input_bytes": self.max_input_bytes,
            "max_form_fields": self.max_form_fields,
        }

        for name, value in limits.items():
            # Không chấp nhận bool dù bool là subclass của int.
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
from dataclasses import dataclass


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
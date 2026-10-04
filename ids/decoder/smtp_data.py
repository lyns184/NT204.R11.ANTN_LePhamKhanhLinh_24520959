from typing import Any

from ids.core.config import DecoderConfig


def extract_smtp_data(
    raw_data: bytes,
    config: DecoderConfig | None = None,
) -> dict[str, Any]:
    """
    Tách một SMTP DATA block từ đầu nội dung email.

    Caller phải xác nhận đang ở giai đoạn DATA.
    Input không chứa command DATA hoặc response 354.
    Hàm chưa tự ghép TCP segment.
    """
    config = config if config is not None else DecoderConfig()

    def failure(
        message: str,
        status: str = "error",
    ) -> dict[str, Any]:
        return {
            "value": None,
            "remaining": b"",
            "status": status,
            "errors": [message],
        }

    if not isinstance(raw_data, bytes):
        return failure("SMTP DATA input must be bytes")

    if len(raw_data) > config.max_input_bytes:
        return failure("SMTP DATA exceeds max_input_bytes")

    # DATA rỗng: ngay từ đầu đã là dòng kết thúc.
    if raw_data.startswith(b".\r\n"):
        return {
            "value": b"",
            "remaining": raw_data[3:],
            "status": "ok",
            "errors": [],
        }

    marker = b"\r\n.\r\n"
    marker_position = raw_data.find(marker)

    if marker_position < 0:
        return failure(
            "SMTP DATA is incomplete; terminator not found",
            "partial",
        )

    # CRLF trước dòng "." vẫn thuộc dòng cuối của email.
    message_end = marker_position + 2
    stuffed_message = raw_data[:message_end]

    remaining = raw_data[
        marker_position + len(marker):
    ]

    # Bỏ một dấu "." ở đầu mỗi dòng có dot-stuffing.
    lines = stuffed_message.split(b"\r\n")

    message = b"\r\n".join(
        line[1:] if line.startswith(b".") else line
        for line in lines
    )

    return {
        "value": message,
        "remaining": remaining,
        "status": "ok",
        "errors": [],
    }
from html import unescape
from typing import Any

from ids.core.config import DecoderConfig


def decode_html_text(
    raw_text: bytes,
    config: DecoderConfig | None = None,
    charset: str = "utf-8",
) -> dict[str, Any]:
    """
    Chuyển bytes thành text và giải mã HTML entities một lần.

    Không thay đổi dữ liệu gốc.
    Bytes không hợp lệ được thay thế và đánh dấu partial.
    """
    config = config or DecoderConfig()

    def failure(message: str) -> dict[str, Any]:
        return {
            "value": None,
            "status": "error",
            "errors": [message],
        }

    if not isinstance(raw_text, bytes):
        return failure("HTML input must be bytes")

    if len(raw_text) > config.max_input_bytes:
        return failure("HTML input exceeds max_input_bytes")

    if not isinstance(charset, str):
        return failure("Charset must be a string")

    charset_aliases = {
        "utf-8": "utf-8",
        "utf8": "utf-8",
        "ascii": "ascii",
        "us-ascii": "ascii",
    }

    encoding = charset_aliases.get(charset.strip().lower())

    if encoding is None:
        return failure(f"Unsupported charset: {charset}")

    errors: list[str] = []

    try:
        text = raw_text.decode(encoding, errors="strict")
    except UnicodeDecodeError:
        text = raw_text.decode(encoding, errors="replace")
        errors.append(f"Invalid bytes for charset {encoding}")

    return {
        "value": unescape(text),
        "status": "partial" if errors else "ok",
        "errors": errors,
    }
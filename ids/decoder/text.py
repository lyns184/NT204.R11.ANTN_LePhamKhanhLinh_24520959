from typing import Any

from ids.core.config import DecoderConfig


def decode_text(
    raw_text: bytes,
    config: DecoderConfig | None = None,
    charset: str = "utf-8",
) -> dict[str, Any]:
    """
    Chuyển bytes thành text theo ASCII hoặc UTF-8.

    Giữ nguyên input. Bytes lỗi được thay thế và đánh dấu partial.
    """
    config = config if config is not None else DecoderConfig()

    def failure(message: str) -> dict[str, Any]:
        return {
            "value": None,
            "status": "error",
            "errors": [message],
        }

    if not isinstance(raw_text, bytes):
        return failure("Text input must be bytes")

    if len(raw_text) > config.max_input_bytes:
        return failure("Text input exceeds max_input_bytes")

    if not isinstance(charset, str):
        return failure("Charset must be a string")

    charset_aliases = {
        "utf-8": "utf-8",
        "utf8": "utf-8",
        "ascii": "ascii",
        "us-ascii": "ascii",
    }

    encoding = charset_aliases.get(
        charset.strip().lower()
    )

    if encoding is None:
        return failure(f"Unsupported text charset: {charset}")

    try:
        text = raw_text.decode(
            encoding,
            errors="strict",
        )
    except UnicodeDecodeError:
        return {
            "value": raw_text.decode(
                encoding,
                errors="replace",
            ),
            "status": "partial",
            "errors": [
                f"Invalid bytes for charset {encoding}"
            ],
        }

    return {
        "value": text,
        "status": "ok",
        "errors": [],
    }
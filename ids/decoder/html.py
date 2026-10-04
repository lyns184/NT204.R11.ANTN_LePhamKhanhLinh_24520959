from html import unescape
from typing import Any

from ids.core.config import DecoderConfig
from ids.decoder.text import decode_text


def decode_html_text(
    raw_text: bytes,
    config: DecoderConfig | None = None,
    charset: str = "utf-8",
) -> dict[str, Any]:
    """
    Character decoding, sau đó giải mã HTML entities một lần.

    Giữ nguyên dữ liệu gốc và trạng thái lỗi character decoding.
    """
    result = decode_text(
        raw_text=raw_text,
        config=config,
        charset=charset,
    )

    if result["value"] is not None:
        result["value"] = unescape(result["value"])

    return result
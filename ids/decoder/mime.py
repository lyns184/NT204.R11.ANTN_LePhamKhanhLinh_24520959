import base64
import binascii
import quopri
import re
from typing import Any

from ids.core.config import DecoderConfig


INVALID_QP_ESCAPE = re.compile(
    rb"=(?![0-9a-fA-F]{2}|\r\n|\n)"
)


def decode_mime_body(
    raw_body: bytes,
    transfer_encoding: str,
    charset: str = "utf-8",
    config: DecoderConfig | None = None,
) -> dict[str, Any]:
    """
    Decode transfer encoding của một MIME text body đầy đủ.

    transfer_encoding và charset do caller lấy từ MIME headers.
    Không thay đổi bytes gốc.
    """
    config = config if config is not None else DecoderConfig()

    def failure(message: str) -> dict[str, Any]:
        return {
            "value": None,
            "status": "error",
            "errors": [message],
        }

    if not isinstance(raw_body, bytes):
        return failure("MIME body must be bytes")

    if len(raw_body) > config.max_input_bytes:
        return failure("MIME body exceeds max_input_bytes")

    if not isinstance(transfer_encoding, str):
        return failure("Transfer encoding must be a string")

    if not isinstance(charset, str):
        return failure("Charset must be a string")

    encoding = transfer_encoding.strip().lower()

    charset_aliases = {
        "utf-8": "utf-8",
        "utf8": "utf-8",
        "ascii": "ascii",
        "us-ascii": "ascii",
    }
    text_encoding = charset_aliases.get(charset.strip().lower())

    if text_encoding is None:
        return failure(f"Unsupported MIME charset: {charset}")

    errors: list[str] = []

    if encoding == "base64":
        # MIME Base64 cho phép xuống dòng và khoảng trắng.
        compact = re.sub(rb"[ \t\r\n]", b"", raw_body)

        try:
            decoded_bytes = base64.b64decode(
                compact,
                validate=True,
            )
        except (binascii.Error, ValueError):
            return failure("Invalid MIME Base64 data")

    elif encoding == "quoted-printable":
        if INVALID_QP_ESCAPE.search(raw_body):
            errors.append("Malformed quoted-printable escape")

        # header=False: dấu _ trong body được giữ nguyên.
        decoded_bytes = quopri.decodestring(
            raw_body,
            header=False,
        )

    elif encoding in ("7bit", "8bit"):
        decoded_bytes = raw_body

        if encoding == "7bit" and any(
            byte > 127 for byte in raw_body
        ):
            errors.append("Non-ASCII byte in MIME 7bit body")

    else:
        return failure(
            f"Unsupported Content-Transfer-Encoding: {encoding}"
        )

    if len(decoded_bytes) > config.max_input_bytes:
        return failure("Decoded MIME body exceeds max_input_bytes")

    try:
        text = decoded_bytes.decode(
            text_encoding,
            errors="strict",
        )
    except UnicodeDecodeError:
        text = decoded_bytes.decode(
            text_encoding,
            errors="replace",
        )
        errors.append(
            f"Invalid bytes for MIME charset {text_encoding}"
        )

    return {
        "value": text,
        "status": "partial" if errors else "ok",
        "errors": errors,
    }
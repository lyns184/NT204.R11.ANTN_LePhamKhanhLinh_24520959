import base64
import binascii
import quopri
import re

from typing import Any

from ids.core.config import DecoderConfig
from email import policy
from email.parser import BytesHeaderParser


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

def decode_mime_message(
    raw_message: bytes,
    config: DecoderConfig | None = None,
) -> dict[str, Any]:
    """
    Decode một MIME message đầy đủ, gồm headers và body.

    Caller phải xác định ranh giới message trước khi gọi.
    Hàm không tự ghép TCP segment hoặc bỏ SMTP terminator.
    """
    config = config if config is not None else DecoderConfig()

    def failure(
        message: str,
        status: str = "error",
    ) -> dict[str, Any]:
        return {
            "value": None,
            "status": status,
            "errors": [message],
        }

    if not isinstance(raw_message, bytes):
        return failure("MIME message must be bytes")

    if len(raw_message) > config.max_input_bytes:
        return failure("MIME message exceeds max_input_bytes")

    if b"\r\n\r\n" in raw_message:
        header_data, body = raw_message.split(b"\r\n\r\n", 1)
    elif b"\n\n" in raw_message:
        header_data, body = raw_message.split(b"\n\n", 1)
    else:
        return failure("MIME headers are incomplete", "partial")

    try:
        headers = BytesHeaderParser(
            policy=policy.default,
        ).parsebytes(header_data + b"\r\n\r\n")
    except Exception as error:
        return failure(f"MIME header parsing failed: {error}")

    # Không chọn tùy ý khi có nhiều header quyết định cách decode.
    for name in (
        "Content-Type",
        "Content-Transfer-Encoding",
        "MIME-Version",
    ):
        if len(headers.get_all(name, [])) > 1:
            return failure(f"Multiple {name} headers")

    content_type = headers.get_content_type()

    if headers.get_content_maintype() == "multipart":
        return failure(
            "Multipart MIME is not supported yet",
            "partial",
        )

    if content_type not in ("text/plain", "text/html"):
        return failure(
            f"Unsupported MIME content type: {content_type}",
            "partial",
        )

    # MIME text mặc định dùng US-ASCII khi không khai báo charset.
    charset = headers.get_content_charset() or "us-ascii"

    # Khi thiếu Content-Transfer-Encoding, mặc định là 7bit.
    transfer_encoding = str(
        headers.get("Content-Transfer-Encoding", "7bit")
    ).strip().lower()

    result = decode_mime_body(
        raw_body=body,
        transfer_encoding=transfer_encoding,
        charset=charset,
        config=config,
    )

    header_errors = [
        f"MIME header defect: {type(defect).__name__}"
        for defect in headers.defects
    ]

    for name in ("Content-Type", "Content-Transfer-Encoding"):
        header = headers.get(name)

        for defect in getattr(header, "defects", ()):
            header_errors.append(
                f"{name} defect: {type(defect).__name__}"
            )

    if header_errors:
        result["errors"].extend(header_errors)

        if result["status"] == "ok":
            result["status"] = "partial"

    result["content_type"] = content_type
    result["charset"] = charset
    result["transfer_encoding"] = transfer_encoding

    return result
import re
from typing import Any
from urllib.parse import unquote_to_bytes

from ids.core.config import DecoderConfig
from ids.core.event import IDSEvent
from email.message import Message
from ids.decoder.html import decode_html_text
from ids.decoder.text import decode_text

INVALID_PERCENT = re.compile(rb"%(?![0-9a-fA-F]{2})")


def check_input(
    raw: bytes,
    config: DecoderConfig,
) -> str | None:
    """Kiểm tra kiểu và giới hạn đầu vào trước khi decode."""
    if not isinstance(raw, bytes):
        return "Input must be bytes"

    if len(raw) > config.max_input_bytes:
        return "Input exceeds max_input_bytes"

    return None


def decode_component(raw: bytes) -> dict[str, Any]:
    """Decode percent một lần, sau đó chuyển bytes thành UTF-8."""
    errors: list[str] = []

    if INVALID_PERCENT.search(raw):
        errors.append("Malformed percent escape")

    decoded_bytes = unquote_to_bytes(raw)

    try:
        text = decoded_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        errors.append("Invalid UTF-8 byte sequence")
        text = decoded_bytes.decode("utf-8", errors="replace")

    return {
        "value": text,
        "status": "partial" if errors else "ok",
        "errors": errors,
    }


def decode_uri(
    raw_uri: bytes,
    config: DecoderConfig | None = None,
) -> dict[str, Any]:
    """Decode URI, không đổi dấu + và không sửa dữ liệu gốc."""
    config = config if config is not None else DecoderConfig()
    error = check_input(raw_uri, config)

    if error is not None:
        return {
            "value": None,
            "status": "error",
            "errors": [error],
        }

    return decode_component(raw_uri)


def decode_form(
    raw_body: bytes,
    config: DecoderConfig | None = None,
) -> dict[str, Any]:
    """Decode URL-encoded form, giữ thứ tự và các tên field trùng."""
    config = config if config is not None else DecoderConfig()
    error = check_input(raw_body, config)

    if error is not None:
        return {
            "value": None,
            "status": "error",
            "errors": [error],
        }

    # Kiểm tra số phần trước khi tạo danh sách bằng split().
    field_count = raw_body.count(b"&") + 1 if raw_body else 0

    if field_count > config.max_form_fields:
        return {
            "value": None,
            "status": "error",
            "errors": ["Form exceeds max_form_fields"],
        }

    fields: list[dict[str, str]] = []
    errors: list[str] = []

    for index, part in enumerate(raw_body.split(b"&"), start=1):
        if not part:
            continue

        # Tách delimiter trước khi decode để %26 không trở thành
        # dấu phân cách field và %3D không trở thành delimiter mới.
        raw_name, _, raw_value = part.partition(b"=")

        name_result = decode_component(
            raw_name.replace(b"+", b" ")
        )
        value_result = decode_component(
            raw_value.replace(b"+", b" ")
        )

        fields.append({
            "name": name_result["value"],
            "value": value_result["value"],
        })

        for message in name_result["errors"]:
            errors.append(f"Field {index} name: {message}")

        for message in value_result["errors"]:
            errors.append(f"Field {index} value: {message}")

    return {
        "value": fields,
        "status": "partial" if errors else "ok",
        "errors": errors,
    }

def decode_http_request_uri(
    event: IDSEvent,
    config: DecoderConfig | None = None,
) -> dict[str, Any]:
    """Lấy request-target từ dòng HTTP gốc và decode một lần."""
    config = config if config is not None else DecoderConfig()
    payload = event.raw_payload

    # Chỉ đọc dòng đầu, không chuyển toàn bộ payload thành text.
    first_line, separator, _ = payload.partition(b"\n")

    if not separator:
        return {
            "value": None,
            "status": "error",
            "errors": ["Incomplete HTTP request line"],
        }

    first_line = first_line.removesuffix(b"\r")
    parts = first_line.split(b" ", 2)

    if len(parts) != 3:
        return {
            "value": None,
            "status": "error",
            "errors": ["Malformed HTTP request line"],
        }

    method, raw_uri, version = parts

    if not method or not raw_uri or version not in (
        b"HTTP/1.0",
        b"HTTP/1.1",
    ):
        return {
            "value": None,
            "status": "error",
            "errors": ["Invalid HTTP request line"],
        }

    return decode_uri(raw_uri, config)

def extract_http_body(
    event: IDSEvent,
    config: DecoderConfig | None = None,
) -> dict[str, Any]:
    """Lấy body đầy đủ của một HTTP message trong packet hiện tại."""
    config = config if config is not None else DecoderConfig()
    headers = event.application.get("fields", {}).get("headers", {})

    def failure(
        message: str,
        status: str = "partial",
    ) -> dict[str, Any]:
        return {
            "value": None,
            "status": status,
            "errors": [message],
        }

    if (
        event.network.get("fragment_offset", 0) != 0
        or "MF" in str(event.network.get("flags", ""))
    ):
        return failure("IP fragment reassembly is not available")

    payload_size = event.transport.get("payload_length")

    if type(payload_size) is not int or payload_size < 0:
        return failure("Transport payload length is unavailable", "error")

    if payload_size > len(event.raw_payload):
        return failure("Captured transport payload is incomplete")

    payload = event.raw_payload[:payload_size]

    if b"\r\n\r\n" in payload:
        header_data, body = payload.split(b"\r\n\r\n", 1)
    elif b"\n\n" in payload:
        header_data, body = payload.split(b"\n\n", 1)
    else:
        return failure("HTTP headers are incomplete")

    # Kiểm tra raw headers vì parser có thể ghi đè header trùng.
    raw_headers: dict[bytes, list[bytes]] = {}

    for line in header_data.splitlines()[1:]:
        name, separator, value = line.partition(b":")

        if separator:
            key = name.strip().lower()
            raw_headers.setdefault(key, []).append(value.strip())

    if (
        b"transfer-encoding" in raw_headers
        or headers.get("transfer-encoding", "").strip()
    ):
        return failure("Transfer-Encoding is not supported yet")

    encoding_values = raw_headers.get(b"content-encoding", [])

    if len(encoding_values) > 1:
        return failure("Multiple Content-Encoding headers", "error")

    content_encoding = headers.get(
        "content-encoding", ""
    ).strip().lower()

    if content_encoding not in ("", "identity"):
        return failure(
            f"Content-Encoding is not supported: {content_encoding}"
        )

    length_values = raw_headers.get(b"content-length", [])

    if not length_values:
        return failure("Content-Length is missing; body boundary unknown")

    if len(length_values) != 1:
        return failure("Multiple Content-Length headers", "error")

    raw_length = length_values[0]

    if re.fullmatch(rb"[0-9]+", raw_length) is None:
        return failure("Invalid Content-Length", "error")

    try:
        declared_length = int(raw_length)
    except ValueError:
        return failure("Invalid Content-Length", "error")

    if declared_length > config.max_input_bytes:
        return failure("HTTP body exceeds max_input_bytes", "error")

    if len(body) < declared_length:
        return failure(
            "HTTP body is incomplete; TCP stream reassembly required"
        )

    return {
        "value": body[:declared_length],
        "status": "ok",
        "errors": [],
    }


def decode_http_form_body(
    event: IDSEvent,
    config: DecoderConfig | None = None,
) -> dict[str, Any] | None:
    """Decode URL-encoded form body."""
    headers = event.application.get("fields", {}).get("headers", {})

    content_type = Message()
    content_type["Content-Type"] = headers.get("content-type", "")

    if (
        content_type.get_content_type()
        != "application/x-www-form-urlencoded"
    ):
        return None

    charset = content_type.get_content_charset() or "utf-8"

    if charset not in ("utf-8", "utf8", "ascii", "us-ascii"):
        return {
            "value": None,
            "status": "partial",
            "errors": [f"Unsupported form charset: {charset}"],
        }

    body_result = extract_http_body(event, config)

    if body_result["status"] != "ok":
        return body_result

    result = decode_form(body_result["value"], config)

    if (
        charset in ("ascii", "us-ascii")
        and result["value"] is not None
    ):
        try:
            for item in result["value"]:
                item["name"].encode("ascii")
                item["value"].encode("ascii")
        except UnicodeEncodeError:
            result["status"] = "partial"
            result["errors"].append(
                "Decoded form contains non-ASCII characters"
            )

    return result


def decode_http_html_body(
    event: IDSEvent,
    config: DecoderConfig | None = None,
) -> dict[str, Any] | None:
    """Decode HTML entities khi Content-Type là text/html."""
    headers = event.application.get("fields", {}).get("headers", {})

    content_type = Message()
    content_type["Content-Type"] = headers.get("content-type", "")

    if content_type.get_content_type() != "text/html":
        return None

    body_result = extract_http_body(event, config)

    if body_result["status"] != "ok":
        return body_result

    charset = content_type.get_content_charset() or "utf-8"

    return decode_html_text(
        raw_text=body_result["value"],
        config=config,
        charset=charset,
    )

def decode_http_text_body(
    event: IDSEvent,
    config: DecoderConfig | None = None,
) -> dict[str, Any] | None:
    """Character decoding cho HTTP body có Content-Type text/plain."""
    headers = event.application.get(
        "fields", {}
    ).get("headers", {})

    raw_content_type = headers.get("content-type", "").strip()
    if not raw_content_type:
        return None

    content_type = Message()
    content_type["Content-Type"] = raw_content_type

    if content_type.get_content_type() != "text/plain":
        return None

    body_result = extract_http_body(
        event,
        config,
    )

    if body_result["status"] != "ok":
        return body_result

    # Chính sách hiện tại: dùng UTF-8 nếu không khai báo charset.
    charset = content_type.get_content_charset() or "utf-8"

    return decode_text(
        raw_text=body_result["value"],
        config=config,
        charset=charset,
    )

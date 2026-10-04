import re
from typing import Any
from urllib.parse import unquote_to_bytes

from ids.core.config import DecoderConfig


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
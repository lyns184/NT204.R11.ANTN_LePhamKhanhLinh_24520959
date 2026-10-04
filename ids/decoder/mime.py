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

def split_mime_headers(raw: bytes) -> tuple[bytes, bytes]:
    """Tách headers/body, kể cả phần có headers rỗng."""
    if raw.startswith(b"\r\n"):
        return b"", raw[2:]

    if raw.startswith(b"\n"):
        return b"", raw[1:]

    if b"\r\n\r\n" in raw:
        return tuple(raw.split(b"\r\n\r\n", 1))

    if b"\n\n" in raw:
        return tuple(raw.split(b"\n\n", 1))

    raise ValueError("MIME headers are incomplete")


def split_multipart_body(
    body: bytes,
    boundary: str,
    remaining_parts: int,
) -> list[bytes]:
    """Tách boundary có giới hạn, yêu cầu closing boundary."""
    try:
        boundary_bytes = boundary.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("MIME boundary must be ASCII") from None

    if (
        not 1 <= len(boundary_bytes) <= 70
        or re.fullmatch(
            rb"[0-9A-Za-z'()+_,./:=? -]+",
            boundary_bytes,
        ) is None
        or boundary_bytes.endswith(b" ")
    ):
        raise ValueError("Invalid MIME boundary")

    pattern = re.compile(
        rb"(?m)^--"
        + re.escape(boundary_bytes)
        + rb"(?P<closing>--)?[ \t]*(?:\r?\n|$)"
    )

    parts: list[bytes] = []
    part_start: int | None = None
    closed = False

    for match in pattern.finditer(body):
        if part_start is not None:
            if len(parts) >= remaining_parts:
                raise ValueError("MIME exceeds max_mime_parts")

            part_end = match.start()

            # Một newline trước boundary thuộc delimiter.
            if body[part_start:part_end].endswith(b"\r\n"):
                part_end -= 2
            elif body[part_start:part_end].endswith(b"\n"):
                part_end -= 1

            parts.append(body[part_start:part_end])

        if match.group("closing"):
            closed = True
            break

        part_start = match.end()

    if not closed:
        raise ValueError("MIME closing boundary is missing")

    if not parts:
        raise ValueError("Multipart MIME has no body parts")

    return parts


def decode_mime_message(
    raw_message: bytes,
    config: DecoderConfig | None = None,
) -> dict[str, Any]:
    """
    Decode single-part hoặc multipart MIME text.

    Duyệt bằng stack, giới hạn kích thước, số phần và độ sâu.
    Caller phải cung cấp message đầy đủ, đã bỏ SMTP framing.
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

    # Stack item: raw entity, part ID, depth.
    pending = [(raw_message, "0", 0)]
    created_parts = 1

    leaf_results: list[dict[str, Any]] = []
    container_errors: list[str] = []
    root_content_type = ""
    root_is_multipart = False

    while pending:
        raw_entity, part_id, depth = pending.pop()

        try:
            header_data, body = split_mime_headers(raw_entity)
        except ValueError as error:
            result = failure(str(error), "partial")
            result["part_id"] = part_id
            leaf_results.append(result)
            continue

        try:
            headers = BytesHeaderParser(
                policy=policy.default,
            ).parsebytes(header_data + b"\r\n\r\n")
        except Exception as error:
            result = failure(f"MIME header parsing failed: {error}")
            result["part_id"] = part_id
            leaf_results.append(result)
            continue

        content_type = headers.get_content_type()
        charset = headers.get_content_charset() or "us-ascii"
        transfer_encoding = str(
            headers.get("Content-Transfer-Encoding", "7bit")
        ).strip().lower()

        metadata = {
            "part_id": part_id,
            "content_type": content_type,
            "charset": charset,
            "transfer_encoding": transfer_encoding,
        }

        if part_id == "0":
            root_content_type = content_type
            root_is_multipart = (
                headers.get_content_maintype() == "multipart"
            )

        duplicate_name = next(
            (
                name
                for name in (
                    "Content-Type",
                    "Content-Transfer-Encoding",
                    "MIME-Version",
                )
                if len(headers.get_all(name, [])) > 1
            ),
            None,
        )

        if duplicate_name is not None:
            result = failure(f"Multiple {duplicate_name} headers")
            result.update(metadata)
            leaf_results.append(result)
            continue

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

        if headers.get_content_maintype() == "multipart":
            container_errors.extend(
                f"Part {part_id}: {message}"
                for message in header_errors
            )

            if transfer_encoding not in ("7bit", "8bit", "binary"):
                return failure(
                    f"Part {part_id}: Invalid multipart transfer encoding"
                )

            # Digest có quy tắc mặc định riêng cho message/rfc822.
            if content_type == "multipart/digest":
                result = failure(
                    "Multipart digest is not supported yet",
                    "partial",
                )
                result.update(metadata)
                leaf_results.append(result)
                continue

            boundary = headers.get_boundary()

            if not boundary:
                result = failure("MIME boundary is missing", "partial")
                result.update(metadata)
                leaf_results.append(result)
                continue

            if depth >= config.max_mime_depth:
                return failure("MIME exceeds max_mime_depth")

            try:
                children = split_multipart_body(
                    body=body,
                    boundary=boundary,
                    remaining_parts=(
                        config.max_mime_parts - created_parts
                    ),
                )
            except ValueError as error:
                message = str(error)

                if message == "MIME exceeds max_mime_parts":
                    return failure(message)

                result = failure(message, "partial")
                result.update(metadata)
                leaf_results.append(result)
                continue

            created_parts += len(children)

            # Push ngược để kết quả giữ thứ tự các phần trong email.
            for index in range(len(children) - 1, -1, -1):
                pending.append((
                    children[index],
                    f"{part_id}.{index + 1}",
                    depth + 1,
                ))

            continue

        if content_type not in ("text/plain", "text/html"):
            result = failure(
                f"Unsupported MIME content type: {content_type}",
                "partial",
            )
        else:
            result = decode_mime_body(
                raw_body=body,
                transfer_encoding=transfer_encoding,
                charset=charset,
                config=config,
            )

        result["errors"].extend(header_errors)

        if header_errors and result["status"] == "ok":
            result["status"] = "partial"

        result.update(metadata)
        leaf_results.append(result)

    # Giữ cấu trúc single-part cũ: value là text.
    if not root_is_multipart and len(leaf_results) == 1:
        return leaf_results[0]

    errors = list(container_errors)

    for result in leaf_results:
        errors.extend(
            f"Part {result['part_id']}: {message}"
            for message in result["errors"]
        )

    statuses = [result["status"] for result in leaf_results]

    if not errors and statuses and all(s == "ok" for s in statuses):
        status = "ok"
    elif (
        not container_errors
        and statuses
        and all(s == "error" for s in statuses)
    ):
        status = "error"
    else:
        status = "partial"

    return {
        "value": leaf_results,
        "status": status,
        "errors": errors,
        "content_type": root_content_type,
        "parts_count": len(leaf_results),
    }
from typing import Any

from scapy.packet import Packet

from ids.parsers.application.detector import get_transport_payload


HTTP_METHODS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "PATCH",
    "CONNECT",
    "TRACE",
}

HTTP_VERSIONS = {
    "HTTP/1.0",
    "HTTP/1.1",
}


def parse_headers(header_lines: list[bytes]) -> dict[str, str]:
    """Chuyển các HTTP header thành dictionary."""
    headers: dict[str, str] = {}

    for line in header_lines:
        if b":" not in line:
            continue

        name, value = line.split(b":", 1)

        header_name = name.decode(
            "iso-8859-1",
            errors="replace",
        ).strip().lower()

        header_value = value.decode(
            "iso-8859-1",
            errors="replace",
        ).strip()

        if header_name:
            headers[header_name] = header_value

    return headers


def parse_http(packet: Packet) -> dict[str, Any] | None:
    """
    Phân tích HTTP/1.x request hoặc response.

    Trả về None nếu payload không phải HTTP hợp lệ.
    """
    payload = get_transport_payload(packet)

    if not payload:
        return None

    if b"\r\n\r\n" in payload:
        header_data, body = payload.split(b"\r\n\r\n", 1)
        header_lines = header_data.split(b"\r\n")
    elif b"\n\n" in payload:
        header_data, body = payload.split(b"\n\n", 1)
        header_lines = header_data.split(b"\n")
    else:
        body = b""
        header_lines = payload.splitlines()

    if not header_lines:
        return None

    first_line = header_lines[0].decode(
        "iso-8859-1",
        errors="replace",
    ).strip()

    headers = parse_headers(header_lines[1:])

    body_text = body.decode(
        "utf-8",
        errors="replace",
    )

    # HTTP response: HTTP/1.1 200 OK
    if first_line.startswith("HTTP/"):
        parts = first_line.split(" ", 2)

        if len(parts) < 2:
            return None

        version = parts[0]

        if version not in HTTP_VERSIONS:
            return None

        try:
            status_code = int(parts[1])
        except ValueError:
            return None

        reason = parts[2] if len(parts) == 3 else ""

        return {
            "message_type": "response",
            "version": version,
            "status_code": status_code,
            "reason": reason,
            "headers": headers,
            "body": body_text,
            "body_length": len(body),
        }

    # HTTP request: GET /index.html HTTP/1.1
    parts = first_line.split(" ", 2)

    if len(parts) != 3:
        return None

    method, path, version = parts

    if method not in HTTP_METHODS:
        return None

    if version not in HTTP_VERSIONS:
        return None

    return {
        "message_type": "request",
        "method": method,
        "path": path,
        "version": version,
        "headers": headers,
        "body": body_text,
        "body_length": len(body),
    }
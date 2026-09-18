from typing import Any

from scapy.packet import Packet

from ids.parsers.application.detector import get_transport_payload


SIMPLE_COMMANDS = {
    "HELO",
    "EHLO",
    "DATA",
    "QUIT",
    "RSET",
    "NOOP",
    "VRFY",
    "EXPN",
    "STARTTLS",
    "AUTH",
}


def parse_smtp(packet: Packet) -> dict[str, Any] | None:
    """
    Phân tích SMTP command hoặc SMTP response.

    Trả về None nếu payload không phải SMTP hợp lệ.
    """
    payload = get_transport_payload(packet)

    if not payload:
        return None

    text = payload.decode(
        "utf-8",
        errors="replace",
    )

    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
    ]

    if not lines:
        return None

    first_line = lines[0]
    upper_line = first_line.upper()

    # SMTP response: 250 OK hoặc 250-First line
    is_response = (
        len(first_line) >= 4
        and first_line[:3].isdigit()
        and first_line[3] in (" ", "-")
    )

    if is_response:
        return {
            "message_type": "response",
            "status_code": int(first_line[:3]),
            "message": first_line[4:].strip(),
            "multiline": first_line[3] == "-",
            "lines": lines,
        }

    # MAIL FROM:<sender@example.com>
    if upper_line.startswith("MAIL FROM:"):
        argument = first_line[len("MAIL FROM:"):].strip()

        return {
            "message_type": "command",
            "command": "MAIL FROM",
            "argument": argument,
            "address": argument.strip("<>"),
        }

    # RCPT TO:<receiver@example.com>
    if upper_line.startswith("RCPT TO:"):
        argument = first_line[len("RCPT TO:"):].strip()

        return {
            "message_type": "command",
            "command": "RCPT TO",
            "argument": argument,
            "address": argument.strip("<>"),
        }

    parts = first_line.split(maxsplit=1)
    command = parts[0].upper()
    argument = parts[1] if len(parts) == 2 else ""

    if command not in SIMPLE_COMMANDS:
        return None

    return {
        "message_type": "command",
        "command": command,
        "argument": argument,
    }
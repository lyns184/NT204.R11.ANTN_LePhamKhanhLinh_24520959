from scapy.layers.dns import DNS
from scapy.layers.inet import TCP, UDP
from scapy.packet import Packet


HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
)

HTTP_RESPONSES = (
    b"HTTP/1.0 ",
    b"HTTP/1.1 ",
)

SMTP_COMMANDS = (
    b"HELO ",
    b"EHLO ",
    b"MAIL FROM:",
    b"RCPT TO:",
    b"DATA",
    b"QUIT",
    b"RSET",
    b"NOOP",
    b"VRFY ",
    b"EXPN ",
    b"STARTTLS",
    b"AUTH ",
)

SMTP_PORTS = {
    25,
    465,
    587,
    2525,
}


def get_transport_payload(packet: Packet) -> bytes:
    """Lấy payload của TCP hoặc UDP."""
    if packet.haslayer(TCP):
        return bytes(packet[TCP].payload)

    if packet.haslayer(UDP):
        return bytes(packet[UDP].payload)

    return b""


def get_transport_ports(packet: Packet) -> set[int]:
    """Lấy cổng nguồn và cổng đích."""
    if packet.haslayer(TCP):
        return {
            int(packet[TCP].sport),
            int(packet[TCP].dport),
        }

    if packet.haslayer(UDP):
        return {
            int(packet[UDP].sport),
            int(packet[UDP].dport),
        }

    return set()


def looks_like_http(payload: bytes) -> bool:
    """Kiểm tra HTTP request hoặc HTTP response."""
    upper_payload = payload.upper()

    return (
        upper_payload.startswith(HTTP_METHODS)
        or upper_payload.startswith(HTTP_RESPONSES)
    )


def looks_like_smtp(payload: bytes, ports: set[int]) -> bool:
    """Kiểm tra SMTP command hoặc SMTP response."""
    first_line = payload.split(b"\r\n", 1)[0].upper()

    if first_line.startswith(SMTP_COMMANDS):
        return True

    is_response = (
        len(first_line) >= 4
        and first_line[:3].isdigit()
        and first_line[3:4] in (b" ", b"-")
    )

    return is_response and bool(ports & SMTP_PORTS)


def looks_like_dns(packet: Packet, payload: bytes) -> bool:
    """Kiểm tra cấu trúc DNS trên port chuẩn hoặc không chuẩn."""
    if packet.haslayer(DNS):
        return True

    dns_payload = payload

    if packet.haslayer(TCP):
        if len(payload) < 2:
            return False

        declared_length = int.from_bytes(
            payload[:2],
            byteorder="big",
        )

        if declared_length != len(payload) - 2:
            return False

        dns_payload = payload[2:]

    if len(dns_payload) < 12:
        return False

    try:
        dns_layer = DNS(dns_payload)
    except Exception:
        return False

    counts = [
        int(dns_layer.qdcount or 0),
        int(dns_layer.ancount or 0),
        int(dns_layer.nscount or 0),
        int(dns_layer.arcount or 0),
    ]

    if any(count > 100 for count in counts):
        return False

    return sum(counts) > 0


def detect_application_protocol(packet: Packet) -> str:
    """
    Nhận diện giao thức ứng dụng bằng payload và port.

    Kết quả: HTTP, DNS, SMTP hoặc UNKNOWN.
    """
    payload = get_transport_payload(packet)

    if not payload:
        return "UNKNOWN"

    ports = get_transport_ports(packet)

    if looks_like_http(payload):
        return "HTTP"

    if looks_like_smtp(payload, ports):
        return "SMTP"

    if looks_like_dns(packet, payload):
        return "DNS"

    return "UNKNOWN"
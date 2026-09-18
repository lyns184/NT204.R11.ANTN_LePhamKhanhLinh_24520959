from typing import Any

from scapy.layers.dns import DNS
from scapy.layers.inet import TCP
from scapy.packet import Packet

from ids.parsers.application.detector import (
    get_transport_payload,
    looks_like_dns,
)


DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


def decode_dns_value(value: Any) -> str:
    """Chuyển tên miền hoặc dữ liệu DNS thành chuỗi."""
    if isinstance(value, bytes):
        return value.decode(
            "utf-8",
            errors="replace",
        ).rstrip(".")

    return str(value).rstrip(".")


def get_dns_records(section: Any, count: int) -> list[Any]:
    """Lấy các record từ một section của DNS."""
    if section is None or count <= 0:
        return []

    if isinstance(section, list):
        return section[:count]

    records = []
    current = section

    while current is not None and len(records) < count:
        records.append(current)

        next_record = getattr(current, "payload", None)

        if next_record is None:
            break

        if next_record.__class__.__name__ == "NoPayload":
            break

        current = next_record

    return records


def extract_dns_layer(packet: Packet) -> DNS | None:
    """Lấy lớp DNS từ packet hoặc phân tích từ raw payload."""
    if packet.haslayer(DNS):
        return packet[DNS]

    payload = get_transport_payload(packet)

    if not looks_like_dns(packet, payload):
        return None

    if packet.haslayer(TCP):
        payload = payload[2:]

    try:
        return DNS(payload)
    except Exception:
        return None


def parse_dns(packet: Packet) -> dict[str, Any] | None:
    """
    Phân tích DNS Query hoặc DNS Response.

    Trả về None nếu packet không phải DNS hợp lệ.
    """
    dns_layer = extract_dns_layer(packet)

    if dns_layer is None:
        return None

    question_count = int(dns_layer.qdcount or 0)
    answer_count = int(dns_layer.ancount or 0)

    questions = []

    for question in get_dns_records(
        dns_layer.qd,
        question_count,
    ):
        query_type_number = int(question.qtype)

        questions.append(
            {
                "domain": decode_dns_value(question.qname),
                "query_type": DNS_TYPES.get(
                    query_type_number,
                    str(query_type_number),
                ),
                "query_type_number": query_type_number,
                "query_class": int(question.qclass),
            }
        )

    answers = []

    for answer in get_dns_records(
        dns_layer.an,
        answer_count,
    ):
        answer_type_number = int(answer.type)

        answers.append(
            {
                "name": decode_dns_value(answer.rrname),
                "type": DNS_TYPES.get(
                    answer_type_number,
                    str(answer_type_number),
                ),
                "type_number": answer_type_number,
                "ttl": int(answer.ttl),
                "data": decode_dns_value(answer.rdata),
            }
        )

    return {
        "transaction_id": int(dns_layer.id),
        "message_type": (
            "response"
            if int(dns_layer.qr) == 1
            else "query"
        ),
        "opcode": int(dns_layer.opcode),
        "authoritative": bool(dns_layer.aa),
        "truncated": bool(dns_layer.tc),
        "recursion_desired": bool(dns_layer.rd),
        "recursion_available": bool(dns_layer.ra),
        "response_code": int(dns_layer.rcode),
        "question_count": question_count,
        "answer_count": answer_count,
        "questions": questions,
        "answers": answers,
    }
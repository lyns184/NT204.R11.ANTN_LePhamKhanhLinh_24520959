import time

from scapy.packet import Packet

from ids.core.event import IDSEvent
from ids.parsers.network.ipv4 import parse_ipv4
from ids.parsers.transport.tcp import parse_tcp
from ids.parsers.transport.udp import parse_udp
from ids.parsers.application.detector import detect_application_protocol
from ids.parsers.application.http import parse_http
from ids.parsers.application.dns import parse_dns
from ids.parsers.application.smtp import parse_smtp

def process_packet(
    packet: Packet,
    packet_id: int,
    capture_source: str,
) -> IDSEvent:
    """
    Chuyển packet Scapy thành IDSEvent chuẩn hóa.
    """
    try:
        timestamp = float(packet.time)
    except (AttributeError, TypeError, ValueError):
        timestamp = time.time()

    event = IDSEvent(
        packet_id=packet_id,
        timestamp=timestamp,
        capture_source=capture_source,
    )

    try:
        network_data = parse_ipv4(packet)

        if network_data is None:
            event.network = {
                "protocol": "UNKNOWN",
            }
        else:
            event.network = network_data

    except Exception as error:
        event.network = {
            "protocol": "UNKNOWN",
        }
        event.parse_errors.append(
            f"Network parser error: {error}"
        )

    try:
        transport_data = parse_tcp(packet)

        if transport_data is None:
            transport_data = parse_udp(packet)

        if transport_data is None:
            event.transport = {
                "protocol": "UNKNOWN",
            }
        else:
            event.transport = transport_data
            event.payload_length = transport_data["payload_length"]

    except Exception as error:
        event.transport = {
            "protocol": "UNKNOWN",
        }
        event.parse_errors.append(
            f"Transport parser error: {error}"
        )

    try:
        application_protocol = detect_application_protocol(packet)
        application_fields = {}

        if application_protocol == "HTTP":
            http_data = parse_http(packet)

            if http_data is not None:
                application_fields = http_data

        elif application_protocol == "DNS":
            dns_data = parse_dns(packet)

            if dns_data is not None:
                application_fields = dns_data

        elif application_protocol == "SMTP":
            smtp_data = parse_smtp(packet)

            if smtp_data is not None:
                application_fields = smtp_data

        event.application = {
            "protocol": application_protocol,
            "fields": application_fields,
        }

    except Exception as error:
        event.application = {
            "protocol": "UNKNOWN",
            "fields": {},
        }
        event.parse_errors.append(
            f"Application parser error: {error}"
        )

    return event
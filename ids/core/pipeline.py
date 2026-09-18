import time

from scapy.packet import Packet

from ids.core.event import IDSEvent
from ids.parsers.network.ipv4 import parse_ipv4
from ids.parsers.transport.tcp import parse_tcp


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

    print(event.to_dict())
    return event
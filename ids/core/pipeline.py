import time

from scapy.packet import Packet

from ids.core.event import IDSEvent
from ids.parsers.network.ipv4 import parse_ipv4


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

    print(event.to_dict())
    return event
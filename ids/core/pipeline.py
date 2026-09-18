import time

from scapy.packet import Packet

from ids.core.event import IDSEvent


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

    print(event.to_dict())

    return event
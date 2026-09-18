from collections.abc import Callable

from scapy.all import sniff
from scapy.packet import Packet


PacketHandler = Callable[[Packet, int], None]


def capture_live(
    interface: str,
    packet_handler: PacketHandler,
    packet_limit: int = 0,
) -> int:
    """
    Bắt packet trực tiếp từ network interface.

    packet_limit = 0: bắt liên tục cho đến khi nhấn Ctrl+C.
    """
    packet_count = 0

    def handle_packet(packet: Packet) -> None:
        nonlocal packet_count

        packet_count += 1
        packet_handler(packet, packet_count)

    try:
        sniff(
            iface=interface,
            prn=handle_packet,
            store=False,
            count=packet_limit,
        )
    except KeyboardInterrupt:
        print("\nĐã dừng live capture.")

    return packet_count
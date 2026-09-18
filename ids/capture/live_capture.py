import time
from collections.abc import Callable

from scapy.all import AsyncSniffer
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

    sniffer = AsyncSniffer(
        iface=interface,
        prn=handle_packet,
        store=False,
        count=packet_limit,
    )

    sniffer.start()

    try:
        while sniffer.running:
            if packet_limit > 0 and packet_count >= packet_limit:
                break

            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\nĐã nhận Ctrl+C, đang dừng live capture...")

    finally:
        if sniffer.running:
            sniffer.stop()
        else:
            sniffer.join()

    return packet_count
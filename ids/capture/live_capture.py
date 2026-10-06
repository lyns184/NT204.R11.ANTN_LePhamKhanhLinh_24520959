import time
from collections.abc import Callable

from scapy.all import AsyncSniffer
from scapy.packet import Packet


PacketHandler = Callable[[Packet, int], None]


def capture_live(
    interface: str,
    packet_handler: PacketHandler,
    packet_limit: int = 0,
    tick_handler: Callable[[], None] | None = None,
    tick_interval_seconds: float = 1.0,
) -> int:
    """
    Bắt packet trực tiếp từ network interface.

    packet_limit = 0: bắt liên tục cho đến khi nhấn Ctrl+C.
    """
    packet_count = 0
    callback_error: Exception | None = None
    if tick_handler is not None:
        import math
        if type(tick_interval_seconds) not in (int, float) or not math.isfinite(tick_interval_seconds) or tick_interval_seconds <= 0:
            raise ValueError("tick_interval_seconds must be positive and finite")

    def handle_packet(packet: Packet) -> None:
        nonlocal packet_count, callback_error

        if callback_error is not None:
            return

        packet_count += 1
        try:
            packet_handler(packet, packet_count)
        except Exception as error:
            callback_error = error

    sniffer = AsyncSniffer(
        iface=interface,
        prn=handle_packet,
        store=False,
        count=packet_limit,
    )

    sniffer.start()

    try:
        next_tick = time.monotonic() + tick_interval_seconds
        while sniffer.running:
            if callback_error is not None:
                raise callback_error
            if packet_limit > 0 and packet_count >= packet_limit:
                break

            if tick_handler is not None and time.monotonic() >= next_tick:
                tick_handler()
                next_tick = time.monotonic() + tick_interval_seconds
            time.sleep(min(0.1, tick_interval_seconds) if tick_handler is not None else 0.1)

    except KeyboardInterrupt:
        print("\nĐã nhận Ctrl+C, đang dừng live capture...")

    finally:
        if sniffer.running:
            sniffer.stop()
        else:
            sniffer.join()

    if callback_error is not None:
        raise callback_error
    return packet_count

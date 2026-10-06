import time
import math
from collections.abc import Callable
from threading import Event

from scapy.all import AsyncSniffer
from scapy.packet import Packet
from scapy.error import Scapy_Exception


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

    ready = Event()
    stop_requested = Event()

    def on_started() -> None:
        # Scapy calls this after its sockets and stop callback are ready.
        ready.set()
        if stop_requested.is_set():
            sniffer.stop(join=False)

    sniffer = AsyncSniffer(
        iface=interface,
        prn=handle_packet,
        store=False,
        count=packet_limit,
        started_callback=on_started,
    )

    sniffer.start()

    try:
        # start() launches a thread; running may still be False at this point.
        while not ready.wait(0.05):
            thread = getattr(sniffer, "thread", None)
            if thread is not None and not thread.is_alive():
                sniffer.join()  # Propagate startup errors instead of reporting success.
                return packet_count
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
        stop_requested.set()
        if ready.is_set() and sniffer.running:
            try:
                sniffer.stop(join=False)
            except Scapy_Exception:
                if sniffer.running:
                    raise
        # Join even when the worker stops between the running check and stop().
        # If interrupted during startup, on_started will apply the stop request.
        sniffer.join()

    if callback_error is not None:
        raise callback_error
    return packet_count

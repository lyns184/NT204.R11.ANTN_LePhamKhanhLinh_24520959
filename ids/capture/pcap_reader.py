from collections.abc import Callable
from pathlib import Path

from scapy.all import PcapReader
from scapy.packet import Packet


PacketHandler = Callable[[Packet, int], None]


def read_pcap(
    file_path: str,
    packet_handler: PacketHandler,
) -> int:
    """
    Đọc từng packet từ file PCAP và chuyển packet vào hàm xử lý chung.

    Trả về tổng số packet đã đọc.
    """
    pcap_path = Path(file_path)

    if not pcap_path.is_file():
        raise FileNotFoundError(
            f"Không tìm thấy file PCAP: {file_path}"
        )

    packet_count = 0

    with PcapReader(str(pcap_path)) as reader:
        for packet_count, packet in enumerate(reader, start=1):
            packet_handler(packet, packet_count)

    return packet_count
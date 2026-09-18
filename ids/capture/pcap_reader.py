import struct
from collections.abc import Callable
from pathlib import Path

from scapy.all import PcapReader
from scapy.error import Scapy_Exception
from scapy.packet import Packet


PacketHandler = Callable[[Packet, int], None]


def read_pcap(
    file_path: str,
    packet_handler: PacketHandler,
) -> int:
    """
    Đọc từng packet từ file PCAP.

    Packet bị lỗi không được làm chương trình crash.
    """
    pcap_path = Path(file_path)

    if not pcap_path.is_file():
        raise FileNotFoundError(
            f"Không tìm thấy file PCAP: {file_path}"
        )

    packet_count = 0

    with PcapReader(str(pcap_path)) as reader:
        while True:
            try:
                packet = reader.read_packet()

            except EOFError:
                break

            except (
                Scapy_Exception,
                struct.error,
                ValueError,
            ) as error:
                print(
                    "[WARNING] Không thể đọc packet tiếp theo: "
                    f"{error}"
                )
                break

            if packet is None:
                break

            packet_count += 1
            packet_handler(packet, packet_count)

    return packet_count
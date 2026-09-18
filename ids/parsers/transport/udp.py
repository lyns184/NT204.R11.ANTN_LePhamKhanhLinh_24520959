from typing import Any

from scapy.layers.inet import UDP
from scapy.packet import Packet


def parse_udp(packet: Packet) -> dict[str, Any] | None:
    """
    Trích xuất thông tin UDP.

    Trả về None nếu packet không chứa UDP.
    """
    if not packet.haslayer(UDP):
        return None

    udp_layer = packet[UDP]
    payload_length = len(bytes(udp_layer.payload))

    return {
        "protocol": "UDP",
        "src_port": int(udp_layer.sport),
        "dst_port": int(udp_layer.dport),
        "length": (
            int(udp_layer.len)
            if udp_layer.len is not None
            else None
        ),
        "checksum": (
            int(udp_layer.chksum)
            if udp_layer.chksum is not None
            else None
        ),
        "payload_length": payload_length,
    }
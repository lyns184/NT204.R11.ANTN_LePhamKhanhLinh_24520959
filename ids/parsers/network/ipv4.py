from typing import Any

from scapy.layers.inet import IP
from scapy.packet import Packet


def parse_ipv4(packet: Packet) -> dict[str, Any] | None:
    """
    Trích xuất thông tin IPv4 từ packet.

    Trả về None nếu packet không chứa IPv4.
    """
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]

    header_length = None
    if ip_layer.ihl is not None:
        header_length = int(ip_layer.ihl) * 4

    return {
        "protocol": "IPv4",
        "version": int(ip_layer.version),
        "header_length": header_length,
        "total_length": (
            int(ip_layer.len)
            if ip_layer.len is not None
            else None
        ),
        "identification": int(ip_layer.id),
        "flags": str(ip_layer.flags),
        "fragment_offset": int(ip_layer.frag),
        "ttl": int(ip_layer.ttl),
        "next_protocol": int(ip_layer.proto),
        "checksum": (
            int(ip_layer.chksum)
            if ip_layer.chksum is not None
            else None
        ),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
    }
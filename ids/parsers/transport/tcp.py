from typing import Any

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet


def parse_tcp(packet: Packet) -> dict[str, Any] | None:
    """
    Trích xuất thông tin TCP.

    Trả về None nếu packet không chứa TCP.
    """
    if not packet.haslayer(TCP):
        return None

    tcp_layer = packet[TCP]
    flags_value = int(tcp_layer.flags)

    header_length = None
    if tcp_layer.dataofs is not None:
        header_length = int(tcp_layer.dataofs) * 4

    captured_payload_length = len(bytes(tcp_layer.payload))
    ip_layer = packet.getlayer(IP)

    if (
        ip_layer is not None
        and ip_layer.len is not None
        and ip_layer.ihl is not None
        and tcp_layer.dataofs is not None
    ):
        declared_payload_length = max(
            0,
            int(ip_layer.len)
            - int(ip_layer.ihl) * 4
            - int(tcp_layer.dataofs) * 4,
        )

        payload_length = min(
            captured_payload_length,
            declared_payload_length,
        )
    else:
        payload_length = captured_payload_length

    return {
        "protocol": "TCP",
        "src_port": int(tcp_layer.sport),
        "dst_port": int(tcp_layer.dport),
        "sequence_number": int(tcp_layer.seq),
        "acknowledgment_number": int(tcp_layer.ack),
        "header_length": header_length,
        "flags": str(tcp_layer.flags),
        "flags_detail": {
            "FIN": bool(flags_value & 0x01),
            "SYN": bool(flags_value & 0x02),
            "RST": bool(flags_value & 0x04),
            "PSH": bool(flags_value & 0x08),
            "ACK": bool(flags_value & 0x10),
            "URG": bool(flags_value & 0x20),
            "ECE": bool(flags_value & 0x40),
            "CWR": bool(flags_value & 0x80),
            "NS": bool(flags_value & 0x100),
        },
        "window_size": int(tcp_layer.window),
        "checksum": (
            int(tcp_layer.chksum)
            if tcp_layer.chksum is not None
            else None
        ),
        "urgent_pointer": int(tcp_layer.urgptr),
        "payload_length": payload_length,
    }
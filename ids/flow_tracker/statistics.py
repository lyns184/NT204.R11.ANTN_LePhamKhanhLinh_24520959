"""Thống kê packet quan sát được; mỗi lần track thành công tính một packet."""

import math

from ids.core.event import IDSEvent
from ids.flow_tracker.identity import FlowIdentity, get_flow_direction
from ids.flow_tracker.models import FlowDirection, FlowRecord


def update_flow_statistics(
    flow: FlowRecord,
    event: IDSEvent,
    identity: FlowIdentity,
    direction: FlowDirection,
) -> None:
    """Cập nhật tổng/từng chiều; kiểm tra và tính trước khi sửa record.

    Byte count dùng normalized.network.total_length (byte IPv4, không gồm
    Ethernet). Thiếu length tăng unknown_byte_count, không đoán từ payload.
    Timestamp đảo thứ tự dùng min/max; application_protocol giữ protocol
    biết được đầu tiên và không bị UNKNOWN ghi đè. Không cập nhật TCP flags/state.
    """
    if get_flow_direction(identity, flow) != direction:
        raise ValueError("Statistics direction does not match flow endpoints")
    timestamp = identity.timestamp
    if type(timestamp) not in (int, float) or not math.isfinite(timestamp):
        raise ValueError("Statistics timestamp must be finite")
    normalized = event.normalized
    length = normalized["network"].get("total_length")
    if length is not None and (type(length) is not int or not 20 <= length <= 65535):
        raise ValueError("IPv4 total_length must be an integer in 20..65535 or None")
    application = normalized.get("application")
    if application is None:
        protocol = "UNKNOWN"
    elif not isinstance(application, dict):
        raise ValueError("normalized.application must be a dictionary or None")
    else:
        protocol = application.get("protocol")
        if protocol is None:
            protocol = "UNKNOWN"
        elif not isinstance(protocol, str) or not protocol.strip():
            raise ValueError("Application protocol must be a nonempty string or None")
        else:
            protocol = protocol.strip().upper()

    start_time = min(flow.start_time, timestamp)
    last_seen = max(flow.last_seen, timestamp)
    if not math.isfinite(last_seen - start_time):
        raise ValueError("Flow duration exceeds finite timestamp range")
    counters = flow.forward if direction == "forward" else flow.backward
    known_bytes = length if length is not None else 0
    unknown = int(length is None)
    # Calculate every value before assignments: malformed input must not leave
    # an existing flow with half-updated statistics.
    packet_count = flow.packet_count + 1
    byte_count = flow.byte_count + known_bytes
    unknown_byte_count = flow.unknown_byte_count + unknown
    directional_packets = counters.packet_count + 1
    directional_bytes = counters.byte_count + known_bytes
    directional_unknown = counters.unknown_byte_count + unknown
    application_protocol = (
        protocol if flow.application_protocol == "UNKNOWN" else flow.application_protocol
    )

    flow.start_time = start_time
    flow.last_seen = last_seen
    flow.packet_count = packet_count
    flow.byte_count = byte_count
    flow.unknown_byte_count = unknown_byte_count
    counters.packet_count = directional_packets
    counters.byte_count = directional_bytes
    counters.unknown_byte_count = directional_unknown
    flow.application_protocol = application_protocol

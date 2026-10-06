"""Nhận diện hai chiều từ normalized event, không sửa dữ liệu đầu vào."""

import math
from dataclasses import dataclass

from ids.core.event import IDSEvent
from ids.flow_tracker.models import Endpoint, FlowDirection, FlowKey, FlowRecord


@dataclass(frozen=True)
class FlowIdentity:
    key: FlowKey
    source: Endpoint
    destination: Endpoint
    timestamp: float


def extract_flow_identity(event: IDSEvent) -> FlowIdentity:
    """Kiểm tra các field thiết yếu kể cả khi policy cho phép invalid process.

    Chỉ dùng normalized; không fallback về dữ liệu Parser chưa chuẩn hóa.
    Lỗi được tracker bắt và trả reason; hàm này không áp dụng policy skip.
    """
    if not isinstance(event, IDSEvent):
        raise TypeError("Expected IDSEvent")
    normalized = event.normalized
    if not isinstance(normalized, dict):
        raise ValueError("normalized must be a dictionary")
    network, transport = normalized.get("network"), normalized.get("transport")
    if not isinstance(network, dict) or not isinstance(transport, dict):
        raise ValueError("normalized network/transport must be dictionaries")
    if network.get("protocol") != "IPv4":
        raise ValueError("Flow Tracker requires normalized IPv4")
    protocol = transport.get("protocol")
    if protocol not in ("TCP", "UDP"):
        raise ValueError("Flow Tracker requires normalized TCP or UDP")
    source = Endpoint(network.get("src_ip"), transport.get("src_port"))
    destination = Endpoint(network.get("dst_ip"), transport.get("dst_port"))
    timestamp = normalized.get("timestamp")
    try:
        finite = type(timestamp) in (int, float) and math.isfinite(timestamp)
    except OverflowError:
        finite = False
    if not finite:
        raise ValueError("normalized timestamp must be finite")
    low, high = sorted((source, destination))
    return FlowIdentity(FlowKey(protocol, low, high), source, destination, float(timestamp))


def get_flow_direction(identity: FlowIdentity, flow: FlowRecord) -> FlowDirection:
    """A là sender đầu tiên; hai endpoint trùng hoàn toàn quy ước forward."""
    if identity.key != flow.key:
        raise ValueError("Identity does not belong to this flow")
    if identity.source == flow.endpoint_a and identity.destination == flow.endpoint_b:
        return "forward"
    if identity.source == flow.endpoint_b and identity.destination == flow.endpoint_a:
        return "backward"
    raise ValueError("Identity endpoints do not match the flow")

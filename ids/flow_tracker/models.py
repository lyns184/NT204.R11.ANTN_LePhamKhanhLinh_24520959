"""Schema flow; chưa thực hiện nhận diện flow, cập nhật counters hay TCP state."""

import math
from dataclasses import asdict, dataclass, field
from enum import Enum
from ipaddress import IPv4Address
from typing import Any, Literal


FlowProtocol = Literal["TCP", "UDP"]
FlowDirection = Literal["forward", "backward"]


class TCPState(str, Enum):
    NEW = "NEW"
    HANDSHAKE = "HANDSHAKE"
    ESTABLISHED = "ESTABLISHED"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"
    RESET = "RESET"


@dataclass(frozen=True, order=True)
class Endpoint:
    """Endpoint IPv4 chuẩn hóa, bất biến để dùng trong key tra cứu."""

    ip: str
    port: int

    def __post_init__(self) -> None:
        if not isinstance(self.ip, str) or str(IPv4Address(self.ip)) != self.ip:
            raise ValueError("Endpoint.ip must be a canonical IPv4 string")
        if type(self.port) is not int or not 0 <= self.port <= 65535:
            raise ValueError("Endpoint.port must be an integer in 0..65535")


@dataclass(frozen=True)
class FlowKey:
    """Key hai chiều: task identity sẽ sắp endpoint trước khi tạo key.

    endpoint_low/high dùng thứ tự Endpoint, độc lập với A/B của FlowRecord.
    Key dùng tra cứu nội bộ; không dùng hash(key) làm flow_id.
    """

    protocol: FlowProtocol
    endpoint_low: Endpoint
    endpoint_high: Endpoint

    def __post_init__(self) -> None:
        if self.protocol not in ("TCP", "UDP"):
            raise ValueError("FlowKey.protocol must be TCP or UDP")
        if not isinstance(self.endpoint_low, Endpoint) or not isinstance(self.endpoint_high, Endpoint):
            raise ValueError("FlowKey endpoints must be Endpoint instances")
        if self.endpoint_low > self.endpoint_high:
            raise ValueError("FlowKey endpoints must be ordered")


@dataclass
class DirectionCounters:
    packet_count: int = 0
    # Tổng byte IPv4 có độ dài biết được; không thay bằng payload_length.
    byte_count: int = 0
    # Số packet không có độ dài: byte_count khi đó chỉ là tổng phần biết được.
    unknown_byte_count: int = 0


@dataclass
class TCPFlagCounters:
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0


@dataclass
class TCPTrackingState:
    """Quan sát điều khiển nội bộ; số end đã gồm SYN/FIN và payload nếu biết."""

    initiator: FlowDirection | None = None
    syn_seen: bool = False
    syn_end: int | None = None
    syn_ack_seen: bool = False
    syn_ack_end: int | None = None
    handshake_observed: bool = False
    capture_midstream: bool = False
    forward_fin_seen: bool = False
    forward_fin_end: int | None = None
    forward_fin_acked: bool = False
    backward_fin_seen: bool = False
    backward_fin_end: int | None = None
    backward_fin_acked: bool = False


@dataclass
class FlowRecord:
    """Một phiên flow; A là sender đầu tiên, forward=A→B, backward=B→A.

    start_time/last_seen là timestamp event. Flow mới chưa tính packet nào;
    task statistics sẽ cập nhật tổng và từng chiều cùng lúc. UDP state và
    tcp_flags là None. Đóng/hết hạn rồi dùng lại tuple phải tạo flow_id mới.
    """

    flow_id: str
    key: FlowKey
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    start_time: float
    last_seen: float
    application_protocol: str = "UNKNOWN"
    packet_count: int = 0
    byte_count: int = 0
    unknown_byte_count: int = 0
    forward: DirectionCounters = field(default_factory=DirectionCounters)
    backward: DirectionCounters = field(default_factory=DirectionCounters)
    state: TCPState | None = field(init=False)
    tcp_flags: TCPFlagCounters | None = field(init=False)
    tcp_tracking: TCPTrackingState | None = field(init=False, repr=False)
    close_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.flow_id, str) or not self.flow_id.strip():
            raise ValueError("flow_id must be a nonempty string")
        if not isinstance(self.key, FlowKey):
            raise ValueError("key must be a FlowKey")
        if not isinstance(self.endpoint_a, Endpoint) or not isinstance(self.endpoint_b, Endpoint):
            raise ValueError("Flow endpoints must be Endpoint instances")
        if tuple(sorted((self.endpoint_a, self.endpoint_b))) != (self.key.endpoint_low, self.key.endpoint_high):
            raise ValueError("Flow endpoints must match its key")
        for name in ("start_time", "last_seen"):
            value = getattr(self, name)
            try:
                valid = type(value) in (int, float) and math.isfinite(value)
            except OverflowError:
                valid = False
            if not valid:
                raise ValueError(f"{name} must be a finite timestamp")
        if self.last_seen < self.start_time:
            raise ValueError("last_seen must not precede start_time")
        self.state = TCPState.NEW if self.protocol == "TCP" else None
        self.tcp_flags = TCPFlagCounters() if self.protocol == "TCP" else None
        self.tcp_tracking = TCPTrackingState() if self.protocol == "TCP" else None

    @property
    def protocol(self) -> FlowProtocol:
        return self.key.protocol

    @property
    def duration(self) -> float:
        return self.last_seen - self.start_time

    def to_dict(self) -> dict[str, Any]:
        """Snapshot độc lập để xuất summary, không đưa key tra cứu vào output."""
        result = asdict(self)
        del result["key"]
        del result["tcp_tracking"]
        result["handshake_observed"] = (
            self.tcp_tracking.handshake_observed if self.tcp_tracking is not None else None
        )
        result["capture_midstream"] = (
            self.tcp_tracking.capture_midstream if self.tcp_tracking is not None else None
        )
        result["protocol"] = self.protocol
        result["duration"] = self.duration
        result["state"] = self.state.value if self.state is not None else None
        return result

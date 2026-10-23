"""Data models cho Core Engine; không parse rule hoặc thực hiện matching.

Rule/context là snapshot bất biến. Dùng to_dict() để xuất bản sao JSON-safe;
raw payload của InspectionContext chỉ ở bộ nhớ, không đưa vào bản xuất.
"""

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from types import MappingProxyType
from typing import Any, Literal

from ids.core.event import ProcessingAction
from ids.flow_tracker.models import Endpoint, TCPState


MAX_RULE_NUMBER = 2**31 - 1
MAX_DSIZE_VALUE = 65535  # Phạm vi MVP, không khẳng định mọi Snort 2 parser đều từ chối số lớn hơn.
FLAG_LETTERS = frozenset("FSRPAUCE")
PacketDirection = Literal["to_server", "to_client", "unknown"]


class MatchStatus(str, Enum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    NOT_EVALUABLE = "NOT_EVALUABLE"
    ERROR = "ERROR"


class PayloadStatus(str, Enum):
    AVAILABLE = "available"
    MISSING = "missing"
    INCOMPLETE = "incomplete"
    ERROR = "error"


class ParseStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNSUPPORTED = "unsupported"


def _integer(value: Any, name: str, low: int, high: int | None = None) -> None:
    if type(value) is not int or value < low or (high is not None and value > high):
        limits = f"{low}..{high}" if high is not None else f">= {low}"
        raise ValueError(f"{name} must be an integer in {limits}")
    if high is None:
        str(value)  # Không nhận integer mà Python không thể xuất JSON decimal.


def _text(value: Any, name: str, optional: bool = False) -> None:
    if optional and value is None:
        return
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")


def _choice(value: Any, name: str, choices: tuple[str, ...]) -> None:
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"{name} must be one of {choices}")


def _boolean(value: Any, name: str, optional: bool = False) -> None:
    if optional and value is None:
        return
    if type(value) is not bool:
        raise ValueError(f"{name} must be a boolean" + (" or None" if optional else ""))


def _timestamp(value: Any) -> float:
    try:
        valid = type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError("timestamp must be a finite int or float")
    return float(value)


def _items(value: Any, name: str, kind: type) -> tuple:
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, kind) for item in value):
        raise ValueError(f"{name} must be a list/tuple of {kind.__name__}")
    return tuple(value)


def _snapshot(value: Any, path: str = "data", ancestors: set[int] | None = None,
              depth: int = 0) -> Any:
    """Đóng băng JSON data; từ chối binary, NaN, cycle thay vì sửa input lỗi."""
    if depth > 64:
        raise ValueError(f"{path}: nesting exceeds 64 levels")
    if value is None or type(value) in (str, bool):
        return value
    if type(value) is int:
        # Python có thể từ chối chuyển integer quá lớn sang JSON decimal.
        str(value)
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if not isinstance(value, (Mapping, list, tuple)):
        raise ValueError(f"{path}: expected finite JSON data, got {type(value).__name__}")
    ancestors = set() if ancestors is None else ancestors
    identity = id(value)
    if identity in ancestors:
        raise ValueError(f"{path}: circular reference")
    ancestors.add(identity)
    try:
        if isinstance(value, Mapping):
            result = {}
            for key, item in value.items():
                if type(key) is not str:
                    raise ValueError(f"{path}: keys must be strings")
                result[key] = _snapshot(item, f"{path}.{key}", ancestors, depth + 1)
            return MappingProxyType(result)
        return tuple(_snapshot(item, f"{path}[{index}]", ancestors, depth + 1)
                     for index, item in enumerate(value))
    finally:
        ancestors.remove(identity)


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a mapping")
    return _snapshot(value, name)


def _export(value: Any) -> Any:
    if isinstance(value, JSONModel):
        return value.to_dict()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, IPv4Network):
        return str(value)
    if isinstance(value, Endpoint):
        return {"ip": value.ip, "port": value.port}
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, Mapping):
        return {key: _export(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_export(item) for item in value]
    if isinstance(value, frozenset):
        return sorted(value)
    return value


class JSONModel:
    """Xuất dict độc lập; không dùng dataclasses.asdict trên mappingproxy."""

    def to_dict(self) -> dict[str, Any]:
        return {
            item.metadata.get("json_name", item.name): _export(getattr(self, item.name))
            for item in fields(self) if item.metadata.get("export", True)
        }


@dataclass(frozen=True)
class RuleSource(JSONModel):
    file: str
    line: int

    def __post_init__(self) -> None:
        _text(self.file, "source.file")
        _integer(self.line, "source.line", 1, MAX_RULE_NUMBER)


@dataclass(frozen=True)
class Diagnostic(JSONModel):
    code: str
    reason: str
    category: Literal["invalid", "unsupported", "input", "evaluation", "configuration", "disabled"] = "input"
    source: RuleSource | None = None
    keyword: str | None = None

    def __post_init__(self) -> None:
        _text(self.code, "diagnostic.code")
        _text(self.reason, "diagnostic.reason")
        _choice(self.category, "diagnostic.category",
                ("invalid", "unsupported", "input", "evaluation", "configuration", "disabled"))
        if self.source is not None and not isinstance(self.source, RuleSource):
            raise ValueError("diagnostic.source must be RuleSource or None")
        _text(self.keyword, "diagnostic.keyword", optional=True)


@dataclass(frozen=True)
class PortSpec(JSONModel):
    """None/None là any; start=end là port đơn; khoảng gồm cả hai đầu."""

    start: int | None = None
    end: int | None = None

    def __post_init__(self) -> None:
        if self.start is None and self.end is None:
            return
        _integer(self.start, "port.start", 0, 65535)
        _integer(self.end, "port.end", 0, 65535)
        if self.start > self.end:
            raise ValueError("port.start must not exceed port.end")

    @property
    def is_any(self) -> bool:
        return self.start is None


@dataclass(frozen=True)
class RuleHeader(JSONModel):
    """Parser sau này chuyển any/IP/CIDR thành None/IPv4Network trước khi tạo."""

    protocol: Literal["tcp", "udp", "ip"]
    src_ip: IPv4Network | None = None
    src_port: PortSpec = field(default_factory=PortSpec)
    direction: Literal["->", "<>"] = "->"
    dst_ip: IPv4Network | None = None
    dst_port: PortSpec = field(default_factory=PortSpec)
    action: Literal["alert"] = "alert"

    def __post_init__(self) -> None:
        _choice(self.action, "header.action", ("alert",))
        _choice(self.protocol, "header.protocol", ("tcp", "udp", "ip"))
        _choice(self.direction, "header.direction", ("->", "<>"))
        for name in ("src_ip", "dst_ip"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, IPv4Network):
                raise ValueError(f"header.{name} must be IPv4Network or None")
        for name in ("src_port", "dst_port"):
            if not isinstance(getattr(self, name), PortSpec):
                raise ValueError(f"header.{name} must be PortSpec")
        if self.protocol == "ip" and not (self.src_port.is_any and self.dst_port.is_any):
            raise ValueError("ip rules only support any ports in this MVP")


@dataclass(frozen=True)
class ContentCondition(JSONModel):
    pattern: bytes = field(metadata={"json_name": "pattern_hex"})
    nocase: bool = False
    offset: int | None = None
    depth: int | None = None
    distance: int | None = None
    within: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.pattern, bytes) or not 1 <= len(self.pattern) <= 65535:
            raise ValueError("content.pattern must be 1..65535 bytes")
        _boolean(self.nocase, "content.nocase")
        for name in ("offset", "depth", "distance", "within"):
            value = getattr(self, name)
            if value is not None:
                _integer(value, f"content.{name}", 1 if name in ("depth", "within") else 0, 65535)
        if ((self.offset is not None or self.depth is not None)
                and (self.distance is not None or self.within is not None)):
            raise ValueError("content cannot mix absolute and relative modifiers")
        for name in ("depth", "within"):
            value = getattr(self, name)
            # Snort 2.9.20 PayloadSearchDepth/PayloadSearchWithin cũng ParseError
            # khi literal window nhỏ hơn pattern; đây không phải NO_MATCH runtime.
            if value is not None and value < len(self.pattern):
                raise ValueError(f"content.{name} must cover the complete pattern")


@dataclass(frozen=True)
class FlowCondition(JSONModel):
    direction: Literal["to_server", "to_client"] | None = None
    state: Literal["established", "not_established"] | None = None

    def __post_init__(self) -> None:
        if self.direction is None and self.state is None:
            raise ValueError("flow must specify direction or state")
        if self.direction is not None:
            _choice(self.direction, "flow.direction", ("to_server", "to_client"))
        if self.state is not None:
            _choice(self.state, "flow.state", ("established", "not_established"))


@dataclass(frozen=True)
class FlagsCondition(JSONModel):
    """Exact set tám TCP control bits; frozenset rỗng biểu diễn flags:0."""

    flags: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not isinstance(self.flags, (set, frozenset)) or any(
            type(flag) is not str or flag not in FLAG_LETTERS for flag in self.flags
        ):
            raise ValueError("flags must be a set of supported TCP flag letters")
        object.__setattr__(self, "flags", frozenset(self.flags))


@dataclass(frozen=True)
class DSizeCondition(JSONModel):
    """Condition trong phạm vi MVP; '=' biểu diễn nội bộ cú pháp dsize:n.

    Literal không âm >65535 nằm ngoài MVP. Parser phải báo unsupported trước
    khi tạo model, không gọi mọi ValueError của model là invalid Snort syntax.
    """

    operator: Literal["=", "<", ">"]
    value: int

    def __post_init__(self) -> None:
        _choice(self.operator, "dsize.operator", ("=", "<", ">"))
        _integer(self.value, "dsize.value", 0, MAX_DSIZE_VALUE)


@dataclass(frozen=True)
class Rule(JSONModel):
    header: RuleHeader
    sid: int
    rev: int
    msg: str
    contents: tuple[ContentCondition, ...] = ()
    flow: FlowCondition | None = None
    flags: FlagsCondition | None = None
    dsize: DSizeCondition | None = None
    classtype: str | None = None
    priority: int | None = None
    source: RuleSource | None = None
    raw_text: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.header, RuleHeader):
            raise ValueError("rule.header must be RuleHeader")
        _identification(self.sid, self.rev, self.msg, self.classtype, self.priority)
        contents = _items(self.contents, "rule.contents", ContentCondition)
        if contents and (contents[0].distance is not None or contents[0].within is not None):
            raise ValueError("first content cannot be relative to a preceding content")
        object.__setattr__(self, "contents", contents)
        for name, kind in (("flow", FlowCondition), ("flags", FlagsCondition),
                           ("dsize", DSizeCondition), ("source", RuleSource)):
            value = getattr(self, name)
            if value is not None and not isinstance(value, kind):
                raise ValueError(f"rule.{name} must be {kind.__name__} or None")
        if self.header.protocol != "tcp" and (self.flow is not None or self.flags is not None):
            raise ValueError("flow/flags conditions require a tcp rule in this MVP")
        _text(self.raw_text, "rule.raw_text", optional=True)


def _identification(sid: int, rev: int, msg: str, classtype: str | None,
                    priority: int | None) -> None:
    _integer(sid, "sid", 1, MAX_RULE_NUMBER)
    _integer(rev, "rev", 1, MAX_RULE_NUMBER)
    _text(msg, "msg")
    if classtype is not None and (not isinstance(classtype, str)
                                 or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", classtype) is None):
        raise ValueError("classtype must be an identifier or None")
    if priority is not None:
        _integer(priority, "priority", 1, MAX_RULE_NUMBER)


@dataclass(frozen=True)
class ParseResult(JSONModel):
    """Chỉ valid mới mang Rule; lỗi/unsupported không để lọt partial rule."""

    status: ParseStatus
    rule: Rule | None = None
    diagnostics: tuple[Diagnostic, ...] = ()

    def __post_init__(self) -> None:
        _choice(self.status, "parse.status", tuple(item.value for item in ParseStatus))
        object.__setattr__(self, "status", ParseStatus(self.status))
        diagnostics = _items(self.diagnostics, "parse.diagnostics", Diagnostic)
        object.__setattr__(self, "diagnostics", diagnostics)
        if self.status == ParseStatus.VALID:
            if not isinstance(self.rule, Rule) or diagnostics:
                raise ValueError("valid ParseResult requires Rule and no diagnostics")
        elif self.rule is not None or not diagnostics:
            raise ValueError("invalid/unsupported ParseResult requires diagnostics and no Rule")
        if self.status != ParseStatus.VALID:
            if any(item.category not in ("invalid", "unsupported") for item in diagnostics):
                raise ValueError("parse diagnostics must be invalid or unsupported")
            has_invalid = any(item.category == "invalid" for item in diagnostics)
            if has_invalid != (self.status == ParseStatus.INVALID):
                raise ValueError("ParseResult status must give invalid diagnostics precedence")


@dataclass(frozen=True)
class FlowContext(JSONModel):
    """Snapshot vai trò do caller cung cấp từ bằng chứng, không tự suy đoán.

    UDP có thể có client/server và direction đã biết, nhưng TCP state và
    established/handshake phải là None. MVP chưa match flow keyword trên UDP.
    """

    flow_id: str | None = None
    protocol: Literal["TCP", "UDP"] | None = None
    tcp_state: TCPState | None = None
    client_endpoint: Endpoint | None = None
    server_endpoint: Endpoint | None = None
    packet_direction: PacketDirection = "unknown"
    established_for_packet: bool | None = None
    handshake_observed: bool | None = None

    def __post_init__(self) -> None:
        _text(self.flow_id, "flow_context.flow_id", optional=True)
        if self.protocol is not None:
            _choice(self.protocol, "flow_context.protocol", ("TCP", "UDP"))
        if self.tcp_state is not None and not isinstance(self.tcp_state, TCPState):
            raise ValueError("flow_context.tcp_state must be TCPState or None")
        _boolean(self.established_for_packet, "established_for_packet", optional=True)
        _boolean(self.handshake_observed, "handshake_observed", optional=True)
        _choice(self.packet_direction, "packet_direction", ("to_server", "to_client", "unknown"))
        for name in ("client_endpoint", "server_endpoint"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, Endpoint):
                raise ValueError(f"flow_context.{name} must be Endpoint or None")
        if (self.client_endpoint is None) != (self.server_endpoint is None):
            raise ValueError("client/server endpoints must be both known or both unknown")
        if self.packet_direction != "unknown" and self.client_endpoint is None:
            raise ValueError("known packet direction requires known client/server endpoints")
        if self.protocol != "TCP" and any(value is not None for value in (
            self.tcp_state, self.established_for_packet, self.handshake_observed,
        )):
            raise ValueError("TCP state/established/handshake must be None for UDP or missing protocol")
        if self.protocol is None and self.client_endpoint is not None:
            raise ValueError("known client/server roles require a known flow protocol")


@dataclass(frozen=True)
class InspectionContext(JSONModel):
    timestamp: float
    normalized: Mapping[str, Any] = field(default_factory=dict)
    processing_action: ProcessingAction = "process"
    packet_id: int | None = None
    payload: bytes | None = field(default=None, repr=False, metadata={"export": False})
    payload_status: PayloadStatus = PayloadStatus.MISSING
    flow: FlowContext | None = None
    diagnostics: tuple[Diagnostic, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "timestamp", _timestamp(self.timestamp))
        if self.packet_id is not None:
            _integer(self.packet_id, "packet_id", 1)
        _choice(self.processing_action, "processing_action", ("process", "skip"))
        _choice(self.payload_status, "payload_status", tuple(item.value for item in PayloadStatus))
        object.__setattr__(self, "payload_status", PayloadStatus(self.payload_status))
        if self.payload is not None and not isinstance(self.payload, bytes):
            raise ValueError("payload must be bytes or None")
        if self.payload_status == PayloadStatus.AVAILABLE and self.payload is None:
            raise ValueError("available payload requires bytes, including b'' for a known empty payload")
        if self.payload_status in (PayloadStatus.MISSING, PayloadStatus.ERROR) and self.payload is not None:
            raise ValueError("missing/error payload must be None")
        if self.flow is not None and not isinstance(self.flow, FlowContext):
            raise ValueError("inspection.flow must be FlowContext or None")
        object.__setattr__(self, "normalized", _mapping(self.normalized, "normalized"))
        object.__setattr__(self, "diagnostics", _items(self.diagnostics, "diagnostics", Diagnostic))


@dataclass(frozen=True)
class ContentMatch(JSONModel):
    index: int
    pattern: bytes = field(metadata={"json_name": "pattern_hex"})
    matched: bytes = field(metadata={"json_name": "matched_hex"})
    start: int
    end: int
    nocase: bool = False
    buffer: Literal["payload"] = "payload"

    def __post_init__(self) -> None:
        _integer(self.index, "content_match.index", 0, MAX_RULE_NUMBER)
        _integer(self.start, "content_match.start", 0, MAX_RULE_NUMBER)
        _integer(self.end, "content_match.end", 0, MAX_RULE_NUMBER)
        if not isinstance(self.pattern, bytes) or not 1 <= len(self.pattern) <= 65535:
            raise ValueError("content_match.pattern must be 1..65535 bytes")
        if not isinstance(self.matched, bytes) or len(self.matched) != len(self.pattern):
            raise ValueError("matched bytes must have the same length as pattern")
        if self.end - self.start != len(self.matched):
            raise ValueError("content_match range must cover exactly the matched bytes")
        _boolean(self.nocase, "content_match.nocase")
        _choice(self.buffer, "content_match.buffer", ("payload",))
        expected = self.pattern.lower() if self.nocase else self.pattern
        observed = self.matched.lower() if self.nocase else self.matched
        if expected != observed:
            raise ValueError("content_match bytes do not support the claimed match")


@dataclass(frozen=True)
class MatchedInfo(JSONModel):
    orientation: Literal["direct", "reverse"] = "direct"
    contents: tuple[ContentMatch, ...] = ()
    flow: Mapping[str, Any] | None = None
    flags: Mapping[str, Any] | None = None
    dsize: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        _choice(self.orientation, "matched_info.orientation", ("direct", "reverse"))
        contents = _items(self.contents, "matched_info.contents", ContentMatch)
        if any(match.index != index for index, match in enumerate(contents)):
            raise ValueError("content match indices must be in rule order starting from zero")
        object.__setattr__(self, "contents", contents)
        for name in ("flow", "flags", "dsize"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _mapping(value, f"matched_info.{name}"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "header": {"matched": True, "orientation": self.orientation},
            "flow": _export(self.flow), "flags": _export(self.flags),
            "dsize": _export(self.dsize), "contents": _export(self.contents),
        }


@dataclass(frozen=True)
class MatchResult(JSONModel):
    status: MatchStatus
    sid: int
    reason_code: str | None = None
    reason: str | None = None
    matched_info: MatchedInfo | None = None
    diagnostics: tuple[Diagnostic, ...] = ()

    def __post_init__(self) -> None:
        _choice(self.status, "match.status", tuple(item.value for item in MatchStatus))
        object.__setattr__(self, "status", MatchStatus(self.status))
        _integer(self.sid, "match.sid", 1, MAX_RULE_NUMBER)
        if self.status == MatchStatus.MATCH:
            if not isinstance(self.matched_info, MatchedInfo):
                raise ValueError("MATCH requires MatchedInfo")
        else:
            if self.matched_info is not None:
                raise ValueError("only MATCH may contain matched_info")
            _text(self.reason_code, "match.reason_code")
            _text(self.reason, "match.reason")
        _text(self.reason_code, "match.reason_code", optional=True)
        _text(self.reason, "match.reason", optional=True)
        object.__setattr__(self, "diagnostics", _items(self.diagnostics, "diagnostics", Diagnostic))


@dataclass(frozen=True)
class DetectionEvent(JSONModel):
    timestamp: float
    sid: int
    rev: int
    msg: str
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: Literal["TCP", "UDP"] | None
    application_protocol: str | None
    matched_info: MatchedInfo
    packet_id: int | None = None
    classtype: str | None = None
    priority: int | None = None
    flow_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "timestamp", _timestamp(self.timestamp))
        _identification(self.sid, self.rev, self.msg, self.classtype, self.priority)
        if self.packet_id is not None:
            _integer(self.packet_id, "detection.packet_id", 1)
        for name in ("src_ip", "dst_ip"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or str(IPv4Address(value)) != value):
                raise ValueError(f"detection.{name} must be a canonical IPv4 string")
        for name in ("src_port", "dst_port"):
            if getattr(self, name) is not None:
                _integer(getattr(self, name), f"detection.{name}", 0, 65535)
        if self.protocol is not None:
            _choice(self.protocol, "detection.protocol", ("TCP", "UDP"))
        _text(self.application_protocol, "detection.application_protocol", optional=True)
        _text(self.flow_id, "detection.flow_id", optional=True)
        if not isinstance(self.matched_info, MatchedInfo):
            raise ValueError("detection.matched_info must be MatchedInfo")

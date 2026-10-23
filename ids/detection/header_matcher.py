"""Match riêng header IPv4; kết quả MATCH chưa phải toàn bộ rule/detection."""

from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Any, Literal

from ids.detection.models import (
    Diagnostic, InspectionContext, JSONModel, MatchStatus, PortSpec, RuleHeader,
    _choice, _items, _text,
)


@dataclass(frozen=True)
class HeaderMatchResult(JSONModel):
    """MATCH chỉ chứng minh header; không dùng làm MatchResult của cả rule."""

    status: MatchStatus
    orientation: Literal["direct", "reverse"] | None = None
    reason_code: str | None = None
    reason: str | None = None
    diagnostics: tuple[Diagnostic, ...] = ()

    def __post_init__(self) -> None:
        _choice(self.status, "header.status", tuple(item.value for item in MatchStatus))
        object.__setattr__(self, "status", MatchStatus(self.status))
        object.__setattr__(self, "diagnostics", _items(self.diagnostics, "header.diagnostics", Diagnostic))
        if self.status == MatchStatus.MATCH:
            _choice(self.orientation, "header.orientation", ("direct", "reverse"))
        else:
            if self.orientation is not None:
                raise ValueError("only header MATCH may contain orientation")
            _text(self.reason_code, "header.reason_code")
            _text(self.reason, "header.reason")
        _text(self.reason_code, "header.reason_code", optional=True)
        _text(self.reason, "header.reason", optional=True)
        if self.status in (MatchStatus.NOT_EVALUABLE, MatchStatus.ERROR) and not self.diagnostics:
            raise ValueError("header NOT_EVALUABLE/ERROR requires diagnostics")


# None là điều kiện chưa đánh giá được; không ép thành False.
_Check = tuple[bool | None, Diagnostic | None]


def _unknown(value: Any, field: str, expected: str) -> _Check:
    missing = value is None
    return None, Diagnostic(
        "missing_header_field" if missing else "invalid_header_field",
        f"{field} is {'missing' if missing else 'invalid'}; expected {expected}",
        category="input", keyword=field,
    )


def _ipv4_family(value: Any) -> _Check:
    if isinstance(value, str):
        if value == "IPv4":
            return True, None
        if value in ("IPv6", "ARP"):
            return False, None
    return _unknown(value, "network.protocol", "canonical IPv4/IPv6/ARP")


def _transport_protocol(header: RuleHeader, value: Any) -> _Check:
    # Rule ip chỉ ràng buộc IPv4, không đòi transport protocol/port cụ thể.
    # Pipeline mặc định vẫn chỉ inspect TCP/UDP; không thêm parser ICMP ở đây.
    if header.protocol == "ip":
        return True, None
    if isinstance(value, str) and value in ("TCP", "UDP"):
        return value.lower() == header.protocol, None
    return _unknown(value, "transport.protocol", "canonical TCP or UDP")


def _address(selector: IPv4Network | None, value: Any, field: str) -> _Check:
    if selector is None:
        return True, None
    if isinstance(value, str):
        try:
            address = IPv4Address(value)
        except ValueError:
            pass
        else:
            if str(address) == value:
                return address in selector, None
    return _unknown(value, field, "canonical IPv4 address string")


def _port(selector: PortSpec, value: Any, field: str) -> _Check:
    if selector.is_any:
        return True, None
    if type(value) is int and 0 <= value <= 65535:
        return selector.start <= value <= selector.end, None
    return _unknown(value, field, "integer port in 0..65535")


def _orientation(header: RuleHeader, network: Mapping, transport: Mapping,
                 reverse: bool) -> tuple[_Check, ...]:
    src, dst = ("dst", "src") if reverse else ("src", "dst")
    return (
        _address(header.src_ip, network.get(f"{src}_ip"), f"network.{src}_ip"),
        _port(header.src_port, transport.get(f"{src}_port"), f"transport.{src}_port"),
        _address(header.dst_ip, network.get(f"{dst}_ip"), f"network.{dst}_ip"),
        _port(header.dst_port, transport.get(f"{dst}_port"), f"transport.{dst}_port"),
    )


def _and(checks: tuple[_Check, ...]) -> bool | None:
    if any(value is False for value, _ in checks):
        return False
    return None if any(value is None for value, _ in checks) else True


def _diagnostics(checks: tuple[_Check, ...]) -> tuple[Diagnostic, ...]:
    return tuple(dict.fromkeys(diag for _, diag in checks if diag is not None))


def match_header(header: RuleHeader, context: InspectionContext) -> HeaderMatchResult:
    """Kiểm tra protocol/IP/port/direction từ normalized, không đổi input.

    Chỉ selector cụ thể đòi IP/port hợp lệ; any không cần giá trị đó. Family
    IPv4 luôn bắt buộc, TCP/UDP rule đòi đúng transport protocol canonical.
    Không fallback từ FlowContext, application, raw data hoặc Scapy. Dữ liệu
    thiếu/sai kiểu là unknown; một điều kiện chắc chắn False đủ NO_MATCH.

    Với <>: một orientation True đủ MATCH (ưu tiên direct); nếu không có
    True mà còn unknown thì NOT_EVALUABLE; cả hai False mới NO_MATCH.
    Sai kiểu API gây TypeError. Lỗi nội bộ ngoài dự kiến trả ERROR, không
    biến thành missing hoặc NO_MATCH. Không áp processing_action/flow/options.
    """
    if not isinstance(header, RuleHeader):
        raise TypeError("header must be RuleHeader")
    if not isinstance(context, InspectionContext):
        raise TypeError("context must be InspectionContext")
    try:
        network = context.normalized.get("network")
        transport = context.normalized.get("transport")
        network = network if isinstance(network, Mapping) else {}
        transport = transport if isinstance(transport, Mapping) else {}
        common = (_ipv4_family(network.get("protocol")),
                  _transport_protocol(header, transport.get("protocol")))
        if _and(common) is False:
            return HeaderMatchResult(MatchStatus.NO_MATCH, reason_code="header_no_match",
                                     reason="Network family or transport protocol does not match",
                                     diagnostics=_diagnostics(common))

        outcomes = []
        checks_seen = common
        for reverse in ((False, True) if header.direction == "<>" else (False,)):
            checks = common + _orientation(header, network, transport, reverse)
            outcome = _and(checks)
            if outcome is True:
                return HeaderMatchResult(MatchStatus.MATCH,
                                         orientation="reverse" if reverse else "direct")
            outcomes.append(outcome)
            checks_seen += checks
        if any(value is None for value in outcomes):
            return HeaderMatchResult(
                MatchStatus.NOT_EVALUABLE, reason_code="header_not_evaluable",
                reason="Header has an unresolved orientation due to missing or invalid fields",
                diagnostics=_diagnostics(checks_seen),
            )
        return HeaderMatchResult(MatchStatus.NO_MATCH, reason_code="header_no_match",
                                 reason="Header does not match in any permitted orientation",
                                 diagnostics=_diagnostics(checks_seen))
    except Exception as exc:
        diagnostic = Diagnostic("header_evaluation_error",
                                f"Header evaluation failed ({type(exc).__name__}): {exc}",
                                category="evaluation")
        return HeaderMatchResult(MatchStatus.ERROR, reason_code=diagnostic.code,
                                 reason=diagnostic.reason, diagnostics=(diagnostic,))

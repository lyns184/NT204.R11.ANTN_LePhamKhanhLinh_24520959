"""Exact TCP flags và raw payload dsize; không full-rule evaluation."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ids.detection.models import (
    DSizeCondition, Diagnostic, FlagsCondition, InspectionContext, JSONModel,
    MatchStatus, PayloadStatus, _choice, _items, _mapping, _text,
)


_FLAG_NAMES = dict(zip("FSRPAUECN", ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "NS")))
_CONTROL_FLAGS = "FSRPAUEC"


@dataclass(frozen=True)
class PacketMatchResult(JSONModel):
    status: MatchStatus
    matched: Mapping[str, Any] | None = None
    reason_code: str | None = None
    reason: str | None = None
    diagnostics: tuple[Diagnostic, ...] = ()

    def __post_init__(self) -> None:
        _choice(self.status, "packet.status", tuple(item.value for item in MatchStatus))
        object.__setattr__(self, "status", MatchStatus(self.status))
        object.__setattr__(self, "diagnostics", _items(self.diagnostics, "packet.diagnostics", Diagnostic))
        if self.status == MatchStatus.MATCH:
            object.__setattr__(self, "matched", _mapping(self.matched, "packet.matched"))
        else:
            if self.matched is not None:
                raise ValueError("only packet MATCH may contain matched evidence")
            _text(self.reason_code, "packet.reason_code")
            _text(self.reason, "packet.reason")
        _text(self.reason_code, "packet.reason_code", optional=True)
        _text(self.reason, "packet.reason", optional=True)
        if self.status in (MatchStatus.NOT_EVALUABLE, MatchStatus.ERROR) and not self.diagnostics:
            raise ValueError("packet NOT_EVALUABLE/ERROR requires diagnostics")


class _FlagsIssue(Exception):
    pass


def _read_flags(transport: Mapping) -> dict[str, bool]:
    text, detail = transport.get("flags"), transport.get("flags_detail")
    if text is not None and (not isinstance(text, str) or any(char not in _FLAG_NAMES for char in text)):
        raise _FlagsIssue("TCP flags must use canonical FSRPAUECN letters")
    if detail is not None and (not isinstance(detail, Mapping) or any(
            name not in _FLAG_NAMES.values() or type(value) is not bool for name, value in detail.items())):
        raise _FlagsIssue("TCP flags_detail must map known flag names to booleans")
    known = {letter: letter in text for letter in _FLAG_NAMES} if text is not None else {}
    if detail is not None:
        for letter, name in _FLAG_NAMES.items():
            if name in detail:
                if letter in known and known[letter] != detail[name]:
                    raise _FlagsIssue("TCP flags and flags_detail disagree")
                known[letter] = detail[name]
    # NS ở reserved/header bit, không thuộc octet tám control bits của subset.
    return {letter: value for letter, value in known.items() if letter in _CONTROL_FLAGS}


def _unavailable(code: str, reason: str) -> PacketMatchResult:
    return PacketMatchResult(MatchStatus.NOT_EVALUABLE, reason_code=code, reason=reason,
                             diagnostics=(Diagnostic(code, reason, category="input"),))


def _error(exc: Exception) -> PacketMatchResult:
    diag = Diagnostic("packet_evaluation_error", f"Packet evaluation failed ({type(exc).__name__}): {exc}",
                      category="evaluation")
    return PacketMatchResult(MatchStatus.ERROR, reason_code=diag.code, reason=diag.reason, diagnostics=(diag,))


def match_flags(condition: FlagsCondition, context: InspectionContext) -> PacketMatchResult:
    """Exact tám bit. Partial detail: bit biết sai đủ NO_MATCH, còn thiếu -> unknown.

    Text/detail mâu thuẫn hoặc malformed không được dùng để suy NO_MATCH.
    Không đọc state/flow, không áp action=skip; không xử lý modifier ngoài MVP.
    """
    if not isinstance(condition, FlagsCondition) or not isinstance(context, InspectionContext):
        raise TypeError("expected FlagsCondition and InspectionContext")
    try:
        transport = context.normalized.get("transport")
        if not isinstance(transport, Mapping) or transport.get("protocol") not in ("TCP", "UDP"):
            return _unavailable("missing_flags_protocol", "Flags require canonical TCP transport metadata")
        if transport["protocol"] != "TCP":
            return PacketMatchResult(MatchStatus.NO_MATCH, reason_code="flags_protocol_mismatch",
                                     reason="TCP flags do not match a UDP packet")
        known = _read_flags(transport)
        if any(value != (letter in condition.flags) for letter, value in known.items()):
            return PacketMatchResult(MatchStatus.NO_MATCH, reason_code="flags_no_match",
                                     reason="Observed TCP control bit differs from the exact rule flags")
        if len(known) != len(_CONTROL_FLAGS):
            return _unavailable("missing_tcp_flags", "Exact flags matching requires all eight control bits")
        expression = "".join(letter for letter in _CONTROL_FLAGS if letter in condition.flags) or "0"
        return PacketMatchResult(MatchStatus.MATCH, matched={"expression": expression, "actual": expression})
    except _FlagsIssue as exc:
        return _unavailable("invalid_tcp_flags", str(exc))
    except Exception as exc:
        return _error(exc)


def _size_matches(condition: DSizeCondition, actual: int) -> bool:
    if condition.operator == "=":
        return actual == condition.value
    return actual < condition.value if condition.operator == "<" else actual > condition.value


def match_dsize(condition: DSizeCondition, context: InspectionContext) -> PacketMatchResult:
    """Đếm bytes raw payload đầy đủ; không dùng decoded text hoặc captured length lỗi."""
    if not isinstance(condition, DSizeCondition) or not isinstance(context, InspectionContext):
        raise TypeError("expected DSizeCondition and InspectionContext")
    try:
        if context.payload_status != PayloadStatus.AVAILABLE:
            return _unavailable("payload_not_available",
                                f"dsize requires complete payload; status is {context.payload_status.value}")
        actual = len(context.payload)
        if not _size_matches(condition, actual):
            return PacketMatchResult(MatchStatus.NO_MATCH, reason_code="dsize_no_match",
                                     reason=f"Payload size {actual} does not satisfy dsize")
        operator = "" if condition.operator == "=" else condition.operator
        return PacketMatchResult(MatchStatus.MATCH,
                                 matched={"expression": f"{operator}{condition.value}", "actual": actual})
    except Exception as exc:
        return _error(exc)

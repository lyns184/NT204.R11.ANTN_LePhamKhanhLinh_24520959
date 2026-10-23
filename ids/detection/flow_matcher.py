"""Match riêng flow condition; không xác nhận toàn bộ rule hoặc sinh detection."""

from dataclasses import dataclass

from ids.detection.models import (
    Diagnostic, FlowCondition, FlowContext, InspectionContext, JSONModel,
    MatchStatus, _choice, _items, _text,
)


@dataclass(frozen=True)
class FlowMatchResult(JSONModel):
    status: MatchStatus
    flow: FlowContext | None = None
    reason_code: str | None = None
    reason: str | None = None
    diagnostics: tuple[Diagnostic, ...] = ()

    def __post_init__(self) -> None:
        _choice(self.status, "flow.status", tuple(item.value for item in MatchStatus))
        object.__setattr__(self, "status", MatchStatus(self.status))
        object.__setattr__(self, "diagnostics", _items(self.diagnostics, "flow.diagnostics", Diagnostic))
        if self.status == MatchStatus.MATCH:
            if not isinstance(self.flow, FlowContext) or self.flow.protocol != "TCP":
                raise ValueError("flow MATCH requires TCP FlowContext evidence")
        else:
            if self.flow is not None:
                raise ValueError("only flow MATCH may carry flow evidence")
            _text(self.reason_code, "flow.reason_code")
            _text(self.reason, "flow.reason")
        _text(self.reason_code, "flow.reason_code", optional=True)
        _text(self.reason, "flow.reason", optional=True)
        if self.status in (MatchStatus.NOT_EVALUABLE, MatchStatus.ERROR) and not self.diagnostics:
            raise ValueError("flow NOT_EVALUABLE/ERROR requires diagnostics")


def _conditions(condition: FlowCondition, flow: FlowContext) -> tuple[list[bool | None], list[Diagnostic]]:
    checks: list[bool | None] = []
    diagnostics = []
    if condition.direction is not None:
        known = flow.packet_direction != "unknown"
        checks.append(flow.packet_direction == condition.direction if known else None)
        if not known:
            diagnostics.append(Diagnostic("unknown_flow_direction", "Client/server direction is unknown",
                                          category="input", keyword="flow.direction"))
    if condition.state is not None:
        known = flow.established_for_packet is not None
        checks.append(flow.established_for_packet == (condition.state == "established") if known else None)
        if not known:
            diagnostics.append(Diagnostic("unknown_flow_established", "TCP established evidence is unknown",
                                          category="input", keyword="flow.state"))
    return checks, diagnostics


def match_flow(condition: FlowCondition, context: InspectionContext) -> FlowMatchResult:
    """Chỉ TCP; false thắng unknown trong AND, unknown không thành false.

    Tin snapshot FlowContext do caller cung cấp, không suy từ tcp_state,
    handshake_observed, normalized port hoặc hướng header direct/reverse.
    processing_action=skip do Evaluation xử lý sau này.
    """
    if not isinstance(condition, FlowCondition):
        raise TypeError("condition must be FlowCondition")
    if not isinstance(context, InspectionContext):
        raise TypeError("context must be InspectionContext")
    try:
        flow = context.flow
        if flow is None or flow.protocol is None:
            diag = Diagnostic("missing_tcp_flow_context", "TCP flow context is unavailable", category="input")
            return FlowMatchResult(MatchStatus.NOT_EVALUABLE, reason_code=diag.code,
                                   reason=diag.reason, diagnostics=(diag,))
        if flow.protocol != "TCP":
            return FlowMatchResult(MatchStatus.NO_MATCH, reason_code="flow_protocol_mismatch",
                                   reason="Flow conditions require TCP in this MVP")
        checks, diagnostics = _conditions(condition, flow)
        if any(value is False for value in checks):
            return FlowMatchResult(MatchStatus.NO_MATCH, reason_code="flow_no_match",
                                   reason="At least one flow condition does not match",
                                   diagnostics=tuple(diagnostics))
        if any(value is None for value in checks):
            return FlowMatchResult(MatchStatus.NOT_EVALUABLE, reason_code="flow_not_evaluable",
                                   reason="Required flow evidence is unknown", diagnostics=tuple(diagnostics))
        return FlowMatchResult(MatchStatus.MATCH, flow=flow)
    except Exception as exc:
        diag = Diagnostic("flow_evaluation_error", f"Flow evaluation failed ({type(exc).__name__}): {exc}",
                          category="evaluation")
        return FlowMatchResult(MatchStatus.ERROR, reason_code=diag.code,
                               reason=diag.reason, diagnostics=(diag,))

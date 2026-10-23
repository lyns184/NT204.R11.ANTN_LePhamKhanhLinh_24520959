"""Tổng hợp matcher thành kết quả cả rule; không sinh hoặc ghi detection."""

from dataclasses import replace

from ids.detection.content_matcher import ContentMatchResult, ContentSearchLimits, match_contents
from ids.detection.flow_matcher import FlowMatchResult, match_flow
from ids.detection.header_matcher import HeaderMatchResult, match_header
from ids.detection.models import (
    Diagnostic, InspectionContext, MatchedInfo, MatchResult, MatchStatus, Rule,
)
from ids.detection.packet_matcher import PacketMatchResult, match_dsize, match_flags


def _unique(diagnostics: list[Diagnostic] | tuple[Diagnostic, ...]) -> tuple[Diagnostic, ...]:
    return tuple(dict.fromkeys(diagnostics))


def _adapter_fault(stage: str, context: InspectionContext) -> tuple[Diagnostic, ...]:
    """Chỉ lỗi nội bộ của adapter mà stage này cần; không nâng mọi warning thành ERROR."""
    code = ("flow_context_error" if stage == "flow" else
            "payload_preparation_error" if stage in ("dsize", "content") else None)
    return tuple(item for item in context.diagnostics
                 if code is not None and item.code == code and item.category == "evaluation")


def match_rule(rule: Rule, context: InspectionContext, *,
               content_limits: ContentSearchLimits | None = None) -> MatchResult:
    """Header -> Flow -> Flags -> Dsize -> Content, chỉ gọi điều kiện có trong rule.

    NO_MATCH/ERROR được short-circuit; NOT_EVALUABLE vẫn xét các điều kiện
    độc lập còn lại. ERROR đã gặp không bị biến thành NO_MATCH. Không tìm
    lỗi trong stage đã không cần gọi. Bằng chứng chỉ xuất khi cả rule MATCH.
    Engine lọc skip trước chọn candidate; guard ở đây cũng ngăn gọi trực tiếp
    match_rule trên event skip sinh MATCH. Không áp policy skip ở matcher con.
    """
    if not isinstance(rule, Rule) or not isinstance(context, InspectionContext):
        raise TypeError("expected Rule and InspectionContext")
    if content_limits is None:
        content_limits = ContentSearchLimits()
    if not isinstance(content_limits, ContentSearchLimits):
        raise TypeError("content_limits must be ContentSearchLimits or None")
    diagnostics = list(context.diagnostics)
    if context.processing_action == "skip":
        diag = Diagnostic("event_skipped", "Event is marked skip; no rule evaluation", category="input")
        return MatchResult(MatchStatus.NOT_EVALUABLE, rule.sid, reason_code=diag.code, reason=diag.reason,
                           diagnostics=_unique(diagnostics + [diag]))
    stage = "header"
    try:
        stages = [("header", lambda: match_header(rule.header, context), HeaderMatchResult)]
        if rule.flow is not None:
            stages.append(("flow", lambda: match_flow(rule.flow, context), FlowMatchResult))
        if rule.flags is not None:
            stages.append(("flags", lambda: match_flags(rule.flags, context), PacketMatchResult))
        if rule.dsize is not None:
            stages.append(("dsize", lambda: match_dsize(rule.dsize, context), PacketMatchResult))
        if rule.contents:
            stages.append(("content", lambda: match_contents(rule.contents, context, limits=content_limits),
                           ContentMatchResult))
        outcomes = {}
        unknown = []
        for stage, evaluate, expected_type in stages:
            faults = _adapter_fault(stage, context)
            if faults:
                return MatchResult(MatchStatus.ERROR, rule.sid, reason_code=faults[0].code,
                                   reason=f"{stage}: {faults[0].reason}", diagnostics=_unique(diagnostics + list(faults)))
            result = evaluate()
            if not isinstance(result, expected_type):
                raise TypeError(f"{stage} matcher returned {type(result).__name__}, expected {expected_type.__name__}")
            outcomes[stage] = result
            diagnostics.extend(replace(item, source=rule.source)
                               if item.source is None and rule.source is not None else item
                               for item in result.diagnostics)
            if result.status in (MatchStatus.NO_MATCH, MatchStatus.ERROR):
                return MatchResult(result.status, rule.sid, reason_code=result.reason_code,
                                   reason=f"{stage}: {result.reason}", diagnostics=_unique(diagnostics))
            if result.status == MatchStatus.NOT_EVALUABLE:
                unknown.append(stage)
        if unknown:
            return MatchResult(MatchStatus.NOT_EVALUABLE, rule.sid, reason_code="rule_not_evaluable",
                               reason=f"Cannot evaluate required stages: {', '.join(unknown)}",
                               diagnostics=_unique(diagnostics))
        flow = outcomes.get("flow")
        info = MatchedInfo(
            orientation=outcomes["header"].orientation,
            flow={"condition": rule.flow.to_dict(), "actual": flow.flow.to_dict()} if flow is not None else None,
            flags=outcomes["flags"].matched if "flags" in outcomes else None,
            dsize=outcomes["dsize"].matched if "dsize" in outcomes else None,
            contents=outcomes["content"].contents if "content" in outcomes else (),
        )
        return MatchResult(MatchStatus.MATCH, rule.sid, matched_info=info, diagnostics=_unique(diagnostics))
    except Exception as exc:
        diag = Diagnostic("rule_evaluation_error", f"Rule {rule.sid} failed during {stage} ({type(exc).__name__}): {exc}",
                          category="evaluation", source=rule.source)
        return MatchResult(MatchStatus.ERROR, rule.sid, reason_code=diag.code, reason=diag.reason,
                           diagnostics=_unique(diagnostics + [diag]))

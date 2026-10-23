"""Đánh giá candidate theo event, giữ nhiều MATCH và counters; chưa tạo detection."""

from dataclasses import dataclass, field, replace

from ids.detection.content_matcher import ContentSearchLimits
from ids.detection.matcher import match_rule
from ids.detection.models import (
    Diagnostic, InspectionContext, JSONModel, MatchResult, MatchStatus,
    _boolean, _integer, _items,
)
from ids.detection.repository import RuleRepository


@dataclass(frozen=True)
class EvaluationMetrics(JSONModel):
    events_evaluated: int = 0
    events_skipped: int = 0
    candidate_rules: int = 0
    matches: int = 0
    rule_evaluation_errors: int = 0
    rule_not_evaluable: int = 0

    def __post_init__(self) -> None:
        for name in ("events_evaluated", "events_skipped", "candidate_rules", "matches",
                     "rule_evaluation_errors", "rule_not_evaluable"):
            _integer(getattr(self, name), name, 0)


@dataclass(frozen=True)
class EvaluationResult(JSONModel):
    rule_results: tuple[MatchResult, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    skipped: bool = False
    metrics: EvaluationMetrics = field(default_factory=EvaluationMetrics)

    def __post_init__(self) -> None:
        object.__setattr__(self, "rule_results", _items(self.rule_results, "evaluation.rule_results", MatchResult))
        object.__setattr__(self, "diagnostics", _items(self.diagnostics, "evaluation.diagnostics", Diagnostic))
        _boolean(self.skipped, "evaluation.skipped")
        if not isinstance(self.metrics, EvaluationMetrics):
            raise ValueError("evaluation.metrics must be EvaluationMetrics")
        if len({result.sid for result in self.rule_results}) != len(self.rule_results):
            raise ValueError("evaluation must contain at most one result per SID")
        if self.skipped and self.rule_results:
            raise ValueError("skipped evaluation must not contain rule results")

    @property
    def matched_results(self) -> tuple[MatchResult, ...]:
        return tuple(result for result in self.rule_results if result.status == MatchStatus.MATCH)


class EvaluationEngine:
    """Một engine mỗi capture, dùng tuần tự; không dedup kết quả xuyên packet.

    Metrics là snapshot bất biến. Commit counters sau khi có EvaluationResult;
    lỗi chọn candidate là lỗi toàn lần evaluate và propagate, không giả làm
    candidate rỗng thành công. Lỗi riêng từng rule được chứa rồi tiếp tục.
    """

    def __init__(self, repository: RuleRepository, *, content_limits: ContentSearchLimits | None = None):
        if not isinstance(repository, RuleRepository):
            raise TypeError("repository must be RuleRepository")
        if content_limits is None:
            content_limits = ContentSearchLimits()
        if not isinstance(content_limits, ContentSearchLimits):
            raise TypeError("content_limits must be ContentSearchLimits or None")
        self._repository = repository
        self._content_limits = content_limits
        self._metrics = EvaluationMetrics()

    @property
    def repository(self) -> RuleRepository:
        return self._repository

    @property
    def content_limits(self) -> ContentSearchLimits:
        return self._content_limits

    @property
    def metrics(self) -> EvaluationMetrics:
        return self._metrics

    def evaluate(self, context: InspectionContext) -> EvaluationResult:
        if not isinstance(context, InspectionContext):
            raise TypeError("context must be InspectionContext")
        diagnostics = list(context.diagnostics)
        if context.processing_action == "skip":
            diagnostics.append(Diagnostic("event_skipped", "Event is marked skip; no candidate selection or matching",
                                          category="input"))
            metrics = replace(self._metrics, events_skipped=self._metrics.events_skipped + 1)
            result = EvaluationResult(diagnostics=tuple(dict.fromkeys(diagnostics)), skipped=True, metrics=metrics)
            self._metrics = metrics
            return result
        candidates = self._repository.candidates(context)
        results = []
        for rule in candidates:
            try:
                result = match_rule(rule, context, content_limits=self._content_limits)
                if not isinstance(result, MatchResult) or result.sid != rule.sid:
                    raise ValueError("Rule matcher returned invalid result type or mismatched SID")
            except Exception as exc:
                diag = Diagnostic("engine_rule_error", f"Rule {rule.sid} evaluation failed ({type(exc).__name__}): {exc}",
                                  category="evaluation", source=rule.source)
                result = MatchResult(MatchStatus.ERROR, rule.sid, reason_code=diag.code, reason=diag.reason,
                                     diagnostics=(diag,))
            results.append(result)
            diagnostics.extend(result.diagnostics)
        metrics = replace(self._metrics,
            events_evaluated=self._metrics.events_evaluated + 1,
            candidate_rules=self._metrics.candidate_rules + len(results),
            matches=self._metrics.matches + sum(result.status == MatchStatus.MATCH for result in results),
            rule_evaluation_errors=self._metrics.rule_evaluation_errors + sum(result.status == MatchStatus.ERROR for result in results),
            rule_not_evaluable=self._metrics.rule_not_evaluable + sum(result.status == MatchStatus.NOT_EVALUABLE for result in results))
        result = EvaluationResult(tuple(results), tuple(dict.fromkeys(diagnostics)), metrics=metrics)
        self._metrics = metrics
        return result

"""Tìm chuỗi content trên một raw payload đầy đủ; không full-rule evaluation."""

from dataclasses import dataclass

from ids.detection.models import (
    MAX_RULE_NUMBER, ContentCondition, ContentMatch, Diagnostic, InspectionContext,
    JSONModel, MatchStatus, PayloadStatus, _choice, _integer, _items, _text,
)


@dataclass(frozen=True)
class ContentSearchLimits(JSONModel):
    """Giới hạn công việc mỗi lần gọi, không phải giới hạn cú pháp rule.

    search_bytes tính toàn bộ vùng truyền vào find mỗi lần (upper bound),
    không phải số byte CPU thực sự đọc hoặc thời gian chạy. Range rỗng không
    gọi find. Các giới hạn được kiểm tra trước cấp phát bản lowercase payload.
    """

    max_search_calls: int = 10000
    max_search_bytes: int = 8 * 1024 * 1024
    max_contents: int = 256
    max_payload_bytes: int = 65535

    def __post_init__(self) -> None:
        for name in ("max_search_calls", "max_search_bytes", "max_contents", "max_payload_bytes"):
            _integer(getattr(self, name), name, 1, MAX_RULE_NUMBER)


@dataclass(frozen=True)
class ContentMatchResult(JSONModel):
    """MATCH mang một tổ hợp evidence theo thứ tự content, không tạo detection."""

    status: MatchStatus
    contents: tuple[ContentMatch, ...] = ()
    search_calls: int = 0
    search_bytes: int = 0
    reason_code: str | None = None
    reason: str | None = None
    diagnostics: tuple[Diagnostic, ...] = ()

    def __post_init__(self) -> None:
        _choice(self.status, "content.status", tuple(item.value for item in MatchStatus))
        object.__setattr__(self, "status", MatchStatus(self.status))
        object.__setattr__(self, "contents", _items(self.contents, "content.matches", ContentMatch))
        object.__setattr__(self, "diagnostics", _items(self.diagnostics, "content.diagnostics", Diagnostic))
        _integer(self.search_calls, "content.search_calls", 0)
        _integer(self.search_bytes, "content.search_bytes", 0)
        if self.status == MatchStatus.MATCH:
            if any(item.index != index for index, item in enumerate(self.contents)):
                raise ValueError("content evidence indices must follow rule order starting at zero")
        else:
            if self.contents:
                raise ValueError("only content MATCH may contain evidence")
            _text(self.reason_code, "content.reason_code")
            _text(self.reason, "content.reason")
        _text(self.reason_code, "content.reason_code", optional=True)
        _text(self.reason, "content.reason", optional=True)
        if self.status in (MatchStatus.NOT_EVALUABLE, MatchStatus.ERROR) and not self.diagnostics:
            raise ValueError("content NOT_EVALUABLE/ERROR requires diagnostics")


class _SearchLimit(Exception):
    pass


@dataclass
class _Budget:
    limits: ContentSearchLimits
    calls: int = 0
    bytes: int = 0

    def reserve(self, size: int) -> None:
        if self.calls >= self.limits.max_search_calls:
            raise _SearchLimit("Content search call limit reached")
        if size > self.limits.max_search_bytes - self.bytes:
            raise _SearchLimit("Content search byte budget reached")
        self.calls += 1
        self.bytes += size


@dataclass
class _Frame:
    index: int
    anchor: int | None
    cursor: int
    end: int


def _relative(condition: ContentCondition) -> bool:
    return condition.distance is not None or condition.within is not None


def _frame(index: int, previous_end: int, conditions: tuple[ContentCondition, ...], size: int) -> _Frame:
    condition = conditions[index]
    relative = _relative(condition)
    start = previous_end + (condition.distance or 0) if relative else (condition.offset or 0)
    length = condition.within if relative else condition.depth
    end = min(size, start + length) if length is not None else size
    return _Frame(index, previous_end if relative else None, start, end)


def _find(payload: bytes, pattern: bytes, start: int, end: int) -> int:
    return payload.find(pattern, start, end)


def _search(conditions: tuple[ContentCondition, ...], payload: bytes, budget: _Budget) -> tuple[int, ...] | None:
    """DFS lặp, thử cả occurrence overlap; cache suffix đã chứng minh thất bại.

    Relative suffix chỉ phụ thuộc (index, previous_end). Absolute suffix độc
    lập prefix; nếu đã thử hết suffix đó thì không prefix nào cứu được rule.
    Cache/stack theo số search calls/content, không dựng toàn bộ tổ hợp.
    """
    stack = [_frame(0, 0, conditions, len(payload))]
    path: list[int] = []
    failed: set[tuple[int, int | None]] = set()
    folded_payload = None
    folded_patterns: dict[int, bytes] = {}
    while stack:
        frame = stack[-1]
        condition = conditions[frame.index]
        length = len(condition.pattern)
        position = -1
        if frame.cursor + length <= frame.end:
            budget.reserve(frame.end - frame.cursor)
            if condition.nocase:
                if folded_payload is None:
                    folded_payload = payload.lower()  # ASCII bytes only; offsets không đổi.
                if frame.index not in folded_patterns:
                    folded_patterns[frame.index] = condition.pattern.lower()
                haystack, needle = folded_payload, folded_patterns[frame.index]
            else:
                haystack, needle = payload, condition.pattern
            position = _find(haystack, needle, frame.cursor, frame.end)
        if position < 0:
            failed.add((frame.index, frame.anchor))
            if frame.anchor is None:
                return None
            stack.pop()
            path.pop()
            continue
        frame.cursor = position + 1  # Bao gồm occurrence chồng lấp.
        if frame.index == len(conditions) - 1:
            return tuple(path + [position])
        following = _frame(frame.index + 1, position + length, conditions, len(payload))
        if (following.index, following.anchor) not in failed:
            path.append(position)
            stack.append(following)
    return None


def _limited(reason: str, budget: _Budget) -> ContentMatchResult:
    diagnostic = Diagnostic("content_search_limit", reason, category="evaluation", keyword="content")
    return ContentMatchResult(MatchStatus.NOT_EVALUABLE, search_calls=budget.calls, search_bytes=budget.bytes,
                              reason_code=diagnostic.code, reason=reason, diagnostics=(diagnostic,))


def match_contents(conditions: tuple[ContentCondition, ...] | list[ContentCondition],
                   context: InspectionContext, *, limits: ContentSearchLimits | None = None) -> ContentMatchResult:
    """AND tất cả content, trả tổ hợp đầu tiên tìm được theo thứ tự DFS.

    Absolute dùng offset/depth từ đầu payload; relative dùng previous_end +
    distance, within tính từ start đã dịch. Không modifier thì tìm từ đầu.
    Payload phải available; không đọc decoded/normalized body hoặc stream.
    Không có content là điều kiện rỗng MATCH, không đòi payload.

    API sai kiểu hoặc first-relative list gây TypeError/ValueError; rule hợp
    lệ do Parser tạo đã loại first-relative. Hết budget không phải NO_MATCH.
    Không áp processing_action; Evaluation chịu trách nhiệm skip sau này.
    """
    if not isinstance(conditions, (list, tuple)):
        raise TypeError("conditions must be a list/tuple of ContentCondition")
    if not isinstance(context, InspectionContext):
        raise TypeError("context must be InspectionContext")
    if limits is None:
        limits = ContentSearchLimits()
    if not isinstance(limits, ContentSearchLimits):
        raise TypeError("limits must be ContentSearchLimits or None")
    budget = _Budget(limits)
    if len(conditions) > limits.max_contents:
        return _limited("Content count exceeds the configured search limit", budget)
    if any(not isinstance(item, ContentCondition) for item in conditions):
        raise TypeError("conditions must contain only ContentCondition")
    conditions = tuple(conditions)
    if conditions and _relative(conditions[0]):
        raise ValueError("first content cannot be relative to a preceding content")
    if not conditions:
        return ContentMatchResult(MatchStatus.MATCH)
    try:
        if context.payload_status != PayloadStatus.AVAILABLE:
            diag = Diagnostic("payload_not_available", "Content requires a complete available payload", category="input")
            return ContentMatchResult(MatchStatus.NOT_EVALUABLE, reason_code=diag.code,
                                      reason=diag.reason, diagnostics=(diag,))
        payload = context.payload
        if len(payload) > limits.max_payload_bytes:
            return _limited("Payload size exceeds the configured content search limit", budget)
        positions = _search(conditions, payload, budget)
        if positions is None:
            return ContentMatchResult(MatchStatus.NO_MATCH, search_calls=budget.calls, search_bytes=budget.bytes,
                                      reason_code="content_no_match", reason="No position combination satisfies all contents")
        evidence = tuple(ContentMatch(index, condition.pattern,
            payload[position:position + len(condition.pattern)], position, position + len(condition.pattern),
            nocase=condition.nocase) for index, (condition, position) in enumerate(zip(conditions, positions)))
        return ContentMatchResult(MatchStatus.MATCH, contents=evidence,
                                  search_calls=budget.calls, search_bytes=budget.bytes)
    except _SearchLimit as exc:
        return _limited(str(exc), budget)
    except Exception as exc:
        diag = Diagnostic("content_evaluation_error", f"Content evaluation failed ({type(exc).__name__}): {exc}",
                          category="evaluation")
        return ContentMatchResult(MatchStatus.ERROR, search_calls=budget.calls, search_bytes=budget.bytes,
                                  reason_code=diag.code, reason=diag.reason, diagnostics=(diag,))

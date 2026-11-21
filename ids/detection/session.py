"""Nối event/packet snapshot với Engine, Generator và caller ghi JSONL."""

from collections.abc import Callable
from typing import Any

from ids.core.event import IDSEvent
from ids.flow_tracker import FlowTrackingResult
from ids.detection.context import make_inspection_context
from ids.detection.engine import EvaluationEngine, EvaluationResult
from ids.detection.flow_context import FlowContextResult, build_flow_context
from ids.detection.generator import generate_detection
from ids.detection.models import Diagnostic
from ids.detection.payload import prepare_payload


class DetectionSession:
    """Một session/capture, caller tuần tự hóa callback và chịu trách nhiệm I/O.

    matches của engine và detections_written riêng biệt. Số written tăng khi
    record_handler thành công, trước khi chuyển record cho after_record.
    Không lưu lịch sử event, payload, result hoặc detection trong session.
    """

    def __init__(self, engine: EvaluationEngine, record_handler: Callable[[dict[str, Any]], None],
                 diagnostic_handler: Callable[[Diagnostic], None] | None = None, *,
                 after_record: Callable[[dict[str, Any]], None] | None = None):
        if not isinstance(engine, EvaluationEngine):
            raise TypeError("engine must be EvaluationEngine")
        if not callable(record_handler) or any(
            handler is not None and not callable(handler) for handler in (diagnostic_handler, after_record)
        ):
            raise TypeError("record/diagnostic/after_record handlers must be callable")
        self.engine = engine
        self._rules = {rule.sid: rule for rule in engine.repository.rules}
        self._record_handler = record_handler
        self._diagnostic_handler = diagnostic_handler
        self._after_record = after_record
        self._detections_written = 0

    @property
    def detections_written(self) -> int:
        return self._detections_written

    def process(self, event: IDSEvent, tracking_result: FlowTrackingResult | None) -> EvaluationResult:
        flow = (build_flow_context(event, tracking_result) if tracking_result is not None else
                FlowContextResult(diagnostics=(Diagnostic(
                    "flow_tracking_unavailable", "No tracking result for this packet", category="input"),)))
        context = make_inspection_context(event, prepare_payload(event), flow)
        result = self.engine.evaluate(context)
        if self._diagnostic_handler is not None:
            for diagnostic in result.diagnostics:
                self._diagnostic_handler(diagnostic)
        for match in result.matched_results:
            detection = generate_detection(self._rules[match.sid], context, match)
            record = detection.to_dict()
            self._record_handler(record)
            self._detections_written += 1
            if self._after_record is not None:
                self._after_record(record)
        return result

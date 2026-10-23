"""Tạo snapshot input cho Engine từ event và kết quả các adapter."""

from ids.core.event import IDSEvent
from ids.detection.flow_context import FlowContextResult
from ids.detection.models import InspectionContext
from ids.detection.payload import PayloadResult


def make_inspection_context(event: IDSEvent, payload_result: PayloadResult,
                            flow_context: FlowContextResult) -> InspectionContext:
    if not isinstance(event, IDSEvent):
        raise TypeError("event must be IDSEvent")
    if not isinstance(payload_result, PayloadResult):
        raise TypeError("payload_result must be PayloadResult")
    if not isinstance(flow_context, FlowContextResult):
        raise TypeError("flow_context must be FlowContextResult")
    return InspectionContext(
        timestamp=event.timestamp, packet_id=event.packet_id,
        normalized=event.normalized, processing_action=event.processing_action,
        payload=payload_result.payload, payload_status=payload_result.status,
        flow=flow_context.flow,
        diagnostics=tuple(dict.fromkeys(payload_result.diagnostics + flow_context.diagnostics)),
    )

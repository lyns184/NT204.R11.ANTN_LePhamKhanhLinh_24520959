"""Bảng flow hai chiều và statistics; TCP transitions và expiry bổ sung sau."""

from dataclasses import dataclass
from typing import Literal
from uuid import uuid4

from ids.core.config import FlowTrackerConfig
from ids.core.event import IDSEvent
from ids.flow_tracker.identity import extract_flow_identity, get_flow_direction
from ids.flow_tracker.models import FlowDirection, FlowKey, FlowRecord
from ids.flow_tracker.statistics import update_flow_statistics


@dataclass(frozen=True)
class FlowTrackingResult:
    """Kết quả riêng, không ghi đè status/reason của Preprocessor."""

    status: Literal["tracked", "skipped", "error"]
    flow: FlowRecord | None = None
    direction: FlowDirection | None = None
    reason: str | None = None


class FlowTracker:
    """Một instance cho mỗi capture; ID ổn định trong phiên flow đang active.

    UUID mới mỗi lần tạo record, không dùng hash() hay tuple làm ID phiên.
    Chưa tích hợp pipeline: caller gọi track sau preprocess_event.
    """

    def __init__(self, config: FlowTrackerConfig | None = None) -> None:
        self.config = config if config is not None else FlowTrackerConfig()
        if not isinstance(self.config, FlowTrackerConfig):
            raise TypeError("Expected FlowTrackerConfig")
        self.active_flows: dict[FlowKey, FlowRecord] = {}

    def track(self, event: IDSEvent) -> FlowTrackingResult:
        """Tìm/tạo flow, cập nhật statistics và metadata; chưa cập nhật TCP state.

        Skip/error không tạo flow và xóa metadata flow cũ trên event. Sai kiểu
        API gây TypeError; IDSEvent malformed được chứa lỗi và trả reason.
        Khi bảng đầy vẫn tìm được flow cũ, nhưng không tạo thêm flow mới.
        """
        if not isinstance(event, IDSEvent):
            raise TypeError("FlowTracker.track expects IDSEvent")
        event.flow_id = None
        event.direction = None
        if event.processing_action != "process":
            return FlowTrackingResult("skipped", reason="Event is not marked for processing")
        if event.preprocess_status not in ("valid", "partial", "invalid"):
            return FlowTrackingResult("skipped", reason="Event has not completed preprocessing")
        stage = "identity"
        try:
            identity = extract_flow_identity(event)
            flow = self.active_flows.get(identity.key)
            is_new = flow is None
            if is_new:
                if len(self.active_flows) >= self.config.max_active_flows:
                    return FlowTrackingResult("skipped", reason="Active flow limit reached")
                flow = FlowRecord(
                    flow_id=uuid4().hex,
                    key=identity.key,
                    endpoint_a=identity.source,
                    endpoint_b=identity.destination,
                    start_time=identity.timestamp,
                    last_seen=identity.timestamp,
                )
            direction = get_flow_direction(identity, flow)
            stage = "statistics"
            update_flow_statistics(flow, event, identity, direction)
            if is_new:
                self.active_flows[identity.key] = flow
        except Exception as error:
            return FlowTrackingResult(
                "error", reason=f"Flow {stage} error: {type(error).__name__}: {error}"
            )
        event.flow_id = flow.flow_id
        event.direction = direction
        return FlowTrackingResult("tracked", flow=flow, direction=direction)

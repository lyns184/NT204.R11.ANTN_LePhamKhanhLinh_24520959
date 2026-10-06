"""Bảng flow hai chiều, statistics, TCP state và vòng đời flow."""

import math
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Literal
from uuid import uuid4

from ids.core.config import FlowTrackerConfig
from ids.core.event import IDSEvent
from ids.flow_tracker.identity import extract_flow_identity, get_flow_direction
from ids.flow_tracker.models import FlowDirection, FlowKey, FlowRecord, TCPState
from ids.flow_tracker.statistics import update_flow_statistics
from ids.flow_tracker.tcp_state import apply_tcp_update, prepare_tcp_update


@dataclass(frozen=True)
class FlowTrackingResult:
    """Kết quả riêng, không ghi đè status/reason của Preprocessor."""

    status: Literal["tracked", "skipped", "error"]
    flow: FlowRecord | None = None
    direction: FlowDirection | None = None
    reason: str | None = None
    # Caller xuất ngay; tracker không giữ queue flow đã đóng trong bộ nhớ.
    completed_flows: tuple[dict[str, Any], ...] = ()


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
        self._time_watermark: float | None = None

    @staticmethod
    def _timestamp(value: float) -> float:
        try:
            valid = type(value) in (int, float) and math.isfinite(value)
        except OverflowError:
            valid = False
        if not valid:
            raise ValueError("Lifecycle timestamp must be finite")
        return float(value)

    def _idle(self, flow: FlowRecord, now: float) -> bool:
        timeout = (
            self.config.tcp_idle_timeout_seconds if flow.protocol == "TCP"
            else self.config.udp_idle_timeout_seconds
        )
        return now - flow.last_seen >= timeout

    @staticmethod
    def _summary(flow: FlowRecord, reason: str, now: float) -> dict[str, Any]:
        summary = flow.to_dict()
        summary["close_reason"] = reason
        summary["exported_at"] = now
        return summary

    def expire(self, now: float) -> list[dict[str, Any]]:
        """Đóng/xuất flow idle ở ngưỡng >= timeout; clock không lùi.

        Caller live phải gọi định kỳ kể cả không có packet (tích hợp task 6).
        Không dùng wall clock cho replay PCAP. Duration vẫn tính từ packet
        đầu/cuối, không cộng thời gian chờ timeout. Không lưu lịch sử đã xuất.
        """
        now = self._timestamp(now)
        if self._time_watermark is not None:
            now = max(now, self._time_watermark)
        completed = []
        keys = []
        for key, flow in self.active_flows.items():
            terminal = flow.state in (TCPState.CLOSED, TCPState.RESET)
            if terminal or self._idle(flow, now):
                reason = (flow.close_reason or "tcp_closed") if terminal else "idle_timeout"
                completed.append(self._summary(flow, reason, now))
                keys.append(key)
        for key in keys:
            del self.active_flows[key]
        self._time_watermark = now
        return completed

    def flush(self, reason: str = "capture_end", now: float | None = None) -> list[dict[str, Any]]:
        """Xuất bản chụp mọi flow còn lại và giải phóng bảng khi dừng capture.

        Không tự gán TCP CLOSED: EOF/dừng capture không chứng minh đã đóng TCP.
        Có thể dùng reason capture_error/shutdown từ caller task tích hợp.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("Flush reason must be a nonempty string")
        if now is not None:
            now = self._timestamp(now)
        completed = [self._summary(flow, reason, max(flow.last_seen, now) if now is not None else flow.last_seen)
                     for flow in self.active_flows.values()]
        self.active_flows.clear()
        return completed

    def track(self, event: IDSEvent) -> FlowTrackingResult:
        """Tìm/tạo flow, cập nhật statistics, TCP state và metadata.

        Skip/error không tạo flow và xóa metadata flow cũ trên event. Sai kiểu
        API gây TypeError; IDSEvent malformed được chứa lỗi và trả reason.
        Hết hạn trước lookup; bảng đầy vẫn tìm được flow cũ nhưng bỏ flow mới.
        completed_flows chứa summary hết hạn/đóng để caller xuất ngay.
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
        completed: list[dict[str, Any]] = []
        try:
            identity = extract_flow_identity(event)
            now = max(identity.timestamp, self._time_watermark) if self._time_watermark is not None else identity.timestamp
            flow = self.active_flows.get(identity.key)
            is_new = flow is None or self._idle(flow, now) or flow.state in (TCPState.CLOSED, TCPState.RESET)
            if is_new:
                candidate = FlowRecord(
                    flow_id=uuid4().hex,
                    key=identity.key,
                    endpoint_a=identity.source,
                    endpoint_b=identity.destination,
                    start_time=identity.timestamp,
                    last_seen=identity.timestamp,
                )
            else:
                candidate = deepcopy(flow)
            direction = get_flow_direction(identity, candidate)
            stage = "TCP state"
            tcp_update = prepare_tcp_update(candidate, event, direction)
            stage = "statistics"
            update_flow_statistics(candidate, event, identity, direction)
            apply_tcp_update(candidate, tcp_update)
            # Validate on a candidate before expiry or changes to an old record.
            stage = "lifecycle"
            completed = self.expire(now)
            if is_new:
                if len(self.active_flows) >= self.config.max_active_flows:
                    return FlowTrackingResult("skipped", reason="Active flow limit reached",
                                              completed_flows=tuple(completed))
                flow = candidate
                self.active_flows[identity.key] = flow
            else:
                # Preserve the FlowRecord reference returned on earlier packets.
                flow.__dict__.update(candidate.__dict__)
            if flow.state in (TCPState.CLOSED, TCPState.RESET):
                completed.append(self._summary(flow, flow.close_reason or "tcp_closed", now))
                del self.active_flows[identity.key]
        except Exception as error:
            return FlowTrackingResult(
                "error", reason=f"Flow {stage} error: {type(error).__name__}: {error}",
                completed_flows=tuple(completed),
            )
        event.flow_id = flow.flow_id
        event.direction = direction
        return FlowTrackingResult("tracked", flow=flow, direction=direction,
                                  completed_flows=tuple(completed))

"""Adapter từ snapshot packet của Tracker sang FlowContext cho detection."""

from dataclasses import dataclass

from ids.core.event import IDSEvent
from ids.flow_tracker.identity import extract_flow_identity
from ids.flow_tracker.models import FlowPacketSnapshot
from ids.flow_tracker.tracker import FlowTrackingResult
from ids.detection.models import Diagnostic, FlowContext, JSONModel, _items


@dataclass(frozen=True)
class FlowContextResult(JSONModel):
    flow: FlowContext | None = None
    diagnostics: tuple[Diagnostic, ...] = ()

    def __post_init__(self) -> None:
        if self.flow is not None and not isinstance(self.flow, FlowContext):
            raise ValueError("flow context result requires FlowContext or None")
        object.__setattr__(self, "diagnostics", _items(self.diagnostics, "flow.diagnostics", Diagnostic))
        if self.flow is None and not self.diagnostics:
            raise ValueError("missing flow context requires diagnostics")


def _from_snapshot(event: IDSEvent, snapshot: FlowPacketSnapshot) -> FlowContext:
    identity = extract_flow_identity(event)
    if snapshot.direction not in ("forward", "backward"):
        raise ValueError("snapshot has invalid tracker direction")
    source, target = ((snapshot.endpoint_a, snapshot.endpoint_b) if snapshot.direction == "forward"
                      else (snapshot.endpoint_b, snapshot.endpoint_a))
    if (identity.source != source or identity.destination != target
            or identity.key.protocol != snapshot.protocol or identity.timestamp != snapshot.timestamp
            or type(event.packet_id) is not int or event.packet_id <= 0
            or type(snapshot.packet_id) is not int or event.packet_id != snapshot.packet_id
            or event.flow_id != snapshot.flow_id or event.direction != snapshot.direction):
        raise ValueError("tracking snapshot does not belong to this packet")
    client = server = None
    direction = "unknown"
    if snapshot.protocol == "TCP" and snapshot.client_direction is not None:
        if snapshot.client_direction not in ("forward", "backward"):
            raise ValueError("snapshot has invalid client direction")
        client, server = ((snapshot.endpoint_a, snapshot.endpoint_b)
                          if snapshot.client_direction == "forward"
                          else (snapshot.endpoint_b, snapshot.endpoint_a))
        if client == server:
            client = server = None
        else:
            direction = "to_server" if snapshot.direction == snapshot.client_direction else "to_client"
    return FlowContext(
        flow_id=snapshot.flow_id, protocol=snapshot.protocol, tcp_state=snapshot.tcp_state,
        client_endpoint=client, server_endpoint=server, packet_direction=direction,
        established_for_packet=snapshot.established_for_packet,
        handshake_observed=snapshot.handshake_observed,
    )


def build_flow_context(event: IDSEvent, tracking_result: FlowTrackingResult) -> FlowContextResult:
    """Dùng snapshot đúng packet, không lookup active table hoặc đọc state mutable.

    Skip/error/missing snapshot cho flow=None và diagnostic; không đoán role
    từ port/A-B hoặc ESTABLISHED cũ. UDP chỉ có flow_id/protocol, role unknown.
    Caller gắn result.flow/diagnostics vào InspectionContext ở bước integration.
    """
    if not isinstance(event, IDSEvent):
        raise TypeError("event must be IDSEvent")
    if not isinstance(tracking_result, FlowTrackingResult):
        raise TypeError("tracking_result must be FlowTrackingResult")
    if tracking_result.status != "tracked":
        return FlowContextResult(diagnostics=(Diagnostic(
            "flow_tracking_unavailable", f"Flow tracker {tracking_result.status}: {tracking_result.reason}",
            category="input"),))
    if not isinstance(tracking_result.snapshot, FlowPacketSnapshot):
        return FlowContextResult(diagnostics=(Diagnostic(
            "missing_flow_snapshot", "Tracking result has no immutable packet snapshot", category="input"),))
    try:
        return FlowContextResult(flow=_from_snapshot(event, tracking_result.snapshot))
    except ValueError as exc:
        return FlowContextResult(diagnostics=(Diagnostic(
            "invalid_flow_snapshot", f"Cannot use tracking snapshot: {exc}", category="input"),))
    except Exception as exc:
        return FlowContextResult(diagnostics=(Diagnostic(
            "flow_context_error", f"Flow context failed ({type(exc).__name__}): {exc}",
            category="evaluation"),))

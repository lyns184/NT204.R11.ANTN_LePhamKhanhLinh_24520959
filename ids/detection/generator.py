"""Chuyển MATCH thành DetectionEvent; không chạy lại matching hoặc lookup flow."""

from collections.abc import Mapping
from ipaddress import IPv4Address

from ids.detection.models import DetectionEvent, InspectionContext, MatchResult, MatchStatus, Rule


def _ip(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return value if str(IPv4Address(value)) == value else None
    except ValueError:
        return None


def _port(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= 65535 else None


def generate_detection(rule: Rule, context: InspectionContext, match: MatchResult) -> DetectionEvent:
    if not isinstance(rule, Rule) or not isinstance(context, InspectionContext) or not isinstance(match, MatchResult):
        raise TypeError("generate_detection requires Rule, InspectionContext and MatchResult")
    if context.processing_action == "skip" or match.status != MatchStatus.MATCH or match.sid != rule.sid:
        raise ValueError("Detection requires a MATCH for this rule and a process context")
    normalized = context.normalized
    sections = [normalized.get(name) for name in ("network", "transport", "application")]
    network, transport, application = [value if isinstance(value, Mapping) else {} for value in sections]
    protocol = transport.get("protocol")
    protocol = protocol if protocol in ("TCP", "UDP") else None
    application_protocol = application.get("protocol")
    if not isinstance(application_protocol, str) or not application_protocol.strip():
        application_protocol = None
    return DetectionEvent(
        timestamp=context.timestamp, packet_id=context.packet_id,
        sid=rule.sid, rev=rule.rev, msg=rule.msg, classtype=rule.classtype, priority=rule.priority,
        src_ip=_ip(network.get("src_ip")), dst_ip=_ip(network.get("dst_ip")),
        src_port=_port(transport.get("src_port")) if protocol is not None else None,
        dst_port=_port(transport.get("dst_port")) if protocol is not None else None,
        protocol=protocol, application_protocol=application_protocol,
        flow_id=context.flow.flow_id if context.flow is not None else None,
        matched_info=match.matched_info,
    )

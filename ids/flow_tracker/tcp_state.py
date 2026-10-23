"""TCP state logic từ packet quan sát; không mô phỏng đầy đủ TCP endpoint."""

from copy import deepcopy
from dataclasses import dataclass

from ids.core.event import IDSEvent
from ids.flow_tracker.models import (
    FlowDirection, FlowRecord, TCPFlagCounters, TCPHandshakeEvidence, TCPState, TCPTrackingState,
)

FLAG_NAMES = dict(zip("FSRPAUECN", ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "NS")))


@dataclass(frozen=True)
class TCPUpdate:
    state: TCPState
    tracking: TCPTrackingState
    flags: TCPFlagCounters
    close_reason: str | None


def _flags(transport: dict) -> dict[str, bool] | None:
    detail, text = transport.get("flags_detail"), transport.get("flags")
    if detail is not None and (not isinstance(detail, dict) or any(
        name not in FLAG_NAMES.values() or type(value) is not bool
        for name, value in detail.items()
    )):
        raise ValueError("TCP flags_detail must contain known flags with boolean values")
    parsed = None
    if text is not None:
        if not isinstance(text, str) or any(char not in FLAG_NAMES for char in text):
            raise ValueError("TCP flags must use Scapy flag letters FSRPAUECN")
        parsed = {name: char in text for char, name in FLAG_NAMES.items()}
    if detail:
        if parsed is not None and any(parsed[name] != value for name, value in detail.items()):
            raise ValueError("TCP flags and flags_detail disagree")
        return {**(parsed or {}), **detail}
    return parsed


def _number(value, name: str) -> int | None:
    if value is not None and (type(value) is not int or not 0 <= value <= 2**32 - 1):
        raise ValueError(f"TCP {name} must be an unsigned 32-bit integer or None")
    return value


def _covers(ack: int | None, end: int | None) -> bool:
    # Missing optional sequence/ack fields allow logical direction-based tracking.
    # Otherwise compare cumulative ACK in the 32-bit sequence number space.
    return ack is None or end is None or (ack - end) % 2**32 < 2**31


def _acks_syn(ack: int | None, start: int | None, end: int | None) -> bool:
    # SYN chiếm một sequence number; ACK không được vượt phần đã quan sát.
    # Cho phép peer chỉ ACK SYN hoặc một phần data mang trên SYN (RFC 9293).
    return (ack is not None and start is not None and end is not None
            and 0 < (ack - start) % 2**32 <= (end - start) % 2**32)


def _update_evidence(evidence: TCPHandshakeEvidence, flags: dict[str, bool] | None,
                     sequence: int | None, ack: int | None, payload: int | None,
                     direction: FlowDirection) -> None:
    """Handshake đủ số liệu mới xác nhận; không dựa vào state suy đoán.

    SYN/SYNACK hợp lệ của packet hiện tại cho known-false trước xác nhận.
    ACK/data/FIN/RST đứng riêng là unknown. Latch xác nhận giữ qua đóng flow.
    """
    evidence.established_for_packet = True if evidence.established_confirmed else None
    if evidence.conflicted:
        evidence.established_for_packet = None
        return
    if flags is None or any(name not in flags for name in ("SYN", "ACK", "FIN", "RST")):
        return
    syn, ack_flag, fin, rst = (flags[name] for name in ("SYN", "ACK", "FIN", "RST"))
    if fin or rst:
        return
    opposite = "backward" if direction == "forward" else "forward"
    end = (sequence + payload + 1) % 2**32 if sequence is not None and payload is not None else None
    if syn and not ack_flag and sequence is not None:
        if (evidence.client_direction not in (None, direction)
                or evidence.syn_sequence not in (None, sequence)):
            evidence.conflicted = True
        else:
            if evidence.syn_sequence is None:
                # SYNACK thấy trước SYN không chứng minh thứ tự ba bước.
                evidence.syn_ack_sequence = evidence.syn_ack_end = evidence.client_next = None
            evidence.client_direction = direction
            evidence.syn_sequence = sequence
            if end is not None:
                if evidence.syn_end not in (None, end):
                    evidence.conflicted = True
                evidence.syn_end = end
                if not evidence.established_confirmed:
                    evidence.established_for_packet = False
    elif syn and ack_flag and sequence is not None and ack is not None:
        if evidence.client_direction not in (None, opposite):
            evidence.conflicted = True
        elif (evidence.syn_sequence is None
              or _acks_syn(ack, evidence.syn_sequence, evidence.syn_end)):
            evidence.client_direction = opposite
            if (evidence.syn_ack_sequence not in (None, sequence)
                    or evidence.client_next not in (None, ack)
                    or (end is not None and evidence.syn_ack_end not in (None, end))):
                evidence.conflicted = True
            else:
                evidence.syn_ack_sequence = sequence
                evidence.syn_ack_end = end
                evidence.client_next = ack
                if end is not None and not evidence.established_confirmed:
                    evidence.established_for_packet = False
    elif (not syn and ack_flag and sequence is not None and ack is not None
          and direction == evidence.client_direction
          and evidence.syn_sequence is not None and evidence.syn_end is not None
          and sequence == evidence.client_next
          and _acks_syn(ack, evidence.syn_ack_sequence, evidence.syn_ack_end)):
        evidence.established_confirmed = True
        evidence.established_for_packet = True
    if evidence.conflicted:
        evidence.established_for_packet = None


def prepare_tcp_update(flow: FlowRecord, event: IDSEvent, direction: FlowDirection) -> TCPUpdate | None:
    """Tính trên bản sao; lỗi không được thay đổi state/counters flow cũ.

    SYN→SYN/ACK chiều ngược→ACK chiều ban đầu mới xác nhận full handshake.
    ACK/data đầu capture suy ra ESTABLISHED và đánh dấu capture_midstream.
    CLOSED cần thấy FIN hai chiều và ACK từng FIN; RST ưu tiên RESET.
    """
    if flow.protocol == "UDP":
        return None
    if direction not in ("forward", "backward"):
        raise ValueError("Invalid TCP direction")
    transport = event.normalized["transport"]
    flags = _flags(transport)
    sequence = _number(transport.get("sequence_number"), "sequence_number")
    ack = _number(transport.get("acknowledgment_number"), "acknowledgment_number")
    payload = transport.get("payload_length")
    if payload is not None and (type(payload) is not int or not 0 <= payload <= 65535):
        raise ValueError("TCP payload_length must be an integer in 0..65535 or None")
    tracking, counters = deepcopy(flow.tcp_tracking), deepcopy(flow.tcp_flags)
    state, reason = flow.state, flow.close_reason
    if tracking is None or counters is None or state is None:
        raise ValueError("TCP flow is missing internal tracking state")
    _update_evidence(tracking.detection, flags, sequence, ack, payload, direction)
    if flags is None:
        return TCPUpdate(state, tracking, counters, reason)
    syn, ack_flag, fin, rst = (flags.get(name, False) for name in ("SYN", "ACK", "FIN", "RST"))
    counters.syn_count += int(syn)
    counters.ack_count += int(ack_flag)
    counters.fin_count += int(fin)
    counters.rst_count += int(rst)
    if state in (TCPState.CLOSED, TCPState.RESET):
        return TCPUpdate(state, tracking, counters, reason)
    if rst:
        return TCPUpdate(TCPState.RESET, tracking, counters, "tcp_reset")

    opposite = "backward" if direction == "forward" else "forward"
    end = (sequence + payload + 1) % 2**32 if sequence is not None and payload is not None else None
    if state in (TCPState.NEW, TCPState.HANDSHAKE):
        if syn and not ack_flag:
            if tracking.initiator is None:
                tracking.initiator = direction
            if direction == tracking.initiator and not tracking.syn_seen:
                tracking.syn_seen = True
                tracking.syn_end = end
            state = TCPState.HANDSHAKE
        elif syn and ack_flag:
            if tracking.initiator is None:
                tracking.initiator = opposite
                tracking.capture_midstream = True
            acknowledges_syn = ack is None or tracking.syn_end is None or ack == tracking.syn_end
            if direction != tracking.initiator and acknowledges_syn and not tracking.syn_ack_seen:
                tracking.syn_ack_seen = True
                tracking.syn_ack_end = end
            state = TCPState.HANDSHAKE
        elif ack_flag and tracking.syn_ack_seen and direction == tracking.initiator:
            initiator_sequence = sequence is None or tracking.syn_end is None or sequence == tracking.syn_end
            if initiator_sequence and _covers(ack, tracking.syn_ack_end):
                state = TCPState.ESTABLISHED
                tracking.handshake_observed = tracking.syn_seen
        elif state == TCPState.NEW and (ack_flag or (payload is not None and payload > 0)):
            state = TCPState.ESTABLISHED
            tracking.capture_midstream = True

    # ACK on FIN/ACK can acknowledge the opposite FIN in the same packet.
    if ack_flag and getattr(tracking, f"{opposite}_fin_seen"):
        if _covers(ack, getattr(tracking, f"{opposite}_fin_end")):
            setattr(tracking, f"{opposite}_fin_acked", True)
    if fin:
        if not tracking.handshake_observed:
            tracking.capture_midstream = True
        if not getattr(tracking, f"{direction}_fin_seen"):
            setattr(tracking, f"{direction}_fin_seen", True)
            setattr(tracking, f"{direction}_fin_end", end)
        state = TCPState.CLOSING
    if (tracking.forward_fin_seen and tracking.backward_fin_seen
            and tracking.forward_fin_acked and tracking.backward_fin_acked):
        state, reason = TCPState.CLOSED, "tcp_fin"
    return TCPUpdate(state, tracking, counters, reason)


def apply_tcp_update(flow: FlowRecord, update: TCPUpdate | None) -> None:
    """Chỉ gán kết quả đã tính; gọi sau statistics thành công."""
    if update is not None:
        flow.state = update.state
        flow.tcp_tracking = update.tracking
        flow.tcp_flags = update.flags
        flow.close_reason = update.close_reason

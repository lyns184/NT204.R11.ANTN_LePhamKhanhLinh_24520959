import math
from dataclasses import dataclass, field
from typing import Any

from ids.core.config import DecoderConfig, SMTPDecoderConfig
from ids.core.event import IDSEvent
from ids.decoder.mime import decode_mime_message
from ids.decoder.smtp_data import extract_smtp_data


Endpoint = tuple[str, int]
SessionKey = tuple[str, Endpoint, Endpoint]


@dataclass
class SMTPSession:
    client: Endpoint
    next_sequence: int
    last_seen: float
    phase: str = "waiting_354"
    buffer: bytearray = field(default_factory=bytearray)


class SMTPDataTracker:
    def __init__(
        self,
        decoder_config: DecoderConfig | None = None,
        session_config: SMTPDecoderConfig | None = None,
    ) -> None:
        self.decoder_config = (
            decoder_config
            if decoder_config is not None
            else DecoderConfig()
        )
        self.session_config = (
            session_config
            if session_config is not None
            else SMTPDecoderConfig()
        )

        self.sessions: dict[SessionKey, SMTPSession] = {}
        self.expired_sessions = 0

    @staticmethod
    def failure(
        message: str,
        status: str = "partial",
    ) -> dict[str, Any]:
        return {
            "value": None,
            "status": status,
            "errors": [message],
        }

    def expire(self, now: float) -> int:
        """Bỏ trạng thái SMTP quá thời gian không hoạt động."""
        expired = [
            key
            for key, session in self.sessions.items()
            if now - session.last_seen
            >= self.session_config.idle_timeout_seconds
        ]

        for key in expired:
            del self.sessions[key]

        self.expired_sessions += len(expired)
        return len(expired)

    def feed(self, event: IDSEvent) -> dict[str, Any] | None:
        """
        Nhận event sau parser.

        None: không có kết quả MIME ở event này.
        Dictionary: kết quả decode hoặc lỗi/thiếu dữ liệu.
        """
        if event.transport.get("protocol") != "TCP":
            return None

        src_ip = event.network.get("src_ip")
        dst_ip = event.network.get("dst_ip")
        src_port = event.transport.get("src_port")
        dst_port = event.transport.get("dst_port")

        if (
            not isinstance(src_ip, str)
            or not isinstance(dst_ip, str)
            or type(src_port) is not int
            or type(dst_port) is not int
        ):
            return None

        src = (src_ip, src_port)
        dst = (dst_ip, dst_port)
        endpoint_a, endpoint_b = sorted((src, dst))

        key = (
            event.capture_source,
            endpoint_a,
            endpoint_b,
        )

        try:
            timestamp = float(event.timestamp)
        except (TypeError, ValueError):
            return self.failure(
                "Invalid SMTP event timestamp",
                "error",
            )

        if not math.isfinite(timestamp):
            return self.failure(
                "Invalid SMTP event timestamp",
                "error",
            )

        self.expire(timestamp)
        session = self.sessions.get(key)

        flags = event.transport.get("flags_detail", {})

        if flags.get("RST") or flags.get("FIN") or flags.get("SYN"):
            if session is not None:
                del self.sessions[key]
                return self.failure(
                    "TCP connection changed before SMTP DATA completed"
                )
            return None

        if (
            event.network.get("fragment_offset", 0) != 0
            or "MF" in str(event.network.get("flags", ""))
        ):
            if session is not None:
                del self.sessions[key]
                return self.failure(
                    "SMTP IP fragment reassembly is not available"
                )
            return None

        payload_size = event.transport.get("payload_length")
        sequence = event.transport.get("sequence_number")

        if (
            type(payload_size) is not int
            or payload_size < 0
            or type(sequence) is not int
            or not 0 <= sequence < 2**32
            or not isinstance(event.raw_payload, bytes)
            or payload_size > len(event.raw_payload)
        ):
            if session is not None:
                del self.sessions[key]
                return self.failure(
                    "Invalid or incomplete SMTP transport data",
                    "error",
                )
            return None

        payload = event.raw_payload[:payload_size]

        if session is not None:
            session.last_seen = max(
                session.last_seen,
                timestamp,
            )

        if not payload:
            return None

        if session is None:
            # Chỉ mở session khi parser xác nhận command DATA
            # và toàn bộ payload là một command đầy đủ.
            fields = event.application.get("fields", {})

            if not (
                event.application.get("protocol") == "SMTP"
                and fields.get("message_type") == "command"
                and fields.get("command") == "DATA"
            ):
                return None

            if payload.upper() != b"DATA\r\n":
                return self.failure(
                    "SMTP DATA command framing is not supported"
                )

            if len(self.sessions) >= self.session_config.max_sessions:
                return self.failure(
                    "SMTP session limit reached",
                    "error",
                )

            self.sessions[key] = SMTPSession(
                client=src,
                next_sequence=(
                    sequence + len(payload)
                ) % 2**32,
                last_seen=timestamp,
            )
            return None

        # Payload từ server.
        if src != session.client:
            if session.phase == "waiting_354":
                first_line, separator, _ = payload.partition(
                    b"\r\n"
                )

                if (
                    separator
                    and first_line.startswith(b"354 ")
                ):
                    session.phase = "receiving_data"
                    return None

                del self.sessions[key]
                return self.failure(
                    "SMTP DATA was not confirmed by a complete 354 reply"
                )

            # Response từ server không phải email body.
            return None

        # Payload từ client.
        if session.phase != "receiving_data":
            del self.sessions[key]
            return self.failure(
                "SMTP content arrived before the 354 reply"
            )

        # Sequence của byte đầu tiên đang lưu trong buffer.
        # Luôn tính biến này, kể cả khi sequence đúng dự kiến.
        buffer_start = (
            session.next_sequence - len(session.buffer)
        ) % 2**32

        offset = (sequence - buffer_start) % 2**32

        if offset > len(session.buffer):
            del self.sessions[key]
            return self.failure(
                "SMTP TCP sequence gap or unsupported reordering"
            )

        overlap_length = min(
            len(payload),
            len(session.buffer) - offset,
        )

        if overlap_length:
            existing = bytes(
                session.buffer[
                    offset:offset + overlap_length
                ]
            )

            if existing != payload[:overlap_length]:
                del self.sessions[key]
                return self.failure(
                    "Conflicting SMTP TCP retransmission bytes",
                    "error",
                )

        # Chỉ giữ bytes mới sau phần overlap đã kiểm tra.
        new_payload = payload[overlap_length:]

        if not new_payload:
            # Retransmission hoàn toàn: không thêm lần nữa.
            return None

        if (
            len(session.buffer) + len(new_payload)
            > self.decoder_config.max_input_bytes
        ):
            del self.sessions[key]
            return self.failure(
                "SMTP DATA exceeds max_input_bytes",
                "error",
            )

        session.buffer.extend(new_payload)
        session.next_sequence = (
            session.next_sequence + len(new_payload)
        ) % 2**32

        framed = extract_smtp_data(
            bytes(session.buffer),
            self.decoder_config,
        )

        if framed["status"] == "partial":
            return framed_without_bytes(framed)

        del self.sessions[key]

        if framed["status"] != "ok":
            return framed_without_bytes(framed)

        result = decode_mime_message(
            framed["value"],
            self.decoder_config,
        )

        # Không đưa bytes command phía sau email vào JSON.
        result["remaining_bytes"] = len(
            framed["remaining"]
        )
        return result


def framed_without_bytes(
    result: dict[str, Any],
) -> dict[str, Any]:
    """Chỉ giữ các trường có thể xuất JSON."""
    return {
        "value": None,
        "status": result["status"],
        "errors": result["errors"],
    }
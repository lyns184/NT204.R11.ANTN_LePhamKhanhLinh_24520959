import time

from scapy.packet import Packet

from ids.core.event import IDSEvent
from ids.parsers.network.ipv4 import parse_ipv4
from ids.parsers.transport.tcp import parse_tcp
from ids.parsers.transport.udp import parse_udp
from ids.parsers.application.detector import (
    detect_application_protocol,
    get_transport_payload,
)
from ids.parsers.application.http import parse_http
from ids.parsers.application.dns import parse_dns
from ids.parsers.application.smtp import parse_smtp
from ids.core.config import DecoderConfig
from ids.decoder.http import (
    decode_http_request_uri,
    decode_http_form_body,
    decode_http_html_body,
)
from ids.decoder.smtp_session import SMTPDataTracker

def process_packet(
    packet: Packet,
    packet_id: int,
    capture_source: str,
    decoder_config: DecoderConfig | None = None,
    smtp_tracker: SMTPDataTracker | None = None,
) -> IDSEvent:
    """
    Chuyển packet Scapy thành IDSEvent chuẩn hóa.
    """
    try:
        timestamp = float(packet.time)
    except (AttributeError, TypeError, ValueError):
        timestamp = time.time()

    event = IDSEvent(
        packet_id=packet_id,
        timestamp=timestamp,
        capture_source=capture_source,
    )
    # Giữ bytes gốc để Decoder sử dụng.
    # Lỗi lấy payload không được làm dừng việc phân tích packet.
    try:
        event.raw_payload = get_transport_payload(packet)
    except Exception as error:
        event.raw_payload = b""
        event.parse_errors.append(
            f"Payload extraction error: {error}"
        )

    try:
        network_data = parse_ipv4(packet)

        if network_data is None:
            event.network = {
                "protocol": "UNKNOWN",
            }
        else:
            event.network = network_data

    except Exception as error:
        event.network = {
            "protocol": "UNKNOWN",
        }
        event.parse_errors.append(
            f"Network parser error: {error}"
        )

    try:
        transport_data = parse_tcp(packet)

        if transport_data is None:
            transport_data = parse_udp(packet)

        if transport_data is None:
            event.transport = {
                "protocol": "UNKNOWN",
            }
        else:
            event.transport = transport_data
            event.payload_length = transport_data["payload_length"]

    except Exception as error:
        event.transport = {
            "protocol": "UNKNOWN",
        }
        event.parse_errors.append(
            f"Transport parser error: {error}"
        )

    try:
        application_protocol = detect_application_protocol(packet)
        application_fields = {}

        if application_protocol == "HTTP":
            http_data = parse_http(packet)

            if http_data is not None:
                application_fields = http_data

        elif application_protocol == "DNS":
            dns_data = parse_dns(packet)

            if dns_data is not None:
                application_fields = dns_data

        elif application_protocol == "SMTP":
            smtp_data = parse_smtp(packet)

            if smtp_data is not None:
                application_fields = smtp_data

        event.application = {
            "protocol": application_protocol,
            "fields": application_fields,
        }

    except Exception as error:
        event.application = {
            "protocol": "UNKNOWN",
            "fields": {},
        }
        event.parse_errors.append(
            f"Application parser error: {error}"
        )

    # Decoder chạy sau parser, áp dụng cho HTTP request và response.
    if event.application.get("protocol") == "HTTP":
        try:
            http_results = {}
            fields = event.application.get("fields", {})

            if fields.get("message_type") == "request":
                http_results["uri"] = decode_http_request_uri(
                    event,
                    decoder_config,
                )

                form_result = decode_http_form_body(
                    event,
                    decoder_config,
                )

                if form_result is not None:
                    http_results["form"] = form_result

            html_result = decode_http_html_body(
                event,
                decoder_config,
            )

            if html_result is not None:
                http_results["html"] = html_result

            # Không có decoder phù hợp: giữ not_processed.
            if http_results:
                event.decoded["http"] = http_results

                for name, result in http_results.items():
                    event.decode_errors.extend(
                        f"HTTP {name}: {message}"
                        for message in result["errors"]
                    )

                statuses = [
                    result["status"]
                    for result in http_results.values()
                ]

                if all(status == "ok" for status in statuses):
                    event.decode_status = "ok"
                elif all(status == "error" for status in statuses):
                    event.decode_status = "error"
                else:
                    event.decode_status = "partial"

        except Exception as error:
            event.decode_status = "error"
            event.decode_errors.append(
                f"HTTP decoder error: {error}"
            )
    # Tracker cần nhận cả TCP packet có application UNKNOWN.
    if smtp_tracker is not None:
        try:
            smtp_result = smtp_tracker.feed(event)

            if smtp_result is not None:
                event.decoded["smtp"] = {
                    "mime": smtp_result,
                }

                event.decode_errors.extend(
                    f"SMTP MIME: {message}"
                    for message in smtp_result["errors"]
                )

                statuses = [smtp_result["status"]]

                if event.decode_status != "not_processed":
                    statuses.append(event.decode_status)

                if all(status == "ok" for status in statuses):
                    event.decode_status = "ok"
                elif all(status == "error" for status in statuses):
                    event.decode_status = "error"
                else:
                    event.decode_status = "partial"

        except Exception as error:
            event.decode_status = "error"
            event.decode_errors.append(
                f"SMTP decoder error: {error}"
            )

    return event

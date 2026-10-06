import argparse
import time
from pathlib import Path
from threading import RLock

from scapy.packet import Packet

from ids.capture.live_capture import capture_live
from ids.capture.pcap_reader import read_pcap
from ids.core.pipeline import process_packet
from ids.output.jsonl_writer import JSONLWriter
from ids.decoder.smtp_session import SMTPDataTracker
from ids.flow_tracker import FlowTracker, FlowTrackerConfig

def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Packet Capture & Parser cho hệ thống IDS"
    )

    source_group = parser.add_mutually_exclusive_group(required=True)

    source_group.add_argument(
        "--pcap",
        help="Đường dẫn đến file PCAP cần phân tích",
    )

    source_group.add_argument(
        "--interface",
        help="Network interface dùng để bắt packet trực tiếp",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Số packet cần bắt ở live mode; 0 là không giới hạn",
    )

    parser.add_argument(
        "--output",
        default="output/events.jsonl",
        help="Đường dẫn file JSON Lines đầu ra",
    )

    parser.add_argument("--flow-output", help="File JSONL flow summary; mặc định cạnh file event với hậu tố _flows")
    parser.add_argument("--tcp-idle-timeout", type=float, default=300.0)
    parser.add_argument("--udp-idle-timeout", type=float, default=60.0)
    parser.add_argument("--flow-check-interval", type=float, default=1.0)
    parser.add_argument("--max-active-flows", type=int, default=10_000)
    return parser


def process_and_log(
    packet: Packet,
    packet_id: int,
    capture_source: str,
    writer: JSONLWriter,
    smtp_tracker: SMTPDataTracker,
    flow_tracker: FlowTracker | None = None,
    flow_writer: JSONLWriter | None = None,
) -> None:
    event = process_packet(
        packet=packet,
        packet_id=packet_id,
        capture_source=capture_source,
        smtp_tracker=smtp_tracker,
        flow_tracker=flow_tracker,
        flow_summary_handler=flow_writer.write_record if flow_writer is not None else None,
    )

    writer.write(event)
    print(event.to_dict())


def run_pcap_mode(
    file_path: str,
    writer: JSONLWriter,
    smtp_tracker: SMTPDataTracker,
    flow_tracker: FlowTracker | None = None,
    flow_writer: JSONLWriter | None = None,
) -> int:
    print(f"Đang đọc PCAP: {file_path}")

    return read_pcap(
        file_path=file_path,
        packet_handler=lambda packet, packet_id: process_and_log(
            packet=packet,
            packet_id=packet_id,
            capture_source=f"pcap:{file_path}",
            writer=writer,
            smtp_tracker=smtp_tracker,
            flow_tracker=flow_tracker,
            flow_writer=flow_writer,
        ),
    )


def run_live_mode(
    interface: str,
    packet_limit: int,
    writer: JSONLWriter,
    smtp_tracker: SMTPDataTracker,
    flow_tracker: FlowTracker | None = None,
    flow_writer: JSONLWriter | None = None,
) -> int:
    print(f"Đang bắt packet từ interface: {interface}")

    # Sniffer callbacks and the main-thread timer share tracker/output state.
    lock = RLock()

    def handle(packet: Packet, packet_id: int) -> None:
        with lock:
            process_and_log(
                packet=packet,
                packet_id=packet_id,
                capture_source=f"interface:{interface}",
                writer=writer,
                smtp_tracker=smtp_tracker,
                flow_tracker=flow_tracker,
                flow_writer=flow_writer,
            )

    def tick() -> None:
        with lock:
            for summary in flow_tracker.expire(time.time()):
                if flow_writer is not None:
                    flow_writer.write_record(summary)

    options = {}
    if flow_tracker is not None:
        options = {"tick_handler": tick,
                   "tick_interval_seconds": flow_tracker.config.expiration_check_interval_seconds}
    return capture_live(interface=interface, packet_limit=packet_limit,
                        packet_handler=handle, **options)


def main() -> int:
    parser = create_argument_parser()
    args = parser.parse_args()

    if args.count < 0:
        parser.error("--count không được là số âm")
    try:
        flow_config = FlowTrackerConfig(args.tcp_idle_timeout, args.udp_idle_timeout,
                                        args.flow_check_interval, args.max_active_flows)
    except ValueError as error:
        parser.error(str(error))
    event_path = Path(args.output)
    flow_path = Path(args.flow_output) if args.flow_output else event_path.with_name(event_path.stem + "_flows.jsonl")
    if event_path.resolve() == flow_path.resolve():
        parser.error("File event và flow summary phải khác nhau")
    if args.pcap and Path(args.pcap).resolve() in (event_path.resolve(), flow_path.resolve()):
        parser.error("File output không được trùng PCAP đầu vào")

    # Một tracker cho toàn bộ packet trong lần chạy này.
    smtp_tracker = SMTPDataTracker()
    flow_tracker = FlowTracker(flow_config)

    try:
        with JSONLWriter(args.output) as writer, JSONLWriter(str(flow_path)) as flow_writer:
            finish_reason = "capture_end"
            try:
                if args.pcap:
                    packet_count = run_pcap_mode(
                        file_path=args.pcap,
                        writer=writer,
                        smtp_tracker=smtp_tracker,
                        flow_tracker=flow_tracker,
                        flow_writer=flow_writer,
                    )
                else:
                    packet_count = run_live_mode(
                        interface=args.interface,
                        packet_limit=args.count,
                        writer=writer,
                        smtp_tracker=smtp_tracker,
                        flow_tracker=flow_tracker,
                        flow_writer=flow_writer,
                    )
            except KeyboardInterrupt:
                finish_reason = "shutdown"
                raise
            except Exception:
                finish_reason = "capture_error"
                raise
            finally:
                for summary in flow_tracker.flush(reason=finish_reason):
                    flow_writer.write_record(summary)

    except Exception as error:
        print(f"[ERROR] {error}")
        return 1
    except KeyboardInterrupt:
        print("Đã dừng capture và xuất flow còn lại.")
        return 130

    print(f"Đã xử lý {packet_count} packet.")
    print(f"Đã ghi kết quả vào: {args.output}")
    print(f"Đã ghi flow summary vào: {flow_path}")

    print(
        "SMTP sessions chưa hoàn tất:",
        len(smtp_tracker.sessions),
    )
    print(
        "SMTP sessions đã hết hạn:",
        smtp_tracker.expired_sessions,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

import argparse

from scapy.error import Scapy_Exception
from scapy.packet import Packet

from ids.capture.live_capture import capture_live
from ids.capture.pcap_reader import read_pcap
from ids.core.pipeline import process_packet
from ids.output.jsonl_writer import JSONLWriter
from ids.decoder.smtp_session import SMTPDataTracker

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

    return parser


def process_and_log(
    packet: Packet,
    packet_id: int,
    capture_source: str,
    writer: JSONLWriter,
    smtp_tracker: SMTPDataTracker,
) -> None:
    event = process_packet(
        packet=packet,
        packet_id=packet_id,
        capture_source=capture_source,
        smtp_tracker=smtp_tracker,
    )

    writer.write(event)
    print(event.to_dict())


def run_pcap_mode(
    file_path: str,
    writer: JSONLWriter,
    smtp_tracker: SMTPDataTracker,
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
        ),
    )


def run_live_mode(
    interface: str,
    packet_limit: int,
    writer: JSONLWriter,
    smtp_tracker: SMTPDataTracker,
) -> int:
    print(f"Đang bắt packet từ interface: {interface}")

    return capture_live(
        interface=interface,
        packet_limit=packet_limit,
        packet_handler=lambda packet, packet_id: process_and_log(
            packet=packet,
            packet_id=packet_id,
            capture_source=f"interface:{interface}",
            writer=writer,
            smtp_tracker=smtp_tracker,
        ),
    )


def main() -> int:
    parser = create_argument_parser()
    args = parser.parse_args()

    if args.count < 0:
        parser.error("--count không được là số âm")

    # Một tracker cho toàn bộ packet trong lần chạy này.
    smtp_tracker = SMTPDataTracker()

    try:
        with JSONLWriter(args.output) as writer:
            if args.pcap:
                packet_count = run_pcap_mode(
                    file_path=args.pcap,
                    writer=writer,
                    smtp_tracker=smtp_tracker,
                )
            else:
                packet_count = run_live_mode(
                    interface=args.interface,
                    packet_limit=args.count,
                    writer=writer,
                    smtp_tracker=smtp_tracker,
                )

    except (OSError, Scapy_Exception, ValueError) as error:
        print(f"[ERROR] {error}")
        return 1

    print(f"Đã xử lý {packet_count} packet.")
    print(f"Đã ghi kết quả vào: {args.output}")

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
import argparse
import json
import sqlite3
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from threading import RLock

from scapy.packet import Packet

from ids.alert.config import load_alert_config
from ids.alert.manager import AlertManager
from ids.alert.repository import AlertRepository, sqlite_storage_paths
from ids.capture.live_capture import capture_live
from ids.capture.pcap_reader import read_pcap
from ids.core.pipeline import process_packet
from ids.output.jsonl_writer import JSONLWriter
from ids.decoder.smtp_session import SMTPDataTracker
from ids.flow_tracker import FlowTracker, FlowTrackerConfig
from ids.detection import (
    DetectionSession, EvaluationEngine, RuleConfigError, RuleLoadError,
    RuleRepository, load_rule_config, load_rules,
)
from ids.output.paths import validate_output_paths
from ids.report.cli import run_report_cli

def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Packet Capture, Parser và Core Engine cho hệ thống IDS",
        epilog="Để báo cáo từ SQLite, chạy: python main.py report --help",
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
    parser.add_argument("--rules", action="append", help="File Snort 2-style rules; có thể truyền nhiều lần")
    parser.add_argument("--rule-config", help="JSON cấu hình disabled_files/disabled_sids")
    parser.add_argument("--detection-output", help="Detection JSONL; mặc định detections.jsonl cạnh event output")
    parser.add_argument("--alert-config", help="Bật Alert Manager bằng file cấu hình JSON; cần --rules")
    parser.add_argument("--alert-output", help="File tóm tắt alert; mặc định in ra console khi bật Alert Manager")
    return parser


def process_and_log(
    packet: Packet,
    packet_id: int,
    capture_source: str,
    writer: JSONLWriter,
    smtp_tracker: SMTPDataTracker,
    flow_tracker: FlowTracker | None = None,
    flow_writer: JSONLWriter | None = None,
    detection_session: DetectionSession | None = None,
) -> None:
    event = process_packet(
        packet=packet,
        packet_id=packet_id,
        capture_source=capture_source,
        smtp_tracker=smtp_tracker,
        flow_tracker=flow_tracker,
        flow_summary_handler=flow_writer.write_record if flow_writer is not None else None,
        inspection_handler=detection_session.process if detection_session is not None else None,
    )

    writer.write(event)
    print(event.to_dict())


def run_pcap_mode(
    file_path: str,
    writer: JSONLWriter,
    smtp_tracker: SMTPDataTracker,
    flow_tracker: FlowTracker | None = None,
    flow_writer: JSONLWriter | None = None,
    detection_session: DetectionSession | None = None,
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
            detection_session=detection_session,
        ),
    )


def run_live_mode(
    interface: str,
    packet_limit: int,
    writer: JSONLWriter,
    smtp_tracker: SMTPDataTracker,
    flow_tracker: FlowTracker | None = None,
    flow_writer: JSONLWriter | None = None,
    detection_session: DetectionSession | None = None,
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
                detection_session=detection_session,
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
    if sys.argv[1:2] == ["report"]:
        return run_report_cli(sys.argv[2:])
    parser = create_argument_parser()
    args = parser.parse_args()

    if args.count < 0:
        parser.error("--count không được là số âm")
    if not args.rules and (args.rule_config is not None or args.detection_output is not None):
        parser.error("--rule-config và --detection-output cần --rules")
    if args.alert_config is not None and not args.rules:
        parser.error("--alert-config cần --rules")
    if args.alert_output is not None and args.alert_config is None:
        parser.error("--alert-output cần --alert-config")
    try:
        flow_config = FlowTrackerConfig(args.tcp_idle_timeout, args.udp_idle_timeout,
                                        args.flow_check_interval, args.max_active_flows)
    except ValueError as error:
        parser.error(str(error))
    def report_diagnostic(diagnostic) -> None:
        print("[DETECTION] " + json.dumps(diagnostic.to_dict(), ensure_ascii=True, allow_nan=False), file=sys.stderr)

    engine = None
    detection_path = None
    alert_config = None
    try:
        event_path = Path(args.output)
        flow_path = Path(args.flow_output) if args.flow_output is not None else event_path.with_name(event_path.stem + "_flows.jsonl")
        outputs = {"event": args.output, "flow": args.flow_output if args.flow_output is not None else flow_path}
        inputs = [args.pcap] if args.pcap is not None else []
        if args.rules:
            rule_config = load_rule_config(args.rule_config)
            detection_path = Path(args.detection_output) if args.detection_output is not None else event_path.with_name("detections.jsonl")
            outputs["detection"] = args.detection_output if args.detection_output is not None else detection_path
            inputs.extend(args.rules)
            inputs.extend(rule_config.disabled_files)
            if args.rule_config is not None:
                inputs.append(args.rule_config)

        if args.alert_config is not None:
            alert_config = load_alert_config(args.alert_config)
            inputs.append(args.alert_config)
            for label, path in zip(
                ("alert DB", "alert DB journal", "alert DB WAL", "alert DB SHM"),
                sqlite_storage_paths(alert_config.storage_path),
            ):
                outputs[label] = path
            if args.alert_output is not None:
                outputs["alert export"] = args.alert_output
        validate_output_paths(outputs, inputs)

        if args.rules:
            report = load_rules(args.rules, rule_config)
            for diagnostic in report.diagnostics:
                report_diagnostic(diagnostic)
            engine = EvaluationEngine(RuleRepository(report.enabled_rules))
            print("[RULES] " + json.dumps(report.counts, ensure_ascii=True))
    except RuleLoadError as error:
        for diagnostic in error.report.diagnostics:
            report_diagnostic(diagnostic)
        report_diagnostic(error.diagnostic)
        parser.error(str(error))
    except RuleConfigError as error:
        report_diagnostic(error.diagnostic)
        parser.error(str(error))
    except (OSError, ValueError, RuntimeError) as error:
        parser.error(str(error))

    # Một tracker cho toàn bộ packet trong lần chạy này.
    smtp_tracker = SMTPDataTracker()
    flow_tracker = FlowTracker(flow_config)

    detection_session = None
    alert_manager = None

    def process_alert(record) -> None:
        if alert_manager is None:
            return
        try:
            result = alert_manager.process(record)
        except sqlite3.Error as error:
            raise RuntimeError(f"Không thể ghi alert vào SQLite: {error}") from error
        if result.status == "rejected":
            print("[ALERT DIAGNOSTIC] " + json.dumps({
                "status": result.status, "reason": result.reason,
                "packet_id": record.get("packet_id"), "sid": record.get("sid"),
            }, ensure_ascii=True), file=sys.stderr)

    try:
        if alert_config is not None:
            try:
                repository = AlertRepository(alert_config.storage_path)
            except (OSError, sqlite3.Error) as error:
                raise RuntimeError(f"Không thể mở SQLite tại {alert_config.storage_path}: {error}") from error
            alert_manager = AlertManager(alert_config, repository)
        with ExitStack() as stack:
            writer = stack.enter_context(JSONLWriter(args.output))
            flow_writer = stack.enter_context(JSONLWriter(str(flow_path)))
            if engine is not None:
                detection_writer = stack.enter_context(JSONLWriter(str(detection_path)))
                detection_session = DetectionSession(
                    engine, detection_writer.write_record, report_diagnostic,
                    after_record=process_alert if alert_manager is not None else None,
                )
            finish_reason = "capture_end"
            try:
                if args.pcap is not None:
                    packet_count = run_pcap_mode(
                        file_path=args.pcap,
                        writer=writer,
                        smtp_tracker=smtp_tracker,
                        flow_tracker=flow_tracker,
                        flow_writer=flow_writer,
                        detection_session=detection_session,
                    )
                else:
                    packet_count = run_live_mode(
                        interface=args.interface,
                        packet_limit=args.count,
                        writer=writer,
                        smtp_tracker=smtp_tracker,
                        flow_tracker=flow_tracker,
                        flow_writer=flow_writer,
                        detection_session=detection_session,
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

        if alert_manager is not None:
            alert_manager.export_alerts(args.alert_output if args.alert_output is not None else sys.stdout)
    except Exception as error:
        print(f"[ERROR] {error}")
        return 1
    except KeyboardInterrupt:
        print("Đã dừng capture và xuất flow còn lại.")
        return 130
    finally:
        if engine is not None:
            print("[DETECTION SUMMARY] " + json.dumps({**engine.metrics.to_dict(),
                "detections_written": detection_session.detections_written if detection_session is not None else 0},
                ensure_ascii=True, allow_nan=False))
        if alert_manager is not None:
            print("[ALERT SUMMARY] " + json.dumps({
                "run_id": alert_manager.run_id, **alert_manager.counts,
            }, ensure_ascii=True, allow_nan=False))

    print(f"Đã xử lý {packet_count} packet.")
    print(f"Đã ghi kết quả vào: {args.output}")
    print(f"Đã ghi flow summary vào: {flow_path}")
    if detection_path is not None:
        print(f"Đã ghi detection vào: {detection_path}")

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

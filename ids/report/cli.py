"""Lệnh CLI đọc kho cảnh báo và xuất báo cáo."""

import argparse
import sqlite3
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from ids.alert.config import load_alert_config
from ids.alert.repository import AlertRepository, sqlite_storage_paths
from ids.report.exporter import write_report
from ids.report.generator import generate_report


def _iso_timestamp(value: str) -> float:
    # datetime.fromisoformat trên Python 3.10 chưa nhận hậu tố Z.
    iso = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        date = datetime.fromisoformat(iso)
        if date.utcoffset() is not None:
            return date.timestamp()
    except (ValueError, OverflowError, OSError):
        pass
    raise argparse.ArgumentTypeError("cần thời gian ISO 8601 có múi giờ, ví dụ 2026-11-21T09:00:00Z")


def run_report_cli(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog=f"{Path(sys.argv[0]).name} report",
        description="Tạo báo cáo từ SQLite theo first_seen trong khoảng [from, to).",
    )
    parser.add_argument("--from", dest="from_time", required=True, type=_iso_timestamp,
                        help="Đầu kỳ, ISO 8601 có múi giờ, lấy cả mốc này")
    parser.add_argument("--to", dest="to_time", required=True, type=_iso_timestamp,
                        help="Cuối kỳ, ISO 8601 có múi giờ, bỏ mốc này")
    parser.add_argument("--alert-config", help="File cấu hình Alert/Report; mặc định dùng output/alerts.sqlite3")
    parser.add_argument("--top-n", type=int, help="Ghi đè giới hạn Top-N trong cấu hình")
    parser.add_argument("--run-id", help="Chỉ thống kê lần chạy có run_id này")
    parser.add_argument("--text-output", help="File báo cáo text; mặc định in ra console")
    parser.add_argument("--json-output", help="File báo cáo JSON; mặc định report.json cạnh file SQLite")
    args = parser.parse_args(argv)
    if args.from_time >= args.to_time:
        parser.error("--from phải sớm hơn --to")
    if args.top_n is not None and args.top_n <= 0:
        parser.error("--top-n phải là số nguyên dương")
    if args.run_id is not None and not args.run_id.strip():
        parser.error("--run-id không được rỗng")

    try:
        config = load_alert_config(args.alert_config)
        repository = AlertRepository(config.storage_path, read_only=True)
        report = generate_report(
            repository, from_time=args.from_time, to_time=args.to_time, run_id=args.run_id,
            top_n=config.top_n if args.top_n is None else args.top_n,
        )
        protected = list(sqlite_storage_paths(repository.path))
        if args.alert_config is not None:
            protected.append(Path(args.alert_config))
        write_report(
            report,
            text_output=sys.stdout if args.text_output is None else args.text_output,
            json_output=config.storage_path.with_name("report.json") if args.json_output is None else args.json_output,
            protected_paths=protected,
        )
    except ValueError as error:
        parser.error(str(error))
    except sqlite3.Error as error:
        print(f"[REPORT ERROR] Không thể đọc SQLite tại {config.storage_path}: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"[REPORT ERROR] {error}", file=sys.stderr)
        return 1
    return 0

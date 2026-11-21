"""TC13 — Kiểm tra thống kê transport, application và số nhóm theo giờ UTC."""

import json
import math
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from ids.alert.config import Severity
from ids.alert.models import Alert
from ids.alert.repository import AlertRepository
from ids.report.generator import generate_report


START = 1699999200.0  # 2023-11-14 22:00 UTC
HOUR = 3600
# first_seen, last_seen, transport, application, count.
ROWS = (
    (START - 5, START + 5, "TCP", "HTTP", 3),
    (START, START + 8, "TCP", "HTTP", 2),
    (START + 3590, START + 3610, "TCP", "SMTP", 4),
    (math.nextafter(START + HOUR, -math.inf), START + HOUR, None, None, 2),
    (START + HOUR, START + HOUR, "UDP", "DNS", 1),
    (START + 3650, START + 3660, "UDP", "DNS", 3),
    (START + 3720, START + 3720, "TCP", None, 1),
    (START + 10810, START + 10810, "UDP", None, 1),
    (START + 4 * HOUR, START + 4 * HOUR, "TCP", "HTTP", 1),
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_checks(log):
    with TemporaryDirectory(prefix="tc13_", dir=FOLDER) as temporary:
        database = Path(temporary) / "alerts.sqlite3"
        writer = AlertRepository(database)
        for index, (first, last, transport, application, count) in enumerate(ROWS, 1):
            writer.insert(Alert(
                alert_id=str(UUID(int=index, version=4)), sid=104130 + index,
                msg="Nhóm Alert cho thống kê giao thức và giờ", severity=Severity.HIGH,
                src_ip="192.0.2.10", dst_ip="198.51.100.20", protocol=transport,
                application_protocol=application, first_seen=first, last_seen=last, count=count,
            ), run_id="fixture-tc13")

        repository = AlertRepository(database, read_only=True)
        report = generate_report(repository, from_time=START, to_time=START + 4 * HOUR, top_n=3)
        require(report["period"] == {
            "from_utc": "2023-11-14T22:00:00Z", "to_utc": "2023-11-15T02:00:00Z",
        }, "Wrong UTC period")
        require((report["total_alerts"], report["total_occurrences"]) == (7, 14), "Wrong period totals")
        require(report["protocol_counts"] == {"TCP": 3, "UDP": 3, "UNKNOWN": 1}, "Wrong transport counts")
        require(report["application_protocol_counts"] == {"DNS": 2, "HTTP": 1, "SMTP": 1, "UNKNOWN": 3},
                "Wrong application counts")
        require(list(report["alerts_by_hour_utc"].items()) == [
            ("2023-11-14T22:00:00Z", 3),
            ("2023-11-14T23:00:00Z", 3),
            ("2023-11-15T01:00:00Z", 1),
        ], "Wrong UTC buckets or empty hour handling")
        log.extend([
            f"PASS transport: {report['protocol_counts']}",
            f"PASS application: {report['application_protocol_counts']}",
            f"PASS UTC buckets: {report['alerts_by_hour_utc']}",
        ])

        first = generate_report(repository, from_time=START, to_time=START + HOUR, top_n=3)
        second = generate_report(repository, from_time=START + HOUR, to_time=START + 2 * HOUR, top_n=3)
        require((first["total_alerts"], first["total_occurrences"]) == (3, 8),
                "Cross-hour groups and the immediately preceding timestamp should count in the first hour")
        require((second["total_alerts"], second["total_occurrences"]) == (3, 5),
                "Only groups starting at or after the exact boundary should count in the next hour")
        require(first["protocol_counts"] == {"TCP": 2, "UNKNOWN": 1} and
                second["protocol_counts"] == {"TCP": 1, "UDP": 2}, "Wrong adjacent-hour transport breakdown")
        log.append("PASS adjacent hours: 3 groups/8 occurrences at 22:00, 3 groups/5 occurrences at 23:00.")

    artifact = {"whole_period": report, "first_hour": first, "second_hour": second}
    output = FOLDER / "result_protocol_time.json"
    output.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    require(json.loads(output.read_text(encoding="utf-8")) == artifact, "JSON result did not roundtrip")
    log.append("PASS TC13: protocol counts, UTC hour boundaries and cross-hour grouping match expectations.")


def main():
    log = ["TC13: nine simulated alert groups, first_seen-based UTC reporting."]
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL TC13: {type(error).__name__}: {error}")
        code = 1
    console = "\n".join(log) + "\n"
    (FOLDER / "console.txt").write_text(console, encoding="utf-8")
    print(console, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

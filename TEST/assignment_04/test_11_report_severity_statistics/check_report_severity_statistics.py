"""TC11 — Đối chiếu tổng nhóm, tổng lượt và phân bố severity."""

import json
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


START = 1700000000.0
RUN_A = "fixture-tc11-a"
RUN_B = "fixture-tc11-b"
# Offset first_seen, offset last_seen, mức độ, số lượt và lần chạy.
ROWS = (
    (-5, 5, Severity.HIGH, 3, RUN_A),
    (0, 12, Severity.CRITICAL, 4, RUN_A),
    (15, 18, Severity.HIGH, 2, RUN_A),
    (20, 20, Severity.HIGH, 1, RUN_B),
    (25, 32, Severity.MEDIUM, 3, RUN_B),
    (35, 35, Severity.LOW, 1, RUN_A),
    (60, 60, Severity.CRITICAL, 7, RUN_B),
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_checks(log):
    reports = {}
    cases = (
        ("all_runs", START, START + 60, None, 5, 11,
         {"LOW": 1, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 1}),
        ("run_a", START, START + 60, RUN_A, 3, 7,
         {"LOW": 1, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 1}),
        ("empty_period", START + 120, START + 180, None, 0, 0,
         {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}),
    )
    with TemporaryDirectory(prefix="tc11_", dir=FOLDER) as temporary:
        database = Path(temporary) / "alerts.sqlite3"
        writer = AlertRepository(database)
        for index, (first, last, severity, count, run_id) in enumerate(ROWS, 1):
            writer.insert(Alert(
                alert_id=str(UUID(int=index, version=4)), sid=104110 + index,
                msg="Nhóm Alert mô phỏng cho thống kê", severity=severity,
                src_ip="192.0.2.10", dst_ip="198.51.100.20",
                first_seen=START + first, last_seen=START + last, count=count,
            ), run_id=run_id)

        reader = AlertRepository(database, read_only=True)
        require(len(reader.query()) == 7, "Fixture should contain seven alert groups")
        for name, start, end, run_id, groups, occurrences, distribution in cases:
            report = generate_report(reader, from_time=start, to_time=end, top_n=3, run_id=run_id)
            expected = (groups, occurrences, distribution)
            actual = (report["total_alerts"], report["total_occurrences"], report["severity_counts"])
            require(actual == expected, f"{name}: expected {expected}, got {actual}")
            require(all(type(value) is int for value in (*actual[:2], *report["severity_counts"].values())),
                    f"{name}: statistics should be integer counts")
            require(sum(report["severity_counts"].values()) == groups,
                    f"{name}: severity counts must add up to the number of groups")
            require(report["time_basis"] == "first_seen" and report["run_id"] == run_id,
                    f"{name}: incorrect query metadata")
            reports[name] = report
            log.append(f"PASS {name}: {groups} groups, {occurrences} occurrences, severity={distribution}")

        require(reports["all_runs"]["period"] == {
            "from_utc": "2023-11-14T22:13:20Z", "to_utc": "2023-11-14T22:14:20Z",
        }, "Main period should be displayed in UTC")

    output = FOLDER / "result_severity_statistics.json"
    output.write_text(json.dumps(reports, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    require(json.loads(output.read_text(encoding="utf-8")) == reports, "JSON result did not roundtrip")
    log.append("PASS TC11: totals and severity distribution agree with the fixture for all three reports.")


def main():
    log = ["TC11: seven simulated alert groups in SQLite, independently calculated report expectations."]
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL TC11: {type(error).__name__}: {error}")
        code = 1
    console = "\n".join(log) + "\n"
    (FOLDER / "console.txt").write_text(console, encoding="utf-8")
    print(console, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

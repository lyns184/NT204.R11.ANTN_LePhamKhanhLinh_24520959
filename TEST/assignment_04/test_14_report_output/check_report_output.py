"""TC14 — Chạy CLI report và đối chiếu hai định dạng đầu ra."""

import json
import subprocess
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


START = 1700000000.0
ROWS = (
    (104141, START, Severity.HIGH, "TCP", "HTTP", "lab-http", "192.0.2.1", 3),
    (104142, START + 3600, Severity.LOW, "UDP", "DNS", None, "192.0.2.2", 1),
    (104143, START + 7200, Severity.CRITICAL, "TCP", "HTTP", "lab-http", "192.0.2.3", 7),
)
EXPECTED_DISTRIBUTIONS = {
    "severity_counts": {"LOW": 1, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 0},
    "sid_counts": {"104141": 1, "104142": 1},
    "classtype_counts": {"UNKNOWN": 1, "lab-http": 1},
    "protocol_counts": {"TCP": 1, "UDP": 1},
    "application_protocol_counts": {"DNS": 1, "HTTP": 1},
    "alerts_by_hour_utc": {"2023-11-14T22:00:00Z": 1, "2023-11-14T23:00:00Z": 1},
}
EXPECTED_RANKINGS = {
    "top_sids": [{"value": 104141, "alerts": 1}, {"value": 104142, "alerts": 1}],
    "top_classtypes": [{"value": "UNKNOWN", "alerts": 1}, {"value": "lab-http", "alerts": 1}],
    "top_src_ips": [{"value": "192.0.2.1", "alerts": 1}, {"value": "192.0.2.2", "alerts": 1}],
    "top_dst_ips": [{"value": "198.51.100.20", "alerts": 2}],
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def check_text(text, report):
    header, *blocks = text.strip().split("\n\n")
    period = report["period"]
    expected_lines = (
        "IDS SECURITY REPORT",
        f"Period (UTC): [{period['from_utc']}, {period['to_utc']})",
        "Run: all",
        "Time basis: first_seen",
        f"Total alerts (groups): {report['total_alerts']}",
        f"Total occurrences (sum of group counts): {report['total_occurrences']}",
        "Distributions and rankings count alert groups.",
    )
    require(tuple(header.splitlines()) == expected_lines, "Text header does not match JSON totals or period")
    section_titles = {
        "Severity": "severity_counts", "Rule SID": "sid_counts", "Classtype": "classtype_counts",
        "Transport protocol": "protocol_counts", "Application protocol": "application_protocol_counts",
        "Alerts per hour (UTC)": "alerts_by_hour_utc", "Top 2 SID": "top_sids",
        "Top 2 classtype": "top_classtypes", "Top 2 source IP": "top_src_ips",
        "Top 2 destination IP": "top_dst_ips",
    }
    seen = set()
    for block in blocks:
        title, *lines = block.splitlines()
        require(title in section_titles and title not in seen, f"Unexpected or duplicate text section {title}")
        seen.add(title)
        pairs = []
        if lines != ["  (none)"]:
            for line in lines:
                label, count = line.strip().rsplit(": ", 1)
                pairs.append((json.loads(label), int(count)))
        data = report[section_titles[title]]
        if isinstance(data, list):
            require(pairs == [(entry["value"], entry["alerts"]) for entry in data], f"{title}: ranking mismatch")
        else:
            require(len(pairs) == len(data) and dict(pairs) == data, f"{title}: distribution mismatch")
    require(seen == set(section_titles), "Missing text sections")


def run_report(log, folder, config, case, start, end, expected):
    json_output = folder / f"result_report_{case}.json"
    text_output = folder / f"result_report_{case}.txt"
    command = [
        sys.executable, "-X", "utf8", "main.py", "report", "--alert-config", str(config),
        "--from", start, "--to", end, "--json-output", str(json_output), "--text-output", str(text_output),
    ]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, encoding="utf-8", timeout=45)
    log.extend([f"$ {subprocess.list2cmdline(command)}", f"{case}: CLI exit={result.returncode}"])
    if result.stdout or result.stderr:
        log.append((result.stdout + result.stderr).rstrip())
    require(result.returncode == 0 and not result.stderr, f"{case}: report CLI failed")
    json_content = json_output.read_text(encoding="utf-8")
    text_content = text_output.read_text(encoding="utf-8")
    actual = json.loads(json_content)
    require(actual == expected, f"{case}: JSON does not match independently calculated expectations")
    check_text(text_content, actual)
    log.append(f"PASS {case}: {actual['total_alerts']} groups, {actual['total_occurrences']} occurrences, "
               "all text sections match JSON.")
    return {json_output.name: json_content, text_output.name: text_content}


def run_checks(log):
    with TemporaryDirectory(prefix="tc14_", dir=FOLDER) as temporary:
        folder = Path(temporary)
        database = folder / "alerts.sqlite3"
        config = folder / "alert_config.json"
        config.write_text(json.dumps({"storage_path": database.name, "top_n": 2}), encoding="utf-8")
        writer = AlertRepository(database)
        for index, (sid, timestamp, severity, transport, app, classtype, source, count) in enumerate(ROWS, 1):
            writer.insert(Alert(
                alert_id=str(UUID(int=index, version=4)), sid=sid, msg="Nhóm Alert cho xuất báo cáo",
                severity=severity, src_ip=source, dst_ip="198.51.100.20", first_seen=timestamp, last_seen=timestamp,
                count=count, protocol=transport, application_protocol=app, classtype=classtype,
            ), run_id="fixture-tc14")
        baseline = database.read_bytes()
        reader = AlertRepository(database, read_only=True)
        period_rows = reader.query(from_time=START, to_time=START + 7200)
        require([(row.sid, row.count) for row in period_rows] == [(104141, 3), (104142, 1)],
                "Wrong fixture data in the selected period")

        metadata = {"run_id": None, "time_basis": "first_seen", "top_n": 2}
        artifacts = run_report(log, folder, config, "period", "2023-11-15T05:13:20+07:00", "2023-11-15T00:13:20Z", {
            **metadata, "period": {"from_utc": "2023-11-14T22:13:20Z", "to_utc": "2023-11-15T00:13:20Z"},
            "total_alerts": 2, "total_occurrences": 4, **EXPECTED_DISTRIBUTIONS, **EXPECTED_RANKINGS,
        })
        artifacts.update(run_report(log, folder, config, "empty", "2023-11-16T00:00:00Z", "2023-11-16T01:00:00Z", {
            **metadata, "period": {"from_utc": "2023-11-16T00:00:00Z", "to_utc": "2023-11-16T01:00:00Z"},
            "total_alerts": 0, "total_occurrences": 0,
            **{field: {} for field in EXPECTED_DISTRIBUTIONS},
            "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            **{field: [] for field in EXPECTED_RANKINGS},
        }))
        require(database.read_bytes() == baseline and len(reader.query()) == 3,
                "Report changed the SQLite source")

    for name, content in artifacts.items():
        (FOLDER / name).write_text(content, encoding="utf-8")
    log.append("PASS TC14: two CLI runs exported consistent text and JSON; SQLite remained unchanged.")


def main():
    log = ["TC14: independent CLI report processes against temporary SQLite fixture."]
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL TC14: {type(error).__name__}: {error}")
        code = 1
    console = "\n".join(log) + "\n"
    (FOLDER / "console.txt").write_text(console, encoding="utf-8")
    print(console, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

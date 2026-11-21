"""TC10 — Truy vấn nhóm alert theo thời gian và bộ lọc kết hợp."""

import json
import sys
from dataclasses import replace
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
RUN_A = "fixture-tc10-a"
RUN_B = "fixture-tc10-b"
SID = 104101
SOURCE = "192.0.2.10"
DESTINATION = "198.51.100.20"

# Mỗi biến thể nới một tiêu chí của truy vấn đầy đủ.
ROWS = (
    ("before_range", -1, RUN_A, {"last_seen": START + 2, "count": 2}),
    ("at_start", 0, RUN_A, {}),
    ("inside", 10, RUN_A, {}),
    ("other_severity", 20, RUN_A, {"severity": Severity.LOW}),
    ("other_sid", 25, RUN_A, {"sid": 104102}),
    ("other_source", 30, RUN_A, {"src_ip": "192.0.2.11"}),
    ("other_destination", 35, RUN_A, {"dst_ip": "198.51.100.21"}),
    ("other_run", 40, RUN_B, {}),
    ("at_end", 60, RUN_A, {}),
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_checks(log):
    ids = {label: str(UUID(int=index, version=4)) for index, (label, *_) in enumerate(ROWS, 1)}
    keys = {value: key for key, value in ids.items()}
    period = {"from_time": START, "to_time": START + 60}
    criteria = {"severity": "HIGH", "sid": SID, "src_ip": SOURCE, "dst_ip": DESTINATION}
    queries = (
        ("all_rows", {}, list(ids)),
        ("period_only", period, ["at_start", "inside", "other_severity", "other_sid",
                                 "other_source", "other_destination", "other_run"]),
        ("combined", {**period, **criteria, "run_id": RUN_A}, ["at_start", "inside"]),
        ("combined_all_runs", {**period, **criteria}, ["at_start", "inside", "other_run"]),
        ("adjacent_period", {**criteria, "from_time": START + 60, "to_time": START + 120,
                             "run_id": RUN_A}, ["at_end"]),
        ("empty", {**period, "sid": 104999}, []),
    )
    results = []
    with TemporaryDirectory(prefix="tc10_", dir=FOLDER) as temporary:
        database = Path(temporary) / "alerts.sqlite3"
        writer = AlertRepository(database)
        for label, offset, run_id, changes in reversed(ROWS):
            timestamp = START + offset
            group = Alert(
                alert_id=ids[label], sid=SID, severity=Severity.HIGH, msg=label,
                src_ip=SOURCE, dst_ip=DESTINATION, first_seen=timestamp, last_seen=timestamp,
            )
            writer.insert(replace(group, **changes), run_id=run_id)

        reader = AlertRepository(database, read_only=True)
        for name, filters, expected in queries:
            rows = reader.query(**filters)
            actual = [keys.get(row.alert_id, row.alert_id) for row in rows]
            require(actual == expected, f"{name}: expected {expected}, got {actual}")
            results.append({"query": name, "filters": filters, "expected": expected, "actual": actual,
                            "alerts": [row.to_dict() for row in rows]})
            log.append(f"PASS {name}: {len(actual)} alerts ({', '.join(actual) or 'empty'})")

        for case, bounds in (
            ("equal_bounds", {"from_time": START, "to_time": START}),
            ("reversed_bounds", {"from_time": START + 60, "to_time": START}),
        ):
            try:
                reader.query(**bounds)
            except ValueError as error:
                require("from_time" in str(error), f"{case}: missing time diagnostic")
                results.append({"query": case, "filters": bounds, "error": str(error)})
                log.append(f"PASS {case}: {error}")
            else:
                raise AssertionError(f"{case}: invalid period accepted")

    output = FOLDER / "result_queries.json"
    output.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    require(json.loads(output.read_text(encoding="utf-8")) == results, "JSON result did not roundtrip")
    log.append("PASS TC10: all query criteria, period boundaries, empty result and invalid ranges.")


def main():
    log = ["TC10: nine simulated alert groups in SQLite, queried by first_seen and metadata."]
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL TC10: {type(error).__name__}: {error}")
        code = 1
    console = "\n".join(log) + "\n"
    (FOLDER / "console.txt").write_text(console, encoding="utf-8")
    print(console, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

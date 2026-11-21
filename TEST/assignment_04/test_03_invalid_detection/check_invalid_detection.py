"""TC03 — Kiểm tra detection lỗi và luồng xử lý sau lỗi."""

import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from ids.alert.config import AlertConfig
from ids.alert.manager import AlertManager
from ids.alert.repository import AlertRepository


BASE = {
    "timestamp": 1700000000.0, "sid": 104030, "msg": "Kiểm thử detection lỗi",
    "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "src_port": 12345,
    "dst_port": 80, "protocol": "TCP", "application_protocol": "HTTP", "priority": 2,
}
MISSING = ("timestamp", "sid", "msg", "src_ip", "dst_ip")
MALFORMED = (
    ("timestamp", "1700000000"),
    ("sid", True),
    ("src_ip", "999.0.0.1"),
    ("dst_port", 65536),
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_checks(log):
    invalid = [
        (f"missing_{field}", field, {key: value for key, value in BASE.items() if key != field})
        for field in MISSING
    ] + [
        (f"invalid_{field}", field, {**BASE, field: value})
        for field, value in MALFORMED
    ]
    outcomes = []
    with TemporaryDirectory(prefix="tc03_", dir=FOLDER) as temporary:
        config = AlertConfig(storage_path=Path(temporary) / "alerts.sqlite3")
        repository = AlertRepository(config.storage_path)
        manager = AlertManager(config, repository)

        before = manager.process(BASE.copy())
        require(before.status == "created" and before.alert is not None, "Initial valid event should create an alert")
        first = before.alert
        outcomes.append({"case": "valid_before", "status": before.status, "reason": before.reason})

        for case, field, event in invalid:
            original = event.copy()
            result = manager.process(event)
            require(result.status == "rejected" and result.alert is None, f"{case}: expected rejected without alert")
            require(result.reason and field in result.reason, f"{case}: missing diagnostic for {field}")
            require(event == original, f"{case}: input changed")
            outcomes.append({"case": case, "status": result.status, "reason": result.reason})
            log.append(f"PASS {case}: {result.status}, {result.reason}")

        after = manager.process({**BASE, "timestamp": 1700000001.0})
        require(after.status == "aggregated" and after.alert is not None,
                "Valid event after rejected inputs should aggregate")
        outcomes.append({"case": "valid_after", "status": after.status, "reason": after.reason})
        alert = after.alert
        require(alert.alert_id == first.alert_id, "Valid events should share the same alert ID")
        require((alert.count, alert.first_seen, alert.last_seen) == (2, 1700000000.0, 1700000001.0),
                "Only the two valid events should change the alert count and window")
        counts = manager.counts
        require(counts == {
            "received": 11, "rejected": 9, "filtered": 0, "created": 1, "aggregated": 1,
            "storage_errors": 0,
            "filtered_by_reason": {"sid_suppressed": 0, "below_min_severity": 0},
        }, f"Unexpected counters: {counts}")
        persisted = AlertRepository(config.storage_path, read_only=True).query()
        require(persisted == [alert], "SQLite should contain only the group from valid detections")

    report = {"outcomes": outcomes, "counts": counts, "stored_alerts": [alert.to_dict() for alert in persisted]}
    output = FOLDER / "result_invalid_detection.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    require(json.loads(output.read_text(encoding="utf-8")) == report, "Result JSON did not roundtrip")
    log.append("PASS TC03: nine rejections diagnosed, valid processing continued, one stored group with count=2.")


def main():
    log = ["TC03: simulated Detection Events, real AlertManager and temporary SQLite."]
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL TC03: {type(error).__name__}: {error}")
        code = 1
    console = "\n".join(log) + "\n"
    (FOLDER / "console.txt").write_text(console, encoding="utf-8")
    print(console, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

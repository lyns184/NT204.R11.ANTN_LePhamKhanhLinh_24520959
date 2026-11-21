"""TC06 — Kiểm tra detection khác khóa tạo nhóm độc lập."""

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


START = 1700000000.0
KEY_FIELDS = ("sid", "src_ip", "dst_ip", "protocol", "application_protocol")
CASES = (
    ("baseline",     (104061, "192.0.2.10", "198.51.100.20", "UDP", "DNS")),
    ("other_sid",    (104062, "192.0.2.10", "198.51.100.20", "UDP", "DNS")),
    ("other_source", (104061, "192.0.2.11", "198.51.100.20", "UDP", "DNS")),
    ("other_dest",   (104061, "192.0.2.10", "198.51.100.21", "UDP", "DNS")),
    ("other_proto",  (104061, "192.0.2.10", "198.51.100.20", "TCP", "DNS")),
    ("unknown_app",  (104061, "192.0.2.10", "198.51.100.20", "UDP", None)),
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_checks(log):
    with TemporaryDirectory(prefix="tc06_", dir=FOLDER) as temporary:
        config = AlertConfig(storage_path=Path(temporary) / "alerts.sqlite3")
        require(config.aggregation_enabled and config.aggregation_window_seconds == 60,
                "Expected default 60-second aggregation")
        manager = AlertManager(config, AlertRepository(config.storage_path))
        created = []
        cases = []
        for offset, (name, expected_key) in enumerate(CASES):
            timestamp = START + offset
            detection = dict(zip(KEY_FIELDS, expected_key, strict=True))
            if name == "unknown_app":
                detection["application_protocol"] = "UNKNOWN"
            result = manager.process({
                **detection, "timestamp": timestamp, "msg": "Kiểm thử nhóm độc lập",
                "priority": 2, "src_port": 53000, "dst_port": 53,
            })
            require(result.status == "created" and result.alert is not None and result.reason is None,
                    f"{name}: expected a new group, got {result}")
            alert = result.alert
            actual_key = tuple(getattr(alert, field) for field in KEY_FIELDS)
            require(actual_key == expected_key, f"{name}: wrong stored key {actual_key}")
            require((alert.first_seen, alert.last_seen, alert.count) == (timestamp, timestamp, 1),
                    f"{name}: group did not start as a single occurrence")
            created.append(alert)
            cases.append({"case": name, "offset_seconds": offset, "status": result.status,
                          "alert_id": alert.alert_id, "expected_key": dict(zip(KEY_FIELDS, expected_key, strict=True))})
            log.append(f"PASS {name}: created, count=1, alert_id={alert.alert_id}")

        require(len({alert.alert_id for alert in created}) == 6, "Expected six distinct alert IDs")
        counts = manager.counts
        require(counts == {
            "received": 6, "rejected": 0, "filtered": 0, "created": 6, "aggregated": 0,
            "storage_errors": 0, "filtered_by_reason": {"sid_suppressed": 0, "below_min_severity": 0},
        }, f"Unexpected counters: {counts}")
        stored = AlertRepository(config.storage_path, read_only=True).query(run_id=manager.run_id)
        require(stored == created, "SQLite should contain exactly the six new groups in time order")

    report = {"cases": cases, "counts": counts, "stored_alerts": [alert.to_dict() for alert in stored]}
    output = FOLDER / "result_distinct_groups.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    require(json.loads(output.read_text(encoding="utf-8")) == report, "JSON result did not roundtrip")
    log.append("PASS TC06: six different keys within one 60-second window, six groups and zero merges.")


def main():
    log = ["TC06: distinct aggregation keys, real AlertManager and temporary SQLite."]
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL TC06: {type(error).__name__}: {error}")
        code = 1
    console = "\n".join(log) + "\n"
    (FOLDER / "console.txt").write_text(console, encoding="utf-8")
    print(console, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

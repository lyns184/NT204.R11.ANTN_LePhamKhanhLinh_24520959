"""TC07 — Kiểm tra detection lặp trong cửa sổ gom nhóm."""

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
# Offset, port nguồn, flow_id và status kỳ vọng.
CASES = (
    (0.0, 12345, "flow-original", "created"),
    (0.0, 12345, "flow-original", "aggregated"),
    (15.0, 23456, "flow-later", "aggregated"),
    (59.5, 34567, "flow-near-boundary", "aggregated"),
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_checks(log):
    steps = []
    with TemporaryDirectory(prefix="tc07_", dir=FOLDER) as temporary:
        config = AlertConfig(storage_path=Path(temporary) / "alerts.sqlite3")
        require(config.aggregation_enabled and config.aggregation_window_seconds == 60,
                "Expected aggregation enabled with a 60-second window")
        manager = AlertManager(config, AlertRepository(config.storage_path))
        alert_id = None
        for count, (offset, port, flow_id, expected_status) in enumerate(CASES, 1):
            timestamp = START + offset
            result = manager.process({
                "timestamp": timestamp, "sid": 104071, "priority": 2, "msg": "Kiểm thử gom trong cửa sổ",
                "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "src_port": port, "dst_port": 80,
                "protocol": "TCP", "application_protocol": "HTTP", "flow_id": flow_id,
            })
            require(result.status == expected_status and result.alert is not None and result.reason is None,
                    f"Event {count}: expected {expected_status}, got {result}")
            alert = result.alert
            if count == 1:
                alert_id = alert.alert_id
            require(alert.alert_id == alert_id, f"Event {count}: alert_id changed")
            require((alert.first_seen, alert.last_seen, alert.count) == (START, timestamp, count),
                    f"Event {count}: incorrect first_seen, last_seen or count")
            require((alert.src_port, alert.flow_id) == (12345, "flow-original"),
                    f"Event {count}: first detection metadata changed")
            steps.append({"offset_seconds": offset, "input_src_port": port, "input_flow_id": flow_id,
                          "expected_status": expected_status, "status": result.status, "alert": alert.to_dict()})
            log.append(f"PASS event {count}: t+{offset:g}s -> {result.status}, count={alert.count}")

        counts = manager.counts
        require(counts == {
            "received": 4, "rejected": 0, "filtered": 0, "created": 1, "aggregated": 3,
            "storage_errors": 0, "filtered_by_reason": {"sid_suppressed": 0, "below_min_severity": 0},
        }, f"Unexpected counters: {counts}")
        stored = AlertRepository(config.storage_path, read_only=True).query(run_id=manager.run_id)
        require(stored == [alert], "SQLite should contain one final group with count=4")

    report = {"window_seconds": config.aggregation_window_seconds, "steps": steps,
              "counts": counts, "stored_alerts": [item.to_dict() for item in stored]}
    output = FOLDER / "result_aggregation.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    require(json.loads(output.read_text(encoding="utf-8")) == report, "JSON result did not roundtrip")
    log.append("PASS TC07: four events in one group with the same alert_id and correct timestamps.")


def main():
    log = ["TC07: repeated detections inside a fixed 60-second window."]
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL TC07: {type(error).__name__}: {error}")
        code = 1
    console = "\n".join(log) + "\n"
    (FOLDER / "console.txt").write_text(console, encoding="utf-8")
    print(console, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

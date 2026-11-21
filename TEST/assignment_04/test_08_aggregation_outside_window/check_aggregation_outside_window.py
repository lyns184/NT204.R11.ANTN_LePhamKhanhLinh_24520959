"""TC08 — Kiểm tra tạo nhóm tại và sau biên cửa sổ gom."""

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
# Offset (giây), nhóm kỳ vọng, status, thời điểm bắt đầu nhóm, count.
CASES = (
    (0.0, "A", "created", 0.0, 1),
    (59.5, "A", "aggregated", 0.0, 2),
    (60.0, "B", "created", 60.0, 1),
    (119.5, "B", "aggregated", 60.0, 2),
    (121.0, "C", "created", 121.0, 1),
    (180.5, "C", "aggregated", 121.0, 2),
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_checks(log):
    steps = []
    with TemporaryDirectory(prefix="tc08_", dir=FOLDER) as temporary:
        config = AlertConfig(storage_path=Path(temporary) / "alerts.sqlite3")
        require(config.aggregation_enabled and config.aggregation_window_seconds == 60,
                "Expected aggregation enabled with a 60-second window")
        manager = AlertManager(config, AlertRepository(config.storage_path))
        group_ids = {}
        for offset, group, status, start_offset, count in CASES:
            result = manager.process({
                "sid": 104081, "timestamp": START + offset, "priority": 2, "msg": "Kiểm thử biên cửa sổ",
                "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "src_port": 12345, "dst_port": 80,
                "protocol": "TCP", "application_protocol": "HTTP",
            })
            require(result.status == status and result.reason is None and result.alert is not None,
                    f"t+{offset:g}s: expected {status}, got {result}")
            alert = result.alert
            if status == "created":
                require(alert.alert_id not in group_ids.values(), f"Group {group}: reused a previous ID")
                group_ids[group] = alert.alert_id
            require(alert.alert_id == group_ids[group], f"t+{offset:g}s: assigned to the wrong group")
            require((alert.first_seen, alert.last_seen, alert.count) == (START + start_offset, START + offset, count),
                    f"t+{offset:g}s: unexpected group timestamps or count")
            steps.append({"offset_seconds": offset, "expected_group": group,
                          "expected_status": status, "status": result.status, "alert": alert.to_dict()})
            log.append(f"PASS t+{offset:g}s: {result.status} group {group}, count={alert.count}")

        counts = manager.counts
        require(counts == {
            "received": 6, "rejected": 0, "filtered": 0, "created": 3, "aggregated": 3,
            "storage_errors": 0, "filtered_by_reason": {"sid_suppressed": 0, "below_min_severity": 0},
        }, f"Unexpected counters: {counts}")
        stored = AlertRepository(config.storage_path, read_only=True).query(run_id=manager.run_id)
        actual = [(alert.alert_id, alert.first_seen, alert.last_seen, alert.count) for alert in stored]
        require(actual == [
            (group_ids["A"], START, START + 59.5, 2),
            (group_ids["B"], START + 60, START + 119.5, 2),
            (group_ids["C"], START + 121, START + 180.5, 2),
        ], f"Unexpected SQLite groups: {actual}")

    report = {"window_seconds": config.aggregation_window_seconds, "steps": steps,
              "counts": counts, "stored_alerts": [alert.to_dict() for alert in stored]}
    output = FOLDER / "result_outside_window.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    require(json.loads(output.read_text(encoding="utf-8")) == report, "JSON result did not roundtrip")
    log.append("PASS TC08: exact and past-window events started new groups; SQLite contains three groups of two.")


def main():
    log = ["TC08: one key, exclusive right boundary and fixed 60-second windows."]
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL TC08: {type(error).__name__}: {error}")
        code = 1
    console = "\n".join(log) + "\n"
    (FOLDER / "console.txt").write_text(console, encoding="utf-8")
    print(console, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

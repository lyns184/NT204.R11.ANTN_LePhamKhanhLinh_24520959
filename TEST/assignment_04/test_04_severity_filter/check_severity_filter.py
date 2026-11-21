"""TC04 — Kiểm tra alert ở dưới, bằng và trên ngưỡng severity."""

import json
import sys
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from ids.alert.config import load_alert_config
from ids.alert.manager import AlertManager
from ids.alert.repository import AlertRepository


START = 1700000000.0
# Offset, SID, priority, severity kỳ vọng và kết quả xử lý.
CASES = (
    (0, 104042, 2, "HIGH", "created"),
    (1, 104043, 3, "MEDIUM", "filtered"),
    (2, 104044, 4, "LOW", "filtered"),
    (3, 104041, 1, "CRITICAL", "created"),
    (4, 104042, 2, "HIGH", "aggregated"),
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_checks(log):
    cases = []
    expected_counts = {
        "received": 5, "rejected": 0, "filtered": 2, "created": 2, "aggregated": 1,
        "storage_errors": 0, "filtered_by_reason": {"sid_suppressed": 0, "below_min_severity": 2},
    }
    with TemporaryDirectory(prefix="tc04_", dir=FOLDER) as temporary:
        config = replace(load_alert_config(FOLDER / "alert_config.json"),
                         storage_path=Path(temporary) / "alerts.sqlite3")
        require(config.min_severity.value == "HIGH" and not config.suppressed_sids,
                "Fixture should enable only the severity filter")
        repository = AlertRepository(config.storage_path)
        manager = AlertManager(config, repository)
        for offset, sid, priority, severity, status in CASES:
            result = manager.process({
                "timestamp": START + offset, "sid": sid, "priority": priority, "msg": "Kiểm thử ngưỡng severity",
                "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "protocol": "TCP",
            })
            require(result.status == status, f"Offset {offset}: expected {status}, got {result.status}")
            if status == "filtered":
                require(result.reason == "below_min_severity" and result.alert is None,
                        f"{severity}: expected below_min_severity without alert")
            else:
                require(result.reason is None and result.alert is not None
                        and result.alert.severity.value == severity, f"{severity}: unexpected accepted alert")
            cases.append({"offset_seconds": offset, "sid": sid, "priority": priority,
                          "expected_severity": severity, "expected_status": status,
                          "status": result.status, "reason": result.reason})
            log.append(f"PASS t+{offset}s: SID {sid} ({severity}) -> {result.status}")

        counts = manager.counts
        require(counts == expected_counts, f"Unexpected counters: {counts}")
        alerts = AlertRepository(config.storage_path, read_only=True).query(run_id=manager.run_id)
        actual = [(item.sid, item.severity.value, item.count, item.first_seen, item.last_seen) for item in alerts]
        require(actual == [
            (104042, "HIGH", 2, START, START + 4),
            (104041, "CRITICAL", 1, START + 3, START + 3),
        ], f"Unexpected SQLite groups: {actual}")

    report = {"min_severity": config.min_severity.value, "cases": cases, "counts": counts,
              "stored_alerts": [item.to_dict() for item in alerts]}
    output = FOLDER / "result_severity_filter.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    require(json.loads(output.read_text(encoding="utf-8")) == report, "JSON result did not roundtrip")
    log.append("PASS TC04: two below-threshold events filtered; SQLite contains two groups and three occurrences.")


def main():
    log = ["TC04: min_severity=HIGH, real AlertManager and temporary SQLite."]
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL TC04: {type(error).__name__}: {error}")
        code = 1
    console = "\n".join(log) + "\n"
    (FOLDER / "console.txt").write_text(console, encoding="utf-8")
    print(console, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

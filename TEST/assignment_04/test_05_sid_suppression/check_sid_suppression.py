"""TC05 — Kiểm tra lọc theo SID trước khi lưu và gom alert."""

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
# SID, priority, status và reason kỳ vọng, theo thứ tự nhận detection.
CASES = (
    (104051, 1, "created", None),
    (104052, 1, "filtered", "sid_suppressed"),
    (104053, 4, "filtered", "sid_suppressed"),
    (104054, 4, "filtered", "below_min_severity"),
    (104052, 1, "filtered", "sid_suppressed"),
    (104051, 1, "aggregated", None),
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_checks(log):
    decisions = []
    with TemporaryDirectory(prefix="tc05_", dir=FOLDER) as temporary:
        config = replace(load_alert_config(FOLDER / "alert_config.json"),
                         storage_path=Path(temporary) / "alerts.sqlite3")
        require(config.suppressed_sids == {104052, 104053}, "Unexpected suppression config")
        repository = AlertRepository(config.storage_path)
        manager = AlertManager(config, repository)
        accepted = []
        for offset, (sid, priority, expected_status, expected_reason) in enumerate(CASES):
            result = manager.process({
                "timestamp": START + offset, "sid": sid, "priority": priority, "msg": "Kiểm thử lọc SID",
                "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "protocol": "TCP",
            })
            require((result.status, result.reason) == (expected_status, expected_reason),
                    f"t+{offset}s/SID {sid}: unexpected decision {result}")
            if expected_status == "filtered":
                require(result.alert is None, f"t+{offset}s/SID {sid}: filtered result returned an alert")
            else:
                require(result.alert is not None and result.alert.severity.value == "CRITICAL",
                        f"t+{offset}s/SID {sid}: expected a CRITICAL alert")
                accepted.append(result.alert)
            decisions.append({"offset_seconds": offset, "sid": sid, "priority": priority,
                              "expected_status": expected_status, "expected_reason": expected_reason,
                              "status": result.status, "reason": result.reason})
            log.append(f"PASS t+{offset}s: SID {sid} -> {result.status} ({result.reason or '-'})")

        counts = manager.counts
        require(counts == {
            "received": 6, "rejected": 0, "filtered": 4, "created": 1, "aggregated": 1,
            "storage_errors": 0, "filtered_by_reason": {"sid_suppressed": 3, "below_min_severity": 1},
        }, f"Unexpected counters: {counts}")
        first, last = accepted
        require(first.alert_id == last.alert_id, "Allowed SID should aggregate into the original group")
        alerts = AlertRepository(config.storage_path, read_only=True).query()
        require(alerts == [last], "SQLite should contain only the group for SID 104051")
        require((last.sid, last.count, last.first_seen, last.last_seen) == (104051, 2, START, START + 5),
                "Suppression should not affect the permitted group's counter or window")

    report = {"suppressed_sids": sorted(config.suppressed_sids), "min_severity": config.min_severity.value,
              "cases": decisions, "counts": counts, "stored_alerts": [alert.to_dict() for alert in alerts]}
    output = FOLDER / "result_sid_suppression.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    require(json.loads(output.read_text(encoding="utf-8")) == report, "JSON result did not roundtrip")
    log.append("PASS TC05: three SID suppressions, one severity rejection, one stored group with count=2.")


def main():
    log = ["TC05: configured SID suppression, real AlertManager and temporary SQLite."]
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL TC05: {type(error).__name__}: {error}")
        code = 1
    console = "\n".join(log) + "\n"
    (FOLDER / "console.txt").write_text(console, encoding="utf-8")
    print(console, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

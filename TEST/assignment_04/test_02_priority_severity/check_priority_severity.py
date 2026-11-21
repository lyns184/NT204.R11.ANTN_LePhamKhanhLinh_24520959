"""TC02 — Kiểm tra priority → severity theo cấu hình thực tế."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from ids.alert.config import load_alert_config
from ids.alert.conversion import convert_detection


# expected_default và expected_custom được xác định độc lập từ đặc tả test.
CASES = (
    ("priority_1", {"priority": 1}, "CRITICAL", "MEDIUM"),
    ("priority_2", {"priority": 2}, "HIGH", "CRITICAL"),
    ("priority_3", {"priority": 3}, "MEDIUM", "HIGH"),
    ("priority_4", {"priority": 4}, "LOW", "HIGH"),
    ("priority_7", {"priority": 7}, "LOW", "LOW"),
    ("priority_8", {"priority": 8}, "LOW", "HIGH"),
    ("priority_null", {"priority": None}, "LOW", "HIGH"),
    ("priority_missing", {}, "LOW", "HIGH"),
)


def run_checks(log):
    config_file = FOLDER / "alert_config.json"
    original = config_file.read_bytes()
    default = load_alert_config()
    custom = load_alert_config(config_file)
    results = []
    for index, (name, priority_field, expected_default, expected_custom) in enumerate(CASES, 1):
        record = {
            "sid": 104020, "msg": "Kiểm thử ánh xạ priority",
            "timestamp": 1700000000 + index, "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20",
            "protocol": "TCP", **priority_field,
        }
        snapshot = record.copy()
        for config_name, config, expected in (
            ("default", default, expected_default),
            ("custom", custom, expected_custom),
        ):
            result = convert_detection(record, config)
            if result.status != "accepted" or result.alert is None or result.reason is not None:
                raise AssertionError(f"{name}/{config_name}: unexpected conversion result {result}")
            actual = result.alert.to_dict()
            if actual["severity"] != expected:
                raise AssertionError(f"{name}/{config_name}: expected {expected}, got {actual['severity']}")
            if actual["priority"] != priority_field.get("priority"):
                raise AssertionError(f"{name}/{config_name}: input priority changed")
            results.append({
                "case": name, "config": config_name, "priority_present": "priority" in record,
                "priority": actual["priority"], "expected": expected, "actual": actual["severity"],
            })
        if record != snapshot:
            raise AssertionError(f"{name}: input detection changed")
        log.append(f"PASS {name}: default={expected_default}, custom={expected_custom}")

    if config_file.read_bytes() != original:
        raise AssertionError("Input configuration changed")
    output = FOLDER / "result_severity.json"
    output.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if json.loads(output.read_text(encoding="utf-8")) != results:
        raise AssertionError("JSON result did not roundtrip")
    log.append(f"PASS TC02: {len(CASES)} cases, {len(results)} conversions, all severities match.")


def main():
    log = ["TC02: simulated Detection Events and two configuration profiles."]
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL TC02: {type(error).__name__}: {error}")
        code = 1
    console = "\n".join(log) + "\n"
    (FOLDER / "console.txt").write_text(console, encoding="utf-8")
    print(console, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

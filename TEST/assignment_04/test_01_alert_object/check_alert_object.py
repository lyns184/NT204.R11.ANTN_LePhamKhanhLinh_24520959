"""TC01 — Kiểm tra chuyển Detection Event hợp lệ thành Alert."""

import json
import sys
from copy import deepcopy
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from ids.alert.config import AlertConfig
from ids.alert.conversion import convert_detection
from ids.alert.models import Alert
from ids.detection.models import DetectionEvent, MatchedInfo


EXPECTED_TCP = {
    "sid": 104001, "rev": 2, "msg": "Cảnh báo kiểm thử HTTP",
    "severity": "HIGH", "priority": 2, "classtype": "test-traffic",
    "src_ip": "192.0.2.10", "src_port": 12345, "dst_ip": "198.51.100.20", "dst_port": 80,
    "protocol": "TCP", "application_protocol": "HTTP", "flow_id": "test-flow-01",
    "timestamp": 1700000000.25, "first_seen": 1700000000.25, "last_seen": 1700000000.25,
    "count": 1, "run_id": None,
}
EXPECTED_UDP = {
    "sid": 104002, "rev": 1, "msg": "Cảnh báo kiểm thử UDP",
    "severity": "LOW", "priority": None, "classtype": None,
    "src_ip": "192.0.2.11", "src_port": 53000, "dst_ip": "198.51.100.21", "dst_port": 53,
    "protocol": "UDP", "application_protocol": None, "flow_id": None,
    "timestamp": 1700000001.0, "first_seen": 1700000001.0, "last_seen": 1700000001.0,
    "count": 1, "run_id": None,
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_checks(log):
    fixture = FOLDER / "input_detections.jsonl"
    input_bytes = fixture.read_bytes()
    records = [json.loads(line) for line in input_bytes.decode("utf-8").splitlines()]
    tcp, udp = records
    original_records = deepcopy(records)
    typed = DetectionEvent(
        **{key: value for key, value in tcp.items() if key != "matched_info"},
        matched_info=MatchedInfo(),
    )
    require(typed.to_dict() == tcp, "Typed fixture must represent the same TCP detection")

    config = AlertConfig()
    outputs = []
    for label, detection, expected in (
        ("TCP callback record", tcp, EXPECTED_TCP),
        ("same TCP detection as object", typed, EXPECTED_TCP),
        ("UDP callback with optional fields absent or unknown", udp, EXPECTED_UDP),
    ):
        result = convert_detection(detection, config)
        require(result.status == "accepted" and result.reason is None, f"{label}: {result.reason}")
        require(isinstance(result.alert, Alert), f"{label}: expected Alert")
        exported = result.alert.to_dict()
        require(set(exported) == set(expected) | {"alert_id"}, f"{label}: unexpected alert schema")
        for key, value in expected.items():
            actual = exported[key]
            require(type(actual) is type(value) and actual == value,
                    f"{label}.{key}: expected {value!r}, got {actual!r}")
        alert_id = exported["alert_id"]
        require(type(alert_id) is str and str(UUID(alert_id, version=4)) == alert_id,
                f"{label}: expected canonical UUIDv4")
        outputs.append(exported)
        log.append(f"PASS {label}: sid={exported['sid']}, severity={exported['severity']}, "
                   f"count={exported['count']}, alert_id={alert_id}")

    require(len({row["alert_id"] for row in outputs}) == 3, "Alert IDs must be unique even for repeated input")
    require(records == original_records and typed.to_dict() == tcp, "Converter changed input object")
    require(fixture.read_bytes() == input_bytes, "Test changed input fixture")

    output = FOLDER / "result_alerts.jsonl"
    output.write_text("".join(json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n" for row in outputs),
                      encoding="utf-8")
    require([json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()] == outputs,
            "Output JSONL did not roundtrip")
    log.append("PASS TC01: three complete alerts, three unique UUIDv4 IDs, input unchanged and JSONL roundtrip.")


def main():
    log = ["TC01: two simulated Detection Events, three conversion calls."]
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL TC01: {type(error).__name__}: {error}")
        code = 1
    console = "\n".join(log) + "\n"
    (FOLDER / "console.txt").write_text(console, encoding="utf-8")
    print(console, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

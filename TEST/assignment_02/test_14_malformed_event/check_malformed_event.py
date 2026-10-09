"""T14: unsupported PCAP and invalid events followed by valid events."""

import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from ids.core.event import IDSEvent
from ids.flow_tracker import FlowTracker
from ids.output.jsonl_writer import JSONLWriter
from ids.preprocessor.processor import preprocess_event


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def check_cli(log):
    relative = FOLDER.relative_to(ROOT)
    run = subprocess.run([
        sys.executable, "-X", "utf8", "main.py",
        "--pcap", str(relative / "input.pcap"),
        "--output", str(relative / "result.jsonl"),
        "--flow-output", str(relative / "result_flows.jsonl"),
    ], cwd=ROOT, capture_output=True, encoding="utf-8")
    log.append(run.stdout + run.stderr)
    require(run.returncode == 0, "CLI failed")
    events = [json.loads(x) for x in (FOLDER / "result.jsonl").read_text(encoding="utf-8").splitlines()]
    flows = [json.loads(x) for x in (FOLDER / "result_flows.jsonl").read_text(encoding="utf-8").splitlines()]
    require(len(events) == 2 and len(flows) == 1, "Expected 2 events and 1 flow")
    unsupported, valid = events
    require(unsupported["preprocess_status"] == "partial" and unsupported["processing_action"] == "skip", "ARP policy")
    require("unsupported_protocol" in unsupported["reason"], "ARP reason missing")
    require(unsupported["flow_tracking_status"] == "skipped" and unsupported["flow_id"] is None, "ARP created flow")
    require(valid["packet_id"] == 2 and valid["preprocess_status"] == "valid", "Following packet lost")
    require(valid["processing_action"] == "process" and valid["flow_tracking_status"] == "tracked", "Valid packet skipped")
    require(valid["flow_id"] == flows[0]["flow_id"] and flows[0]["packet_count"] == 1, "Flow polluted")
    require(flows[0]["byte_count"] == 40 and flows[0]["state"] == "HANDSHAKE", "SYN flow summary")
    log.append("PASS PCAP: ARP retained with partial/skip/reason; following TCP packet processed and tracked.\n")


def make_event(number, case):
    return IDSEvent(
        packet_id=number, timestamp=100.0 + number, capture_source=f"test:T14:{case}",
        network={"protocol": "IPv4", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "total_length": 40},
        transport={"protocol": "TCP", "src_port": 12345, "dst_port": 80,
                   "flags": "S", "sequence_number": 1000, "acknowledgment_number": 0, "payload_length": 0},
    )


def check_direct(log):
    tracker = FlowTracker()
    records = []
    cases = (("invalid_ip", "network.src_ip"), ("invalid_port_type", "transport.dst_port"),
             ("invalid_binary_body", "application.fields.body"))
    with JSONLWriter(str(FOLDER / "direct_result.jsonl")) as writer:
        for case, field in cases:
            invalid = make_event(len(records) + 1, case)
            if case == "invalid_ip":
                invalid.network["src_ip"] = "abc"
            elif case == "invalid_port_type":
                invalid.transport["dst_port"] = "80"
            else:
                invalid.application = {"protocol": "HTTP", "fields": {
                    "message_type": "request", "method": "GET", "path": "/", "body": b"Hello \xff",
                }}
            for event, expected in ((invalid, "invalid"), (make_event(len(records) + 2, f"valid_after_{case}"), "valid")):
                original = deepcopy((event.network, event.transport, event.application))
                preprocess_event(event)
                require((event.network, event.transport, event.application) == original, "Original data changed")
                require(event.preprocess_status == expected, f"{case}: unexpected status {event.reason}")
                result = tracker.track(event)
                event.flow_tracking_status = result.status
                event.flow_tracking_reason = result.reason
                if expected == "invalid":
                    require(event.processing_action == "skip" and field in event.reason, f"{case}: status/reason")
                    require(result.status == "skipped" and event.flow_id is None, "Invalid event tracked")
                else:
                    require(event.processing_action == "process" and event.reason is None, "Valid policy")
                    require(result.status == "tracked" and event.flow_id, "Valid event not tracked")
                writer.write(event)
                records.append(event.to_dict())
                log.append(json.dumps({"case": event.capture_source, "packet_id": event.packet_id,
                                       "preprocess_status": event.preprocess_status,
                                       "processing_action": event.processing_action, "reason": event.reason,
                                       "flow_tracking_status": event.flow_tracking_status, "result": "PASS"}) + "\n")
    exported = [json.loads(x) for x in (FOLDER / "direct_result.jsonl").read_text(encoding="utf-8").splitlines()]
    require(exported == records and len(exported) == 6, "JSONL roundtrip/continuation")
    require([e["preprocess_status"] for e in exported] == ["invalid", "valid"] * 3, "Event sequence")
    binary = exported[4]
    require(binary["application"]["fields"]["body"] == {
        "type": "bytes", "encoding": "base64", "value": "SGVsbG8g/w==",
    }, "Binary export not safe")
    require(binary.get("serialization_errors"), "Binary conversion not recorded")
    summary = tracker.flush()
    require(len(summary) == 1 and summary[0]["packet_count"] == 3 and summary[0]["byte_count"] == 120,
            "Invalid events polluted flow counters")
    log.append("PASS direct: 3 invalid events each followed by valid event; reasons correct; 6 JSONL records; "
               "binary safely exported as Base64; only valid events counted in flow.\n")


def main():
    log = []
    code = 0
    try:
        check_cli(log)
        check_direct(log)
        log.append("PASS T14: unsupported/invalid events retained; processing continued; statuses and reasons correct.\n")
    except Exception as error:
        log.append(f"FAIL T14: {type(error).__name__}: {error}\n")
        code = 1
    (FOLDER / "console.txt").write_text("".join(log), encoding="utf-8")
    print("".join(log[-2:]), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

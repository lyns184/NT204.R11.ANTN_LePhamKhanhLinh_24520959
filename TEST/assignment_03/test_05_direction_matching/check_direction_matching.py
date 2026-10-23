"""T05: match -> and <> against complete endpoint pairs from offline events."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
AUXILIARY = ROOT / "output" / "t05_direction_matching"
sys.path.insert(0, str(ROOT))

from scapy.all import Ether, IP, PcapReader, TCP

from ids.detection.header_matcher import match_header
from ids.detection.loader import load_rules
from ids.detection.models import InspectionContext


# Independent expected packet data and complete header-result matrix.
# src_ip, src_port, dst_ip, dst_port, flags, seq, ack
PACKETS = (
    ("10.0.0.1", 12345, "10.0.0.2", 80, "S", 1000, 0),
    ("10.0.0.2", 80, "10.0.0.1", 12345, "SA", 2000, 1001),
    ("10.0.0.1", 12345, "10.0.0.2", 81, "S", 1000, 0),
    ("10.0.0.2", 12345, "10.0.0.1", 80, "S", 1000, 0),
    ("10.0.0.9", 12345, "10.0.0.2", 80, "S", 1000, 0),
)
EXPECTED_HEADERS = (
    (("MATCH", "direct"), ("MATCH", "direct")),
    (("NO_MATCH", None), ("MATCH", "reverse")),
    (("NO_MATCH", None), ("NO_MATCH", None)),
    (("NO_MATCH", None), ("NO_MATCH", None)),
    (("NO_MATCH", None), ("NO_MATCH", None)),
)
EXPECTED_DETECTIONS = ((1, 100501, "direct"), (1, 100502, "direct"), (2, 100502, "reverse"))


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def check_inputs(log):
    report = load_rules([FOLDER / "input.rules"])
    require(report.counts == {
        "files_requested": 1, "files_loaded": 1, "files_disabled": 0, "files_duplicate": 0,
        "lines_read": 2, "rules_total": 2, "rules_enabled": 2, "rules_invalid": 0,
        "rules_unsupported": 0, "rules_disabled": 0, "rules_duplicate": 0,
    } and not report.diagnostics, "Expected exactly two valid enabled rules")
    require([rule.sid for rule in report.enabled_rules] == [100501, 100502], "Rule order mismatch")
    for rule, direction, message in zip(report.enabled_rules, ("->", "<>"), ("Forward only", "Both directions")):
        require(rule.header.to_dict() == {
            "action": "alert", "protocol": "tcp", "src_ip": "10.0.0.1/32",
            "src_port": {"start": 12345, "end": 12345}, "direction": direction,
            "dst_ip": "10.0.0.2/32", "dst_port": {"start": 80, "end": 80},
        }, f"SID {rule.sid}: fixture header mismatch")
        require(rule.rev == 1 and rule.msg == message and not rule.contents
                and rule.flow is None and rule.flags is None and rule.dsize is None,
                f"SID {rule.sid}: expected header-only rule")
    with PcapReader(str(FOLDER / "input.pcap")) as reader:
        packets = list(reader)
    require(len(packets) == len(PACKETS) == 5, "Expected five PCAP packets")
    macs = {"10.0.0.1": "02:00:00:00:00:01", "10.0.0.2": "02:00:00:00:00:02", "10.0.0.9": "02:00:00:00:00:09"}
    for index, (packet, expected) in enumerate(zip(packets, PACKETS), 1):
        require(packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(TCP), f"Packet {index}: layers")
        actual = (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport,
                  str(packet[TCP].flags), packet[TCP].seq, packet[TCP].ack)
        require(actual == expected, f"Packet {index}: endpoints/flags/sequence mismatch")
        require(packet[Ether].src == macs[expected[0]] and packet[Ether].dst == macs[expected[2]],
                f"Packet {index}: MAC addresses")
        require(packet[IP].ihl == packet[TCP].dataofs == 5 and packet[IP].len == 40
                and len(bytes(packet[TCP].payload)) == 0, f"Packet {index}: lengths/payload")
        require(float(packet.time) == 1700000000.0 + index - 1, f"Packet {index}: timestamp")
        log.append(f"Packet {index}: {expected[0]}:{expected[1]} -> {expected[2]}:{expected[3]}, flags={expected[4]}.\n")
    return report


def check_cli(log, report):
    relative = FOLDER.relative_to(ROOT)
    AUXILIARY.mkdir(parents=True, exist_ok=True)
    for filename in ("result.jsonl", "result_matches.jsonl", "result_detections.jsonl"):
        (FOLDER / filename).unlink(missing_ok=True)
    command = [
        sys.executable, "-X", "utf8", "main.py", "--pcap", str(relative / "input.pcap"),
        "--rules", str(relative / "input.rules"), "--output", str(relative / "result.jsonl"),
        "--detection-output", str(relative / "result_detections.jsonl"),
        "--flow-output", str(AUXILIARY.relative_to(ROOT) / "flows.jsonl"),
    ]
    log.append("\nCLI: " + subprocess.list2cmdline(command) + "\n")
    run = subprocess.run(command, cwd=ROOT, capture_output=True, encoding="utf-8", timeout=30)
    log.append("\nCLI stdout:\n" + run.stdout + "\nCLI stderr:\n" + run.stderr)
    log.append(f"\nCLI exit code: {run.returncode}\n")
    require(run.returncode == 0, f"CLI failed: exit code {run.returncode}")
    diagnostics = [line for line in run.stderr.splitlines() if line.startswith("[DETECTION] ")]
    require(not diagnostics, f"Unexpected detection diagnostics: {diagnostics}")
    counts = [json.loads(line.removeprefix("[RULES] ")) for line in run.stdout.splitlines() if line.startswith("[RULES] ")]
    require(counts == [report.counts], "CLI Loader counters mismatch")
    summaries = [json.loads(line.removeprefix("[DETECTION SUMMARY] ")) for line in run.stdout.splitlines()
                 if line.startswith("[DETECTION SUMMARY] ")]
    require(summaries == [{"events_evaluated": 5, "events_skipped": 0, "candidate_rules": 7,
                           "matches": 3, "rule_evaluation_errors": 0, "rule_not_evaluable": 0,
                           "detections_written": 3}], f"Unexpected Engine summary: {summaries}")
    events = read_jsonl(FOLDER / "result.jsonl")
    require(len(events) == 5, "CLI must retain all five packet events")
    for index, (event, expected) in enumerate(zip(events, PACKETS), 1):
        require(event["packet_id"] == index and event["timestamp"] == 1700000000.0 + index - 1,
                f"Event {index}: identity/timestamp")
        normalized = event["normalized"]
        network, transport = normalized["network"], normalized["transport"]
        require((network["src_ip"], transport["src_port"], network["dst_ip"], transport["dst_port"])
                == expected[:4], f"Event {index}: endpoints")
        require(network["protocol"] == "IPv4" and transport["protocol"] == "TCP"
                and transport["flags"] == expected[4], f"Event {index}: protocol/flags")
        require(event["preprocess_status"] == "valid" and event["processing_action"] == "process"
                and event["flow_tracking_status"] == "tracked" and event["flow_id"], f"Event {index}: processing/flow")
        require(not event["parse_errors"] and not event["decode_errors"] and event["payload_length"] == 0,
                f"Event {index}: errors/payload")
    return events


def check_headers(log, rules, events):
    records = []
    for event, expectations in zip(events, EXPECTED_HEADERS):
        context = InspectionContext(timestamp=event["timestamp"], packet_id=event["packet_id"],
                                    normalized=event["normalized"], processing_action=event["processing_action"])
        for rule, expected in zip(rules, expectations):
            result = match_header(rule.header, context)
            require((result.status.value, result.orientation) == expected,
                    f"Packet {event['packet_id']}, SID {rule.sid}: expected {expected}, got {result.to_dict()}")
            require(not result.diagnostics, f"Packet {event['packet_id']}, SID {rule.sid}: unexpected diagnostics")
            if result.status == "NO_MATCH":
                require(result.reason_code == "header_no_match" and bool(result.reason), "NO_MATCH must have a reason")
            records.append({"packet_id": event["packet_id"], "sid": rule.sid, **result.to_dict()})
            log.append(f"Header: packet_id={event['packet_id']}, sid={rule.sid}, "
                       f"status={result.status.value}, orientation={result.orientation}.\n")
    require(len(records) == 10 and sum(record["status"] == "MATCH" for record in records) == 3,
            "Expected 10 header results: 3 MATCH and 7 NO_MATCH")
    result_path = FOLDER / "result_matches.jsonl"
    result_path.write_text("".join(json.dumps(record, ensure_ascii=True, allow_nan=False) + "\n"
                                   for record in records), encoding="utf-8")
    require(read_jsonl(result_path) == records, "Header result JSONL roundtrip mismatch")
    return records


def check_detections(log, events, header_results, rules):
    detections = read_jsonl(FOLDER / "result_detections.jsonl")
    require([(d["packet_id"], d["sid"], d["matched_info"]["header"]["orientation"]) for d in detections]
            == list(EXPECTED_DETECTIONS), "Expected exactly three detections with direct/direct/reverse orientations")
    messages = {rule.sid: rule.msg for rule in rules}
    for detection in detections:
        packet_id, sid = detection["packet_id"], detection["sid"]
        event = events[packet_id - 1]
        require((detection["src_ip"], detection["src_port"], detection["dst_ip"], detection["dst_port"])
                == PACKETS[packet_id - 1][:4], f"Detection packet {packet_id}, SID {sid}: observed endpoints were changed")
        require(detection["timestamp"] == event["timestamp"] and detection["flow_id"] == event["flow_id"],
                f"Detection packet {packet_id}, SID {sid}: event correlation")
        require(detection["protocol"] == "TCP" and detection["application_protocol"] == "UNKNOWN"
                and detection["rev"] == 1 and detection["msg"] == messages[sid], "Detection metadata mismatch")
        header = next(result for result in header_results if result["packet_id"] == packet_id and result["sid"] == sid)
        require(detection["matched_info"] == {"header": {"matched": True, "orientation": header["orientation"]},
                "flow": None, "flags": None, "dsize": None, "contents": []}, "Detection/header evidence mismatch")
        log.append(f"Detection: packet_id={packet_id}, sid={sid}, orientation={header['orientation']}; "
                   "observed endpoints/timestamp/flow_id preserved.\n")


def run_checks(log):
    originals = {name: (FOLDER / name).read_bytes() for name in ("input.rules", "input.pcap")}
    log.append("T05: real CLI and Header Matcher; synthetic PCAP, no live traffic.\n")
    report = check_inputs(log)
    events = check_cli(log, report)
    header_results = check_headers(log, report.enabled_rules, events)
    check_detections(log, events, header_results, report.enabled_rules)
    for name, original in originals.items():
        require((FOLDER / name).read_bytes() == original, f"Test changed {name}")
    log.append("Inputs unchanged; events, header results and detections read back as JSON.\n")
    log.append("PASS T05: 5 packet events, 10 header results (3 MATCH/7 NO_MATCH), exactly 3 detections; "
               "-> and <> preserve complete endpoints and correct orientation.\n")


def main():
    log = []
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL T05: {type(error).__name__}: {error}\n")
        code = 1
    (FOLDER / "console.txt").write_text("".join(log), encoding="utf-8")
    print("".join(log), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

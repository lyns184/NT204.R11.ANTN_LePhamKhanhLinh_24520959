"""T07: header rejection must stop full-rule evaluation before content search."""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
AUXILIARY = ROOT / "output" / "t07_header_short_circuit"
PAYLOAD = b"GET /admin HTTP/1.1\r\nHost: ids.test\r\n\r\n"
sys.path.insert(0, str(ROOT))

from scapy.all import Ether, IP, PcapReader, TCP

from ids.detection.content_matcher import match_contents
from ids.detection.header_matcher import match_header
from ids.detection.loader import load_rules
from ids.detection.matcher import match_rule
from ids.detection.models import InspectionContext
from ids.detection.repository import RuleRepository


# src_ip, src_port, dst_ip, dst_port, expected full-rule status, content calls.
CASES = (
    ("10.0.0.9", 12345, "10.0.0.2", 80, "NO_MATCH", 0),
    ("10.0.0.1", 12346, "10.0.0.3", 80, "NO_MATCH", 0),
    ("10.0.0.1", 12347, "10.0.0.2", 80, "MATCH", 1),
)
MATCHED_INFO = {
    "header": {"matched": True, "orientation": "direct"},
    "flow": None, "flags": None, "dsize": None,
    "contents": [{"index": 0, "buffer": "payload", "pattern_hex": "61646d696e",
                  "matched_hex": "61646d696e", "start": 5, "end": 10, "nocase": False}],
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def check_inputs(log):
    report = load_rules([FOLDER / "input.rules"])
    require(report.counts == {
        "files_requested": 1, "files_loaded": 1, "files_disabled": 0, "files_duplicate": 0,
        "lines_read": 1, "rules_total": 1, "rules_enabled": 1, "rules_invalid": 0,
        "rules_unsupported": 0, "rules_disabled": 0, "rules_duplicate": 0,
    } and not report.diagnostics, "Expected one valid enabled rule")
    rule = report.enabled_rules[0]
    require((rule.sid, rule.rev, rule.msg) == (100701, 1, "Header before content"), "Rule identification")
    require(rule.header.to_dict() == {
        "action": "alert", "protocol": "tcp", "src_ip": "10.0.0.1/32", "dst_ip": "10.0.0.2/32",
        "src_port": {"start": None, "end": None}, "dst_port": {"start": 80, "end": 80}, "direction": "->",
    }, "Rule fixture header mismatch")
    require(len(rule.contents) == 1 and rule.contents[0].to_dict() == {
        "pattern_hex": "61646d696e", "nocase": False, "offset": None, "depth": None,
        "distance": None, "within": None,
    }, "Expected one unmodified content admin")
    require(rule.flow is None and rule.flags is None and rule.dsize is None, "Unexpected extra conditions")
    with PcapReader(str(FOLDER / "input.pcap")) as reader:
        packets = list(reader)
    require(len(packets) == len(CASES) == 3, "Expected three PCAP packets")
    macs = {"10.0.0.1": "02:00:00:00:00:01", "10.0.0.2": "02:00:00:00:00:02",
            "10.0.0.3": "02:00:00:00:00:03", "10.0.0.9": "02:00:00:00:00:09"}
    for number, (packet, expected) in enumerate(zip(packets, CASES), 1):
        require(packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(TCP), f"Packet {number}: layers")
        require((packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport) == expected[:4],
                f"Packet {number}: endpoints")
        require(packet[Ether].src == macs[expected[0]] and packet[Ether].dst == macs[expected[2]],
                f"Packet {number}: MAC addresses")
        require(str(packet[TCP].flags) == "PA" and packet[TCP].seq == 1001 and packet[TCP].ack == 2001,
                f"Packet {number}: flags/sequence/acknowledgment")
        require(packet[IP].ihl == packet[TCP].dataofs == 5 and packet[IP].len == 40 + len(PAYLOAD)
                and bytes(packet[TCP].payload) == PAYLOAD, f"Packet {number}: complete identical payload")
        require(float(packet.time) == 1700000000.0 + number - 1, f"Packet {number}: timestamp")
        log.append(f"Packet {number}: {expected[0]}:{expected[1]} -> {expected[2]}:{expected[3]}, "
                   f"HTTP GET /admin, {len(PAYLOAD)} payload bytes.\n")
    return report, packets


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
    require(not any(line.startswith("[DETECTION] ") for line in run.stderr.splitlines()), "Unexpected diagnostics")
    counts = [json.loads(line.removeprefix("[RULES] ")) for line in run.stdout.splitlines() if line.startswith("[RULES] ")]
    require(counts == [report.counts], "CLI Loader counters mismatch")
    summaries = [json.loads(line.removeprefix("[DETECTION SUMMARY] ")) for line in run.stdout.splitlines()
                 if line.startswith("[DETECTION SUMMARY] ")]
    require(summaries == [{"events_evaluated": 3, "events_skipped": 0, "candidate_rules": 3, "matches": 1,
                           "rule_evaluation_errors": 0, "rule_not_evaluable": 0, "detections_written": 1}],
            f"Unexpected Engine summary: {summaries}")
    events = read_jsonl(FOLDER / "result.jsonl")
    require(len(events) == 3, "CLI must retain all three packet events")
    for number, (event, expected) in enumerate(zip(events, CASES), 1):
        network, transport = event["normalized"]["network"], event["normalized"]["transport"]
        require(event["packet_id"] == number and event["timestamp"] == 1700000000.0 + number - 1,
                f"Event {number}: identity/timestamp")
        require((network["src_ip"], transport["src_port"], network["dst_ip"], transport["dst_port"]) == expected[:4]
                and network["protocol"] == "IPv4" and transport["protocol"] == "TCP", f"Event {number}: header")
        require(event["preprocess_status"] == "valid" and event["processing_action"] == "process"
                and event["flow_tracking_status"] == "tracked" and event["flow_id"], f"Event {number}: processing/flow")
        require(not event["parse_errors"] and not event["decode_errors"] and event["payload_length"] == len(PAYLOAD),
                f"Event {number}: errors/payload")
        require(event["normalized"]["application"]["protocol"] == "HTTP"
                and event["normalized"]["application"]["fields"]["path"] == "/admin", f"Event {number}: HTTP path")
    return events


def check_matches(log, rule, packets, events):
    repository = RuleRepository((rule,))
    records = []
    for event, packet, expected in zip(events, packets, CASES):
        number = event["packet_id"]
        # Normalized metadata comes from CLI; bytes come from the validated PCAP,
        # not decoded URI/body. Complete IPv4/TCP lengths were checked above.
        context = InspectionContext(timestamp=event["timestamp"], packet_id=number,
            normalized=event["normalized"], processing_action=event["processing_action"],
            payload=bytes(packet[TCP].payload), payload_status="available")
        candidate_sids = [candidate.sid for candidate in repository.candidates(context)]
        require(candidate_sids == [100701], f"Packet {number}: rule must reach Matcher through Indexer")
        before = context.to_dict()
        with patch("ids.detection.matcher.match_header", wraps=match_header) as header_spy, \
             patch("ids.detection.matcher.match_contents", wraps=match_contents) as content_spy:
            trace = Mock()
            trace.attach_mock(header_spy, "header")
            trace.attach_mock(content_spy, "content")
            result = match_rule(rule, context)
        expected_status, expected_content_calls = expected[4:]
        require(result.sid == 100701 and result.status == expected_status,
                f"Packet {number}: expected {expected_status}, got {result.to_dict()}")
        require(header_spy.call_count == 1, f"Packet {number}: header matcher must run exactly once")
        require(content_spy.call_count == expected_content_calls,
                f"Packet {number}: expected {expected_content_calls} content calls, got {content_spy.call_count}")
        call_order = [call[0] for call in trace.mock_calls]
        expected_order = ["header", "content"] if expected_content_calls else ["header"]
        require(call_order == expected_order, f"Packet {number}: wrong matcher call order {call_order}")
        require(not result.diagnostics, f"Packet {number}: unexpected matcher diagnostics")
        if expected_status == "NO_MATCH":
            require(result.reason_code == "header_no_match" and result.reason.startswith("header:")
                    and result.matched_info is None, f"Packet {number}: expected rejection at header stage")
        else:
            require(result.matched_info.to_dict() == MATCHED_INFO, "Expected header/direct and content admin at [5,10)")
        require(context.to_dict() == before and context.payload == PAYLOAD, f"Packet {number}: context/payload changed")
        records.append({"packet_id": number, "candidate_sids": candidate_sids,
                        "header_matcher_calls": header_spy.call_count, "content_matcher_calls": content_spy.call_count,
                        "matcher_calls": call_order, **result.to_dict()})
        log.append(f"Matcher: packet_id={number}, candidate_sids={candidate_sids}, status={result.status.value}, "
                   f"header_calls={header_spy.call_count}, content_calls={content_spy.call_count}, order={call_order}.\n")
    require(len(records) == 3 and [row["content_matcher_calls"] for row in records] == [0, 0, 1],
            "Expected content call counts 0, 0, 1")
    result_path = FOLDER / "result_matches.jsonl"
    result_path.write_text("".join(json.dumps(row, ensure_ascii=True, allow_nan=False) + "\n" for row in records),
                           encoding="utf-8")
    require(read_jsonl(result_path) == records, "Full-rule result JSONL roundtrip mismatch")


def check_detections(log, events):
    detections = read_jsonl(FOLDER / "result_detections.jsonl")
    require([(row["packet_id"], row["sid"]) for row in detections] == [(3, 100701)],
            "Expected exactly one detection for packet 3 and SID 100701")
    detection, event = detections[0], events[2]
    require((detection["src_ip"], detection["src_port"], detection["dst_ip"], detection["dst_port"])
            == CASES[2][:4], "Detection endpoints mismatch")
    require(detection["timestamp"] == event["timestamp"] and detection["flow_id"] == event["flow_id"],
            "Detection/event timestamp or flow ID mismatch")
    require(detection["protocol"] == "TCP" and detection["application_protocol"] == "HTTP"
            and detection["rev"] == 1 and detection["msg"] == "Header before content", "Detection metadata mismatch")
    require(detection["matched_info"] == MATCHED_INFO, "Detection evidence mismatch")
    log.append("Detection: packet_id=3, sid=100701; header/direct, content admin at [5,10), event metadata preserved.\n")


def run_checks(log):
    originals = {name: (FOLDER / name).read_bytes() for name in ("input.rules", "input.pcap")}
    log.append("T07: real CLI/full-rule/Header/Content matchers; wraps spies observe calls without replacing results.\n")
    log.append("Input is a synthetic PCAP, not live traffic. All packets contain the same raw admin payload.\n")
    report, packets = check_inputs(log)
    events = check_cli(log, report)
    check_matches(log, report.enabled_rules[0], packets, events)
    check_detections(log, events)
    for name, original in originals.items():
        require((FOLDER / name).read_bytes() == original, f"Test changed {name}")
    log.append("Inputs unchanged; events, full-rule results and detections read back as JSON.\n")
    log.append("PASS T07: 3 candidates; header failures skip content (calls 0,0), valid header calls content once; "
               "exactly 1 detection for packet 3.\n")


def main():
    log = []
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL T07: {type(error).__name__}: {error}\n")
        code = 1
    (FOLDER / "console.txt").write_text("".join(log), encoding="utf-8")
    print("".join(log), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

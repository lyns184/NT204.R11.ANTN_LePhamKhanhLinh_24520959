"""T10: absolute offset/depth windows on complete raw TCP payload bytes."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
AUXILIARY = ROOT / "output" / "t10_offset_depth"
sys.path.insert(0, str(ROOT))

from scapy.all import Ether, IP, PcapReader, TCP

from ids.detection.loader import load_rules
from ids.detection.matcher import match_rule
from ids.detection.models import InspectionContext
from ids.detection.repository import RuleRepository


# SID, message, expected offset/depth; expectations are not taken from Parser.
RULE_CASES = (
    (101001, "Unrestricted admin", None, None),
    (101002, "Admin after offset", 4, None),
    (101003, "Admin inside depth", None, 5),
    (101004, "Admin offset and depth", 4, 5),
)
# Case, exact raw payload, four expected statuses, original match start.
# These expectations are declared independently of the matching code.
CASES = (
    ("before_offset", b"admin1234", ("MATCH", "NO_MATCH", "MATCH", "NO_MATCH"), 0),
    ("exact_window", b"1234admin", ("MATCH", "MATCH", "NO_MATCH", "MATCH"), 4),
    ("past_window_end", b"12345admin", ("MATCH", "MATCH", "NO_MATCH", "NO_MATCH"), 5),
    ("crosses_window_start", b"123admin", ("MATCH", "NO_MATCH", "NO_MATCH", "NO_MATCH"), 3),
    ("different_last_byte", b"1234admiX", ("NO_MATCH", "NO_MATCH", "NO_MATCH", "NO_MATCH"), None),
    ("short_payload", b"1234adm", ("NO_MATCH", "NO_MATCH", "NO_MATCH", "NO_MATCH"), None),
)
EXPECTED_DETECTIONS = (
    (1, 101001), (1, 101003), (2, 101001), (2, 101002), (2, 101004),
    (3, 101001), (3, 101002), (4, 101001),
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def expected_info(start):
    return {
        "header": {"matched": True, "orientation": "direct"},
        "flow": None, "flags": None, "dsize": None,
        "contents": [{"index": 0, "buffer": "payload", "pattern_hex": "61646d696e",
                      "matched_hex": "61646d696e", "start": start, "end": start + 5, "nocase": False}],
    }


def check_inputs(log):
    report = load_rules([FOLDER / "input.rules"])
    require(report.counts == {
        "files_requested": 1, "files_loaded": 1, "files_disabled": 0, "files_duplicate": 0,
        "lines_read": 4, "rules_total": 4, "rules_enabled": 4, "rules_invalid": 0,
        "rules_unsupported": 0, "rules_disabled": 0, "rules_duplicate": 0,
    } and not report.diagnostics, "Expected four valid enabled rules")
    require([rule.sid for rule in report.enabled_rules] == [row[0] for row in RULE_CASES], "Rule SID order")
    for rule, (sid, message, offset, depth) in zip(report.enabled_rules, RULE_CASES):
        require(rule.sid == sid and rule.rev == 1 and rule.msg == message, f"SID {sid}: metadata")
        require(rule.header.to_dict() == {
            "action": "alert", "protocol": "tcp", "src_ip": None, "dst_ip": None,
            "src_port": {"start": None, "end": None}, "dst_port": {"start": 80, "end": 80}, "direction": "->",
        }, f"SID {sid}: header")
        require(len(rule.contents) == 1 and rule.contents[0].to_dict() == {
            "pattern_hex": "61646d696e", "nocase": False, "offset": offset, "depth": depth,
            "distance": None, "within": None,
        } and rule.contents[0].pattern == b"admin", f"SID {sid}: content/offset/depth")
        require(rule.flow is None and rule.flags is None and rule.dsize is None, "Unexpected extra conditions")
    with PcapReader(str(FOLDER / "input.pcap")) as reader:
        packets = list(reader)
    require(len(packets) == len(CASES) == 6, "Expected six PCAP packets")
    for number, (packet, case) in enumerate(zip(packets, CASES), 1):
        name, payload, statuses, start = case
        require(packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(TCP), f"Packet {number}: layers")
        require((packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
                == ("10.0.0.1", 12344 + number, "10.0.0.2", 80), f"Packet {number}: endpoints")
        require(packet[Ether].src == "02:00:00:00:00:01" and packet[Ether].dst == "02:00:00:00:00:02",
                f"Packet {number}: MAC addresses")
        require(str(packet[TCP].flags) == "PA" and packet[TCP].seq == 1001 and packet[TCP].ack == 2001,
                f"Packet {number}: flags/sequence/acknowledgment")
        require(packet[IP].ihl == packet[TCP].dataofs == 5 and packet[IP].len == 40 + len(payload)
                and bytes(packet[TCP].payload) == payload, f"Packet {number}: exact raw payload/length")
        require(float(packet.time) == 1700000000.0 + number - 1, f"Packet {number}: timestamp")
        if start is not None:
            require(payload[start:start + 5] == b"admin", f"Packet {number}: fixture match byte range")
        log.append(f"Packet {number}: {name}, raw payload={payload!r}, {len(payload)} bytes, expected={statuses}.\n")
    return report, packets


def check_cli(log, report):
    relative = FOLDER.relative_to(ROOT)
    AUXILIARY.mkdir(parents=True, exist_ok=True)
    for name in ("result.jsonl", "result_matches.jsonl", "result_detections.jsonl"):
        (FOLDER / name).unlink(missing_ok=True)
    command = [sys.executable, "-X", "utf8", "main.py", "--pcap", str(relative / "input.pcap"),
               "--rules", str(relative / "input.rules"), "--output", str(relative / "result.jsonl"),
               "--flow-output", str(AUXILIARY.relative_to(ROOT) / "flows.jsonl"),
               "--detection-output", str(relative / "result_detections.jsonl")]
    log.append("\nCLI: " + subprocess.list2cmdline(command) + "\n")
    run = subprocess.run(command, cwd=ROOT, capture_output=True, encoding="utf-8", timeout=30)
    log.append("\nCLI stdout:\n" + run.stdout + "\nCLI stderr:\n" + run.stderr + f"\nCLI exit code: {run.returncode}\n")
    require(run.returncode == 0, f"CLI failed: exit code {run.returncode}")
    require(not any(line.startswith("[DETECTION] ") for line in run.stderr.splitlines()), "Unexpected detection diagnostics")
    counts = [json.loads(line.removeprefix("[RULES] ")) for line in run.stdout.splitlines() if line.startswith("[RULES] ")]
    require(counts == [report.counts], "CLI Loader counters")
    metrics = [json.loads(line.removeprefix("[DETECTION SUMMARY] ")) for line in run.stdout.splitlines()
               if line.startswith("[DETECTION SUMMARY] ")]
    require(metrics == [{"events_evaluated": 6, "events_skipped": 0, "candidate_rules": 24, "matches": 8,
                         "rule_evaluation_errors": 0, "rule_not_evaluable": 0, "detections_written": 8}],
            f"Unexpected CLI metrics: {metrics}")
    events = read_jsonl(FOLDER / "result.jsonl")
    require(len(events) == 6, "CLI must retain all six packet events")
    for number, (event, case) in enumerate(zip(events, CASES), 1):
        payload = case[1]
        network, transport = event["normalized"]["network"], event["normalized"]["transport"]
        require(event["packet_id"] == number and event["timestamp"] == 1700000000.0 + number - 1,
                f"Event {number}: identity/timestamp")
        require((network["src_ip"], transport["src_port"], network["dst_ip"], transport["dst_port"])
                == ("10.0.0.1", 12344 + number, "10.0.0.2", 80)
                and network["protocol"] == "IPv4" and transport["protocol"] == "TCP", f"Event {number}: header")
        require(event["preprocess_status"] == "valid" and event["processing_action"] == "process"
                and event["flow_tracking_status"] == "tracked" and event["flow_id"]
                and not event["parse_errors"] and not event["decode_errors"], f"Event {number}: processing/errors")
        require(event["payload_length"] == len(payload), f"Event {number}: payload length")
        require(event["normalized"]["application"]["protocol"] == "UNKNOWN"
                and event["decode_status"] == "not_processed", f"Event {number}: raw TCP payload needs no text decoding")
    return events


def check_matches(log, rules, packets, events):
    repository = RuleRepository(rules)
    records = []
    for event, packet, (name, payload, statuses, start) in zip(events, packets, CASES):
        number = event["packet_id"]
        # These bytes are the verified complete PCAP payload, not decoded text.
        context = InspectionContext(timestamp=event["timestamp"], packet_id=number,
            normalized=event["normalized"], processing_action=event["processing_action"],
            payload=bytes(packet[TCP].payload), payload_status="available")
        candidates = [rule.sid for rule in repository.candidates(context)]
        require(candidates == [101001, 101002, 101003, 101004], f"Packet {number}: candidate rules")
        before = context.to_dict()
        for rule, status, (_, _, offset, depth) in zip(rules, statuses, RULE_CASES):
            result = match_rule(rule, context)
            require(result.sid == rule.sid and result.status == status,
                    f"Packet {number}, SID {rule.sid}: expected {status}, got {result.to_dict()}")
            require(not result.diagnostics, f"Packet {number}, SID {rule.sid}: unexpected diagnostics")
            if status == "MATCH":
                require(result.matched_info.to_dict() == expected_info(start),
                        f"Packet {number}, SID {rule.sid}: wrong original bytes/absolute byte range")
            else:
                require(result.reason_code == "content_no_match" and result.reason.startswith("content:")
                        and result.matched_info is None, f"Packet {number}, SID {rule.sid}: content rejection")
            require(context.to_dict() == before and context.payload == payload, "Matcher changed context/raw bytes")
            records.append({"packet_id": number, "case": name, "candidate_sids": candidates,
                            "payload_source": "pcap_tcp_payload", "offset": offset, "depth": depth, **result.to_dict()})
            log.append(f"Matcher: packet_id={number}, case={name}, sid={rule.sid}, offset={offset}, "
                       f"depth={depth}, status={result.status.value}.\n")
    require(len(records) == 24 and sum(row["status"] == "MATCH" for row in records) == 8
            and sum(row["status"] == "NO_MATCH" for row in records) == 16,
            "Expected 24 full-rule results: 8 MATCH and 16 NO_MATCH")
    path = FOLDER / "result_matches.jsonl"
    path.write_text("".join(json.dumps(row, ensure_ascii=True, allow_nan=False) + "\n" for row in records), encoding="utf-8")
    require(read_jsonl(path) == records, "Full-rule JSONL roundtrip")
    return records


def check_detections(log, rules, events, records):
    detections = read_jsonl(FOLDER / "result_detections.jsonl")
    require([(d["packet_id"], d["sid"]) for d in detections] == list(EXPECTED_DETECTIONS),
            "Expected exactly eight detections for the independently declared packet/SID pairs")
    messages = {rule.sid: rule.msg for rule in rules}
    for detection in detections:
        number, sid = detection["packet_id"], detection["sid"]
        event = events[number - 1]
        require((detection["src_ip"], detection["src_port"], detection["dst_ip"], detection["dst_port"])
                == ("10.0.0.1", 12344 + number, "10.0.0.2", 80), "Detection endpoints")
        require(detection["timestamp"] == event["timestamp"] and detection["flow_id"] == event["flow_id"],
                "Detection/event correlation")
        require(detection["protocol"] == "TCP" and detection["application_protocol"] == "UNKNOWN"
                and detection["rev"] == 1 and detection["msg"] == messages[sid], "Detection metadata")
        record = next(row for row in records if row["packet_id"] == number and row["sid"] == sid)
        require(detection["matched_info"] == record["matched_info"], "CLI and API match evidence differ")
        require(detection["matched_info"] == expected_info(CASES[number - 1][3]), "Detection byte evidence")
        content = detection["matched_info"]["contents"][0]
        log.append(f"Detection: packet_id={number}, sid={sid}, matched_hex={content['matched_hex']}, "
                   f"range=[{content['start']},{content['end']}).\n")


def run_checks(log):
    originals = {name: (FOLDER / name).read_bytes() for name in ("input.rules", "input.pcap")}
    log.append("T10: real Loader/CLI/full-rule offset/depth matching; synthetic PCAP, no live traffic.\n")
    report, packets = check_inputs(log)
    events = check_cli(log, report)
    records = check_matches(log, report.enabled_rules, packets, events)
    check_detections(log, report.enabled_rules, events, records)
    for name, original in originals.items():
        require((FOLDER / name).read_bytes() == original, f"Test changed {name}")
    log.append("Inputs/raw payloads unchanged; event/match/detection JSONL read back successfully.\n")
    log.append("PASS T10: 6 events, 24 rule results (8 MATCH/16 NO_MATCH), 8 detections; "
               "offset is a minimum search position, depth starts at offset, whole pattern must fit.\n")


def main():
    log = []
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL T10: {type(error).__name__}: {error}\n")
        code = 1
    (FOLDER / "console.txt").write_text("".join(log), encoding="utf-8")
    print("".join(log), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

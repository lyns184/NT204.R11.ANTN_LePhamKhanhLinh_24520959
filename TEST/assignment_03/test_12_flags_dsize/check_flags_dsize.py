"""T12: exact TCP flags and raw payload byte count, including UTF-8 and empty payload."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
AUXILIARY = ROOT / "output" / "t12_flags_dsize"
sys.path.insert(0, str(ROOT))

from scapy.all import Ether, IP, PcapReader, TCP

from ids.detection.loader import load_rules
from ids.detection.matcher import match_rule
from ids.detection.models import InspectionContext
from ids.detection.repository import RuleRepository


# SID, message, exact flags (None means no condition), dsize operator, value.
RULE_CASES = (
    (101201, "SYN without payload", "S", "=", 0),
    (101202, "SYN ACK without payload", "SA", "=", 0),
    (101203, "PSH ACK five payload bytes", "PA", "=", 5),
    (101204, "Payload smaller than five bytes", None, "<", 5),
    (101205, "Payload larger than five bytes", None, ">", 5),
    (101206, "No flags and no payload", "0", "=", 0),
)
F = "flags_no_match"
D = "dsize_no_match"
# Case, observed flags, complete raw payload, six expected rejection codes.
# None means MATCH; expected results are declared independently of Matcher.
CASES = (
    ("syn_empty", "S", b"", (None, F, F, None, D, F)),
    ("syn_ack_empty", "SA", b"", (F, None, F, None, D, F)),
    ("below_size", "PA", b"1234", (F, F, D, None, D, F)),
    ("equal_size", "PA", b"12345", (F, F, None, D, D, F)),
    ("above_size", "PA", b"123456", (F, F, D, D, None, F)),
    ("right_size_wrong_flags", "A", b"12345", (F, F, F, D, D, F)),
    ("right_syn_flags_wrong_size", "S", b"12345", (D, F, F, D, D, F)),
    ("zero_flags_empty", "", b"", (F, F, F, None, D, None)),
    ("utf8_five_bytes_four_characters", "PA", b"\xc3\xa9ABC", (F, F, None, D, D, F)),
)
EXPECTED_DETECTIONS = (
    (1, 101201), (1, 101204), (2, 101202), (2, 101204), (3, 101204),
    (4, 101203), (5, 101205), (8, 101204), (8, 101206), (9, 101203),
)
FLAG_NAMES = (
    ("F", "FIN"), ("S", "SYN"), ("R", "RST"), ("P", "PSH"), ("A", "ACK"),
    ("U", "URG"), ("E", "ECE"), ("C", "CWR"), ("N", "NS"),
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def expected_info(rule_index, payload_size):
    _, _, flags, operator, value = RULE_CASES[rule_index]
    expression = ("" if operator == "=" else operator) + str(value)
    return {
        "header": {"matched": True, "orientation": "direct"}, "flow": None,
        "flags": None if flags is None else {"expression": flags, "actual": flags},
        "dsize": {"expression": expression, "actual": payload_size}, "contents": [],
    }


def check_inputs(log):
    report = load_rules([FOLDER / "input.rules"])
    require(report.counts == {
        "files_requested": 1, "files_loaded": 1, "files_disabled": 0, "files_duplicate": 0,
        "lines_read": 6, "rules_total": 6, "rules_enabled": 6, "rules_invalid": 0,
        "rules_unsupported": 0, "rules_disabled": 0, "rules_duplicate": 0,
    } and not report.diagnostics, "Expected six valid enabled rules")
    require([rule.sid for rule in report.enabled_rules] == [101201, 101202, 101203, 101204, 101205, 101206],
            "Rule SID order")
    for rule, (sid, message, flags, operator, value) in zip(report.enabled_rules, RULE_CASES):
        require(rule.sid == sid and rule.rev == 1 and rule.msg == message, f"SID {sid}: metadata")
        require(rule.header.to_dict() == {
            "action": "alert", "protocol": "tcp", "src_ip": None, "dst_ip": None,
            "src_port": {"start": None, "end": None}, "dst_port": {"start": 80, "end": 80}, "direction": "->",
        }, f"SID {sid}: header")
        if flags is None:
            require(rule.flags is None, f"SID {sid}: no flags condition")
        else:
            require(rule.flags is not None and rule.flags.flags == frozenset("" if flags == "0" else flags),
                    f"SID {sid}: exact flags/zero flags")
        require(rule.dsize is not None and rule.dsize.to_dict() == {"operator": operator, "value": value},
                f"SID {sid}: dsize operator/value")
        require(not rule.contents and rule.flow is None, "Unexpected content/flow condition")
    with PcapReader(str(FOLDER / "input.pcap")) as reader:
        packets = list(reader)
    require(len(packets) == len(CASES) == 9, "Expected nine PCAP packets")
    for number, (packet, (name, flags, payload, reasons)) in enumerate(zip(packets, CASES), 1):
        require(packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(TCP), f"Packet {number}: layers")
        require((packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
                == ("10.0.0.1", 12344 + number, "10.0.0.2", 80), f"Packet {number}: endpoints")
        require(packet[Ether].src == "02:00:00:00:00:01" and packet[Ether].dst == "02:00:00:00:00:02",
                f"Packet {number}: MAC addresses")
        require(str(packet[TCP].flags) == flags and packet[TCP].seq == 1001 and packet[TCP].ack == 2001,
                f"Packet {number}: flags/sequence/acknowledgment")
        require(packet[IP].ihl == packet[TCP].dataofs == 5 and packet[IP].len == 40 + len(payload)
                and bytes(packet[TCP].payload) == payload, f"Packet {number}: exact raw payload/length")
        require(float(packet.time) == 1700000000.0 + number - 1, f"Packet {number}: timestamp")
        require(len(reasons) == 6, f"Packet {number}: six independent expectations")
        log.append(f"Packet {number}: {name}, flags={flags or '0'}, raw payload={payload!r}, "
                   f"{len(payload)} bytes, expected rejection codes={reasons}.\n")
    require(CASES[8][2].decode("utf-8") == "\u00e9ABC" and len(CASES[8][2]) == 5
            and len(CASES[8][2].decode("utf-8")) == 4, "UTF-8 fixture must have five bytes but four characters")
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
    require(metrics == [{"events_evaluated": 9, "events_skipped": 0, "candidate_rules": 54, "matches": 10,
                         "rule_evaluation_errors": 0, "rule_not_evaluable": 0, "detections_written": 10}],
            f"Unexpected CLI metrics: {metrics}")
    events = read_jsonl(FOLDER / "result.jsonl")
    require(len(events) == 9, "CLI must retain all nine packet events")
    for number, (event, (_, flags, payload, _)) in enumerate(zip(events, CASES), 1):
        network, transport = event["normalized"]["network"], event["normalized"]["transport"]
        require(event["packet_id"] == number and event["timestamp"] == 1700000000.0 + number - 1,
                f"Event {number}: identity/timestamp")
        require((network["src_ip"], transport["src_port"], network["dst_ip"], transport["dst_port"])
                == ("10.0.0.1", 12344 + number, "10.0.0.2", 80)
                and network["protocol"] == "IPv4" and transport["protocol"] == "TCP", f"Event {number}: header")
        require(transport["flags"] == flags
                and transport["flags_detail"] == {name: letter in flags for letter, name in FLAG_NAMES},
                f"Event {number}: complete flag bits, including known zero flags")
        require(event["preprocess_status"] == "valid" and event["processing_action"] == "process"
                and event["flow_tracking_status"] == "tracked" and event["flow_id"]
                and not event["parse_errors"] and not event["decode_errors"], f"Event {number}: processing/errors")
        require(event["payload_length"] == transport["payload_length"] == len(payload)
                and network["total_length"] == 40 + len(payload), f"Event {number}: payload length excludes headers")
        require(event["normalized"]["application"]["protocol"] == "UNKNOWN"
                and event["decode_status"] == "not_processed", f"Event {number}: payload needs no text decoding")
    return events


def check_matches(log, rules, packets, events):
    repository = RuleRepository(rules)
    records = []
    for event, packet, (name, flags, payload, reasons) in zip(events, packets, CASES):
        number = event["packet_id"]
        context = InspectionContext(timestamp=event["timestamp"], packet_id=number,
            normalized=event["normalized"], processing_action=event["processing_action"],
            payload=bytes(packet[TCP].payload), payload_status="available")
        candidates = [rule.sid for rule in repository.candidates(context)]
        require(candidates == [101201, 101202, 101203, 101204, 101205, 101206], f"Packet {number}: candidate rules")
        before = context.to_dict()
        for index, (rule, reason) in enumerate(zip(rules, reasons)):
            status = "MATCH" if reason is None else "NO_MATCH"
            result = match_rule(rule, context)
            require(result.sid == rule.sid and result.status == status,
                    f"Packet {number}, SID {rule.sid}: expected {status}, got {result.to_dict()}")
            require(not result.diagnostics, f"Packet {number}, SID {rule.sid}: unexpected diagnostics")
            if status == "MATCH":
                require(result.matched_info.to_dict() == expected_info(index, len(payload)),
                        f"Packet {number}, SID {rule.sid}: wrong flags/dsize evidence")
            else:
                stage = "flags:" if reason == F else "dsize:"
                require(result.reason_code == reason and result.reason.startswith(stage) and result.matched_info is None,
                        f"Packet {number}, SID {rule.sid}: wrong rejection stage/partial evidence")
            require(context.to_dict() == before and context.payload == payload, "Matcher changed context/raw bytes")
            records.append({"packet_id": number, "case": name, "candidate_sids": candidates,
                            "payload_source": "pcap_tcp_payload", "observed_flags": flags or "0",
                            "payload_length": len(payload), **result.to_dict()})
            log.append(f"Matcher: packet_id={number}, case={name}, sid={rule.sid}, "
                       f"status={result.status.value}, reason_code={result.reason_code}.\n")
    require(len(records) == 54 and sum(row["status"] == "MATCH" for row in records) == 10
            and sum(row["status"] == "NO_MATCH" for row in records) == 44,
            "Expected 54 full-rule results: 10 MATCH and 44 NO_MATCH")
    path = FOLDER / "result_matches.jsonl"
    path.write_text("".join(json.dumps(row, ensure_ascii=True, allow_nan=False) + "\n" for row in records), encoding="utf-8")
    require(read_jsonl(path) == records, "Full-rule JSONL roundtrip")
    return records


def check_detections(log, rules, events, records):
    detections = read_jsonl(FOLDER / "result_detections.jsonl")
    require([(d["packet_id"], d["sid"]) for d in detections] == list(EXPECTED_DETECTIONS),
            "Expected exactly ten detections; none for packets 6/7, UTF-8 packet 9 must alert")
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
        index = [row[0] for row in RULE_CASES].index(sid)
        require(detection["matched_info"] == expected_info(index, len(CASES[number - 1][2])), "Detection packet evidence")
        info = detection["matched_info"]
        log.append(f"Detection: packet_id={number}, sid={sid}, flags={info['flags']}, dsize={info['dsize']}.\n")


def run_checks(log):
    originals = {name: (FOLDER / name).read_bytes() for name in ("input.rules", "input.pcap")}
    log.append("T12: real Loader/CLI/full-rule flags/dsize matching; synthetic PCAP, no live traffic.\n")
    report, packets = check_inputs(log)
    events = check_cli(log, report)
    records = check_matches(log, report.enabled_rules, packets, events)
    check_detections(log, report.enabled_rules, events, records)
    for name, original in originals.items():
        require((FOLDER / name).read_bytes() == original, f"Test changed {name}")
    log.append("Inputs/raw payloads unchanged; event/match/detection JSONL read back successfully.\n")
    log.append("PASS T12: 9 events, 54 rule results (10 MATCH/44 NO_MATCH), 10 detections; exact flags, "
               "strict dsize boundaries, complete empty payload, UTF-8 counted as five bytes not four characters.\n")


def main():
    log = []
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL T12: {type(error).__name__}: {error}\n")
        code = 1
    (FOLDER / "console.txt").write_text("".join(log), encoding="utf-8")
    print("".join(log), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

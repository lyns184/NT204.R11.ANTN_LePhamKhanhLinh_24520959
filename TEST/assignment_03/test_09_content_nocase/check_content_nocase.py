"""T09: case-sensitive/nocase content uses raw bytes and preserves match evidence."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
AUXILIARY = ROOT / "output" / "t09_content_nocase"
sys.path.insert(0, str(ROOT))

from scapy.all import Ether, IP, PcapReader, TCP

from ids.detection.loader import load_rules
from ids.detection.matcher import match_rule
from ids.detection.models import InspectionContext
from ids.detection.repository import RuleRepository


# case, raw payload, HTTP path (None means binary), expected statuses for two
# rules, expected match start, expected original matched bytes.
CASES = (
    ("lowercase", b"GET /admin HTTP/1.1\r\nHost: ids.test\r\n\r\n", "/admin",
     ("MATCH", "MATCH"), 5, b"admin"),
    ("uppercase", b"GET /ADMIN HTTP/1.1\r\nHost: ids.test\r\n\r\n", "/ADMIN",
     ("NO_MATCH", "MATCH"), 5, b"ADMIN"),
    ("mixed_case", b"GET /AdMiN HTTP/1.1\r\nHost: ids.test\r\n\r\n", "/AdMiN",
     ("NO_MATCH", "MATCH"), 5, b"AdMiN"),
    ("absent", b"GET /public HTTP/1.1\r\nHost: ids.test\r\n\r\n", "/public",
     ("NO_MATCH", "NO_MATCH"), None, None),
    ("percent_encoded", b"GET /%61dmin HTTP/1.1\r\nHost: ids.test\r\n\r\n", "/%61dmin",
     ("NO_MATCH", "NO_MATCH"), None, None),
    ("binary", b"\x00AdMiN\xff", None, ("NO_MATCH", "MATCH"), 1, b"AdMiN"),
)
EXPECTED_DETECTIONS = ((1, 100901), (1, 100902), (2, 100902), (3, 100902), (6, 100902))


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def expected_info(nocase, start, matched):
    return {
        "header": {"matched": True, "orientation": "direct"}, "flow": None, "flags": None, "dsize": None,
        "contents": [{"index": 0, "buffer": "payload", "pattern_hex": "61646d696e",
                      "matched_hex": matched.hex(), "start": start, "end": start + 5, "nocase": nocase}],
    }


def check_inputs(log):
    report = load_rules([FOLDER / "input.rules"])
    require(report.counts == {
        "files_requested": 1, "files_loaded": 1, "files_disabled": 0, "files_duplicate": 0,
        "lines_read": 2, "rules_total": 2, "rules_enabled": 2, "rules_invalid": 0,
        "rules_unsupported": 0, "rules_disabled": 0, "rules_duplicate": 0,
    } and not report.diagnostics, "Expected two valid enabled rules")
    require([rule.sid for rule in report.enabled_rules] == [100901, 100902], "Rule SID order")
    for rule, nocase, message in zip(report.enabled_rules, (False, True),
                                     ("Case sensitive admin", "Case insensitive admin")):
        require(rule.rev == 1 and rule.msg == message, f"SID {rule.sid}: metadata")
        require(rule.header.to_dict() == {
            "action": "alert", "protocol": "tcp", "src_ip": None, "dst_ip": None,
            "src_port": {"start": None, "end": None}, "dst_port": {"start": 80, "end": 80}, "direction": "->",
        }, f"SID {rule.sid}: header")
        require(len(rule.contents) == 1 and rule.contents[0].to_dict() == {
            "pattern_hex": "61646d696e", "nocase": nocase, "offset": None, "depth": None,
            "distance": None, "within": None,
        } and rule.contents[0].pattern == b"admin", f"SID {rule.sid}: content/nocase")
        require(rule.flow is None and rule.flags is None and rule.dsize is None, "Unexpected extra conditions")
    with PcapReader(str(FOLDER / "input.pcap")) as reader:
        packets = list(reader)
    require(len(packets) == len(CASES) == 6, "Expected six PCAP packets")
    for number, (packet, case) in enumerate(zip(packets, CASES), 1):
        name, payload, path, statuses, start, matched = case
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
            require(payload[start:start + 5] == matched, f"Packet {number}: fixture match byte range")
        log.append(f"Packet {number}: {name}, payload={len(payload)} bytes, HTTP path={path!r}, expected={statuses}.\n")
    require(b"admin" not in CASES[4][1] and b"%61dmin" in CASES[4][1], "Encoded fixture must not contain literal admin")
    try:
        CASES[5][1].decode("utf-8")
    except UnicodeDecodeError:
        log.append("Binary fixture contains invalid UTF-8; matching must use bytes directly.\n")
    else:
        raise AssertionError("Expected invalid UTF-8 in binary fixture")
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
    require(metrics == [{"events_evaluated": 6, "events_skipped": 0, "candidate_rules": 12, "matches": 5,
                         "rule_evaluation_errors": 0, "rule_not_evaluable": 0, "detections_written": 5}],
            f"Unexpected CLI metrics: {metrics}")
    events = read_jsonl(FOLDER / "result.jsonl")
    require(len(events) == 6, "CLI must retain all six packet events")
    for number, (event, case) in enumerate(zip(events, CASES), 1):
        name, payload, path, _, _, _ = case
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
        application = event["normalized"]["application"]
        if path is not None:
            require(application["protocol"] == "HTTP" and application["fields"]["path"] == path,
                    f"Event {number}: raw HTTP path must be preserved")
        else:
            require(application["protocol"] == "UNKNOWN" and event["decode_status"] == "not_processed",
                    "Binary payload is not text HTTP and must not require text decoding")
    require(events[4]["decoded"]["http"]["uri"]["value"] == "/admin", "Encoded URI must decode to /admin separately")
    require(events[4]["normalized"]["application"]["fields"]["path"] == "/%61dmin", "Normalized URI must remain raw")
    log.append("CLI packet 5 has decoded URI /admin but raw URI /%61dmin; packet 6 remains UNKNOWN/process.\n")
    return events


def check_matches(log, rules, packets, events):
    repository = RuleRepository(rules)
    records = []
    for event, packet, case in zip(events, packets, CASES):
        name, payload, _, statuses, start, matched = case
        number = event["packet_id"]
        # Raw bytes come from the verified complete PCAP payload, not decoded URI.
        context = InspectionContext(timestamp=event["timestamp"], packet_id=number,
            normalized=event["normalized"], processing_action=event["processing_action"],
            payload=bytes(packet[TCP].payload), payload_status="available")
        candidates = [rule.sid for rule in repository.candidates(context)]
        require(candidates == [100901, 100902], f"Packet {number}: candidate rules")
        before = context.to_dict()
        for rule, status, nocase in zip(rules, statuses, (False, True)):
            result = match_rule(rule, context)
            require(result.sid == rule.sid and result.status == status,
                    f"Packet {number}, SID {rule.sid}: expected {status}, got {result.to_dict()}")
            require(not result.diagnostics, f"Packet {number}, SID {rule.sid}: unexpected diagnostics")
            if status == "MATCH":
                require(result.matched_info.to_dict() == expected_info(nocase, start, matched),
                        f"Packet {number}, SID {rule.sid}: wrong byte range/original matched bytes/nocase evidence")
            else:
                require(result.reason_code == "content_no_match" and result.reason.startswith("content:")
                        and result.matched_info is None, f"Packet {number}, SID {rule.sid}: content rejection")
            require(context.to_dict() == before and context.payload == payload, "Matcher changed context/raw bytes")
            records.append({"packet_id": number, "case": name, "candidate_sids": candidates,
                            "payload_source": "pcap_tcp_payload", "nocase": nocase, **result.to_dict()})
            log.append(f"Matcher: packet_id={number}, case={name}, sid={rule.sid}, nocase={nocase}, "
                       f"status={result.status.value}.\n")
    require(len(records) == 12 and sum(row["status"] == "MATCH" for row in records) == 5,
            "Expected 12 full-rule results: 5 MATCH and 7 NO_MATCH")
    path = FOLDER / "result_matches.jsonl"
    path.write_text("".join(json.dumps(row, ensure_ascii=True, allow_nan=False) + "\n" for row in records), encoding="utf-8")
    require(read_jsonl(path) == records, "Full-rule JSONL roundtrip")
    return records


def check_detections(log, rules, events, records):
    detections = read_jsonl(FOLDER / "result_detections.jsonl")
    require([(d["packet_id"], d["sid"]) for d in detections] == list(EXPECTED_DETECTIONS),
            "Expected exactly 5 detections, including binary packet 6; no encoded/absent payload alerts")
    messages = {rule.sid: rule.msg for rule in rules}
    for detection in detections:
        number, sid = detection["packet_id"], detection["sid"]
        event = events[number - 1]
        require((detection["src_ip"], detection["src_port"], detection["dst_ip"], detection["dst_port"])
                == ("10.0.0.1", 12344 + number, "10.0.0.2", 80), "Detection endpoints")
        require(detection["timestamp"] == event["timestamp"] and detection["flow_id"] == event["flow_id"],
                "Detection/event correlation")
        require(detection["protocol"] == "TCP" and detection["application_protocol"] == ("UNKNOWN" if number == 6 else "HTTP")
                and detection["rev"] == 1 and detection["msg"] == messages[sid], "Detection metadata")
        record = next(row for row in records if row["packet_id"] == number and row["sid"] == sid)
        require(detection["matched_info"] == record["matched_info"], "CLI and API match evidence differ")
        content = detection["matched_info"]["contents"][0]
        log.append(f"Detection: packet_id={number}, sid={sid}, matched_hex={content['matched_hex']}, "
                   f"range=[{content['start']},{content['end']}), nocase={content['nocase']}.\n")


def run_checks(log):
    originals = {name: (FOLDER / name).read_bytes() for name in ("input.rules", "input.pcap")}
    log.append("T09: real Loader/CLI/full-rule content matching; synthetic PCAP, no live traffic.\n")
    report, packets = check_inputs(log)
    events = check_cli(log, report)
    records = check_matches(log, report.enabled_rules, packets, events)
    check_detections(log, report.enabled_rules, events, records)
    for name, original in originals.items():
        require((FOLDER / name).read_bytes() == original, f"Test changed {name}")
    log.append("Inputs/raw payloads unchanged; event/match/detection JSONL read back successfully.\n")
    log.append("PASS T09: 6 events, 12 rule results (5 MATCH/7 NO_MATCH), 5 detections; nocase uses raw bytes "
               "and preserves case/byte offsets; percent-encoded URI does not match.\n")


def main():
    log = []
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL T09: {type(error).__name__}: {error}\n")
        code = 1
    (FOLDER / "console.txt").write_text("".join(log), encoding="utf-8")
    print("".join(log), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

"""T14: DetectionEvent schema/values, real CLI and one separate nullable-ID API case."""

import json
import math
import subprocess
import sys
from ipaddress import IPv4Address
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
AUXILIARY = ROOT / "output" / "t14_detection_schema"
sys.path.insert(0, str(ROOT))

from scapy.all import DNS, Ether, IP, PcapReader, TCP, UDP

from ids.detection.generator import generate_detection
from ids.detection.loader import load_rules
from ids.detection.matcher import match_rule
from ids.detection.models import InspectionContext
from ids.detection.repository import RuleRepository
from ids.output.jsonl_writer import JSONLWriter


# Expectations are fixed independently of models/Matcher/Generator output.
DETECTION_KEYS = frozenset((
    "timestamp", "packet_id", "sid", "rev", "msg", "classtype", "priority",
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "application_protocol", "flow_id", "matched_info",
))
RULE_CASES = (
    (101401, 2, "Phát hiện admin", "web-application-attack", 1, b"admin"),
    (101402, 1, "DNS marker", None, None, b"example"),
    (101403, 3, "Binary response", None, None, b"\x00\xffA"),
)
CASES = (
    {"name": "http_unicode_metadata", "protocol": "TCP", "application_protocol": "HTTP",
     "src_ip": "10.0.0.1", "src_port": 12345, "dst_ip": "10.0.0.2", "dst_port": 80,
     "payload": b"GET /admin HTTP/1.1\r\nHost: ids.test\r\n\r\n", "candidates": (101401, 101402), "matched_sid": 101401},
    {"name": "udp_matched_by_ip_rule", "protocol": "UDP", "application_protocol": "DNS",
     "src_ip": "10.0.0.3", "src_port": 53000, "dst_ip": "10.0.0.2", "dst_port": 53,
     "payload": bytes.fromhex("140201000001000000000000076578616d706c6504746573740000010001"),
     "candidates": (101402,), "matched_sid": 101402},
    {"name": "reverse_binary", "protocol": "TCP", "application_protocol": "UNKNOWN",
     "src_ip": "10.0.0.2", "src_port": 8080, "dst_ip": "10.0.0.1", "dst_port": 12345,
     "payload": b"\x00\xffA", "candidates": (101402, 101403), "matched_sid": 101403},
    {"name": "no_detection", "protocol": "TCP", "application_protocol": "HTTP",
     "src_ip": "10.0.0.1", "src_port": 12346, "dst_ip": "10.0.0.2", "dst_port": 80,
     "payload": b"GET /public HTTP/1.1\r\nHost: ids.test\r\n\r\n", "candidates": (101401, 101402), "matched_sid": None},
)
EXPECTED_DETECTIONS = ((1, 101401), (2, 101402), (3, 101403))
EVIDENCE = {101401: ("61646d696e", 5, 10), 101402: ("6578616d706c65", 13, 20), 101403: ("00ff41", 0, 3)}
MACS = {"10.0.0.1": "02:00:00:00:00:01", "10.0.0.2": "02:00:00:00:00:02", "10.0.0.3": "02:00:00:00:00:03"}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"Non-finite JSON number: {value}")


def read_jsonl(path):
    raw = path.read_bytes()
    require(raw.endswith(b"\n"), f"{path.name}: JSONL must end with a newline")
    rows = [json.loads(line, object_pairs_hook=unique_object, parse_constant=reject_constant)
            for line in raw.decode("utf-8").splitlines()]
    require(all(type(row) is dict for row in rows), f"{path.name}: each line must be one JSON object")
    return rows


def expected_info(sid):
    pattern, start, end = EVIDENCE[sid]
    return {"header": {"matched": True, "orientation": "reverse" if sid == 101403 else "direct"},
            "flow": None, "flags": None, "dsize": None,
            "contents": [{"index": 0, "buffer": "payload", "pattern_hex": pattern, "matched_hex": pattern,
                          "start": start, "end": end, "nocase": False}]}


def expected_detection(number, sid, flow_id, packet_id):
    case = CASES[number - 1]
    _, rev, msg, classtype, priority, _ = next(row for row in RULE_CASES if row[0] == sid)
    return {"timestamp": 1700000000.0 + number - 1, "packet_id": packet_id, "sid": sid, "rev": rev,
            "msg": msg, "classtype": classtype, "priority": priority,
            **{key: case[key] for key in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "application_protocol")},
            "flow_id": flow_id, "matched_info": expected_info(sid)}


def check_schema(row, label):
    require(type(row) is dict and set(row) == DETECTION_KEYS and len(row) == 15, f"{label}: exact 15 detection keys")
    require(type(row["timestamp"]) in (int, float) and math.isfinite(row["timestamp"]), f"{label}: timestamp type")
    for key in ("sid", "rev"):
        require(type(row[key]) is int and row[key] > 0, f"{label}: {key} must be an integer, not bool/text")
    for key in ("packet_id", "priority"):
        require(row[key] is None or (type(row[key]) is int and row[key] > 0), f"{label}: nullable {key} type")
    require(type(row["msg"]) is str and bool(row["msg"]), f"{label}: message type")
    for key in ("classtype", "application_protocol", "flow_id"):
        require(row[key] is None or (type(row[key]) is str and bool(row[key])), f"{label}: nullable {key} type")
    for key in ("src_ip", "dst_ip"):
        require(row[key] is None or (type(row[key]) is str and str(IPv4Address(row[key])) == row[key]),
                f"{label}: canonical IPv4 {key}")
    for key in ("src_port", "dst_port"):
        require(row[key] is None or (type(row[key]) is int and 0 <= row[key] <= 65535), f"{label}: nullable port type")
    require(row["protocol"] is None or row["protocol"] in ("TCP", "UDP"), f"{label}: actual transport protocol")
    info = row["matched_info"]
    require(type(info) is dict and set(info) == {"header", "flow", "flags", "dsize", "contents"}, f"{label}: matched_info schema")
    header = info["header"]
    require(type(header) is dict and set(header) == {"matched", "orientation"} and header["matched"] is True
            and header["orientation"] in ("direct", "reverse"), f"{label}: header evidence")
    require(info["flow"] is info["flags"] is info["dsize"] is None, f"{label}: undeclared conditions must be null")
    require(type(info["contents"]) is list and len(info["contents"]) == 1, f"{label}: one content evidence")
    content = info["contents"][0]
    require(type(content) is dict and set(content) == {"index", "buffer", "pattern_hex", "matched_hex", "start", "end", "nocase"},
            f"{label}: content evidence schema; raw payload must not be exported")
    require(all(type(content[key]) is int for key in ("index", "start", "end")) and content["index"] == 0
            and 0 <= content["start"] < content["end"], f"{label}: byte range/index types")
    require(content["buffer"] == "payload" and content["nocase"] is False, f"{label}: buffer/nocase")
    for key in ("pattern_hex", "matched_hex"):
        require(type(content[key]) is str and bytes.fromhex(content[key]).hex() == content[key], f"{label}: canonical hex evidence")
    require(content["pattern_hex"] == content["matched_hex"]
            and len(bytes.fromhex(content["matched_hex"])) == content["end"] - content["start"], f"{label}: evidence length/bytes")


def check_inputs(log):
    report = load_rules([FOLDER / "input.rules"])
    require(report.counts == {
        "files_requested": 1, "files_loaded": 1, "files_disabled": 0, "files_duplicate": 0,
        "lines_read": 3, "rules_total": 3, "rules_enabled": 3, "rules_invalid": 0,
        "rules_unsupported": 0, "rules_disabled": 0, "rules_duplicate": 0,
    } and not report.diagnostics, "Expected three valid enabled rules")
    require([rule.sid for rule in report.enabled_rules] == [101401, 101402, 101403], "Rule SID order")
    headers = (
        ("tcp", "10.0.0.1/32", None, None, "->", "10.0.0.2/32", 80, 80),
        ("ip", None, None, None, "->", None, None, None),
        ("tcp", "10.0.0.1/32", 12345, 12345, "<>", "10.0.0.2/32", 8080, 8080),
    )
    for rule, definition, header in zip(report.enabled_rules, RULE_CASES, headers):
        sid, rev, msg, classtype, priority, pattern = definition
        require((rule.sid, rule.rev, rule.msg, rule.classtype, rule.priority) == (sid, rev, msg, classtype, priority),
                f"SID {sid}: explicit/nullable metadata")
        protocol, src, low_src, high_src, direction, dst, low_dst, high_dst = header
        require(rule.header.to_dict() == {"action": "alert", "protocol": protocol, "src_ip": src, "dst_ip": dst,
            "src_port": {"start": low_src, "end": high_src}, "dst_port": {"start": low_dst, "end": high_dst}, "direction": direction},
            f"SID {sid}: header")
        require(len(rule.contents) == 1 and rule.contents[0].pattern == pattern and rule.contents[0].to_dict() == {
            "pattern_hex": pattern.hex(), "nocase": False, "offset": None, "depth": None, "distance": None, "within": None,
        } and rule.flow is rule.flags is rule.dsize is None, f"SID {sid}: content-only condition")
    with PcapReader(str(FOLDER / "input.pcap")) as reader:
        packets = list(reader)
    require(len(packets) == len(CASES) == 4, "Expected four PCAP packets")
    for number, (packet, case) in enumerate(zip(packets, CASES), 1):
        layer = TCP if case["protocol"] == "TCP" else UDP
        require(packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(layer), f"Packet {number}: layers")
        require((packet[IP].src, packet[layer].sport, packet[IP].dst, packet[layer].dport)
                == tuple(case[key] for key in ("src_ip", "src_port", "dst_ip", "dst_port")), f"Packet {number}: actual endpoints")
        require(packet[Ether].src == MACS[case["src_ip"]] and packet[Ether].dst == MACS[case["dst_ip"]], f"Packet {number}: MACs")
        require(packet[IP].ihl == 5 and bytes(packet[layer].payload) == case["payload"]
                and packet[IP].len == len(case["payload"]) + (40 if layer is TCP else 28), f"Packet {number}: complete raw payload")
        if layer is TCP:
            require(packet[TCP].dataofs == 5 and str(packet[TCP].flags) == "PA"
                    and (packet[TCP].seq, packet[TCP].ack) == ((2001, 1001) if number == 3 else (1001, 2001)), f"Packet {number}: TCP fields")
        else:
            require(packet[UDP].len == 38 and packet.haslayer(DNS) and packet[DNS].id == 0x1402
                    and packet[DNS].qd[0].qname == b"example.test.", "Packet 2: DNS fixture")
        require(float(packet.time) == 1700000000.0 + number - 1, f"Packet {number}: timestamp")
        if case["matched_sid"] is not None:
            pattern, start, end = EVIDENCE[case["matched_sid"]]
            require(case["payload"][start:end].hex() == pattern, f"Packet {number}: independent evidence range")
        log.append(f"Packet {number}: {case['name']}, {case['protocol']}/{case['application_protocol']}, "
                   f"payload={len(case['payload'])} bytes, expected SID={case['matched_sid']}.\n")
    return report, packets


def check_cli(log, report):
    relative = FOLDER.relative_to(ROOT)
    AUXILIARY.mkdir(parents=True, exist_ok=True)
    for name in ("result.jsonl", "result_matches.jsonl", "result_detections.jsonl", "direct_detections.jsonl"):
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
    require(metrics == [{"events_evaluated": 4, "events_skipped": 0, "candidate_rules": 7, "matches": 3,
                         "rule_evaluation_errors": 0, "rule_not_evaluable": 0, "detections_written": 3}], f"CLI metrics: {metrics}")
    events = read_jsonl(FOLDER / "result.jsonl")
    require(len(events) == 4, "CLI must retain four events including no-match packet 4")
    for number, (event, case) in enumerate(zip(events, CASES), 1):
        network, transport, application = (event["normalized"][key] for key in ("network", "transport", "application"))
        require(event["packet_id"] == number and event["timestamp"] == 1700000000.0 + number - 1, f"Event {number}: identity")
        require((network["src_ip"], transport["src_port"], network["dst_ip"], transport["dst_port"])
                == tuple(case[key] for key in ("src_ip", "src_port", "dst_ip", "dst_port"))
                and network["protocol"] == "IPv4" and transport["protocol"] == case["protocol"], f"Event {number}: endpoints/protocol")
        require(application["protocol"] == case["application_protocol"] and event["payload_length"] == len(case["payload"]),
                f"Event {number}: application/payload length")
        require(event["preprocess_status"] == "valid" and event["processing_action"] == "process"
                and event["flow_tracking_status"] == "tracked" and event["flow_id"]
                and not event["parse_errors"] and not event["decode_errors"], f"Event {number}: processing/errors")
    require(events[2]["decode_status"] == "not_processed", "Binary payload must not require text decoding")
    return events


def check_matches(log, rules, packets, events):
    repository = RuleRepository(rules)
    records, contexts, results = [], [], {}
    for number, (event, packet, case) in enumerate(zip(events, packets, CASES), 1):
        layer = TCP if case["protocol"] == "TCP" else UDP
        context = InspectionContext(timestamp=event["timestamp"], packet_id=number, normalized=event["normalized"],
            processing_action=event["processing_action"], payload=bytes(packet[layer].payload), payload_status="available")
        contexts.append(context)
        candidates = repository.candidates(context)
        require(tuple(rule.sid for rule in candidates) == case["candidates"], f"Packet {number}: candidates")
        before = context.to_dict()
        for rule in candidates:
            result = match_rule(rule, context)
            status = "MATCH" if rule.sid == case["matched_sid"] else "NO_MATCH"
            require(result.sid == rule.sid and result.status == status and not result.diagnostics,
                    f"Packet {number}, SID {rule.sid}: expected {status}, got {result.to_dict()}")
            if status == "MATCH":
                require(result.matched_info.to_dict() == expected_info(rule.sid), f"Packet {number}: independent match evidence")
            else:
                require(result.reason_code == "content_no_match" and result.reason.startswith("content:")
                        and result.matched_info is None, f"Packet {number}: content rejection")
            results[(number, rule.sid)] = result
            records.append({"packet_id": number, "case": case["name"], "candidate_sids": list(case["candidates"]),
                            "payload_source": "pcap_transport_payload", **result.to_dict()})
        require(context.to_dict() == before and context.payload == case["payload"], "Matcher changed context/raw bytes")
        log.append(f"Matcher: packet_id={number}, candidates={case['candidates']}, matched SID={case['matched_sid']}.\n")
    require(len(records) == 7 and sum(row["status"] == "MATCH" for row in records) == 3, "Expected seven results: three MATCH/four NO_MATCH")
    path = FOLDER / "result_matches.jsonl"
    path.write_text("".join(json.dumps(row, ensure_ascii=True, allow_nan=False) + "\n" for row in records), encoding="utf-8")
    require(read_jsonl(path) == records, "MatchResult JSONL roundtrip")
    return contexts, results


def check_detections(log, events, results):
    path = FOLDER / "result_detections.jsonl"
    rows = read_jsonl(path)
    require([(row["packet_id"], row["sid"]) for row in rows] == list(EXPECTED_DETECTIONS), "Expected exactly three CLI detections")
    for row, (number, sid) in zip(rows, EXPECTED_DETECTIONS):
        label = f"CLI packet {number}"
        check_schema(row, label)
        require(row == expected_detection(number, sid, events[number - 1]["flow_id"], number), f"{label}: exact expected field values")
        require(row["matched_info"] == results[(number, sid)].matched_info.to_dict(), f"{label}: CLI/API evidence")
        log.append(f"Detection: packet_id={number}, sid={sid}, 15 keys/types/values PASS; "
                   f"protocol={row['protocol']}, orientation={row['matched_info']['header']['orientation']}.\n")
    require(path.read_bytes().isascii() and b"\\u00e1" in path.read_bytes(), "Writer must escape Unicode and preserve Vietnamese after JSON decode")
    log.append("CLI JSONL uses escaped Unicode; Vietnamese message and binary hex evidence roundtrip correctly.\n")


def check_direct_api(log, rules, contexts, results):
    # Explicitly simulated optional-ID absence; no extra captured packet/event.
    source = contexts[0]
    context = InspectionContext(timestamp=source.timestamp, normalized=source.normalized,
        payload=source.payload, payload_status="available", packet_id=None, flow=None)
    before = context.to_dict()
    match = match_rule(rules[0], context)
    require(match.status == "MATCH" and not match.diagnostics and match.matched_info.to_dict() == expected_info(101401),
            "Direct API context must MATCH via real header/content evaluation")
    detection = generate_detection(rules[0], context, match)
    record = detection.to_dict()
    check_schema(record, "Direct API")
    require(record == expected_detection(1, 101401, None, None), "Direct API must preserve null packet_id/flow_id")
    with JSONLWriter(str(FOLDER / "direct_detections.jsonl")) as writer:
        writer.write_record(record)
    require(read_jsonl(FOLDER / "direct_detections.jsonl") == [record], "Direct API JSONL roundtrip")
    record["matched_info"]["contents"][0]["start"] = 999
    require(detection.to_dict() == expected_detection(1, 101401, None, None)
            and context.to_dict() == before and context.payload == source.payload, "Serialization mutated detection/context")
    try:
        generate_detection(rules[0], contexts[3], results[(4, 101401)])
    except ValueError:
        log.append("Generator rejects the actual NO_MATCH from packet 4 with ValueError.\n")
    else:
        raise AssertionError("Generator must reject NO_MATCH")
    log.append("Direct API only: real MATCH then Generator/JSONLWriter; packet_id/flow_id null, no fabricated packet 5.\n")


def run_checks(log):
    originals = {name: (FOLDER / name).read_bytes() for name in ("input.rules", "input.pcap")}
    log.append("T14: real Loader/CLI/Matcher/Generator/JSONLWriter; synthetic PCAP plus one separate simulated API context.\n")
    report, packets = check_inputs(log)
    events = check_cli(log, report)
    contexts, results = check_matches(log, report.enabled_rules, packets, events)
    check_detections(log, events, results)
    check_direct_api(log, report.enabled_rules, contexts, results)
    for name, original in originals.items():
        require((FOLDER / name).read_bytes() == original, f"Test changed {name}")
    log.append("Inputs/context/raw bytes unchanged; all four JSONL outputs read back successfully.\n")
    log.append("PASS T14: 4 PCAP events, 7 rule results (3 MATCH/4 NO_MATCH), 3 CLI detections + 1 separate API detection; "
               "15-key schema/types/values, nullable IDs, actual UDP, reverse endpoints, Unicode/binary JSONL verified.\n")


def main():
    log = []
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL T14: {type(error).__name__}: {error}\n")
        code = 1
    (FOLDER / "console.txt").write_text("".join(log), encoding="utf-8")
    print("".join(log), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

"""T13: all matching rules produce detections, with one Engine across five packets."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
AUXILIARY = ROOT / "output" / "t13_multiple_matches"
sys.path.insert(0, str(ROOT))

from scapy.all import Ether, IP, PcapReader, TCP

from ids.detection.engine import EvaluationEngine
from ids.detection.loader import load_rules
from ids.detection.models import InspectionContext
from ids.detection.repository import RuleRepository


RULE_CASES = (
    (101301, "Admin marker", b"admin"),
    (101302, "Root marker", b"root"),
    (101303, "Login marker", b"login"),
    (101304, "Nonempty payload", None),
)
# Case, complete raw payload, sequence, expected matched SIDs, cumulative matches.
# Expected matches/counters are independent of Engine output.
CASES = (
    ("three_matches_repeated_content", b"admin admin login", 1001, (101301, 101303, 101304), 3),
    ("two_matches", b"admin", 1018, (101301, 101304), 5),
    ("one_match", b"public", 1023, (101304,), 6),
    ("no_match", b"", 1029, (), 6),
    ("same_flow_repeated_payload", b"admin admin login", 1029, (101301, 101303, 101304), 9),
)
EXPECTED_DETECTIONS = (
    (1, 101301), (1, 101303), (1, 101304), (2, 101301), (2, 101304),
    (3, 101304), (5, 101301), (5, 101303), (5, 101304),
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def expected_metrics(events, matches):
    return {"events_evaluated": events, "events_skipped": 0, "candidate_rules": 4 * events,
            "matches": matches, "rule_evaluation_errors": 0, "rule_not_evaluable": 0}


def expected_info(sid, number):
    info = {"header": {"matched": True, "orientation": "direct"},
            "flow": None, "flags": None, "dsize": None, "contents": []}
    if sid == 101304:
        info["dsize"] = {"expression": ">0", "actual": len(CASES[number - 1][1])}
    else:
        require(sid in (101301, 101303), "Only independently expected SIDs may have MATCH evidence")
        pattern, start, end = (("61646d696e", 0, 5) if sid == 101301 else ("6c6f67696e", 12, 17))
        info["contents"] = [{"index": 0, "buffer": "payload", "pattern_hex": pattern,
                             "matched_hex": pattern, "start": start, "end": end, "nocase": False}]
    return info


def check_inputs(log):
    report = load_rules([FOLDER / "input.rules"])
    require(report.counts == {
        "files_requested": 1, "files_loaded": 1, "files_disabled": 0, "files_duplicate": 0,
        "lines_read": 4, "rules_total": 4, "rules_enabled": 4, "rules_invalid": 0,
        "rules_unsupported": 0, "rules_disabled": 0, "rules_duplicate": 0,
    } and not report.diagnostics, "Expected four valid enabled rules")
    require([rule.sid for rule in report.enabled_rules] == [101301, 101302, 101303, 101304], "Rule SID order")
    for rule, (sid, message, pattern) in zip(report.enabled_rules, RULE_CASES):
        require(rule.sid == sid and rule.rev == 1 and rule.msg == message, f"SID {sid}: metadata")
        require(rule.header.to_dict() == {
            "action": "alert", "protocol": "tcp", "src_ip": None, "dst_ip": None,
            "src_port": {"start": None, "end": None}, "dst_port": {"start": 80, "end": 80}, "direction": "->",
        }, f"SID {sid}: header")
        if pattern is None:
            require(not rule.contents and rule.dsize is not None
                    and rule.dsize.to_dict() == {"operator": ">", "value": 0}, f"SID {sid}: dsize condition")
        else:
            require(len(rule.contents) == 1 and rule.contents[0].pattern == pattern
                    and rule.contents[0].to_dict() == {
                        "pattern_hex": pattern.hex(), "nocase": False, "offset": None, "depth": None,
                        "distance": None, "within": None,
                    } and rule.dsize is None, f"SID {sid}: content condition")
        require(rule.flow is None and rule.flags is None, "Unexpected flow/flags conditions")
    with PcapReader(str(FOLDER / "input.pcap")) as reader:
        packets = list(reader)
    require(len(packets) == len(CASES) == 5, "Expected five PCAP packets")
    for number, (packet, (name, payload, sequence, sids, _)) in enumerate(zip(packets, CASES), 1):
        require(packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(TCP), f"Packet {number}: layers")
        require((packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
                == ("10.0.0.1", 12345, "10.0.0.2", 80), f"Packet {number}: same flow endpoints")
        require(packet[Ether].src == "02:00:00:00:00:01" and packet[Ether].dst == "02:00:00:00:00:02",
                f"Packet {number}: MAC addresses")
        require(str(packet[TCP].flags) == "PA" and packet[TCP].seq == sequence and packet[TCP].ack == 2001,
                f"Packet {number}: flags/sequence/acknowledgment")
        require(packet[IP].ihl == packet[TCP].dataofs == 5 and packet[IP].len == 40 + len(payload)
                and bytes(packet[TCP].payload) == payload, f"Packet {number}: exact raw payload/length")
        require(float(packet.time) == 1700000000.0 + number - 1, f"Packet {number}: timestamp")
        log.append(f"Packet {number}: {name}, raw payload={payload!r}, {len(payload)} bytes, expected matched SIDs={sids}.\n")
    require(CASES[0][1] == CASES[4][1] and CASES[0][1].count(b"admin") == 2,
            "Packets 1/5 must repeat the same payload with two admin occurrences")
    require(all(b"root" not in case[1] for case in CASES), "Interleaved root rule must never match")
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
    require(metrics == [{**expected_metrics(5, 9), "detections_written": 9}], f"Unexpected CLI metrics: {metrics}")
    events = read_jsonl(FOLDER / "result.jsonl")
    require(len(events) == 5, "CLI must retain all five events, including no-match packet 4")
    for number, (event, (_, payload, sequence, _, _)) in enumerate(zip(events, CASES), 1):
        network, transport = event["normalized"]["network"], event["normalized"]["transport"]
        require(event["packet_id"] == number and event["timestamp"] == 1700000000.0 + number - 1,
                f"Event {number}: identity/timestamp")
        require((network["src_ip"], transport["src_port"], network["dst_ip"], transport["dst_port"])
                == ("10.0.0.1", 12345, "10.0.0.2", 80)
                and network["protocol"] == "IPv4" and transport["protocol"] == "TCP", f"Event {number}: header")
        require(transport["flags"] == "PA" and transport["sequence_number"] == sequence,
                f"Event {number}: flags/sequence")
        require(event["preprocess_status"] == "valid" and event["processing_action"] == "process"
                and event["flow_tracking_status"] == "tracked" and event["flow_id"]
                and not event["parse_errors"] and not event["decode_errors"], f"Event {number}: processing/errors")
        require(event["payload_length"] == transport["payload_length"] == len(payload)
                and network["total_length"] == 40 + len(payload), f"Event {number}: payload length")
        require(event["normalized"]["application"]["protocol"] == "UNKNOWN"
                and event["decode_status"] == "not_processed", f"Event {number}: raw TCP payload")
    require(len({event["flow_id"] for event in events}) == 1, "All five CLI events must belong to the same flow")
    return events


def check_engine(log, rules, packets, events):
    engine = EvaluationEngine(RuleRepository(rules))
    require(engine.metrics.to_dict() == expected_metrics(0, 0), "Engine counters must start at zero")
    records, snapshots = [], []
    for event, packet, (name, payload, _, expected_sids, cumulative_matches) in zip(events, packets, CASES):
        number = event["packet_id"]
        context = InspectionContext(timestamp=event["timestamp"], packet_id=number,
            normalized=event["normalized"], processing_action=event["processing_action"],
            payload=bytes(packet[TCP].payload), payload_status="available")
        candidates = [rule.sid for rule in engine.repository.candidates(context)]
        require(candidates == [101301, 101302, 101303, 101304], f"Packet {number}: candidate rules")
        before = context.to_dict()
        evaluation = engine.evaluate(context)
        require(not evaluation.skipped and not evaluation.diagnostics, f"Packet {number}: evaluation diagnostics/skip")
        require([result.sid for result in evaluation.rule_results] == [101301, 101302, 101303, 101304],
                f"Packet {number}: Engine must evaluate all four rules in order")
        matched_sids = [result.sid for result in evaluation.matched_results]
        require(matched_sids == list(expected_sids), f"Packet {number}: wrong Engine matched_results {matched_sids}")
        metrics = evaluation.metrics.to_dict()
        require(metrics == engine.metrics.to_dict() == expected_metrics(number, cumulative_matches),
                f"Packet {number}: wrong cumulative Engine metrics")
        snapshots.append((evaluation, evaluation.to_dict()))
        for result in evaluation.rule_results:
            status = "MATCH" if result.sid in expected_sids else "NO_MATCH"
            require(result.status == status and not result.diagnostics,
                    f"Packet {number}, SID {result.sid}: expected {status}, got {result.to_dict()}")
            if status == "MATCH":
                require(result.matched_info.to_dict() == expected_info(result.sid, number),
                        f"Packet {number}, SID {result.sid}: wrong rule-specific match evidence")
            else:
                stage = "dsize" if result.sid == 101304 else "content"
                require(result.reason_code == stage + "_no_match" and result.reason.startswith(stage + ":")
                        and result.matched_info is None, f"Packet {number}, SID {result.sid}: rejection/partial evidence")
            records.append({"packet_id": number, "case": name, "candidate_sids": candidates,
                            "payload_source": "pcap_tcp_payload", "engine_matched_sids": matched_sids,
                            "engine_metrics": metrics, **result.to_dict()})
        require(context.to_dict() == before and context.payload == payload, "Engine changed context/raw bytes")
        log.append(f"Engine: packet_id={number}, matched_sids={matched_sids}, metrics={metrics}.\n")
    for evaluation, exported in snapshots:
        require(evaluation.to_dict() == exported, "Later evaluations changed an earlier result/metrics snapshot")
    require(len(records) == 20 and sum(row["status"] == "MATCH" for row in records) == 9
            and sum(row["status"] == "NO_MATCH" for row in records) == 11,
            "Expected 20 Engine rule results: 9 MATCH and 11 NO_MATCH")
    path = FOLDER / "result_matches.jsonl"
    path.write_text("".join(json.dumps(row, ensure_ascii=True, allow_nan=False) + "\n" for row in records), encoding="utf-8")
    require(read_jsonl(path) == records, "Engine result JSONL roundtrip")
    return records


def check_detections(log, rules, events, records):
    detections = read_jsonl(FOLDER / "result_detections.jsonl")
    pairs = [(d["packet_id"], d["sid"]) for d in detections]
    require(pairs == list(EXPECTED_DETECTIONS), "Expected exactly nine ordered packet/SID detections, including packet 5")
    require(len(set(pairs)) == len(pairs), "Duplicate detection for the same packet/SID")
    messages = {rule.sid: rule.msg for rule in rules}
    for detection in detections:
        number, sid = detection["packet_id"], detection["sid"]
        event = events[number - 1]
        require((detection["src_ip"], detection["src_port"], detection["dst_ip"], detection["dst_port"])
                == ("10.0.0.1", 12345, "10.0.0.2", 80), "Detection endpoints")
        require(detection["timestamp"] == event["timestamp"] and detection["flow_id"] == event["flow_id"],
                "Detection/event correlation")
        require(detection["protocol"] == "TCP" and detection["application_protocol"] == "UNKNOWN"
                and detection["rev"] == 1 and detection["msg"] == messages[sid], "Detection metadata belongs to its rule")
        record = next(row for row in records if row["packet_id"] == number and row["sid"] == sid)
        require(detection["matched_info"] == record["matched_info"] == expected_info(sid, number),
                f"Packet {number}, SID {sid}: wrong CLI/Engine evidence")
        log.append(f"Detection: packet_id={number}, sid={sid}, msg={detection['msg']!r}, "
                   f"matched_info={detection['matched_info']}.\n")
    require([d["sid"] for d in detections if d["packet_id"] == 1]
            == [d["sid"] for d in detections if d["packet_id"] == 5] == [101301, 101303, 101304],
            "Same-flow repeated payload must produce all three detections again")


def run_checks(log):
    originals = {name: (FOLDER / name).read_bytes() for name in ("input.rules", "input.pcap")}
    log.append("T13: real Loader/CLI and one EvaluationEngine across five synthetic PCAP packets; no live traffic.\n")
    report, packets = check_inputs(log)
    events = check_cli(log, report)
    records = check_engine(log, report.enabled_rules, packets, events)
    check_detections(log, report.enabled_rules, events, records)
    for name, original in originals.items():
        require((FOLDER / name).read_bytes() == original, f"Test changed {name}")
    log.append("Inputs/raw payloads unchanged; event/Engine-result/detection JSONL read back successfully.\n")
    log.append("PASS T13: 5 events in one flow, 20 Engine rule results (9 MATCH/11 NO_MATCH), 9 detections; "
               "all matching rules retained, one detection per packet/SID, repeated payload evaluated again.\n")


def main():
    log = []
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL T13: {type(error).__name__}: {error}\n")
        code = 1
    (FOLDER / "console.txt").write_text("".join(log), encoding="utf-8")
    print("".join(log), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

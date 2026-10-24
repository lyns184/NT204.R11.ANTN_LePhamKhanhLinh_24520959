"""T08: use per-packet Tracker evidence, never infer roles/state from ports/ACK."""

import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
REQUEST = b"GET /admin HTTP/1.1\r\nHost: ids.test\r\n\r\n"
RESPONSE = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
            b"Content-Length: 5\r\n\r\nadmin")
sys.path.insert(0, str(ROOT))

from scapy.all import Ether, IP, PcapReader, TCP

from ids.core.pipeline import process_packet
from ids.detection.context import make_inspection_context
from ids.detection.flow_context import build_flow_context
from ids.detection.flow_matcher import match_flow
from ids.detection.header_matcher import match_header
from ids.detection.loader import load_rules
from ids.detection.matcher import match_rule
from ids.detection.models import FlowCondition
from ids.detection.payload import prepare_payload
from ids.detection.repository import RuleRepository
from ids.flow_tracker import Endpoint, FlowPacketSnapshot, FlowTracker


# src_ip, src_port, dst_ip, dst_port, flags, seq, ack, raw TCP payload.
PACKETS = (
    ("10.0.0.1", 12345, "10.0.0.2", 80, "S", 1000, 0, b""),
    ("10.0.0.2", 80, "10.0.0.1", 12345, "SA", 2000, 1001, b""),
    ("10.0.0.1", 12345, "10.0.0.2", 80, "A", 1001, 2001, b""),
    ("10.0.0.1", 12345, "10.0.0.2", 80, "PA", 1001, 2001, REQUEST),
    ("10.0.0.2", 80, "10.0.0.1", 12345, "PA", 2001, 1040, RESPONSE),
    ("10.0.0.3", 12346, "10.0.0.2", 80, "PA", 3000, 4000, REQUEST),
)
# packet direction, strict established, TCP state, strict handshake evidence.
EXPECTED_FLOW = (
    ("to_server", False, "HANDSHAKE", False),
    ("to_client", False, "HANDSHAKE", False),
    ("to_server", True, "ESTABLISHED", True),
    ("to_server", True, "ESTABLISHED", True),
    ("to_client", True, "ESTABLISHED", True),
    ("unknown", None, "ESTABLISHED", None),
)
CONDITIONS = (
    ("to_server,established", FlowCondition("to_server", "established")),
    ("to_client,established", FlowCondition("to_client", "established")),
    ("to_server,not_established", FlowCondition("to_server", "not_established")),
    ("to_client,not_established", FlowCondition("to_client", "not_established")),
)
EXPECTED_CONDITIONS = (
    ("NO_MATCH", "NO_MATCH", "MATCH", "NO_MATCH"),
    ("NO_MATCH", "NO_MATCH", "NO_MATCH", "MATCH"),
    ("MATCH", "NO_MATCH", "NO_MATCH", "NO_MATCH"),
    ("MATCH", "NO_MATCH", "NO_MATCH", "NO_MATCH"),
    ("NO_MATCH", "MATCH", "NO_MATCH", "NO_MATCH"),
    ("NOT_EVALUABLE", "NOT_EVALUABLE", "NOT_EVALUABLE", "NOT_EVALUABLE"),
)
EXPECTED_RULE = ("NO_MATCH", "NO_MATCH", "NO_MATCH", "MATCH", "NO_MATCH", "NOT_EVALUABLE")
UNKNOWN_CODES = {"unknown_flow_direction", "unknown_flow_established"}
CONTENT_INFO = {"index": 0, "buffer": "payload", "pattern_hex": "61646d696e",
                "matched_hex": "61646d696e", "start": 5, "end": 10, "nocase": False}


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
    require((rule.sid, rule.rev, rule.msg) == (100801, 1, "Established client request"), "Rule identification")
    require(rule.header.to_dict() == {
        "action": "alert", "protocol": "tcp", "src_ip": None, "dst_ip": None,
        "src_port": {"start": None, "end": None}, "dst_port": {"start": 80, "end": 80}, "direction": "<>",
    } and rule.flow == CONDITIONS[0][1], "Rule header/flow condition")
    require(len(rule.contents) == 1 and rule.contents[0].to_dict() == {
        "pattern_hex": "61646d696e", "nocase": False, "offset": None, "depth": None,
        "distance": None, "within": None,
    } and rule.flags is None and rule.dsize is None, "Rule content/options")
    with PcapReader(str(FOLDER / "input.pcap")) as reader:
        packets = list(reader)
    require(len(packets) == len(PACKETS) == 6, "Expected six PCAP packets")
    macs = {"10.0.0.1": "02:00:00:00:00:01", "10.0.0.2": "02:00:00:00:00:02", "10.0.0.3": "02:00:00:00:00:03"}
    for number, (packet, expected) in enumerate(zip(packets, PACKETS), 1):
        require(packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(TCP), f"Packet {number}: layers")
        actual = (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport,
                  str(packet[TCP].flags), packet[TCP].seq, packet[TCP].ack, bytes(packet[TCP].payload))
        require(actual == expected, f"Packet {number}: endpoints/flags/sequence/payload")
        require(packet[Ether].src == macs[expected[0]] and packet[Ether].dst == macs[expected[2]],
                f"Packet {number}: MAC addresses")
        require(packet[IP].ihl == packet[TCP].dataofs == 5 and packet[IP].len == 40 + len(expected[7]),
                f"Packet {number}: IP/TCP lengths")
        require(float(packet.time) == 1700000000.0 + number - 1, f"Packet {number}: timestamp")
    require(len(REQUEST) == 39 and len(RESPONSE) == 84 and REQUEST[5:10] == RESPONSE[-5:] == b"admin",
            "Fixture request/response content")
    log.append("PCAP: SYN, SYN/ACK, ACK, client GET /admin, server response admin, separate midstream GET /admin.\n")
    return report, packets


def check_api(log, rule, packets):
    tracker = FlowTracker()
    repository = RuleRepository((rule,))
    records, saved = [], []

    def inspect(event, tracking):
        number = event.packet_id
        require(tracking is not None and tracking.status == "tracked"
                and isinstance(tracking.snapshot, FlowPacketSnapshot), f"Packet {number}: missing tracked snapshot")
        snapshot = tracking.snapshot
        require(snapshot.packet_id == number and snapshot.timestamp == event.timestamp
                and snapshot.flow_id == event.flow_id, f"Packet {number}: snapshot binding")
        adapted = build_flow_context(event, tracking)
        payload = prepare_payload(event)
        require(adapted.flow is not None and not adapted.diagnostics, f"Packet {number}: flow adapter")
        require(payload.status == "available" and payload.payload == PACKETS[number - 1][7], f"Packet {number}: raw payload")
        context = make_inspection_context(event, payload, adapted)
        flow = context.flow
        direction, established, state, handshake = EXPECTED_FLOW[number - 1]
        require(flow.protocol == "TCP" and flow.flow_id == event.flow_id, f"Packet {number}: flow identity/protocol")
        require(flow.packet_direction == direction, f"Packet {number}: expected flow direction {direction}")
        require(flow.established_for_packet is established and flow.handshake_observed is handshake,
                f"Packet {number}: strict established/handshake evidence")
        require(flow.tcp_state.value == state and snapshot.tcp_state.value == state
                and snapshot.established_for_packet is established, f"Packet {number}: TCP state/snapshot evidence")
        if number <= 5:
            require(flow.client_endpoint == Endpoint("10.0.0.1", 12345)
                    and flow.server_endpoint == Endpoint("10.0.0.2", 80), f"Packet {number}: client/server roles")
        else:
            require(flow.client_endpoint is None and flow.server_endpoint is None,
                    "Midstream roles must remain unknown despite destination port 80")
        before = context.to_dict()
        candidates = [candidate.sid for candidate in repository.candidates(context)]
        header = match_header(rule.header, context)
        require(candidates == [100801] and header.status == "MATCH", f"Packet {number}: candidate/header")
        require(header.orientation == ("reverse" if number in (2, 5) else "direct"), f"Packet {number}: header orientation")
        checks = {}
        for (name, condition), status in zip(CONDITIONS, EXPECTED_CONDITIONS[number - 1]):
            result = match_flow(condition, context)
            require(result.status == status, f"Packet {number}, flow {name}: expected {status}, got {result.to_dict()}")
            if status == "MATCH":
                require(result.flow == flow, f"Packet {number}: flow MATCH evidence")
            elif status == "NOT_EVALUABLE":
                require(result.reason_code == "flow_not_evaluable"
                        and {diag.code for diag in result.diagnostics} == UNKNOWN_CODES,
                        "Unknown roles/state must not become established or not_established")
            else:
                require(result.reason_code == "flow_no_match" and not result.diagnostics,
                        f"Packet {number}: known flow NO_MATCH reason")
            checks[name] = {"condition": condition.to_dict(), **result.to_dict()}
        result = match_rule(rule, context)
        require(result.status == EXPECTED_RULE[number - 1],
                f"Packet {number}: expected full-rule {EXPECTED_RULE[number - 1]}, got {result.to_dict()}")
        if number in (1, 2, 5):
            require(result.reason_code == "flow_no_match" and result.reason.startswith("flow:"),
                    f"Packet {number}: expected flow rejection")
        elif number == 3:
            require(result.reason.startswith("content:") and not context.payload,
                    "Handshake ACK flow matches but empty payload must fail content")
        elif number == 4:
            require(result.matched_info.to_dict() == {
                "header": {"matched": True, "orientation": "direct"},
                "flow": {"condition": rule.flow.to_dict(), "actual": flow.to_dict()},
                "flags": None, "dsize": None, "contents": [CONTENT_INFO],
            }, "Client request flow/content evidence")
        else:
            require(result.reason_code == "rule_not_evaluable"
                    and {diag.code for diag in result.diagnostics} == UNKNOWN_CODES,
                    "Midstream full rule must remain NOT_EVALUABLE")
        require(context.to_dict() == before, f"Packet {number}: matcher changed context")
        snapshot_data = asdict(snapshot)
        snapshot_data["tcp_state"] = snapshot.tcp_state.value
        records.append({"input_kind": "api_replay_of_synthetic_pcap", "packet_id": number,
                        "snapshot": snapshot_data, "flow_context": flow.to_dict(), "candidate_sids": candidates,
                        "header": header.to_dict(), "flow_checks": checks, "rule_result": result.to_dict()})
        saved.append((snapshot, asdict(snapshot), context, before))
        log.append(f"API packet {number}: direction={direction}, established={established}, TCP={state}, "
                   f"flow_checks={[checks[name]['status'] for name, _ in CONDITIONS]}, full_rule={result.status.value}.\n")

    for number, packet in enumerate(packets, 1):
        process_packet(packet, number, "test:T08:api_replay", flow_tracker=tracker, inspection_handler=inspect)
    require(len(records) == 6 and len(tracker.active_flows) == 2, "Expected six snapshots and two API flows")
    require(len({row["snapshot"]["flow_id"] for row in records[:5]}) == 1
            and records[5]["snapshot"]["flow_id"] != records[0]["snapshot"]["flow_id"], "API flow grouping")
    summaries = tracker.flush(reason="capture_end")
    require(len(summaries) == 2 and not tracker.active_flows and not tracker.flush(), "API flush must finish without duplicates")
    for snapshot, snapshot_before, context, context_before in saved:
        require(asdict(snapshot) == snapshot_before and context.to_dict() == context_before,
                "Later packets or flush changed an earlier snapshot/context")
    require(saved[0][2].flow.established_for_packet is False and saved[3][2].flow.established_for_packet is True
            and saved[5][2].flow.established_for_packet is None, "Preserve false/true/unknown after capture ends")
    path = FOLDER / "result_matches.jsonl"
    path.write_text("".join(json.dumps(row, ensure_ascii=True, allow_nan=False) + "\n" for row in records), encoding="utf-8")
    require(read_jsonl(path) == records, "API snapshot/match JSONL roundtrip")
    log.append("API: 6 per-packet snapshots, 24 flow-condition checks; earlier snapshots unchanged after later packets/flush.\n")


def check_cli(log, report):
    relative = FOLDER.relative_to(ROOT)
    for name in ("result.jsonl", "result_flows.jsonl", "result_detections.jsonl"):
        (FOLDER / name).unlink(missing_ok=True)
    command = [sys.executable, "-X", "utf8", "main.py", "--pcap", str(relative / "input.pcap"),
               "--rules", str(relative / "input.rules"), "--output", str(relative / "result.jsonl"),
               "--flow-output", str(relative / "result_flows.jsonl"),
               "--detection-output", str(relative / "result_detections.jsonl")]
    log.append("\nCLI: " + subprocess.list2cmdline(command) + "\n")
    run = subprocess.run(command, cwd=ROOT, capture_output=True, encoding="utf-8", timeout=30)
    log.append("\nCLI stdout:\n" + run.stdout + "\nCLI stderr:\n" + run.stderr + f"\nCLI exit code: {run.returncode}\n")
    require(run.returncode == 0, f"CLI failed: exit code {run.returncode}")
    counts = [json.loads(line.removeprefix("[RULES] ")) for line in run.stdout.splitlines() if line.startswith("[RULES] ")]
    require(counts == [report.counts], "CLI Loader counters")
    metrics = [json.loads(line.removeprefix("[DETECTION SUMMARY] ")) for line in run.stdout.splitlines()
               if line.startswith("[DETECTION SUMMARY] ")]
    require(metrics == [{"events_evaluated": 6, "events_skipped": 0, "candidate_rules": 6, "matches": 1,
                         "rule_evaluation_errors": 0, "rule_not_evaluable": 1, "detections_written": 1}],
            f"Unexpected CLI metrics: {metrics}")
    diagnostics = [json.loads(line.removeprefix("[DETECTION] ")) for line in run.stderr.splitlines()
                   if line.startswith("[DETECTION] ")]
    require(len(diagnostics) == 2 and {diag["code"] for diag in diagnostics} == UNKNOWN_CODES,
            "CLI must report unknown flow direction and established evidence")
    require(all(diag["category"] == "input" and diag["source"] == {
        "file": str((FOLDER / "input.rules").resolve()), "line": 1,
    } for diag in diagnostics), "CLI diagnostic category/source")
    events = read_jsonl(FOLDER / "result.jsonl")
    flows = read_jsonl(FOLDER / "result_flows.jsonl")
    detections = read_jsonl(FOLDER / "result_detections.jsonl")
    require(len(events) == 6 and len(flows) == 2, "CLI must export six events and two flow summaries")
    for number, (event, expected) in enumerate(zip(events, PACKETS), 1):
        network, transport = event["normalized"]["network"], event["normalized"]["transport"]
        require(event["packet_id"] == number and event["timestamp"] == 1700000000.0 + number - 1,
                f"CLI event {number}: identity/timestamp")
        require((network["src_ip"], transport["src_port"], network["dst_ip"], transport["dst_port"],
                 transport["flags"], transport["sequence_number"], transport["acknowledgment_number"])
                == expected[:7], f"CLI event {number}: packet fields")
        require(event["preprocess_status"] == "valid" and event["processing_action"] == "process"
                and event["flow_tracking_status"] == "tracked" and event["flow_id"]
                and not event["parse_errors"] and not event["decode_errors"], f"CLI event {number}: processing")
        require(event["payload_length"] == len(expected[7]), f"CLI event {number}: payload length")
    first_id, second_id = events[0]["flow_id"], events[5]["flow_id"]
    require(all(event["flow_id"] == first_id for event in events[:5]) and second_id != first_id, "CLI flow grouping")
    by_id = {flow["flow_id"]: flow for flow in flows}
    require(set(by_id) == {first_id, second_id}, "CLI summary flow IDs")
    first, second = by_id[first_id], by_id[second_id]
    require((first["packet_count"], first["handshake_observed"], first["capture_midstream"]) == (5, True, False)
            and (second["packet_count"], second["handshake_observed"], second["capture_midstream"]) == (1, False, True),
            "CLI full-handshake/midstream summaries")
    require(all(flow["state"] == "ESTABLISHED" and flow["close_reason"] == "capture_end" for flow in flows),
            "Legacy TCP state may be ESTABLISHED for both flows, not strict matching proof")
    require([(d["packet_id"], d["sid"]) for d in detections] == [(4, 100801)], "Only client request packet 4 may alert")
    detection, event = detections[0], events[3]
    require((detection["src_ip"], detection["src_port"], detection["dst_ip"], detection["dst_port"])
            == PACKETS[3][:4] and detection["timestamp"] == event["timestamp"] and detection["flow_id"] == first_id,
            "Detection/event correlation and observed endpoints")
    require(detection["protocol"] == "TCP" and detection["application_protocol"] == "HTTP"
            and detection["rev"] == 1 and detection["msg"] == "Established client request", "Detection metadata")
    info = detection["matched_info"]
    require(info["header"] == {"matched": True, "orientation": "direct"} and info["contents"] == [CONTENT_INFO]
            and info["flags"] is None and info["dsize"] is None, "Detection header/content evidence")
    require(info["flow"] == {"condition": {"direction": "to_server", "state": "established"}, "actual": {
        "flow_id": first_id, "protocol": "TCP", "tcp_state": "ESTABLISHED",
        "client_endpoint": {"ip": "10.0.0.1", "port": 12345}, "server_endpoint": {"ip": "10.0.0.2", "port": 80},
        "packet_direction": "to_server", "established_for_packet": True, "handshake_observed": True,
    }}, "Detection strict flow evidence")
    log.append("PASS CLI: 6 events, 2 flows, 1 detection (packet 4/SID100801); midstream rule NOT_EVALUABLE.\n")


def run_checks(log):
    originals = {name: (FOLDER / name).read_bytes() for name in ("input.rules", "input.pcap")}
    log.append("T08: real pipeline/Tracker snapshots/adapters/matchers and CLI; synthetic PCAP, no live traffic.\n")
    report, packets = check_inputs(log)
    check_api(log, report.enabled_rules[0], packets)
    check_cli(log, report)
    for name, original in originals.items():
        require((FOLDER / name).read_bytes() == original, f"Test changed {name}")
    log.append("API and CLI have separate UUIDs; flow IDs are correlated only within each replay. Inputs unchanged.\n")
    log.append("PASS T08: per-packet direction/false-true-unknown evidence preserved, 24 flow checks correct, "
               "only established to_server admin packet 4 generates a detection.\n")


def main():
    log = []
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL T08: {type(error).__name__}: {error}\n")
        code = 1
    (FOLDER / "console.txt").write_text("".join(log), encoding="utf-8")
    print("".join(log), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

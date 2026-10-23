"""T02: invalid rules have diagnostics; valid rules before/after still run."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
AUXILIARY = ROOT / "output" / "t02_invalid_rules"
sys.path.insert(0, str(ROOT))

from scapy.all import Ether, IP, PcapReader, TCP

from ids.detection.loader import load_rules


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def check_loader(log):
    input_path = FOLDER / "input.rules"
    report = load_rules([input_path])
    expected_counts = {
        "files_requested": 1, "files_loaded": 1, "files_disabled": 0, "files_duplicate": 0,
        "lines_read": 6, "rules_total": 6, "rules_enabled": 2,
        "rules_invalid": 4, "rules_unsupported": 0, "rules_disabled": 0, "rules_duplicate": 0,
    }
    require(report.counts == expected_counts, f"Unexpected Loader counts: {report.counts}")
    require([entry.source.line for entry in report.entries] == list(range(1, 7)), "Rule source line order")
    require([entry.status for entry in report.entries] == ["enabled", "invalid", "invalid", "invalid", "invalid", "enabled"],
            "Expected four invalid rules between two enabled rules")
    expected_diagnostics = {
        2: ("missing_parenthesis", None),
        3: ("out_of_range", "dst_port"),
        4: ("missing_identification", "sid"),
        5: ("unterminated_string", None),
    }
    for entry in report.entries:
        require(entry.source.file == str(input_path.resolve()), f"Line {entry.source.line}: source file")
        if entry.status == "invalid":
            require(entry.rule is None, f"Line {entry.source.line}: invalid rule must not be executable")
            require(entry.diagnostics, f"Line {entry.source.line}: missing diagnostics")
            expected_code, expected_keyword = expected_diagnostics[entry.source.line]
            require(any(d.code == expected_code and d.keyword == expected_keyword for d in entry.diagnostics),
                    f"Line {entry.source.line}: wrong diagnostic type")
            for diagnostic in entry.diagnostics:
                require(diagnostic.category == "invalid" and diagnostic.source == entry.source,
                        f"Line {entry.source.line}: diagnostic category/source")
                require(isinstance(diagnostic.reason, str) and bool(diagnostic.reason.strip()),
                        f"Line {entry.source.line}: missing diagnostic reason")
                log.append(f"INVALID line {entry.source.line}: " + json.dumps(diagnostic.to_dict(), ensure_ascii=True) + "\n")
        else:
            require(entry.rule is not None and not entry.diagnostics, "Enabled rule must not contain diagnostics")
    require([rule.sid for rule in report.enabled_rules] == [100201, 100206], "Enabled SID order")
    for rule, port, line, message in zip(report.enabled_rules, (80, 8080), (1, 6),
                                         ("Valid before errors", "Valid after errors")):
        require(rule.header.protocol == "tcp" and rule.header.action == "alert", f"SID {rule.sid}: header")
        require(rule.header.dst_port.start == rule.header.dst_port.end == port, f"SID {rule.sid}: destination port")
        require(rule.source.line == line and rule.rev == 1 and rule.msg == message, f"SID {rule.sid}: metadata")
    exported = report.to_dict()
    result_path = FOLDER / "result_rules.json"
    result_path.write_text(json.dumps(exported, ensure_ascii=True, allow_nan=False, indent=2) + "\n", encoding="utf-8")
    require(json.loads(result_path.read_text(encoding="utf-8")) == exported, "Loader report JSON roundtrip")
    log.append("Loader counts: " + json.dumps(report.counts, ensure_ascii=True) + "\n")
    log.append("Enabled SIDs: [100201, 100206]; source lines: [1, 6].\n")
    return exported


def check_pcap(log):
    with PcapReader(str(FOLDER / "input.pcap")) as reader:
        packets = list(reader)
    require(len(packets) == 2, "Fixture must contain two packets")
    for index, (packet, source_port, destination_port) in enumerate(zip(packets, (12345, 12346), (80, 8080)), 1):
        require(packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(TCP), f"Packet {index}: layers")
        require(packet[Ether].src == "02:00:00:00:00:01" and packet[Ether].dst == "02:00:00:00:00:02",
                f"Packet {index}: MAC addresses")
        require(packet[IP].src == "10.0.0.1" and packet[IP].dst == "10.0.0.2", f"Packet {index}: IP addresses")
        require(packet[TCP].sport == source_port and packet[TCP].dport == destination_port, f"Packet {index}: ports")
        require(str(packet[TCP].flags) == "S" and packet[TCP].seq == 1000 and packet[TCP].ack == 0,
                f"Packet {index}: SYN sequence/acknowledgment")
        require(len(bytes(packet[TCP].payload)) == 0 and packet[IP].len == 40, f"Packet {index}: lengths")
        require(float(packet.time) == 1700000000.0 + index - 1, f"Packet {index}: timestamp")
    log.append("PCAP: 2 synthetic Ethernet/IPv4/TCP SYN packets, destination ports 80 and 8080, no payload.\n")


def check_cli(log, loader_report):
    relative = FOLDER.relative_to(ROOT)
    AUXILIARY.mkdir(parents=True, exist_ok=True)
    # Không dùng nhầm kết quả cũ nếu một lần chạy mới không tạo output.
    for filename in ("result.jsonl", "result_detections.jsonl"):
        (FOLDER / filename).unlink(missing_ok=True)
    command = [
        sys.executable, "-X", "utf8", "main.py",
        "--pcap", str(relative / "input.pcap"),
        "--rules", str(relative / "input.rules"),
        "--output", str(relative / "result.jsonl"),
        "--detection-output", str(relative / "result_detections.jsonl"),
        "--flow-output", str(AUXILIARY.relative_to(ROOT) / "flows.jsonl"),
    ]
    log.append("\nCLI: " + subprocess.list2cmdline(command) + "\n")
    run = subprocess.run(command, cwd=ROOT, capture_output=True, encoding="utf-8", timeout=30)
    log.append("\nCLI stdout:\n" + run.stdout + "\nCLI stderr:\n" + run.stderr)
    log.append(f"\nCLI exit code: {run.returncode}\n")
    require(run.returncode == 0, f"CLI must continue despite invalid rules; exit code {run.returncode}")
    diagnostics = [json.loads(line.removeprefix("[DETECTION] ")) for line in run.stderr.splitlines()
                   if line.startswith("[DETECTION] ")]
    require(diagnostics == loader_report["diagnostics"], "CLI must report the same invalid-rule diagnostics as Loader")
    counts = [json.loads(line.removeprefix("[RULES] ")) for line in run.stdout.splitlines()
              if line.startswith("[RULES] ")]
    require(counts == [loader_report["counts"]], "CLI Loader counters mismatch")
    summaries = [json.loads(line.removeprefix("[DETECTION SUMMARY] ")) for line in run.stdout.splitlines()
                 if line.startswith("[DETECTION SUMMARY] ")]
    expected_summary = {"events_evaluated": 2, "events_skipped": 0, "candidate_rules": 2, "matches": 2,
                        "rule_evaluation_errors": 0, "rule_not_evaluable": 0, "detections_written": 2}
    require(summaries == [expected_summary], f"Unexpected Engine summary: {summaries}")

    events = read_jsonl(FOLDER / "result.jsonl")
    detections = read_jsonl(FOLDER / "result_detections.jsonl")
    require(len(events) == 2, "CLI must retain both packet events")
    require([(record["packet_id"], record["sid"]) for record in detections] == [(1, 100201), (2, 100206)],
            "Expected exactly one detection per packet from the two enabled rules")
    for index, (event, detection, destination_port, message) in enumerate(zip(
        events, detections, (80, 8080), ("Valid before errors", "Valid after errors"),
    ), 1):
        require(event["packet_id"] == index and event["timestamp"] == 1700000000.0 + index - 1,
                f"Event {index}: identity/timestamp")
        require(event["preprocess_status"] == "valid" and event["processing_action"] == "process",
                f"Event {index}: preprocessing")
        require(event["flow_tracking_status"] == "tracked" and event["flow_id"], f"Event {index}: flow")
        require(not event["parse_errors"] and not event["decode_errors"], f"Event {index}: unexpected packet error")
        require(event["normalized"]["transport"]["dst_port"] == destination_port, f"Event {index}: destination port")
        require(detection["timestamp"] == event["timestamp"] and detection["flow_id"] == event["flow_id"],
                f"Detection {index}: event correlation")
        require((detection["src_ip"], detection["dst_ip"], detection["src_port"], detection["dst_port"], detection["protocol"])
                == ("10.0.0.1", "10.0.0.2", 12344 + index, destination_port, "TCP"),
                f"Detection {index}: endpoints/protocol")
        require(detection["rev"] == 1 and detection["msg"] == message, f"Detection {index}: rule metadata")
        require(detection["application_protocol"] == "UNKNOWN", f"Detection {index}: SYN is not HTTP")
        require(detection["matched_info"] == {"header": {"matched": True, "orientation": "direct"},
                "flow": None, "flags": None, "dsize": None, "contents": []},
                f"Detection {index}: expected header-only evidence")
        log.append(f"Detection: packet_id={index}, sid={detection['sid']}, dst_port={destination_port}, "
                   "header matched; flow_id/timestamp agree with packet event.\n")
    require(events[0]["flow_id"] != events[1]["flow_id"], "Different connections must have different flow IDs")
    log.append("PASS CLI: 2 packets evaluated; 2 candidates, 2 matches, 2 detections; no evaluation errors.\n")


def run_checks(log):
    originals = {name: (FOLDER / name).read_bytes() for name in ("input.rules", "input.pcap")}
    require(len(originals["input.rules"].decode("utf-8").splitlines()) == 6, "Expected six rule lines")
    log.append("T02: real Loader/Parser and offline CLI; synthetic PCAP, no live traffic.\n")
    report = check_loader(log)
    check_pcap(log)
    check_cli(log, report)
    for name, original in originals.items():
        require((FOLDER / name).read_bytes() == original, f"Test changed {name}")
    log.append("Inputs unchanged; rule report, packet events and detections are valid JSON.\n")
    log.append("PASS T02: 4 invalid rules diagnosed with source/reason; valid rules before and after errors "
               "still load and generate the expected detections.\n")


def main():
    log = []
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL T02: {type(error).__name__}: {error}\n")
        code = 1
    (FOLDER / "console.txt").write_text("".join(log), encoding="utf-8")
    print("".join(log), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

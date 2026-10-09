"""T12: PCAP timeout plus active-table removal and boundary checks."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from scapy.all import Ether, IP, TCP, rdpcap
from ids.core.config import FlowTrackerConfig
from ids.core.pipeline import process_packet
from ids.flow_tracker import FlowTracker


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
        "--tcp-idle-timeout", "5", "--udp-idle-timeout", "5",
    ], cwd=ROOT, capture_output=True, encoding="utf-8")
    log.append(run.stdout + run.stderr)
    require(run.returncode == 0, "CLI failed")
    events = [json.loads(x) for x in (FOLDER / "result.jsonl").read_text(encoding="utf-8").splitlines()]
    flows = [json.loads(x) for x in (FOLDER / "result_flows.jsonl").read_text(encoding="utf-8").splitlines()]
    require(len(events) == 3 and len(flows) == 2, "Expected 3 events and 2 summaries")
    require(events[0]["flow_id"] == events[1]["flow_id"] != events[2]["flow_id"], "Flow ID reuse after timeout")
    require([e["direction"] for e in events] == ["forward", "backward", "forward"], "Directions")
    for event in events:
        require(event["flow_tracking_status"] == "tracked" and event["preprocess_status"] == "valid", "Event status")
        require(event["parse_errors"] == [] and event["decode_errors"] == [], "Event errors")
    old, new = flows
    require(old["flow_id"] == events[0]["flow_id"] and new["flow_id"] == events[2]["flow_id"], "Summary IDs")
    require(old["close_reason"] == "idle_timeout" and old["exported_at"] == 1700000007, "Old expiry")
    require(old["last_seen"] == 1700000001 and old["duration"] == 1, "Duration excludes idle wait")
    require(old["packet_count"] == 2 and old["byte_count"] == 141, "Old counters")
    require(old["forward"]["byte_count"] == 57 and old["backward"]["byte_count"] == 84, "Old directions")
    require(new["close_reason"] == "capture_end" and new["packet_count"] == 1 and new["byte_count"] == 57,
            "New counters/EOF")
    require(new["duration"] == 0, "New duration")
    require(old["endpoint_a"] == new["endpoint_a"] and old["endpoint_b"] == new["endpoint_b"], "Same endpoints")
    require(old["protocol"] == new["protocol"] == "UDP", "Same protocol")
    log.append("PASS PCAP: old UDP flow expired at packet 3; same tuple received a new ID; two unique summaries.\n")


def check_active_table(protocol, packets, log):
    tracker = FlowTracker(FlowTrackerConfig(tcp_idle_timeout_seconds=5, udp_idle_timeout_seconds=5))
    completed = []
    for i, packet in enumerate(packets, 1):
        event = process_packet(packet, i, f"test:T12:direct:{protocol}",
                               flow_tracker=tracker, flow_summary_handler=completed.append)
        require(event.flow_tracking_status == "tracked", "Direct tracking failed")
    require(len(tracker.active_flows) == 1 and not completed, "Expected one active flow")
    key, record = next(iter(tracker.active_flows.items()))
    old_id = record.flow_id
    last = record.last_seen
    require(tracker.expire(last + 4.999) == [] and key in tracker.active_flows, "Expired before timeout")
    expired = tracker.expire(last + 5)
    require(len(expired) == 1 and expired[0]["close_reason"] == "idle_timeout", "Boundary expiry")
    require(expired[0]["flow_id"] == old_id and not tracker.active_flows, "Expired flow not removed")
    require(tracker.expire(last + 5) == [], "Duplicate expiry summary")
    fresh = packets[0].copy()
    fresh.time = last + 6
    event = process_packet(fresh, len(packets) + 1, f"test:T12:direct:{protocol}",
                           flow_tracker=tracker, flow_summary_handler=completed.append)
    require(event.flow_tracking_status == "tracked" and event.flow_id != old_id, "New flow ID")
    require(len(tracker.active_flows) == 1 and key in tracker.active_flows, "Same tuple not recreated")
    require(tracker.active_flows[key].packet_count == 1, "Old counters leaked into new flow")
    flushed = tracker.flush()
    require(len(flushed) == 1 and flushed[0]["flow_id"] == event.flow_id, "Flush new flow")
    require(not tracker.active_flows and tracker.flush() == [] and completed == [], "Duplicate final summary")
    log.append(f"PASS direct {protocol}: active count 1 -> 0 at 5s -> 1 after tuple reuse -> 0 after flush; "
               "no early expiry at 4.999s; no duplicate summaries; new ID and reset counters.\n")


def main():
    log = []
    code = 0
    try:
        check_cli(log)
        check_active_table("UDP", list(rdpcap(str(FOLDER / "input.pcap")))[:2], log)
        tcp = []
        for reverse, flags, seq, ack, offset in (
            (False, "S", 1000, 0, 0), (True, "SA", 2000, 1001, 0.5), (False, "A", 1001, 2001, 1),
        ):
            source, target = ("10.0.0.2", "10.0.0.1") if reverse else ("10.0.0.1", "10.0.0.2")
            packet = Ether()/IP(src=source, dst=target)/TCP(
                sport=80 if reverse else 12345, dport=12345 if reverse else 80,
                flags=flags, seq=seq, ack=ack,
            )
            packet = Ether(bytes(packet))
            packet.time = 1700000000 + offset
            tcp.append(packet)
        check_active_table("TCP", tcp, log)
        log.append("PASS T12: CLI idle timeout and direct UDP/TCP active-table lifecycle checks passed.\n")
    except Exception as error:
        log.append(f"FAIL T12: {type(error).__name__}: {error}\n")
        code = 1
    (FOLDER / "console.txt").write_text("".join(log), encoding="utf-8")
    print("".join(log[-3:]), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

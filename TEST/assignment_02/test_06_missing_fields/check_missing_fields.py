"""T06: omitted and null optional fields must produce consistent output."""

import json
import sys
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from ids.core.event import IDSEvent
from ids.output.jsonl_writer import JSONLWriter
from ids.preprocessor.processor import preprocess_event


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def nulls(keys):
    return dict.fromkeys(keys)


NETWORK_OPTIONAL = (
    "version", "header_length", "total_length", "identification", "flags",
    "fragment_offset", "ttl", "next_protocol", "checksum",
)
TCP_OPTIONAL = (
    "payload_length", "sequence_number", "acknowledgment_number", "header_length",
    "flags", "window_size", "checksum", "urgent_pointer",
)
UDP_OPTIONAL = ("payload_length", "length", "checksum")

CASES = (
    ("HTTP", "TCP", 80,
     {"message_type": "request", "method": "GET", "path": "/"},
     {**nulls(("version", "status_code", "reason", "body", "body_length")), "headers": {}}),
    ("DNS", "UDP", 53,
     {"message_type": "query"},
     {**nulls(("transaction_id", "opcode", "authoritative", "truncated", "recursion_desired",
               "recursion_available", "response_code", "question_count", "answer_count")),
      "questions": [], "answers": []}),
    ("SMTP", "TCP", 25,
     {"message_type": "command", "command": "NOOP"},
     {**nulls(("argument", "address", "status_code", "message", "multiline")), "lines": []}),
)


def run_checks(log):
    events = []
    for protocol, transport, port, required, defaults in CASES:
        normalized_pair = []
        for explicit_null in (False, True):
            case = f"{protocol}_{'null' if explicit_null else 'omitted'}"
            network = {"protocol": "IPv4", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}
            transport_fields = {"protocol": transport, "src_port": 12345, "dst_port": port}
            fields = deepcopy(required)
            optional = TCP_OPTIONAL if transport == "TCP" else UDP_OPTIONAL
            if explicit_null:
                network.update(nulls(NETWORK_OPTIONAL))
                transport_fields.update(nulls(optional))
                if transport == "TCP":
                    transport_fields["flags_detail"] = None
                fields.update(nulls(defaults))
            event = IDSEvent(
                packet_id=len(events) + 1, timestamp=100.0, capture_source=f"test:T06:{case}",
                network=network, transport=transport_fields,
                application={"protocol": protocol, "fields": fields},
                raw_payload=b"original bytes",
            )
            original = deepcopy(event.to_dict())
            raw_before = event.raw_payload
            preprocess_event(event)
            after = event.to_dict()
            for key in original:
                if key not in ("normalized", "preprocess_status", "processing_action", "reason"):
                    require(after[key] == original[key], f"{case}: original {key} changed")
            require(event.raw_payload == raw_before, f"{case}: raw bytes changed")
            require(event.preprocess_status == "valid", f"{case}: {event.reason}")
            require(event.processing_action == "process" and event.reason is None, f"{case}: action/reason")
            expected_network = {"protocol": "IPv4", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                                **nulls(NETWORK_OPTIONAL)}
            expected_transport = {"protocol": transport, "src_port": 12345, "dst_port": port,
                                  **nulls(optional)}
            if transport == "TCP":
                expected_transport["flags_detail"] = {}
            require(event.normalized["network"] == expected_network, f"{case}: network defaults")
            require(event.normalized["transport"] == expected_transport, f"{case}: transport defaults")
            require(event.normalized["application"] == {"protocol": protocol, "fields": {**required, **defaults}},
                    f"{case}: application defaults")
            require(event.normalized["payload_length"] == 0 and event.normalized["packet_length"] is None,
                    f"{case}: default event lengths")
            normalized_pair.append(event.normalized)
            events.append(event)
            log.append(json.dumps({"case": case, "packet_id": event.packet_id,
                                   "input": original["application"],
                                   "normalized_fields": event.normalized["application"]["fields"],
                                   "original_preserved": True, "result": "PASS"}) + "\n")
        require(normalized_pair[0] == normalized_pair[1], f"{protocol}: omitted/null differ")
        log.append(f"PASS {protocol}: omitted and null fields have identical normalized output.\n")

    with JSONLWriter(str(FOLDER / "result.jsonl")) as writer:
        for event in events:
            writer.write(event)
    records = [json.loads(line) for line in (FOLDER / "result.jsonl").read_text(encoding="utf-8").splitlines()]
    require(records == [event.to_dict() for event in events], "JSONL roundtrip mismatch")
    require(len(records) == 6, "Expected six output events")
    log.append("PASS T06: 6 events; null/[]/{} defaults correct; originals preserved; JSONL roundtrip passed.\n")


def main():
    log = []
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL T06: {type(error).__name__}: {error}\n")
        code = 1
    (FOLDER / "console.txt").write_text("".join(log), encoding="utf-8")
    print("".join(log[-2:]), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

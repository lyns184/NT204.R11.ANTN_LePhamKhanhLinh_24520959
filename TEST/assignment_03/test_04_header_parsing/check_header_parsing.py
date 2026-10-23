"""T04: parse header selectors into the expected typed Internal Rule Objects."""

import json
import sys
from ipaddress import IPv4Network
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from ids.detection.models import ParseStatus, PortSpec, Rule, RuleHeader, RuleSource
from ids.detection.parser import parse_rule


# Expected values are specified separately from input.rules and Parser output.
# Columns: sid, msg, protocol, src_ip, src_port, direction, dst_ip, dst_port.
CASES = (
    (100401, "Any selectors", "tcp", None, (None, None), "->", None, (None, None)),
    (100402, "Single IPv4 and ports", "tcp", "10.0.0.1/32", (12345, 12345),
     "->", "10.0.0.2/32", (80, 80)),
    (100403, "CIDR and port ranges", "tcp", "10.0.0.0/24", (1000, 2000),
     "->", "192.168.1.0/24", (80, 90)),
    (100404, "Open ranges and bidirectional", "tcp", None, (0, 1023),
     "<>", "10.0.0.2/32", (8080, 65535)),
    (100405, "UDP header", "udp", None, (53000, 53000), "->", "10.0.0.2/32", (53, 53)),
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_checks(log):
    input_path = FOLDER / "input.rules"
    original = input_path.read_bytes()
    lines = original.decode("utf-8").splitlines()
    require(len(lines) == len(CASES) == 5, "Expected five physical rule lines")
    results = []
    log.append("T04: real Parser, direct rule text; no PCAP, events or matching.\n")
    for number, (text, case) in enumerate(zip(lines, CASES), 1):
        sid, message, protocol, src_ip, src_port, direction, dst_ip, dst_port = case
        source = RuleSource(str(input_path.resolve()), number)
        result = parse_rule(text, source)
        require(result.status == ParseStatus.VALID and not result.diagnostics,
                f"Line {number}: expected VALID with no diagnostics; got {result.to_dict()}")
        rule = result.rule
        require(isinstance(rule, Rule) and isinstance(rule.header, RuleHeader),
                f"Line {number}: missing typed Rule/RuleHeader")
        header = rule.header
        require((rule.sid, rule.rev, rule.msg) == (sid, 1, message), f"Line {number}: identification mismatch")
        require(rule.source == source and rule.raw_text == text, f"SID {sid}: source/raw text mismatch")
        require(header.action == "alert" and header.protocol == protocol, f"SID {sid}: action/protocol mismatch")
        require(header.direction == direction, f"SID {sid}: direction mismatch")
        for field, expected in (("src_ip", src_ip), ("dst_ip", dst_ip)):
            actual = getattr(header, field)
            if expected is None:
                require(actual is None, f"SID {sid}: {field} must represent any as None")
            else:
                require(isinstance(actual, IPv4Network) and str(actual) == expected,
                        f"SID {sid}: {field} must be IPv4Network {expected}, got {actual!r}")
        for field, expected in (("src_port", src_port), ("dst_port", dst_port)):
            actual = getattr(header, field)
            require(isinstance(actual, PortSpec), f"SID {sid}: {field} must be PortSpec")
            require((actual.start, actual.end) == expected,
                    f"SID {sid}: {field} expected {expected}, got {(actual.start, actual.end)}")
            require(actual.is_any == (expected == (None, None)), f"SID {sid}: {field}.is_any mismatch")
        require(not rule.contents and all(getattr(rule, name) is None for name in (
            "flow", "flags", "dsize", "classtype", "priority",
        )), f"SID {sid}: unexpected conditions/optional metadata")

        expected_header = {
            "action": "alert", "protocol": protocol,
            "src_ip": src_ip, "src_port": {"start": src_port[0], "end": src_port[1]},
            "direction": direction,
            "dst_ip": dst_ip, "dst_port": {"start": dst_port[0], "end": dst_port[1]},
        }
        require(header.to_dict() == expected_header, f"SID {sid}: exported header mismatch")
        results.append(result)
        log.append(f"Line {number}: VALID sid={sid}, rev=1, msg={message!r}\n")
        log.append("  Input: " + text + "\n")
        log.append("  Header: " + json.dumps(expected_header, ensure_ascii=True) + "\n")
        log.append("  Typed IP/port selectors, source and raw_text verified.\n")

    counts = {"rules_total": len(results), **{
        f"rules_{status}": sum(result.status.value == status for result in results)
        for status in ("valid", "invalid", "unsupported")
    }}
    require(counts == {"rules_total": 5, "rules_valid": 5, "rules_invalid": 0, "rules_unsupported": 0},
            f"Unexpected Parser counts: {counts}")
    exported = {"input_file": str(input_path.resolve()), "counts": counts,
                "results": [result.to_dict() for result in results]}
    result_path = FOLDER / "result_rules.json"
    result_path.write_text(json.dumps(exported, ensure_ascii=True, allow_nan=False, indent=2) + "\n", encoding="utf-8")
    restored = json.loads(result_path.read_text(encoding="utf-8"))
    require(restored == exported, "Parser report JSON roundtrip mismatch")
    require([entry["rule"]["sid"] for entry in restored["results"]] == [case[0] for case in CASES],
            "Saved SID order mismatch")
    require(input_path.read_bytes() == original, "Parser/test changed input.rules")
    log.append("Counts: " + json.dumps(counts, ensure_ascii=True) + "\n")
    log.append("JSON report read back successfully; input.rules unchanged.\n")
    log.append("PASS T04: 5 valid headers; any/IPv4/CIDR, single/closed/open port ranges, "
               "directions and metadata parsed into the expected Rule Objects.\n")


def main():
    log = []
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL T04: {type(error).__name__}: {error}\n")
        code = 1
    (FOLDER / "console.txt").write_text("".join(log), encoding="utf-8")
    print("".join(log), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

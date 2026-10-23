"""T06: candidate protocol/port selection, stable order, dedup and missing data."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from ids.detection.loader import load_rules
from ids.detection.models import InspectionContext, Rule
from ids.detection.repository import RuleRepository


# Expected values are independent of Repository/Indexer output.
# Columns: sid, msg, protocol, destination port bounds, direction.
RULES = (
    (100601, "TCP port 80", "tcp", (80, 80), "->"),
    (100602, "TCP port range", "tcp", (8000, 8080), "->"),
    (100603, "UDP port 53", "udp", (53, 53), "->"),
    (100604, "IPv4 general rule", "ip", (None, None), "->"),
    (100605, "TCP wildcard ports", "tcp", (None, None), "->"),
    (100606, "TCP port 443 both directions", "tcp", (443, 443), "<>"),
)
# case name, normalized transport data, expected ordered SID list.
CASES = (
    ("tcp_port_80", {"protocol": "TCP", "src_port": 12345, "dst_port": 80},
     (100601, 100604, 100605)),
    ("tcp_range_start", {"protocol": "TCP", "src_port": 12345, "dst_port": 8000},
     (100602, 100604, 100605)),
    ("tcp_range_end", {"protocol": "TCP", "src_port": 12345, "dst_port": 8080},
     (100602, 100604, 100605)),
    ("tcp_below_range", {"protocol": "TCP", "src_port": 12345, "dst_port": 7999},
     (100604, 100605)),
    ("tcp_above_range", {"protocol": "TCP", "src_port": 12345, "dst_port": 8081},
     (100604, 100605)),
    ("udp_dns", {"protocol": "UDP", "src_port": 53000, "dst_port": 53},
     (100603, 100604)),
    ("udp_other_port", {"protocol": "UDP", "src_port": 53000, "dst_port": 9999},
     (100604,)),
    ("tcp_443_forward", {"protocol": "TCP", "src_port": 12345, "dst_port": 443},
     (100604, 100605, 100606)),
    ("tcp_443_reverse", {"protocol": "TCP", "src_port": 443, "dst_port": 12345},
     (100604, 100605, 100606)),
    ("tcp_443_both_orientations", {"protocol": "TCP", "src_port": 443, "dst_port": 443},
     (100604, 100605, 100606)),
    ("tcp_missing_dst_port", {"protocol": "TCP", "src_port": 12345},
     (100601, 100602, 100604, 100605, 100606)),
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_checks(log):
    input_path = FOLDER / "input.rules"
    original = input_path.read_bytes()
    require(len(original.decode("utf-8").splitlines()) == len(RULES) == 6, "Expected six physical rule lines")
    log.append("T06: real Loader and Repository; direct simulated contexts, no PCAP or matching.\n")
    report = load_rules([input_path])
    require(report.counts == {
        "files_requested": 1, "files_loaded": 1, "files_disabled": 0, "files_duplicate": 0,
        "lines_read": 6, "rules_total": 6, "rules_enabled": 6, "rules_invalid": 0,
        "rules_unsupported": 0, "rules_disabled": 0, "rules_duplicate": 0,
    } and not report.diagnostics, "Expected exactly six valid enabled rules")
    require([rule.sid for rule in report.enabled_rules] == [row[0] for row in RULES], "Loaded SID order mismatch")
    for number, (rule, expected) in enumerate(zip(report.enabled_rules, RULES), 1):
        sid, message, protocol, port, direction = expected
        require((rule.sid, rule.msg, rule.rev) == (sid, message, 1), f"SID {sid}: identification mismatch")
        require(rule.header.to_dict() == {
            "action": "alert", "protocol": protocol, "src_ip": None, "dst_ip": None,
            "src_port": {"start": None, "end": None},
            "dst_port": {"start": port[0], "end": port[1]}, "direction": direction,
        }, f"SID {sid}: fixture header mismatch")
        require(rule.source.file == str(input_path.resolve()) and rule.source.line == number,
                f"SID {sid}: source mismatch")
        require(not rule.contents and rule.flow is None and rule.flags is None and rule.dsize is None,
                f"SID {sid}: expected header-only rule")

    rules_before = [rule.to_dict() for rule in report.enabled_rules]
    repository = RuleRepository(report.enabled_rules)
    require(len(repository) == 6 and repository.rules == report.enabled_rules, "Repository snapshot/order mismatch")
    cases = []
    for number, (name, transport, expected_sids) in enumerate(CASES, 1):
        normalized = {"network": {"protocol": "IPv4", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
                      "transport": dict(transport)}
        normalized_before = json.dumps(normalized, sort_keys=True)
        context = InspectionContext(timestamp=100.0 + number, normalized=normalized)
        context_before = context.to_dict()
        candidates = repository.candidates(context)
        require(isinstance(candidates, tuple) and all(isinstance(rule, Rule) for rule in candidates),
                f"{name}: candidates must be a tuple of Rule objects")
        candidate_sids = [rule.sid for rule in candidates]
        require(len(candidate_sids) == len(set(candidate_sids)), f"{name}: duplicate candidate SID")
        require(candidate_sids == list(expected_sids),
                f"{name}: expected {list(expected_sids)}, got {candidate_sids}")
        require(context.to_dict() == context_before and json.dumps(normalized, sort_keys=True) == normalized_before,
                f"{name}: query changed context/input data")
        require([rule.to_dict() for rule in report.enabled_rules] == rules_before
                and [rule.to_dict() for rule in repository.rules] == rules_before,
                f"{name}: query changed rules/repository snapshot")
        cases.append({"case": name, "context": context.to_dict(), "expected_sids": list(expected_sids),
                      "candidate_sids": candidate_sids, "result": "PASS"})
        log.append(f"{name}: transport=" + json.dumps(transport, ensure_ascii=True)
                   + f"; expected={list(expected_sids)}; actual={candidate_sids}; PASS.\n")
    require(len(cases) == 11, "Expected eleven indexing cases")
    exported = {
        "input_kind": "direct_simulated_context", "rules": rules_before,
        "counts": {"rules_loaded": len(repository), "cases_total": len(cases),
                   "cases_passed": sum(case["result"] == "PASS" for case in cases)},
        "cases": cases,
    }
    result_path = FOLDER / "result_candidates.json"
    result_path.write_text(json.dumps(exported, ensure_ascii=True, allow_nan=False, indent=2) + "\n", encoding="utf-8")
    require(json.loads(result_path.read_text(encoding="utf-8")) == exported, "Candidate report JSON roundtrip mismatch")
    require(input_path.read_bytes() == original, "Test changed input.rules")
    log.append("JSON report read back successfully; contexts, rules and input.rules unchanged.\n")
    log.append("PASS T06: 6 rules, 11 contexts; candidate membership/order/dedup correct, "
               "ip bucket retained for TCP/UDP, range boundaries and missing destination port handled.\n")


def main():
    log = []
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL T06: {type(error).__name__}: {error}\n")
        code = 1
    (FOLDER / "console.txt").write_text("".join(log), encoding="utf-8")
    print("".join(log), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

"""T01: load valid rules and skip comments/blank lines before parsing."""

import json
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from ids.detection.loader import load_rules
from ids.detection.models import RuleSource
from ids.detection.parser import parse_rule


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_checks(log):
    input_path = FOLDER / "input.rules"
    original = input_path.read_bytes()
    lines = original.decode("utf-8").splitlines()
    require(len(lines) == 6, "Fixture must contain six lines")
    require(lines[0].startswith("#") and lines[4].startswith("    #"),
            "Fixture must contain a normal and an indented comment")
    require(lines[1] == "" and lines[3] == "", "Fixture must contain two blank lines")
    expected_lines = [3, 6]
    expected_sids = [100001, 100002]
    log.append("Input: TEST/assignment3/test_01_rule_loading/input.rules\n")
    log.append("Fixture: 6 lines = 2 comments + 2 blank lines + 2 valid rules.\n")

    # Chỉ ghi nhận lời gọi; wraps vẫn chạy Parser thật trên từng dòng.
    with patch("ids.detection.loader.parse_rule", wraps=parse_rule) as parser_spy:
        report = load_rules([input_path])

    sources = [RuleSource(str(input_path.resolve()), number) for number in expected_lines]
    expected_calls = [(lines[number - 1], source) for number, source in zip(expected_lines, sources)]
    observed_calls = [(call.args, call.kwargs) for call in parser_spy.call_args_list]
    require(observed_calls == [(arguments, {}) for arguments in expected_calls],
            f"Parser must receive only rule lines 3 and 6; observed calls: {observed_calls!r}")
    log.append("Parser calls: 2; received exactly the original rule text at lines 3 and 6.\n")
    log.append("Comments at lines 1/5 and blank lines at lines 2/4 were not passed to Parser.\n")

    expected_counts = {
        "files_requested": 1, "files_loaded": 1, "files_disabled": 0, "files_duplicate": 0,
        "lines_read": 6, "rules_total": 2, "rules_enabled": 2,
        "rules_invalid": 0, "rules_unsupported": 0, "rules_disabled": 0, "rules_duplicate": 0,
    }
    require(report.counts == expected_counts, f"Unexpected Loader counts: {report.counts}")
    require(report.diagnostics == (), f"Unexpected diagnostics: {report.diagnostics}")
    require(len(report.files) == 1 and report.files[0].status == "loaded", "Expected one loaded file")
    require(report.files[0].path == str(input_path.resolve()), "Loaded file path mismatch")
    require([entry.status for entry in report.entries] == ["enabled", "enabled"],
            "Both entries must be enabled")
    require([entry.source for entry in report.entries] == sources, "Rule entry source lines mismatch")
    require([rule.sid for rule in report.enabled_rules] == expected_sids, "Enabled SID order mismatch")

    for rule, protocol, port, message, source in zip(
        report.enabled_rules, ("tcp", "udp"), (80, 53), ("HTTP test", "DNS test"), sources,
    ):
        header = rule.header
        require(header.action == "alert" and header.protocol == protocol, f"SID {rule.sid}: action/protocol")
        require(header.src_ip is None and header.dst_ip is None, f"SID {rule.sid}: IP any selectors")
        require(header.src_port.is_any, f"SID {rule.sid}: source port must be any")
        require(header.dst_port.start == port and header.dst_port.end == port,
                f"SID {rule.sid}: destination port must be {port}")
        require(header.direction == "->", f"SID {rule.sid}: direction mismatch")
        require(rule.rev == 1 and rule.msg == message, f"SID {rule.sid}: identification mismatch")
        require(rule.source == source and rule.raw_text == lines[source.line - 1],
                f"SID {rule.sid}: source/raw text mismatch")
        log.append(f"Rule line {source.line}: sid={rule.sid}, rev={rule.rev}, msg={rule.msg!r}, "
                   f"header=alert {protocol} any any -> any {port}; enabled.\n")

    exported = report.to_dict()
    result_path = FOLDER / "result_rules.json"
    result_path.write_text(json.dumps(exported, ensure_ascii=True, allow_nan=False, indent=2) + "\n",
                           encoding="utf-8")
    restored = json.loads(result_path.read_text(encoding="utf-8"))
    require(restored == exported, "Loader report JSON roundtrip mismatch")
    require(restored["counts"] == expected_counts, "Saved Loader counters mismatch")
    require([rule["sid"] for rule in restored["enabled_rules"]] == expected_sids, "Saved SID order mismatch")
    require(input_path.read_bytes() == original, "Loader/test changed input.rules")
    log.append("Counts: " + json.dumps(report.counts, ensure_ascii=True) + "\n")
    log.append("JSON report read back successfully; input.rules unchanged.\n")
    log.append("PASS T01: 2 valid rules enabled in order; comments/blank lines skipped before Parser; "
               "metadata and JSON report correct.\n")


def main():
    log = []
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL T01: {type(error).__name__}: {error}\n")
        code = 1
    (FOLDER / "console.txt").write_text("".join(log), encoding="utf-8")
    print("".join(log), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

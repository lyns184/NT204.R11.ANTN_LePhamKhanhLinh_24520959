"""Xuất cùng một kết quả thống kê thành báo cáo text và JSON."""

import json
from collections.abc import Iterable
from pathlib import Path
from typing import TextIO

from ids.output.paths import validate_output_paths
from ids.report.generator import AlertReport


def _count_section(title: str, entries: Iterable[tuple[int | str, int]]) -> list[str]:
    rows = [f"  {json.dumps(value, ensure_ascii=False)}: {count}" for value, count in entries]
    return ["", title, *(rows or ["  (none)"])]


def render_report_text(report: AlertReport) -> str:
    period = report["period"]
    run_id = report["run_id"]
    lines = [
        "IDS SECURITY REPORT",
        f"Period (UTC): [{period['from_utc']}, {period['to_utc']})",
        "Run: " + ("all" if run_id is None else json.dumps(run_id, ensure_ascii=False)),
        f"Time basis: {report['time_basis']}",
        f"Total alerts (groups): {report['total_alerts']}",
        f"Total occurrences (sum of group counts): {report['total_occurrences']}",
        "Distributions and rankings count alert groups.",
    ]
    for title, counts in (
        ("Severity", report["severity_counts"]),
        ("Rule SID", report["sid_counts"]),
        ("Classtype", report["classtype_counts"]),
        ("Transport protocol", report["protocol_counts"]),
        ("Application protocol", report["application_protocol_counts"]),
        ("Alerts per hour (UTC)", report["alerts_by_hour_utc"]),
    ):
        lines.extend(_count_section(title, counts.items()))

    for label, ranking in (
        ("SID", report["top_sids"]),
        ("classtype", report["top_classtypes"]),
        ("source IP", report["top_src_ips"]),
        ("destination IP", report["top_dst_ips"]),
    ):
        lines.extend(_count_section(f"Top {report['top_n']} {label}", (
            (entry["value"], entry["alerts"]) for entry in ranking
        )))
    return "\n".join(lines) + "\n"


def render_report_json(report: AlertReport) -> str:
    return json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2) + "\n"


def _write_utf8(path: str | Path, content: str) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")


def write_report(
    report: AlertReport, *, text_output: str | Path | TextIO, json_output: str | Path,
    protected_paths: Iterable[str | Path] = (),
) -> None:
    """Ghi JSON ra file và ghi text ra file hoặc stream do caller quản lý."""
    outputs = {"report JSON": json_output}
    if isinstance(text_output, (str, Path)):
        outputs["report text"] = text_output
    validate_output_paths(outputs, protected_paths)

    text_content = render_report_text(report)
    json_content = render_report_json(report)
    _write_utf8(json_output, json_content)
    if isinstance(text_output, (str, Path)):
        _write_utf8(text_output, text_content)
    else:
        text_output.write(text_content)

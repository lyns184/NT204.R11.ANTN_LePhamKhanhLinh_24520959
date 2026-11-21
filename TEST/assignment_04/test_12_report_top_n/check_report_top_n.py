"""TC12 — Kiểm tra xếp hạng Top-N theo nhóm Alert."""

import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from ids.alert.config import AlertConfig, Severity
from ids.alert.models import Alert
from ids.alert.repository import AlertRepository
from ids.report.generator import generate_report


START = 1700000000.0
# SID, classtype, octet cuối của IP nguồn và IP đích, count.
ROWS = (
    (104121, "lab-http", 1, 3, 1),
    (104123, None, 1, 2, 25),
    (104123, None, 3, 1, 1),
    (104122, "lab-dns", 3, 1, 1),
    (104122, "lab-dns", 2, 2, 1),
    (104121, "lab-http", 1, 2, 1),
    (104121, "lab-http", 2, 3, 1),
)
EXPECTED_RANKS = {
    "top_sids": [(104121, 3), (104122, 2), (104123, 2)],
    "top_classtypes": [("lab-http", 3), ("UNKNOWN", 2), ("lab-dns", 2)],
    "top_src_ips": [("192.0.2.1", 3), ("192.0.2.2", 2), ("192.0.2.3", 2)],
    "top_dst_ips": [("198.51.100.2", 3), ("198.51.100.1", 2), ("198.51.100.3", 2)],
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_checks(log):
    reports = {}
    with TemporaryDirectory(prefix="tc12_", dir=FOLDER) as temporary:
        config = AlertConfig(storage_path=Path(temporary) / "alerts.sqlite3", top_n=2)
        writer = AlertRepository(config.storage_path)
        for index, (sid, classtype, src, dst, count) in enumerate(ROWS, 1):
            timestamp = START + index
            writer.insert(Alert(
                alert_id=str(UUID(int=index, version=4)), sid=sid, msg="Nhóm Alert cho Top-N",
                severity=Severity.HIGH, classtype=classtype, src_ip=f"192.0.2.{src}",
                dst_ip=f"198.51.100.{dst}", first_seen=timestamp, last_seen=timestamp, count=count,
            ), run_id="fixture-tc12")

        reader = AlertRepository(config.storage_path, read_only=True)
        for name, top_n in (("top_2", config.top_n), ("top_10", 10)):
            report = generate_report(reader, from_time=START, to_time=START + 60, top_n=top_n)
            require((report["total_alerts"], report["total_occurrences"]) == (7, 31),
                    f"{name}: fixture should contain seven groups and 31 occurrences")
            require(report["top_n"] == top_n, f"{name}: report lost the selected Top-N")
            for field, ranking in EXPECTED_RANKS.items():
                actual = [(entry["value"], entry["alerts"]) for entry in report[field]]
                require(actual == ranking[:top_n], f"{name}/{field}: unexpected ordering or count: {actual}")
                log.append(f"PASS {name}/{field}: {actual}")
            require(report["sid_counts"] == {"104121": 3, "104122": 2, "104123": 2},
                    f"{name}: full SID counts should remain available")
            require(report["classtype_counts"] == {"UNKNOWN": 2, "lab-dns": 2, "lab-http": 3},
                    f"{name}: full classtype counts should remain available")
            reports[name] = report

    output = FOLDER / "result_top_n.json"
    output.write_text(json.dumps(reports, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    require(json.loads(output.read_text(encoding="utf-8")) == reports, "JSON result did not roundtrip")
    log.append("PASS TC12: all four rankings count groups and handle ties and Top-N limits correctly.")


def main():
    log = ["TC12: seven simulated alert groups; one group alone has count=25."]
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL TC12: {type(error).__name__}: {error}")
        code = 1
    console = "\n".join(log) + "\n"
    (FOLDER / "console.txt").write_text(console, encoding="utf-8")
    print(console, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

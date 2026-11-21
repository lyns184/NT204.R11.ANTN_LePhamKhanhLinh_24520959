"""TC09 — Lưu Alert, mở lại SQLite và đối chiếu toàn bộ dữ liệu."""

import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[3]
FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from ids.alert.config import Severity
from ids.alert.models import Alert
from ids.alert.repository import AlertRepository


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_checks(log):
    fixture = FOLDER / "input_alerts.json"
    original = fixture.read_bytes()
    expected = json.loads(original.decode("utf-8"))
    require(len(expected) == 2, "Expected two fixture alerts")
    with TemporaryDirectory(prefix="tc09_", dir=FOLDER) as temporary:
        database = Path(temporary) / "alerts.sqlite3"
        writer = AlertRepository(database)
        require(writer.query() == [], "New repository should have no alerts")
        # Đảo thứ tự ghi để lần đọc còn kiểm tra sắp xếp theo first_seen.
        for row in reversed(expected):
            fields = row.copy()
            run_id = fields.pop("run_id")
            fields.pop("timestamp")
            fields["severity"] = Severity(fields["severity"])
            saved = writer.insert(Alert(**fields), run_id=run_id)
            require(saved.alert_id == row["alert_id"] and saved.run_id == run_id,
                    "Insert changed the alert ID or its run")
            log.append(f"PASS insert: sid={saved.sid}, run_id={run_id}, count={saved.count}")

        # Repository tự đóng kết nối ghi sau mỗi insert.
        persisted_bytes = database.read_bytes()
        reader = AlertRepository(database, read_only=True)
        actual = [alert.to_dict() for alert in reader.query()]
        require(len(actual) == len(expected), "Reopened DB lost an alert or returned a duplicate")
        for wanted, received in zip(expected, actual, strict=True):
            require(received.keys() == wanted.keys(), f"SID {wanted['sid']}: schema mismatch")
            for key, value in wanted.items():
                require(type(received[key]) is type(value) and received[key] == value,
                        f"SID {wanted['sid']}/{key}: expected {value!r}, got {received[key]!r}")
            log.append(f"PASS reopen: sid={received['sid']}, all {len(wanted)} fields match")
        require(database.read_bytes() == persisted_bytes, "Read-only query changed the DB")

    require(fixture.read_bytes() == original, "Test changed the input fixture")
    output = FOLDER / "result_repository.json"
    output.write_text(json.dumps(actual, ensure_ascii=False, allow_nan=False, indent=2) + "\n", encoding="utf-8")
    require(json.loads(output.read_text(encoding="utf-8")) == expected, "JSON result did not roundtrip")
    log.append("PASS TC09: two alerts reopened, complete and nullable metadata preserved, DB unchanged on read.")


def main():
    log = ["TC09: fixed alert fixtures, real SQLite with independent write/read connections."]
    code = 0
    try:
        run_checks(log)
    except Exception as error:
        log.append(f"FAIL TC09: {type(error).__name__}: {error}")
        code = 1
    console = "\n".join(log) + "\n"
    (FOLDER / "console.txt").write_text(console, encoding="utf-8")
    print(console, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())

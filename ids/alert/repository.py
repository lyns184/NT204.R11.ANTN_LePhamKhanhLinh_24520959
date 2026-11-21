"""Lưu và truy vấn các nhóm Alert trong SQLite."""

import math
import sqlite3
from contextlib import closing
from dataclasses import replace
from pathlib import Path

from ids.alert.config import Severity
from ids.alert.models import Alert, AlertAggregationResult


_CREATE_ALERTS = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY NOT NULL,
    run_id TEXT NOT NULL CHECK (length(run_id) > 0),
    sid INTEGER NOT NULL,
    msg TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL CHECK (last_seen >= first_seen),
    count INTEGER NOT NULL CHECK (typeof(count) = 'integer' AND count >= 1),
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    application_protocol TEXT,
    flow_id TEXT,
    classtype TEXT,
    priority INTEGER,
    rev INTEGER
)
"""

_INSERT_ALERT = """
INSERT INTO alerts (
    alert_id, run_id, sid, msg, severity, src_ip, dst_ip, first_seen, last_seen,
    count, src_port, dst_port, protocol, application_protocol, flow_id, classtype, priority, rev
) VALUES (
    :alert_id, :run_id, :sid, :msg, :severity, :src_ip, :dst_ip, :first_seen, :last_seen,
    :count, :src_port, :dst_port, :protocol, :application_protocol, :flow_id, :classtype, :priority, :rev
)
"""


_FIND_ALERT_GROUP = """
SELECT * FROM alerts
WHERE run_id = :run_id AND sid = :sid AND src_ip = :src_ip AND dst_ip = :dst_ip
  AND protocol IS :protocol AND application_protocol IS :application_protocol
  AND first_seen <= :first_seen
ORDER BY first_seen DESC, alert_id
LIMIT 1
"""


def _finite_timestamp(value: object, name: str) -> float:
    try:
        if type(value) in (int, float) and math.isfinite(value):
            return float(value)
    except OverflowError:
        pass
    raise ValueError(f"{name} must be a finite Unix timestamp")


def _with_run_id(alert: Alert, run_id: str) -> Alert:
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("run_id must be a nonempty string")
    if alert.run_id is not None and alert.run_id != run_id:
        raise ValueError("alert.run_id must match run_id")
    return replace(alert, run_id=run_id)


def _from_row(row: sqlite3.Row) -> Alert:
    return Alert(**{**dict(row), "severity": Severity(row["severity"])})


def sqlite_storage_paths(path: Path) -> tuple[Path, ...]:
    """File DB và các file SQLite có thể tạo cạnh nó."""
    return (path, *(path.with_name(path.name + suffix) for suffix in ("-journal", "-wal", "-shm")))


class AlertRepository:
    """Mỗi thao tác mở và đóng kết nối trên thread gọi.

    File tồn tại qua nhiều lần chạy. Report có thể mở ở chế độ chỉ đọc.
    """

    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        if not isinstance(path, (str, Path)) or not str(path).strip() or "\x00" in str(path):
            raise ValueError("Alert storage path must be nonempty and contain no NUL")
        self.path = Path(path).resolve()
        self._read_only = read_only
        if self.path.is_dir():
            raise ValueError(f"Alert storage path must be a file: {self.path}")
        if not read_only:
            self.path.parent.mkdir(parents=True, exist_ok=True)

        with closing(self._connect()) as connection, connection:
            if read_only:
                connection.execute("SELECT 1 FROM alerts LIMIT 0")
            else:
                connection.execute("BEGIN")
                connection.execute(_CREATE_ALERTS)
                connection.execute("CREATE INDEX IF NOT EXISTS alerts_first_seen_idx ON alerts(first_seen)")
                connection.execute("CREATE INDEX IF NOT EXISTS alerts_run_seen_idx ON alerts(run_id, first_seen)")
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS alerts_group_idx ON alerts("
                    "run_id, sid, src_ip, dst_ip, protocol, application_protocol, first_seen DESC, alert_id)"
                )

    def _connect(self) -> sqlite3.Connection:
        if self._read_only:
            connection = sqlite3.connect(f"{self.path.as_uri()}?mode=ro", uri=True)
        else:
            connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _insert(connection: sqlite3.Connection, alert: Alert) -> None:
        _finite_timestamp(alert.first_seen, "first_seen")
        _finite_timestamp(alert.last_seen, "last_seen")
        connection.execute(_INSERT_ALERT, alert.to_dict())

    def insert(self, alert: Alert, *, run_id: str) -> Alert:
        """Lưu một nhóm mới. Trùng alert_id sẽ báo lỗi và giữ bản ghi cũ."""
        stored = _with_run_id(alert, run_id)
        with closing(self._connect()) as connection, connection:
            self._insert(connection, stored)
        return stored

    def record(
        self, alert: Alert, *, run_id: str, window_seconds: float | None
    ) -> AlertAggregationResult:
        """Ghi một detection đã qua filter. None là chế độ tắt aggregation.

        Nhóm bắt đầu tại first_seen và nhận event trong [first_seen, first_seen + window).
        Nhóm bắt đầu gần nhất ở trước hoặc tại timestamp được ưu tiên. Vì thế
        nhóm tạo từ event đến muộn chỉ nhận event trước khi nhóm kế tiếp bắt đầu.
        """
        timestamp = _finite_timestamp(alert.first_seen, "first_seen")
        last_seen = _finite_timestamp(alert.last_seen, "last_seen")
        if type(alert.count) is not int or alert.count != 1 or last_seen != timestamp:
            raise ValueError("record expects one detection with first_seen equal to last_seen")
        if window_seconds is None:
            return AlertAggregationResult(self.insert(alert, run_id=run_id), "created")
        window = _finite_timestamp(window_seconds, "window_seconds")
        if window <= 0:
            raise ValueError("window_seconds must be positive")
        incoming = _with_run_id(alert, run_id)

        with closing(self._connect()) as connection, connection:
            # Khóa ghi trước SELECT để các callback không đọc cùng count cũ.
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(_FIND_ALERT_GROUP, incoming.to_dict()).fetchone()
            if row is not None and (
                timestamp == row["first_seen"] or timestamp < row["first_seen"] + window
            ):
                group = _from_row(row)
                updated = replace(group, last_seen=max(group.last_seen, timestamp), count=group.count + 1)
                connection.execute(
                    "UPDATE alerts SET last_seen = ?, count = ? WHERE alert_id = ?",
                    (updated.last_seen, updated.count, updated.alert_id),
                )
                return AlertAggregationResult(updated, "aggregated")
            self._insert(connection, incoming)
            return AlertAggregationResult(incoming, "created")

    def query(
        self,
        *,
        from_time: float | None = None,
        to_time: float | None = None,
        severity: Severity | str | None = None,
        sid: int | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        run_id: str | None = None,
    ) -> list[Alert]:
        """Kết hợp filter bằng AND, theo first_seen trong khoảng [from, to)."""
        if from_time is not None:
            from_time = _finite_timestamp(from_time, "from_time")
        if to_time is not None:
            to_time = _finite_timestamp(to_time, "to_time")
        if from_time is not None and to_time is not None and from_time >= to_time:
            raise ValueError("from_time must be earlier than to_time")
        if severity is not None:
            severity = Severity(severity).value

        filters = (
            ("first_seen >= ?", from_time),
            ("first_seen < ?", to_time),
            ("severity = ?", severity),
            ("sid = ?", sid),
            ("src_ip = ?", src_ip),
            ("dst_ip = ?", dst_ip),
            ("run_id = ?", run_id),
        )
        conditions = [clause for clause, value in filters if value is not None]
        parameters = [value for _, value in filters if value is not None]
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM alerts" + where + " ORDER BY first_seen, alert_id",
                parameters,
            )
            return [_from_row(row) for row in rows]

"""Đọc và kiểm tra cấu hình Bài 4 trước khi mở các đầu ra."""

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any

from ids.detection.models import MAX_RULE_NUMBER


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertConfigError(ValueError):
    """Cấu hình Alert/Report không đọc được hoặc không hợp lệ."""


def _severity(value: object, name: str) -> Severity:
    try:
        return Severity(value)
    except ValueError as exc:
        raise AlertConfigError(f"{name} must be LOW, MEDIUM, HIGH or CRITICAL") from exc


def _storage_path(value: str | Path, base: Path | None = None) -> Path:
    if not isinstance(value, (str, Path)) or not str(value).strip() or "\x00" in str(value):
        raise AlertConfigError("storage_path must be a nonempty path without NUL")
    path = Path(value)
    if base is not None:
        path = base / path
    path = path.resolve()
    if path.is_dir():
        raise AlertConfigError(f"storage_path must name a SQLite file, not a directory: {path}")
    return path


@dataclass(frozen=True)
class AlertConfig:
    """Cấu hình dùng chung cho Alert và Report trong một lần chạy."""

    severity_mapping: Mapping[int, Severity] = field(default_factory=lambda: {
        1: Severity.CRITICAL, 2: Severity.HIGH, 3: Severity.MEDIUM, 4: Severity.LOW,
    })
    default_severity: Severity = Severity.LOW
    min_severity: Severity = Severity.LOW
    suppressed_sids: frozenset[int] = frozenset()
    aggregation_enabled: bool = True
    aggregation_window_seconds: float = 60.0
    storage_type: str = "sqlite"
    storage_path: Path = Path("output/alerts.sqlite3")
    top_n: int = 10

    def __post_init__(self) -> None:
        if not isinstance(self.severity_mapping, Mapping):
            raise AlertConfigError("severity_mapping must be an object")
        mapping = {}
        for priority, level in self.severity_mapping.items():
            if type(priority) is not int or not 1 <= priority <= MAX_RULE_NUMBER:
                raise AlertConfigError(f"severity_mapping priorities must be integers in 1..{MAX_RULE_NUMBER}")
            mapping[priority] = _severity(level, f"severity_mapping[{priority}]")
        object.__setattr__(self, "severity_mapping", MappingProxyType(mapping))
        for name in ("default_severity", "min_severity"):
            object.__setattr__(self, name, _severity(getattr(self, name), name))

        if not isinstance(self.suppressed_sids, (list, tuple, set, frozenset)) or any(
            type(sid) is not int or not 1 <= sid <= MAX_RULE_NUMBER for sid in self.suppressed_sids
        ):
            raise AlertConfigError(f"suppressed_sids must be a list of integers in 1..{MAX_RULE_NUMBER}")
        object.__setattr__(self, "suppressed_sids", frozenset(self.suppressed_sids))
        if type(self.aggregation_enabled) is not bool:
            raise AlertConfigError("aggregation_enabled must be a boolean")
        window = self.aggregation_window_seconds
        try:
            valid_window = type(window) in (int, float) and math.isfinite(window) and window > 0
        except OverflowError:
            valid_window = False
        if not valid_window:
            raise AlertConfigError("aggregation_window_seconds must be a finite positive number")
        if self.storage_type != "sqlite":
            raise AlertConfigError("storage_type must be sqlite")
        object.__setattr__(self, "storage_path", _storage_path(self.storage_path))
        if type(self.top_n) is not int or self.top_n <= 0:
            raise AlertConfigError("top_n must be a positive integer")

    def severity_for(self, priority: int | None) -> Severity:
        """Ánh xạ priority đã kiểm tra, dùng mức mặc định khi thiếu mapping."""
        return self.severity_mapping.get(priority, self.default_severity)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AlertConfigError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def load_alert_config(path: str | Path | None = None) -> AlertConfig:
    """Đọc JSON UTF-8/BOM, resolve storage_path tương đối từ thư mục config.

    Nếu không truyền file, dùng các giá trị mặc định từ thư mục làm việc.
    Mapping do người dùng cung cấp thay toàn bộ mapping mặc định.
    """
    if path is None:
        return AlertConfig()
    try:
        config_path = Path(path).resolve()
        data = json.loads(config_path.read_text(encoding="utf-8-sig"), object_pairs_hook=_unique_object)
        if not isinstance(data, dict):
            raise AlertConfigError("config root must be an object")
        unknown = data.keys() - {item.name for item in fields(AlertConfig)}
        if unknown:
            raise AlertConfigError(f"Unknown config keys: {', '.join(sorted(unknown))}")
        if "severity_mapping" in data:
            mapping = data["severity_mapping"]
            if not isinstance(mapping, dict):
                raise AlertConfigError("severity_mapping must be an object")
            if any(
                not key.isascii() or not key.isdecimal() or key.startswith("0")
                or len(key) > len(str(MAX_RULE_NUMBER)) for key in mapping
            ):
                raise AlertConfigError(f"severity_mapping keys must be decimal priorities in 1..{MAX_RULE_NUMBER}")
            data["severity_mapping"] = {int(key): value for key, value in mapping.items()}
        data["storage_path"] = _storage_path(
            data.get("storage_path", AlertConfig.storage_path), config_path.parent
        )
        return AlertConfig(**data)
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        raise AlertConfigError(f"Invalid Alert/Report config {path}: {exc}") from exc

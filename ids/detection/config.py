"""Cấu hình bật/tắt rules; path trong JSON tính từ thư mục file cấu hình."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ids.detection.models import MAX_RULE_NUMBER, Diagnostic, RuleSource


def _resolve_path(value: str | Path, base: Path | None = None) -> Path:
    if not isinstance(value, (str, Path)):
        raise ValueError("path must be a string or pathlib.Path")
    if isinstance(value, str) and (not value.strip() or "\x00" in value):
        raise ValueError("path must be nonempty and contain no NUL")
    path = Path(value)
    if base is not None and not path.is_absolute():
        path = base / path
    return path.resolve()


@dataclass(frozen=True)
class RuleConfig:
    """Snapshot bất biến; constructor trực tiếp resolve path từ cwd.

    Dùng load_rule_config() để resolve disabled_files từ thư mục JSON.
    Không cấu hình tương đương hai tập rỗng; không tự nạp disabled_files.
    """

    disabled_files: frozenset[Path] = frozenset()
    disabled_sids: frozenset[int] = frozenset()

    def __post_init__(self) -> None:
        for name in ("disabled_files", "disabled_sids"):
            if not isinstance(getattr(self, name), (list, tuple, set, frozenset)):
                raise ValueError(f"{name} must be a list, tuple or set")
        files = frozenset(_resolve_path(item) for item in self.disabled_files)
        if any(type(sid) is not int or not 1 <= sid <= MAX_RULE_NUMBER
               for sid in self.disabled_sids):
            raise ValueError(f"disabled_sids must contain integers in 1..{MAX_RULE_NUMBER}")
        object.__setattr__(self, "disabled_files", files)
        object.__setattr__(self, "disabled_sids", frozenset(self.disabled_sids))

    def to_dict(self) -> dict[str, Any]:
        return {"disabled_files": sorted(str(path) for path in self.disabled_files),
                "disabled_sids": sorted(self.disabled_sids)}


class RuleConfigError(ValueError):
    """Lỗi khởi động do file cấu hình; diagnostic có thể xuất JSON."""

    def __init__(self, diagnostic: Diagnostic) -> None:
        self.diagnostic = diagnostic
        super().__init__(diagnostic.reason)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"Non-finite JSON value is not supported: {value}")


def load_rule_config(path: str | Path | None = None) -> RuleConfig:
    """Đọc JSON UTF-8 (chấp nhận BOM); lỗi config không bị bỏ qua.

    Chỉ nhận disabled_files/disabled_sids dạng list. Từ chối key lạ/lặp,
    null, SID bool/string/float và path rỗng. File disabled không cần tồn tại.
    """
    if path is None:
        return RuleConfig()
    source = None
    try:
        resolved = _resolve_path(path)
        source = RuleSource(str(resolved), 1)
    except (ValueError, OSError, RuntimeError) as exc:
        raise RuleConfigError(Diagnostic("config_path_error", f"Invalid config path: {exc}",
                                         category="configuration")) from exc
    try:
        text = resolved.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError, ValueError) as exc:
        raise RuleConfigError(Diagnostic("config_read_error", f"Cannot read config {resolved}: {exc}",
                                         category="configuration", source=source)) from exc
    try:
        data = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, json.JSONDecodeError):
            source = RuleSource(str(resolved), exc.lineno)
        raise RuleConfigError(Diagnostic("config_json_error", f"Invalid config JSON: {exc}",
                                         category="configuration", source=source)) from exc
    try:
        if not isinstance(data, dict):
            raise ValueError("config root must be an object")
        unknown = data.keys() - {"disabled_files", "disabled_sids"}
        if unknown:
            raise ValueError(f"Unknown config keys: {', '.join(sorted(unknown))}")
        for key in ("disabled_files", "disabled_sids"):
            if key in data and not isinstance(data[key], list):
                raise ValueError(f"{key} must be a JSON list")
        files = data.get("disabled_files", [])
        if any(not isinstance(item, str) for item in files):
            raise ValueError("disabled_files entries must be nonempty strings")
        return RuleConfig(disabled_files=[_resolve_path(item, resolved.parent) for item in files],
                          disabled_sids=data.get("disabled_sids", []))
    except (ValueError, OSError, RuntimeError) as exc:
        raise RuleConfigError(Diagnostic("config_validation_error", f"Invalid config: {exc}",
                                         category="configuration", source=source)) from exc

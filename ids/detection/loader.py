"""Nạp rules một lần theo thứ tự file/dòng; chưa index hoặc match packet."""

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ids.detection.config import RuleConfig, _resolve_path
from ids.detection.models import Diagnostic, JSONModel, ParseStatus, Rule, RuleSource
from ids.detection.parser import parse_rule


@dataclass(frozen=True)
class RuleLoadEntry(JSONModel):
    """Một dòng rule; chỉ entry enabled mới được chuyển sang repository."""

    source: RuleSource
    status: Literal["enabled", "invalid", "unsupported", "disabled", "duplicate"]
    rule: Rule | None
    diagnostics: tuple[Diagnostic, ...] = ()


@dataclass(frozen=True)
class RuleFileResult(JSONModel):
    path: str
    status: Literal["loaded", "disabled", "duplicate"]
    lines_read: int = 0
    diagnostic: Diagnostic | None = None


@dataclass(frozen=True)
class LoadReport:
    """Báo cáo bất biến do Loader tạo; counters đếm entry, không đếm diagnostic.

    files có một entry cho mỗi path yêu cầu, kể cả alias bị dedup. entries chỉ
    chứa các dòng không trống/comment trong file loaded. Report trong exception
    là tiến độ trước lỗi, không phải một tập rule đã nạp thành công.
    """

    files: tuple[RuleFileResult, ...] = ()
    entries: tuple[RuleLoadEntry, ...] = ()

    @property
    def enabled_rules(self) -> tuple[Rule, ...]:
        return tuple(entry.rule for entry in self.entries if entry.status == "enabled")

    @property
    def diagnostics(self) -> tuple[Diagnostic, ...]:
        return (tuple(item.diagnostic for item in self.files if item.diagnostic is not None)
                + tuple(diag for entry in self.entries for diag in entry.diagnostics))

    @property
    def counts(self) -> dict[str, int]:
        return {
            "files_requested": len(self.files),
            **{f"files_{status}": sum(item.status == status for item in self.files)
               for status in ("loaded", "disabled", "duplicate")},
            "lines_read": sum(item.lines_read for item in self.files),
            "rules_total": len(self.entries),
            **{f"rules_{status}": sum(entry.status == status for entry in self.entries)
               for status in ("enabled", "invalid", "unsupported", "disabled", "duplicate")},
        }

    def to_dict(self) -> dict[str, Any]:
        return {"enabled_rules": [rule.to_dict() for rule in self.enabled_rules],
                "files": [item.to_dict() for item in self.files],
                "entries": [entry.to_dict() for entry in self.entries],
                "diagnostics": [diag.to_dict() for diag in self.diagnostics],
                "counts": self.counts}


class RuleLoadError(RuntimeError):
    """Lỗi startup; caller phải dừng khởi tạo engine, kể cả đã đọc được rule."""

    def __init__(self, diagnostic: Diagnostic, report: LoadReport) -> None:
        self.diagnostic = diagnostic
        self.report = report
        super().__init__(diagnostic.reason)


def load_rules(paths: Iterable[str | Path], config: RuleConfig | None = None) -> LoadReport:
    """Nạp file UTF-8 (BOM tùy chọn), mỗi rule trên một dòng vật lý.

    Bỏ qua dòng trống/comment, file disabled và path alias đã đọc. Rule lỗi
    được ghi diagnostic rồi tiếp tục. SID disabled chỉ xét sau validation;
    SID trùng giữ rule valid+enabled đầu tiên, không chọn revision lớn hơn.
    File bật không đọc được hoặc không còn rule enabled gây RuleLoadError.
    """
    if isinstance(paths, (str, bytes, Path)) or not isinstance(paths, Iterable):
        raise TypeError("paths must be an iterable of rule file paths, not a single path")
    if config is None:
        config = RuleConfig()
    if not isinstance(config, RuleConfig):
        raise TypeError("config must be RuleConfig or None")

    files: list[RuleFileResult] = []
    entries: list[RuleLoadEntry] = []
    seen_paths: set[Path] = set()
    enabled_by_sid: dict[int, Rule] = {}

    def fail(code: str, reason: str) -> RuleLoadError:
        return RuleLoadError(Diagnostic(code, reason, category="input"),
                             LoadReport(tuple(files), tuple(entries)))

    for value in paths:
        try:
            path = _resolve_path(value)
        except (ValueError, OSError, RuntimeError) as exc:
            raise fail("rule_path_error", f"Invalid rule file path: {exc}") from exc
        if path in seen_paths:
            files.append(RuleFileResult(str(path), "duplicate", diagnostic=Diagnostic(
                "duplicate_file", f"Rule file already requested: {path}", category="input")))
            continue
        seen_paths.add(path)
        if path in config.disabled_files:
            files.append(RuleFileResult(str(path), "disabled", diagnostic=Diagnostic(
                "disabled_file", f"Rule file disabled by config: {path}", category="disabled")))
            continue
        try:
            # Đọc/giải mã toàn file trước parse: lỗi UTF-8 không thành EOF thành công.
            text = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError, ValueError) as exc:
            raise fail("rule_file_read_error", f"Cannot read rule file {path}: {exc}") from exc
        # read_text dùng universal newlines (CRLF/CR -> LF). Không dùng splitlines:
        # VT/FF/NEL trong chuỗi không được trở thành ranh giới rule mới.
        lines = text.split("\n") if text else []
        if lines and lines[-1] == "":
            lines.pop()
        files.append(RuleFileResult(str(path), "loaded", len(lines)))
        for number, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#"):
                continue
            source = RuleSource(str(path), number)
            result = parse_rule(line, source)
            if result.status != ParseStatus.VALID:
                entries.append(RuleLoadEntry(source, result.status.value, None, result.diagnostics))
                continue
            rule = result.rule
            if rule.sid in config.disabled_sids:
                entries.append(RuleLoadEntry(source, "disabled", rule, (Diagnostic(
                    "disabled_sid", f"SID {rule.sid} disabled by config", category="disabled",
                    source=source, keyword="sid"),)))
            elif rule.sid in enabled_by_sid:
                first = enabled_by_sid[rule.sid].source
                entries.append(RuleLoadEntry(source, "duplicate", rule, (Diagnostic(
                    "duplicate_sid", f"SID {rule.sid} already enabled at {first.file}:{first.line}; "
                    "keeping the first valid enabled rule", category="invalid", source=source,
                    keyword="sid"),)))
            else:
                enabled_by_sid[rule.sid] = rule
                entries.append(RuleLoadEntry(source, "enabled", rule))

    report = LoadReport(tuple(files), tuple(entries))
    if not report.enabled_rules:
        raise fail("no_enabled_rules", "No valid enabled rules remain after loading")
    return report

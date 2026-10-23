"""Kiểm tra alias của output/input trước khi mở writer ở mode w."""

from collections.abc import Iterable, Mapping
from pathlib import Path


def _path(value: str | Path) -> Path:
    if not isinstance(value, (str, Path)) or not str(value).strip() or "\x00" in str(value):
        raise ValueError("File path must be nonempty and contain no NUL")
    return Path(value).resolve()


def _same(first: Path, second: Path) -> bool:
    # resolve xử lý relative/symlink và Path equality theo semantics OS.
    # samefile nhận cả hard-link aliases khi hai file đã tồn tại.
    if first == second:
        return True
    try:
        return first.samefile(second)
    except FileNotFoundError:
        return False


def validate_output_paths(outputs: Mapping[str, str | Path], inputs: Iterable[str | Path]) -> None:
    resolved_outputs = [(name, _path(path)) for name, path in outputs.items()]
    resolved_inputs = [_path(path) for path in inputs]
    for index, (name, path) in enumerate(resolved_outputs):
        for other_name, other in resolved_outputs[:index]:
            if _same(path, other):
                raise ValueError(f"Output {name} and {other_name} must be different files: {path}")
        for source in resolved_inputs:
            if _same(path, source):
                raise ValueError(f"Output {name} must not overwrite input: {source}")

import json
from pathlib import Path
from typing import TextIO

from ids.core.event import IDSEvent


class JSONLWriter:
    """Ghi mỗi IDSEvent thành một dòng JSON."""

    def __init__(self, file_path: str) -> None:
        self.path = Path(file_path)
        self.file: TextIO | None = None

    def __enter__(self) -> "JSONLWriter":
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.file = self.path.open(
            mode="w",
            encoding="utf-8",
        )

        return self

    def write(self, event: IDSEvent) -> None:
        if self.file is None:
            raise RuntimeError("JSONLWriter chưa được mở")

        json_line = json.dumps(
            event.to_dict(),
            # Escape Unicode, including lone surrogates that UTF-8 cannot encode.
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        )

        self.file.write(json_line + "\n")
        self.file.flush()

    def __exit__(
        self,
        exception_type,
        exception_value,
        traceback,
    ) -> None:
        if self.file is not None:
            self.file.close()

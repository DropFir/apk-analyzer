"""Small data models shared by the scanner and UI."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

Severity = Literal["info", "warning", "error"]


@dataclass(frozen=True, slots=True)
class Finding:
    severity: Severity
    code: str
    message: str
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}


class ScanFailure(RuntimeError):
    """Raised for a controlled scan failure that should be shown to the editor."""

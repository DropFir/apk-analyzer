from __future__ import annotations

import pytest

import apkba_analyzer.scanner as scanner


@pytest.fixture(autouse=True)
def synthetic_archives_do_not_use_host_signer(monkeypatch: pytest.MonkeyPatch) -> None:
    """Synthetic ZIP fixtures are not signed Android packages."""

    monkeypatch.setattr(scanner, "find_apksigner", lambda _apkanalyzer=None: None)
    monkeypatch.setattr(
        scanner,
        "_verify_apk_signature",
        lambda _path, _tool: {
            "status": "not_verified",
            "verified": False,
            "certificateSha256": [],
            "tool": "none",
            "error": "synthetic fixture",
        },
    )

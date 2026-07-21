from __future__ import annotations

import subprocess
from pathlib import Path

import apkba_analyzer.scanner as scanner


def test_apksigner_uses_current_signer_certificate_only(monkeypatch) -> None:
    output = (
        "Verifies\n"
        "Verified using v2 scheme (APK Signature Scheme v2): true\n"
        f"Signer #1 certificate SHA-256 digest: {'a' * 64}\n"
        f"Signer #1 certificate public key SHA-256 digest: {'b' * 64}\n"
        f"Source Stamp Signer certificate SHA-256 digest: {'c' * 64}\n"
    )
    monkeypatch.setattr(
        scanner,
        "run_tool",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, output, ""),
    )

    result = scanner._verify_signature_with_apksigner(Path("fixture.apk"), Path("apksigner"))

    assert result["verified"] is True
    assert result["certificateSha256"] == ["A" * 64]


def test_apksigner_blocks_missing_certificate_digest(monkeypatch) -> None:
    monkeypatch.setattr(
        scanner,
        "run_tool",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "Verifies\n", ""),
    )

    result = scanner._verify_signature_with_apksigner(Path("fixture.apk"), Path("apksigner"))

    assert result["status"] == "certificate_missing"
    assert result["verified"] is False
    assert result["certificateSha256"] == []

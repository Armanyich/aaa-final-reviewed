from __future__ import annotations

from datetime import date
from pathlib import Path

from webconf_audit.fingerprints import finding_fingerprint
from webconf_audit.models import AnalysisResult, Finding, SourceLocation
from webconf_audit.suppressions import (
    apply_suppressions,
    load_suppression_file,
    suppressed_findings,
)


def _finding() -> Finding:
    return Finding(
        rule_id="nginx.weak_ssl_protocols",
        title="Weak SSL protocols",
        severity="medium",
        description="desc",
        recommendation="rec",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path="nginx.conf",
            line=7,
        ),
    )


def _result() -> AnalysisResult:
    return AnalysisResult(
        mode="local",
        target="nginx.conf",
        server_type="nginx",
        findings=[_finding()],
    )


def _write_suppressions(path: Path, body_lines: list[str]) -> None:
    path.write_text(
        "\n".join(["suppressions:", *body_lines]),
        encoding="utf-8",
    )


def test_missing_default_suppression_file_is_empty(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    suppressions = load_suppression_file(load_default=True)

    assert suppressions.entries == ()
    assert suppressions.issues == ()


def test_fingerprint_suppression_removes_finding(tmp_path: Path) -> None:
    result = _result()
    fingerprint = finding_fingerprint(result, result.findings[0])
    path = tmp_path / ".webconf-audit-ignore.yml"
    _write_suppressions(
        path,
        [
            "  - rule_id: nginx.weak_ssl_protocols",
            f"    fingerprint: {fingerprint}",
            "    reason: accepted during TLS migration",
            "    expires: 2099-01-01",
        ],
    )

    suppressions = load_suppression_file(str(path), today=date(2026, 1, 1))
    apply_suppressions(result, suppressions)

    assert suppressions.issues == ()
    assert result.findings == []
    assert suppressed_findings(result)[0]["reason"] == "accepted during TLS migration"
    assert suppressed_findings(result)[0]["matched_by"] == "fingerprint"


def test_locator_suppression_removes_finding(tmp_path: Path) -> None:
    result = _result()
    path = tmp_path / "ignore.yml"
    _write_suppressions(
        path,
        [
            "  - rule_id: nginx.weak_ssl_protocols",
            "    source: nginx.conf",
            "    line: 7",
            "    reason: legacy endpoint tracked separately",
            "    expires: 2099-01-01",
        ],
    )

    suppressions = load_suppression_file(str(path), today=date(2026, 1, 1))
    apply_suppressions(result, suppressions)

    assert result.findings == []
    assert suppressed_findings(result)[0]["matched_by"] == "locator"


def test_expired_suppression_emits_issue_and_does_not_suppress(tmp_path: Path) -> None:
    result = _result()
    path = tmp_path / "ignore.yml"
    _write_suppressions(
        path,
        [
            "  - rule_id: nginx.weak_ssl_protocols",
            "    source: nginx.conf",
            "    line: 7",
            "    reason: old accepted risk",
            "    expires: 2000-01-01",
        ],
    )

    suppressions = load_suppression_file(str(path), today=date(2026, 1, 1))
    apply_suppressions(result, suppressions)

    assert len(result.findings) == 1
    assert suppressions.entries == ()
    assert suppressions.issues[0].code == "suppression_expired"
    assert suppressions.issues[0].level == "warning"


def test_missing_reason_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "ignore.yml"
    _write_suppressions(
        path,
        [
            "  - rule_id: nginx.weak_ssl_protocols",
            "    source: nginx.conf",
            "    line: 7",
            "    expires: 2099-01-01",
        ],
    )

    suppressions = load_suppression_file(str(path), today=date(2026, 1, 1))

    assert suppressions.entries == ()
    assert suppressions.issues[0].code == "suppression_file_invalid"
    assert suppressions.issues[0].level == "error"
    assert "'reason' is required" in suppressions.issues[0].message


def test_blank_locator_is_rejected_without_blanket_suppression(tmp_path: Path) -> None:
    result = _result()
    path = tmp_path / "ignore.yml"
    _write_suppressions(
        path,
        [
            "  - rule_id: nginx.weak_ssl_protocols",
            "    source: '   '",
            "    reason: invalid blank locator",
            "    expires: 2099-01-01",
        ],
    )

    suppressions = load_suppression_file(str(path), today=date(2026, 1, 1))
    apply_suppressions(result, suppressions)

    assert len(result.findings) == 1
    assert suppressions.entries == ()
    assert "either 'fingerprint' or locator fields are required" in suppressions.issues[0].message


def test_explicit_missing_suppression_file_is_error(tmp_path: Path) -> None:
    suppressions = load_suppression_file(str(tmp_path / "missing.yml"))

    assert suppressions.entries == ()
    assert suppressions.issues[0].code == "suppression_file_not_found"
    assert suppressions.issues[0].level == "error"

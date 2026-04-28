"""Helpers for attaching standards references to rule metadata."""

from __future__ import annotations

from webconf_audit.rule_registry import StandardCoverage, StandardReference

_OWASP_TOP10_2021_URLS = {
    "A01:2021": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "A02:2021": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "A05:2021": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
}


def cwe(
    cwe_id: int,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    return StandardReference(
        standard="CWE",
        reference=f"CWE-{cwe_id}",
        url=f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
        coverage=coverage,
        note=note,
    )


def owasp_top10_2021(
    category: str,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    return StandardReference(
        standard="OWASP Top 10",
        reference=category,
        url=_OWASP_TOP10_2021_URLS.get(category),
        coverage=coverage,
        note=note,
    )


def asvs_5(
    requirement: str,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    return StandardReference(
        standard="OWASP ASVS",
        reference=f"v5.0.0-{requirement}",
        url="https://owasp.org/www-project-application-security-verification-standard/",
        coverage=coverage,
        note=note,
    )


__all__ = ["asvs_5", "cwe", "owasp_top10_2021"]

"""universal.directory_listing_enabled

Fires when directory listing / directory browsing is explicitly enabled.
"""

from __future__ import annotations

from webconf_audit.local.normalized import NormalizedConfig
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

RULE_ID = "universal.directory_listing_enabled"


@rule(
    rule_id=RULE_ID,
    title="Directory listing / browsing enabled",
    severity="medium",
    description="Directory listing is enabled, which may expose internal file structure.",
    recommendation="Disable directory listing unless explicitly required.",
    category="universal",
    input_kind="normalized",
    tags=("access",),
    standards=(
        cwe(548),
        owasp_top10_2021("A05:2021"),
        asvs_5("13.4.3"),
    ),
    order=108,
)
def check(config: NormalizedConfig) -> list[Finding]:
    findings: list[Finding] = []
    for scope in config.scopes:
        if scope.access_policy is None:
            continue
        if scope.access_policy.directory_listing is not True:
            continue
        src = scope.access_policy.source
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Directory listing / browsing enabled",
                severity="medium",
                description=(
                    f"Scope '{scope.scope_name or '(unnamed)'}' has directory "
                    "listing enabled, which may expose internal file structure."
                ),
                recommendation="Disable directory listing unless explicitly required.",
                location=SourceLocation(
                    mode="local",
                    kind="xml" if src.xml_path else "file",
                    file_path=src.file_path,
                    line=src.line,
                    xml_path=src.xml_path,
                    details=f"server_type={config.server_type}",
                ),
            )
        )
    return findings

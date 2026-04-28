"""Verify that docs/rule-coverage.md stays in sync with the rule registry.

The document is the standards-mapping source for Stage 2 work and contains
both auto-generated columns (rule_id, severity, input_kind, tags, counts)
and hand-curated columns (CWE, OWASP, CIS). These tests guard the
auto-generated parts so a PR that adds, removes, or renames a rule cannot
silently leave the doc out of date.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from webconf_audit.cli import _ensure_all_rules_loaded
from webconf_audit.rule_registry import registry

_DOC_PATH = Path(__file__).resolve().parents[1] / "docs" / "rule-coverage.md"
_RULE_ID_PATTERN = re.compile(
    r"`((?:universal|nginx|apache|lighttpd|iis|external)\.[A-Za-z0-9_.]+)`"
)


def _document_text() -> str:
    return _DOC_PATH.read_text(encoding="utf-8")


def _documented_rule_ids() -> set[str]:
    return set(_RULE_ID_PATTERN.findall(_document_text()))


def _registered_rule_ids() -> set[str]:
    _ensure_all_rules_loaded()
    return {meta.rule_id for meta in registry.list_rules()}


def test_every_registered_rule_appears_in_doc() -> None:
    missing = _registered_rule_ids() - _documented_rule_ids()
    assert not missing, (
        "Rules registered but missing from docs/rule-coverage.md: "
        + ", ".join(sorted(missing))
    )


def test_doc_does_not_reference_unknown_rules() -> None:
    unknown = _documented_rule_ids() - _registered_rule_ids()
    assert not unknown, (
        "docs/rule-coverage.md references rules that are not registered: "
        + ", ".join(sorted(unknown))
    )


def test_total_rules_summary_matches_registry() -> None:
    _ensure_all_rules_loaded()
    expected_total = len(registry.list_rules())
    match = re.search(r"Total rules: \*\*(\d+)\*\*", _document_text())
    assert match is not None, "Could not find 'Total rules: **N**' in docs/rule-coverage.md"
    assert int(match.group(1)) == expected_total


def test_per_group_counts_match_registry() -> None:
    _ensure_all_rules_loaded()
    rules = registry.list_rules()

    counts_by_group: dict[str, int] = Counter()
    for meta in rules:
        if meta.category == "universal":
            counts_by_group["Universal Rules"] += 1
        elif meta.category == "external":
            counts_by_group["External (Probe-based)"] += 1
        elif meta.category == "local":
            label = {
                "nginx": "Nginx (Local)",
                "apache": "Apache (Local)",
                "lighttpd": "Lighttpd (Local)",
                "iis": "IIS (Local)",
            }.get(meta.server_type or "", None)
            assert label is not None, f"Unmapped local server_type: {meta.server_type}"
            counts_by_group[label] += 1
        else:
            raise AssertionError(f"Unknown category: {meta.category}")

    text = _document_text()
    for heading, expected in counts_by_group.items():
        # Match `### Heading` followed by `Count: N` on a later line.
        section_match = re.search(
            rf"### {re.escape(heading)}\s*\n+Count:\s*(\d+)",
            text,
        )
        assert section_match is not None, (
            f"Could not find 'Count: N' line under '### {heading}' heading"
        )
        actual = int(section_match.group(1))
        assert actual == expected, (
            f"docs/rule-coverage.md '{heading}' reports {actual} rules but "
            f"registry has {expected}"
        )

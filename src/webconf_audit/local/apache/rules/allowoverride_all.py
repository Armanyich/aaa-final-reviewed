from __future__ import annotations

from pathlib import Path

from webconf_audit.local.apache.htaccess import (
    ALL_OVERRIDE_CATEGORIES,
    extract_allowoverride,
)
from webconf_audit.local.apache.path_matching import (
    directory_path_covers,
    path_match_specificity,
)
from webconf_audit.local.apache.parser import ApacheBlockNode, ApacheConfigAst, ApacheDirectiveNode
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.allowoverride_all_in_directory"


@rule(
    rule_id=RULE_ID,
    title="Directory block leaves AllowOverride too broad",
    severity="medium",
    description=(
        "Directory block explicitly or effectively leaves AllowOverride at "
        "'All' or unspecified, which can let .htaccess override more "
        "directives than intended."
    ),
    recommendation=(
        "Set 'AllowOverride None' or restrict to specific categories to limit "
        "what .htaccess files can override."
    ),
    category="local",
    server_type="apache",
    order=300,
)
def find_allowoverride_all(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    directory_blocks = _iter_directory_blocks(config_ast.nodes)

    for block in directory_blocks:
        direct_allowed = extract_allowoverride(block)
        effective_allowed = _find_effective_allowoverride(block, directory_blocks)

        if direct_allowed == ALL_OVERRIDE_CATEGORIES:
            findings.append(
                _make_finding(
                    block,
                    description=(
                        "'AllowOverride All' allows .htaccess files to "
                        "override any directive in this Directory scope. "
                        "This weakens centralized configuration control."
                    ),
                )
            )
            continue

        if direct_allowed is None and effective_allowed is None:
            findings.append(
                _make_finding(
                    block,
                    description=(
                        "No AllowOverride directive is set in this Directory "
                        "block or any covering parent Directory block. "
                        "Depending on the Apache version and global defaults, "
                        ".htaccess files may be able to override any directive."
                    ),
                )
            )
            continue

        if direct_allowed is None and effective_allowed == ALL_OVERRIDE_CATEGORIES:
            findings.append(
                _make_finding(
                    block,
                    description=(
                        "This Directory block does not set AllowOverride, but "
                        "an inherited parent Directory scope effectively leaves "
                        "it at 'All'. That allows .htaccess files to override "
                        "any directive here."
                    ),
                )
            )

    return findings


def _make_finding(block: ApacheBlockNode, *, description: str) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="Directory block leaves AllowOverride too broad",
        severity="medium",
        description=description,
        recommendation=(
            "Set 'AllowOverride None' or restrict to specific "
            "categories (e.g., 'AllowOverride FileInfo AuthConfig') "
            "to limit what .htaccess can override."
        ),
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=block.source.file_path,
            line=block.source.line,
        ),
    )


def _iter_directory_blocks(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheBlockNode]:
    blocks: list[ApacheBlockNode] = []
    for node in nodes:
        if isinstance(node, ApacheBlockNode):
            if node.name.lower() == "directory":
                blocks.append(node)
            blocks.extend(_iter_directory_blocks(node.children))
    return blocks


def _find_effective_allowoverride(
    block: ApacheBlockNode,
    all_blocks: list[ApacheBlockNode],
) -> frozenset[str] | None:
    block_path = _resolve_block_path(block)
    if block_path is None:
        return None

    best_match: tuple[int, frozenset[str]] | None = None
    for candidate in all_blocks:
        candidate_path = _resolve_block_path(candidate)
        if candidate_path is None:
            continue

        allowed = extract_allowoverride(candidate)
        if allowed is None:
            continue

        if not directory_path_covers(block_path, candidate_path):
            continue

        specificity = path_match_specificity(candidate_path)
        if best_match is None or specificity > best_match[0]:
            best_match = (specificity, allowed)

    return best_match[1] if best_match is not None else None


def _resolve_block_path(block: ApacheBlockNode) -> Path | None:
    if not block.args:
        return None

    raw_path = Path(block.args[0])
    if raw_path.is_absolute():
        return raw_path.resolve()

    source_file_path = block.source.file_path
    if source_file_path is None:
        return raw_path.resolve()

    return (Path(source_file_path).parent / raw_path).resolve()


__all__ = ["find_allowoverride_all"]

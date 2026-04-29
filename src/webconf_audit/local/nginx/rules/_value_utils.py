from __future__ import annotations

import re

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, DirectiveNode

_DURATION_RE = re.compile(r"^(?P<value>\d+(?:\.\d+)?)(?P<unit>ms|s|m|h|d)?$", re.IGNORECASE)
_SIZE_RE = re.compile(r"^(?P<value>\d+)(?P<unit>[kmg])?$", re.IGNORECASE)

_DURATION_MULTIPLIERS = {
    None: 1.0,
    "ms": 0.001,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
}

_SIZE_MULTIPLIERS = {
    None: 1,
    "k": 1024,
    "m": 1024 * 1024,
    "g": 1024 * 1024 * 1024,
}


def parse_duration_seconds(value: str) -> float | None:
    match = _DURATION_RE.match(value)
    if match is None:
        return None
    number = float(match.group("value"))
    unit = match.group("unit")
    multiplier = _DURATION_MULTIPLIERS[unit.lower() if unit else None]
    return number * multiplier


def parse_size_bytes(value: str) -> int | None:
    match = _SIZE_RE.match(value)
    if match is None:
        return None
    number = int(match.group("value"))
    unit = match.group("unit")
    multiplier = _SIZE_MULTIPLIERS[unit.lower() if unit else None]
    return number * multiplier


def iter_direct_child_directives(
    config_ast: ConfigAst,
    directive_name: str,
    *,
    block_names: set[str],
) -> list[tuple[DirectiveNode, BlockNode]]:
    matches: list[tuple[DirectiveNode, BlockNode]] = []

    def walk_blocks(nodes: list[object]) -> None:
        for node in nodes:
            if not isinstance(node, BlockNode):
                continue
            if node.name in block_names:
                matches.extend(
                    (child, node)
                    for child in node.children
                    if isinstance(child, DirectiveNode) and child.name == directive_name
                )
            walk_blocks(node.children)

    walk_blocks(config_ast.nodes)
    return matches


__all__ = [
    "iter_direct_child_directives",
    "parse_duration_seconds",
    "parse_size_bytes",
]

"""Lighttpd condition evaluation for targeted and worst-case static analysis.

Provides a request context model, variable mapping, and condition evaluator
that determines whether a conditional block potentially matches a given
request context.  When no context is provided, all conditions are treated
as potentially matching (worst-case / static analysis default).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from webconf_audit.local.lighttpd.parser import LighttpdCondition


@dataclass(frozen=True, slots=True)
class LighttpdRequestContext:
    """Describes a hypothetical request for targeted condition evaluation.

    Every field is optional.  ``None`` means "unknown" — the evaluator
    treats unknown fields as potentially matching any value.
    """

    host: str | None = None
    url_path: str | None = None
    remote_ip: str | None = None
    scheme: str | None = None
    server_socket: str | None = None
    request_method: str | None = None
    query_string: str | None = None
    referer: str | None = None
    user_agent: str | None = None
    cookie: str | None = None
    physical_path: str | None = None
    physical_existing_path: str | None = None
    request_headers: Mapping[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Variable → context field mapping
# ---------------------------------------------------------------------------

# Keys are the *exact* variable strings produced by the Lighttpd parser
# (e.g.  ``$HTTP["host"]``).  Values are attribute names on
# ``LighttpdRequestContext``.
CONDITION_VARIABLE_MAP: dict[str, str] = {
    '$HTTP["host"]': "host",
    '$HTTP["url"]': "url_path",
    '$HTTP["remoteip"]': "remote_ip",
    '$HTTP["scheme"]': "scheme",
    '$HTTP["request-method"]': "request_method",
    '$HTTP["querystring"]': "query_string",
    '$HTTP["referer"]': "referer",
    '$HTTP["useragent"]': "user_agent",
    '$HTTP["cookie"]': "cookie",
    '$SERVER["socket"]': "server_socket",
    '$PHYSICAL["path"]': "physical_path",
    '$PHYSICAL["existing-path"]': "physical_existing_path",
}


_REQUEST_HEADER_PATTERN = re.compile(r'^\$REQUEST_HEADER\["((?:[^"\\]|\\.)*)"\]$')


# ---------------------------------------------------------------------------
# Single-condition evaluator
# ---------------------------------------------------------------------------

def evaluate_condition(
    condition: LighttpdCondition,
    context: LighttpdRequestContext,
) -> bool | None:
    """Evaluate *condition* against *context*.

    Returns ``True``/``False`` when the outcome is deterministic, or
    ``None`` when the relevant context field is unknown.
    """
    ctx_value = _context_value(condition.variable, context)
    if ctx_value is None:
        # Unknown variable — cannot decide.
        return None
    op = condition.operator
    pattern = condition.value

    if op == "==":
        return ctx_value == pattern
    if op == "!=":
        return ctx_value != pattern
    if op == "=~":
        return _regex_match(pattern, ctx_value)
    if op == "!~":
        m = _regex_match(pattern, ctx_value)
        return None if m is None else not m
    if op == "=^":
        return ctx_value.startswith(pattern)
    if op == "=$":
        return ctx_value.endswith(pattern)

    # Unrecognised operator — unknown.
    return None


def _context_value(variable: str, context: LighttpdRequestContext) -> str | None:
    attr = CONDITION_VARIABLE_MAP.get(variable)
    if attr is not None:
        return getattr(context, attr, None)

    request_header_match = _REQUEST_HEADER_PATTERN.match(variable)
    if request_header_match is not None:
        return _lookup_header(context.request_headers, request_header_match.group(1))

    return None


def _lookup_header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.lower()
    for header_name, value in headers.items():
        if header_name.lower() == wanted:
            return value
    return None


def _regex_match(pattern: str, value: str) -> bool | None:
    """Try a regex match; return ``None`` on invalid pattern."""
    try:
        return re.search(pattern, value) is not None
    except re.error:
        return None


# ---------------------------------------------------------------------------
# Worst-case helper for static analysis
# ---------------------------------------------------------------------------

def is_potentially_matching(
    condition: LighttpdCondition | None,
    context: LighttpdRequestContext | None = None,
) -> bool:
    """Return whether *condition* could match the given *context*.

    * If *context* is ``None``, every condition is potentially matching
      (worst-case static analysis).
    * If *condition* is ``None`` (e.g. an ``else`` block), it is always
      potentially matching because it activates when no prior sibling
      matched.
    * When evaluation is indeterminate (unknown variable / context field),
      the condition is treated as potentially matching.
    """
    if context is None:
        return True
    if condition is None:
        return True

    result = evaluate_condition(condition, context)
    if result is None:
        return True
    return result


__all__ = [
    "CONDITION_VARIABLE_MAP",
    "LighttpdRequestContext",
    "evaluate_condition",
    "is_potentially_matching",
]

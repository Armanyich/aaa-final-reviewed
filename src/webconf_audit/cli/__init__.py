from enum import Enum
from typing import cast

import typer

from webconf_audit.external import analyze_external_target
from webconf_audit.local.apache import analyze_apache_config
from webconf_audit.local.iis import analyze_iis_config
from webconf_audit.local.lighttpd import analyze_lighttpd_config
from webconf_audit.local.nginx import analyze_nginx_config
from webconf_audit.models import AnalysisResult, Severity
from webconf_audit.report import JsonFormatter, ReportData, TextFormatter, deduplicate_findings
from webconf_audit.rule_registry import RuleCategory
from webconf_audit.suppressions import apply_suppressions, load_suppression_file

app = typer.Typer(help="Web server configuration security audit tool")


class OutputFormat(str, Enum):
    text = "text"
    json = "json"


class FailOnSeverity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _suppressions_option() -> str | None:
    return typer.Option(
        None,
        "--suppressions",
        help="Override the suppression YAML file path.",
    )


def _output_result(
    result: AnalysisResult,
    fmt: OutputFormat = OutputFormat.text,
    fail_on: FailOnSeverity | None = None,
    suppressions_path: str | None = None,
) -> None:
    suppression_load_failed = _apply_suppressions(
        result, suppressions_path, load_default=fail_on is not None,
    )
    report = ReportData(results=[result])
    formatter = TextFormatter() if fmt == OutputFormat.text else JsonFormatter()
    typer.echo(formatter.format(report))
    exit_code = _ci_exit_code(
        result,
        fail_on,
        explicit_suppression_error=suppressions_path is not None and suppression_load_failed,
    )
    if exit_code:
        raise typer.Exit(exit_code)


def _apply_suppressions(
    result: AnalysisResult,
    suppressions_path: str | None,
    *,
    load_default: bool,
) -> bool:
    suppression_set = load_suppression_file(suppressions_path, load_default=load_default)
    result.issues.extend(suppression_set.issues)
    apply_suppressions(result, suppression_set)
    return any(
        issue.level == "error" and issue.code.startswith("suppression_")
        for issue in suppression_set.issues
    )


def _ci_exit_code(
    result: AnalysisResult,
    fail_on: FailOnSeverity | None,
    *,
    explicit_suppression_error: bool = False,
) -> int:
    if explicit_suppression_error:
        return 1
    if fail_on is None:
        return 0
    if any(issue.level == "error" for issue in result.issues):
        return 1
    threshold = _SEVERITY_RANK[fail_on.value]
    deduplicated, _ = deduplicate_findings(result.findings)
    if any(_SEVERITY_RANK[finding.severity] >= threshold for finding in deduplicated):
        return 2
    return 0


@app.command("analyze-nginx")
def analyze_nginx(
    config_path: str = typer.Argument(..., help="Path to nginx config file"),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
    fail_on: FailOnSeverity | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 2 when unsuppressed findings at or above this severity exist.",
    ),
    suppressions: str | None = _suppressions_option(),
) -> None:
    result = analyze_nginx_config(config_path)
    _output_result(result, output_format, fail_on, suppressions)


@app.command("analyze-apache")
def analyze_apache(
    config_path: str = typer.Argument(..., help="Path to Apache config file"),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
    fail_on: FailOnSeverity | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 2 when unsuppressed findings at or above this severity exist.",
    ),
    suppressions: str | None = _suppressions_option(),
) -> None:
    result = analyze_apache_config(config_path)
    _output_result(result, output_format, fail_on, suppressions)


@app.command("analyze-lighttpd")
def analyze_lighttpd(
    config_path: str = typer.Argument(..., help="Path to Lighttpd config file"),
    execute_shell: bool = typer.Option(
        False,
        "--execute-shell/--no-execute-shell",
        help="Execute include_shell directives during analysis.",
    ),
    host: str | None = typer.Option(
        None,
        "--host",
        help="Evaluate conditional blocks for a specific host (targeted analysis).",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
    fail_on: FailOnSeverity | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 2 when unsuppressed findings at or above this severity exist.",
    ),
    suppressions: str | None = _suppressions_option(),
) -> None:
    result = analyze_lighttpd_config(
        config_path, execute_shell=execute_shell, host=host,
    )
    _output_result(result, output_format, fail_on, suppressions)


@app.command("analyze-iis")
def analyze_iis(
    config_path: str = typer.Argument(
        ...,
        help="Path to IIS config file (web.config or applicationHost.config)",
    ),
    machine_config: str | None = typer.Option(
        None,
        "--machine-config",
        help="Optional path to machine.config for IIS inheritance analysis.",
    ),
    tls_registry: str | None = typer.Option(
        None,
        "--tls-registry",
        help="Optional JSON export of Windows SChannel TLS registry settings.",
    ),
    no_tls_registry: bool = typer.Option(
        False,
        "--no-tls-registry",
        help="Disable automatic local SChannel registry enrichment on Windows.",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
    fail_on: FailOnSeverity | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 2 when unsuppressed findings at or above this severity exist.",
    ),
    suppressions: str | None = _suppressions_option(),
) -> None:
    kwargs: dict[str, object] = {}
    if machine_config is not None:
        kwargs["machine_config_path"] = machine_config
    if tls_registry is not None:
        kwargs["tls_registry_path"] = tls_registry
    if no_tls_registry:
        kwargs["use_tls_registry"] = False

    result = analyze_iis_config(config_path, **kwargs)
    _output_result(result, output_format, fail_on, suppressions)


def _parse_ports(raw: str) -> tuple[int, ...]:
    """Parse a comma-separated port string with validation.

    Raises :class:`typer.BadParameter` on invalid tokens, out-of-range
    values (must be 1-65535), or an empty result.
    """
    seen: set[int] = set()
    result: list[int] = []
    for idx, token in enumerate(raw.split(",")):
        token = token.strip()
        if not token:
            raise typer.BadParameter(
                f"empty port value at position {idx + 1} in: {raw!r}"
            )
        try:
            port = int(token)
        except ValueError:
            raise typer.BadParameter(f"invalid port value: {token!r}") from None
        if port < 1 or port > 65535:
            raise typer.BadParameter(
                f"port out of range (1-65535): {port}"
            )
        if port not in seen:
            seen.add(port)
            result.append(port)
    if not result:
        raise typer.BadParameter("--ports requires at least one valid port")
    return tuple(result)


@app.command("analyze-external")
def analyze_external(
    target: str = typer.Argument(..., help="URL, host, or host:port to probe"),
    scan_ports: bool = typer.Option(
        True,
        "--scan-ports/--no-scan-ports",
        help="Enable or disable port discovery for bare-host targets.",
    ),
    ports: str | None = typer.Option(
        None,
        "--ports",
        help="Comma-separated list of ports to scan (e.g. '80,443,8080').",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
    fail_on: FailOnSeverity | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 2 when unsuppressed findings at or above this severity exist.",
    ),
    suppressions: str | None = _suppressions_option(),
) -> None:
    parsed_ports: tuple[int, ...] | None = None
    if ports is not None:
        parsed_ports = _parse_ports(ports)
    result = analyze_external_target(target, scan_ports=scan_ports, ports=parsed_ports)
    _output_result(result, output_format, fail_on, suppressions)


@app.command("list-rules")
def list_rules(
    category: str | None = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category (local, external, universal).",
    ),
    server_type: str | None = typer.Option(
        None,
        "--server-type",
        "-s",
        help="Filter by server type (nginx, apache, lighttpd, iis).",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        help="Filter by severity (critical, high, medium, low, info).",
    ),
    tag: str | None = typer.Option(None, "--tag", "-t", help="Filter by tag (e.g. tls, headers)."),
) -> None:
    """List all registered audit rules with optional filtering."""
    from webconf_audit.rule_registry import registry

    _ensure_all_rules_loaded()
    parsed_category = _parse_rule_category(category)
    parsed_server_type = _parse_rule_server_type(server_type)
    parsed_severity = _parse_rule_severity(severity)
    parsed_tag = _parse_rule_tag(tag)

    rules = registry.list_rules(
        category=parsed_category,
        server_type=parsed_server_type,
        severity=parsed_severity,
        tag=parsed_tag,
    )

    if not rules:
        typer.echo("No rules match the given filters.")
        raise typer.Exit()

    typer.echo(f"{'RULE ID':<55} {'SEV':<7} {'CAT':<10} {'SERVER':<10} ORDER")
    typer.echo("-" * 90)
    for m in rules:
        server = m.server_type or ""
        typer.echo(f"{m.rule_id:<55} {m.severity:<7} {m.category:<10} {server:<10} {m.order}")
    typer.echo(f"\nTotal: {len(rules)} rules")


def _parse_rule_category(value: str | None) -> RuleCategory | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    valid = {"local", "external", "universal"}
    if normalized not in valid:
        raise typer.BadParameter(
            f"invalid category {value!r}; expected one of: {', '.join(sorted(valid))}"
        )
    return cast(RuleCategory, normalized)


def _parse_rule_severity(value: str | None) -> Severity | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    valid = {"critical", "high", "medium", "low", "info"}
    if normalized not in valid:
        raise typer.BadParameter(
            f"invalid severity {value!r}; expected one of: {', '.join(sorted(valid))}"
        )
    return cast(Severity, normalized)


def _parse_rule_server_type(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    valid = _available_rule_server_types()
    if normalized not in valid:
        raise typer.BadParameter(
            f"invalid server type {value!r}; expected one of: {', '.join(sorted(valid))}"
        )
    return normalized


def _parse_rule_tag(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    valid = _available_rule_tags()
    if normalized not in valid:
        raise typer.BadParameter(
            f"invalid tag {value!r}; expected one of: {', '.join(sorted(valid))}"
        )
    return normalized


def _available_rule_server_types() -> set[str]:
    from webconf_audit.rule_registry import registry

    return {
        meta.server_type
        for meta in registry.list_rules()
        if meta.server_type is not None
    }


def _available_rule_tags() -> set[str]:
    from webconf_audit.rule_registry import registry

    return {
        tag
        for meta in registry.list_rules()
        for tag in meta.tags
    }


def _ensure_all_rules_loaded() -> None:
    """Load all rule packages + meta-only registrations into the registry."""
    from webconf_audit.rule_registry import registry

    registry.ensure_loaded("webconf_audit.local.rules.universal")
    registry.ensure_loaded("webconf_audit.local.nginx.rules")
    registry.ensure_loaded("webconf_audit.local.apache.rules")
    registry.ensure_loaded("webconf_audit.local.lighttpd.rules")
    registry.ensure_loaded("webconf_audit.local.iis.rules")
    # External meta-only rules register on import.
    import webconf_audit.external.rules._runner  # noqa: F401


if __name__ == "__main__":
    app()

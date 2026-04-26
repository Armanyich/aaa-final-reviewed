# webconf-audit

A security auditing tool for web server configurations.

`webconf-audit` has two independent analysis modes:

- **Local** — static analysis of configuration files on the host that
  runs the web server.
- **External** — black-box probing of a running web endpoint over the
  network using observable HTTP, HTTPS, and TLS signals.

## Supported servers

Local analysis covers four web servers:

- Nginx
- Apache HTTP Server
- Lighttpd
- Microsoft IIS

External probing is server-agnostic; a few checks are activated only
after fingerprinting identifies the underlying server (for example,
Apache `mod_status` exposure or IIS detailed error pages).

## Installation

`webconf-audit` requires Python 3.10 or later.

```bash
pip install .
```

The package exposes a `webconf-audit` console entry point. Every
command is also available via `python -m webconf_audit.cli`.

## Quick start

### Local analysis

```bash
webconf-audit analyze-nginx /etc/nginx/nginx.conf
webconf-audit analyze-apache /etc/apache2/httpd.conf
webconf-audit analyze-lighttpd /etc/lighttpd/lighttpd.conf
webconf-audit analyze-iis C:\inetpub\wwwroot\web.config
```

### External analysis

```bash
webconf-audit analyze-external https://example.com
webconf-audit analyze-external example.com --ports 80,443,8443
webconf-audit analyze-external example.com --no-scan-ports
```

### Output formats

Every `analyze-*` command supports text (default) and JSON output:

```bash
webconf-audit analyze-nginx config.conf --format json
webconf-audit analyze-external example.com -f json
```

The JSON envelope contains a generation timestamp, a summary, the
per-target results, the deduplicated findings list, and the issues
list.

## Local analysis pipeline

Each local analyzer:

1. Reads the main configuration file passed on the command line.
2. Resolves includes or rebuilds the inheritance chain.
3. Builds an effective configuration where the server model
   requires it.
4. Runs server-specific rules over the parsed/effective form.
5. Runs universal rules over a normalized representation shared by
   all four servers.
6. Returns a structured result with findings, technical issues, and
   source metadata.

What each analyzer handles:

- **Nginx** — tokenizer, parser, `include` resolution with glob
  support and cycle detection, AST traversal, source-location
  tracking on every directive.
- **Apache** — `Include` and `IncludeOptional` resolution,
  `.htaccess` discovery from `Directory` blocks and `DocumentRoot`,
  `AllowOverride` filtering, per-`VirtualHost` analysis contexts,
  `Location` and `LocationMatch` layering, header merge semantics.
- **Lighttpd** — variable expansion, `include` resolution,
  `include_shell` handling (skipped with a warning by default, with
  explicit opt-in execution via `--execute-shell`),
  conditional blocks such as `$HTTP["host"] == "..."`, optional
  per-host targeted analysis via `--host`.
- **IIS** — safe XML parsing through `defusedxml`, three-level
  inheritance chain `machine.config` → `applicationHost.config`
  → `web.config`, `<add>` / `<remove>` / `<clear>` collection
  semantics, `<location>` inheritance, `--machine-config` option for
  explicit base config selection.

Each finding records severity, description, remediation hint, and a
source reference: file and line for text configurations, file and XML
path for IIS, observable endpoint or header for external mode.

## External analysis

External mode probes a target without access to its configuration. It
performs:

- Port discovery for bare-host targets (default ports: 80, 443, 8080,
  8443, 8000, 8888, 3000, 5000, 9443; can be overridden with
  `--ports` or disabled with `--no-scan-ports`).
- HTTP and HTTPS probing with `HEAD` → `GET` fallback plus a separate
  `OPTIONS` flow.
- TLS enrichment: negotiated protocol and cipher, supported TLS
  versions, certificate chain completeness, SAN extraction.
- Server fingerprinting from response headers, default error pages,
  and reactions to deliberately malformed requests.
- Sensitive-path probing for paths such as `/.git/HEAD`, `/.env`,
  `/.htaccess`, `/phpinfo.php`, `/web.config`, `/robots.txt`,
  `/sitemap.xml`.
- Redirect chain analysis: loops, scheme switches, off-domain hops.

External rules cover HTTPS availability and HSTS, common security
headers, server identification, cookies, CORS, HTTP methods,
sensitive paths, TLS protocol versions, and certificate validity.

## Rule catalog

The rule catalog is browsable through the CLI:

```bash
webconf-audit list-rules
webconf-audit list-rules --category local --server-type nginx
webconf-audit list-rules --severity high --tag tls
```

Filters: `--category` (`local`, `external`, `universal`),
`--server-type` (`nginx`, `apache`, `lighttpd`, `iis`),
`--severity` (`critical`, `high`, `medium`, `low`, `info`),
`--tag`.

The catalog currently contains 183 rules:

| Category | Rules |
|----------|------:|
| Local — Nginx | 41 |
| Local — Apache | 27 |
| Local — Lighttpd | 15 |
| Local — IIS | 20 |
| Universal (local) | 11 |
| External | 69 |

## Reporting

Results are aggregated into a `ReportData` structure with a summary by
severity, analysis mode, and server type. Two output formatters are
available:

- `TextFormatter` — human-readable command-line output.
- `JsonFormatter` — machine-readable output suitable for downstream
  tooling.

Universal rule findings are deduplicated when a more specific
server-specific rule has already reported the same issue at the same
location.

## Demo

A working local-analysis demo with reproducible Docker-based syntax
checks is provided in `demo/local_admin/`. See
[demo/local_admin/README.md](demo/local_admin/README.md) for the
full walkthrough.

## Development

Run the tests:

```bash
pytest -q
```

Lint:

```bash
ruff check .
```

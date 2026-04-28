# Standards Roadmap

This document is the Stage 2 step 4 output for `webconf-audit`. It turns the
rule inventory in `docs/rule-coverage.md` into a reviewable standards backlog
before we add more rules.

The goal is not to maximize rule count. The goal is to decide, for each useful
CWE, OWASP, CIS, ASVS, or vendor hardening item, whether the project can check
it honestly with its current data model or whether deeper parsing, effective
configuration analysis, external probing, or host inspection is needed first.

## Source Baseline

Sources checked on 2026-04-28:

- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/):
  latest stable ASVS is 5.0.0. Future ASVS references must use the versioned
  identifier form, for example `v5.0.0-1.2.5`, because OWASP notes that
  unversioned identifiers follow the latest content.
- [CIS NGINX Benchmark](https://www.cisecurity.org/benchmark/nginx): the public
  CIS NGINX page lists NGINX Benchmark 3.0.0 as the current Benchmark PDF
  version.
- [CIS Apache HTTP Server Benchmark](https://www.cisecurity.org/benchmark/apache_http_server):
  the public CIS Apache HTTP Server page lists Apache HTTP Server 2.4 Benchmark
  2.3.0 as the current Benchmark PDF version.
- [CIS Microsoft Windows Server Benchmark](https://www.cisecurity.org/benchmark/microsoft_windows_server):
  the public CIS Windows Server page lists active Windows Server Benchmarks for
  2025, 2022, 2019, 2016, and older versions. These are relevant to
  IIS-adjacent host policy, especially TLS and service hardening.
- [CIS unsupported Benchmarks](https://www.cisecurity.org/unsupported-cis-benchmarks):
  the public unsupported list contains legacy IIS 5/6/7/8 benchmarks. No active
  standalone Microsoft IIS Benchmark was found in the current public CIS
  catalog. Treat those legacy IIS documents as non-authoritative unless a
  future task explicitly scopes them.

The current project inventory is 183 rules:

- Universal: 11
- Nginx local: 41
- Apache local: 27
- Lighttpd local: 15
- IIS local: 20
- External probes: 69

Stage 2 step 3 is complete for CWE and OWASP Top 10 mapping. CIS, ASVS, and
vendor-specific section references are intentionally still pending.

## Mapping Rules

- Cite exact standard versions and exact identifiers. Do not add a CIS, ASVS,
  or vendor reference from memory.
- Keep cells empty when the mapping is not honest. Operational advice can map
  to vendor hardening without forcing a CWE.
- Do not copy long CIS or ASVS prose into this repository. Use section IDs,
  short titles, and our own summary.
- Prefer existing local parser/effective-config data over raw string matching.
- Prefer external probe rules only when the configured intent cannot prove the
  runtime behavior.
- Mark host-level requirements as out of scope unless the tool adds an explicit
  host-inspection mode.

## Gap Types

Use these labels in follow-up PRs:

| Label | Meaning | Expected next action |
| --- | --- | --- |
| `covered` | Existing rule already checks the item honestly. | Add the standard reference to `docs/rule-coverage.md`. |
| `direct-rule` | Current parser/probe data is enough. | Add a focused rule and tests. |
| `parser-depth` | The rule needs better AST/effective-config semantics first. | Improve parser/effective analysis, then add the rule. |
| `probe-depth` | The rule needs richer runtime probing first. | Improve external probe collection, then add the rule. |
| `host-depth` | The item needs OS, package, permissions, registry, service, or process data. | Defer until a host-inspection mode exists. |
| `out-of-scope` | The item is outside web server config/probing. | Document why it is excluded. |
| `research` | The source or interpretation is not stable enough yet. | Verify source text before implementation. |

## Work Order

1. Map existing rules to ASVS 5.0.0 where the match is direct.
2. Walk CIS NGINX Benchmark 3.0.0 and fill Nginx CIS matches plus a Nginx gap
   table.
3. Walk CIS Apache HTTP Server 2.4 Benchmark 2.3.0 and fill Apache CIS matches
   plus an Apache gap table.
4. Decide the IIS source of truth: active CIS Windows Server Benchmarks for
   host/SChannel policy, vendor IIS documentation for IIS XML policy, and
   legacy unsupported CIS IIS only when explicitly called out.
5. Add standards metadata to rule definitions only after the doc mapping is
   stable enough to avoid churn in CLI output.
6. Implement new rules in small PRs. If a candidate needs parser or probe
   depth, land that depth first.

## Initial Gap Backlog

These are starting candidates, not final claims that a specific benchmark
section requires the exact rule. Each candidate must be tied to a verified
standard section before implementation.

| ID | Area | Gap type | Priority | Candidate work |
| --- | --- | --- | --- | --- |
| STD-GAP-001 | ASVS 5.0.0 | covered | P1 | Add ASVS references for existing TLS, HTTPS redirect, HSTS, cookie, CORS, security-header, and sensitive-path exposure rules where the requirement match is exact. |
| STD-GAP-002 | Nginx CIS | covered | P1 | Fill CIS references for existing Nginx checks such as `server_tokens_on`, `autoindex_on`, logging, TLS protocol/cipher, request-size, and access-control rules after the NGINX 3.0.0 benchmark walk. |
| STD-GAP-003 | Nginx CIS | direct-rule | P2 | Validate and potentially add Nginx TLS hardening rules not currently represented, such as session ticket, OCSP stapling completeness, or DH parameter posture checks. |
| STD-GAP-004 | Nginx CIS | host-depth | P3 | Classify Nginx file ownership, permissions, package, service user, and filesystem layout recommendations as host-depth unless an explicit host mode is added. |
| STD-GAP-005 | Apache CIS | covered | P1 | Fill CIS references for existing Apache checks such as `server_tokens_not_prod`, `server_signature_not_off`, `trace_enable_not_off`, `options_indexes`, status/info exposure, request limits, and logging. |
| STD-GAP-006 | Apache CIS | direct-rule | P2 | Add Apache TLS directive checks for `SSLProtocol`, `SSLCipherSuite`, `SSLHonorCipherOrder`, stapling, and compression where the parser already exposes enough directive context. |
| STD-GAP-007 | Apache CIS | parser-depth | P2 | Improve module inventory and include/effective handling before adding rules that reason about enabled module sets beyond the existing CGI/status/info checks. |
| STD-GAP-008 | IIS / Windows Server | covered | P1 | Map existing IIS and universal TLS/SChannel registry checks to active Windows Server or Microsoft hardening references where the requirement is host policy rather than IIS XML. |
| STD-GAP-009 | IIS / vendor docs | direct-rule | P2 | Validate additional IIS XML checks around request filtering deny lists, handler exposure, authentication defaults, and response-header behavior against current Microsoft documentation. |
| STD-GAP-010 | IIS legacy CIS | research | P3 | Decide whether unsupported CIS IIS 7/8 documents should be used only as historical notes, not as primary compliance references. |
| STD-GAP-011 | External probes | covered | P1 | Add ASVS references for observable runtime behavior: TLS protocol negotiation, weak cipher negotiation, certificate validity, security headers, dangerous methods, and exposed sensitive files. |
| STD-GAP-012 | Standards output | direct-rule | P2 | After references stabilize, add optional report grouping by standard (`--group-by standard` or JSON `standards`) without changing rule behavior. |

## PR Slicing

Keep standards work small enough for CodeRabbit and human review:

1. ASVS mapping for already-covered rules.
2. CIS Nginx mapping and Nginx-specific gap table.
3. CIS Apache mapping and Apache-specific gap table.
4. IIS source-of-truth decision and IIS/Windows mapping.
5. Standards metadata in the rule registry and report formats.
6. First new rule PR from the prioritized backlog.

## Acceptance Criteria For New Standards Rules

A standards-driven rule is ready only when:

- the source reference is versioned and exact;
- the rule explains which config/probe signal proves the finding;
- tests include a positive case, negative case, and at least one inherited or
  scoped config case when the server supports inheritance;
- `docs/rule-coverage.md` is updated in the same PR;
- false-positive risk is described when the source item depends on host state
  not visible to the current analyzer.

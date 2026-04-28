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
- [CIS Microsoft IIS Benchmark](https://www.cisecurity.org/benchmark/microsoft_iis):
  the public CIS Microsoft IIS page lists Microsoft IIS 10 Benchmark 1.2.1
  among the current available Benchmark PDF versions. Treat it as the primary
  CIS source for IIS-specific hardening, with Windows Server benchmarks used
  for host and SChannel policy.
- [CIS unsupported Benchmarks](https://www.cisecurity.org/unsupported-cis-benchmarks):
  the public unsupported list can still contain legacy IIS documents. Treat
  unsupported or archived IIS benchmarks as non-authoritative unless a future
  task explicitly scopes them.

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
- Store confirmed ASVS references in a dedicated `ASVS` column in
  `docs/rule-coverage.md`, inserted after the existing `OWASP` column. Do not
  append ASVS IDs to the OWASP Top 10 column. Use the exact format
  `ASVS v5.0.0-<requirement-id>`; partial matches must add a short limitation,
  for example `ASVS v5.0.0-12.1.2 (partial: weak-pattern detection only)`.
- Keep cells empty when the mapping is not honest. Operational advice can map
  to vendor hardening without forcing a CWE.
- Do not copy long CIS or ASVS prose into this repository. Use section IDs,
  short titles, and our own summary. Direct quotes are limited to one short
  fragment of 25 words or fewer per standard item, and must include a source
  section ID or URL plus an `evidence_justification` note explaining why the
  exact wording is needed.
- Prefer existing local parser/effective-config data over raw string matching.
- Prefer external probe rules only when the configured intent cannot prove the
  runtime behavior.
- Mark host-level requirements as out of scope unless the tool adds an explicit
  host-inspection mode.

Future ASVS row shape:

| Rule ID | OWASP | ASVS | CIS / Vendor |
| --- | --- | --- | --- |
| `external.hsts_missing` | `[A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)` | `ASVS v5.0.0-3.4.1` | `-` |

Summary template for standards candidates:

- Standard ID and short title.
- Scanner signal that can prove or disprove the item.
- Gap label from the table below.
- Source section ID or URL.
- Visibility limits and false-positive risk.
- Optional `evidence_justification` when a short quote is unavoidable.

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

1. Map existing rules to ASVS 5.0.0 where the match is direct. This document is
   the source of truth while references are still candidates. Only after review
   should confirmed rule-level references be copied into the dedicated `ASVS`
   column in `docs/rule-coverage.md`.
2. Walk CIS NGINX Benchmark 3.0.0 and fill Nginx CIS matches plus a Nginx gap
   table.
3. Walk CIS Apache HTTP Server 2.4 Benchmark 2.3.0 and fill Apache CIS matches
   plus an Apache gap table.
4. Decide the IIS source of truth: active CIS Microsoft IIS 10 Benchmark 1.2.1
   for IIS policy, active CIS Windows Server Benchmarks for host/SChannel
   policy, vendor IIS documentation for implementation detail, and legacy
   unsupported CIS IIS only when explicitly called out.
5. Add standards metadata to rule definitions only after the doc mapping is
   stable enough to avoid churn in CLI output.
6. Implement new rules in small PRs. If a candidate needs parser or probe
   depth, land that depth first.

## ASVS 5.0.0 First Pass

This first ASVS pass is intentionally limited to requirements that a web server
configuration analyzer or black-box HTTP/TLS probe can observe. ASVS remains an
application verification standard; `webconf-audit` should only claim coverage
when the scanner can see the relevant deployment signal.

Primary ASVS chapters for the current rule set:

- [V3 Web Frontend Security](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md)
- [V12 Secure Communication](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x21-V12-Secure-Communication.md)
- [V13 Configuration](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x22-V13-Configuration.md)
- [V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)

### Direct Coverage Candidates (partial where noted)

These requirements have enough current signal to justify adding ASVS references
to `docs/rule-coverage.md` after review. Items marked partial need the stated
limit recorded with the reference or moved to the gap list:

- `v5.0.0-12.1.1` - TLS protocol version posture. Covered by weak protocol
  rules such as `universal.weak_tls_protocol`, `nginx.weak_ssl_protocols`,
  and external TLS protocol probes.
- `v5.0.0-12.1.2` - recommended cipher suite posture. Partial coverage:
  current rules detect known-weak cipher patterns via
  `universal.weak_tls_ciphers`, `lighttpd.weak_ssl_cipher_list`, and
  `external.weak_cipher_suite`, but do not yet prove full recommended-suite
  posture, forward secrecy, or server preference.
- `v5.0.0-12.2.1` - HTTPS must not fall back to cleartext. Covered by
  HTTPS/TLS intent and redirect findings such as
  `universal.tls_intent_without_config`, `external.https_not_available`, and
  `external.http_not_redirected_to_https`.
- `v5.0.0-12.2.2` - publicly trusted certificate posture. Covered by
  certificate probes including `external.tls_certificate_self_signed`,
  `external.cert_chain_incomplete`, `external.cert_san_mismatch`,
  and `external.certificate_expired`.
- `v5.0.0-3.3.1`, `v5.0.0-3.3.2`, and `v5.0.0-3.3.4` - observable cookie
  security attributes. Partial coverage: external cookie rules check `Secure`,
  `SameSite`, `SameSite=None` plus `Secure`, and `HttpOnly`, but do not yet
  validate `__Host-` / `__Secure-` prefix guidance.
- `v5.0.0-3.4.1` - HSTS response header. Covered by universal, local, and
  external HSTS rules, including max-age and includeSubDomains probes.
- `v5.0.0-3.4.2` - CORS origin restrictions. Partial coverage: runtime probes
  detect wildcard origins and wildcard origins with credentials, but cannot
  prove an application allowlist or whether a wildcard response contains
  sensitive information.
- `v5.0.0-3.4.3` - CSP response header. Partial coverage: current rules detect
  missing CSP and unsafe-inline / unsafe-eval, but do not yet validate minimum
  policy quality such as `object-src`, `base-uri`, nonces, hashes, or
  per-response policy.
- `v5.0.0-3.4.4` - `X-Content-Type-Options: nosniff`. Covered by universal,
  local, and external missing/invalid header checks.
- `v5.0.0-3.4.5` - Referrer-Policy. Covered by missing/unsafe Referrer-Policy
  checks where headers are visible.
- `v5.0.0-3.4.8` - COOP. Partial coverage: `external.coop_missing` can flag
  missing COOP on observed runtime responses, but does not determine which
  responses initiate document rendering.
- `v5.0.0-13.4.1` - source control metadata must not be exposed. Covered by
  external `.git` and `.svn` metadata probes.
- `v5.0.0-13.4.2` - production debug features must be disabled. Covered for
  web-server-visible cases such as IIS debug / detailed error settings and
  external debug endpoints (`phpinfo`, ELMAH, ASP.NET trace).
- `v5.0.0-13.4.3` - directory listings must not be exposed unless intended.
  Covered by universal and local directory listing rules.
- `v5.0.0-13.4.4` - TRACE must not be supported in production. Covered by
  Apache/IIS local rules and external TRACE probes.
- `v5.0.0-13.4.5` - documentation and monitoring endpoints should not be
  exposed unless intended. Covered by status/info endpoint rules.
- `v5.0.0-13.4.6` - backend component versions should not be disclosed.
  Covered by server identification, `Server`, `X-Powered-By`,
  `X-AspNet-Version`, and server-token rules.
- `v5.0.0-16.5.1` - generic errors for unexpected/sensitive failures. Partial
  coverage: current rules only see web-server-visible detailed error pages and
  framework diagnostics.

### Partial Or Follow-up Gaps

These ASVS requirements are relevant but should not be marked fully covered
until the listed follow-up exists:

- `v5.0.0-3.3.1` - cookie prefix guidance is not fully checked. Add a cookie
  prefix probe if we want to distinguish `__Host-` and `__Secure-` posture.
- `v5.0.0-3.4.3` - CSP minimum policy quality is deeper than missing /
  unsafe-inline / unsafe-eval. Add checks for `object-src 'none'`, `base-uri
  'none'`, nonce/hash usage, and per-response policy only after deciding how
  strict the external probe should be.
- `v5.0.0-3.4.6` - ASVS prefers CSP `frame-ancestors`; current X-Frame-Options
  checks are useful but not an exact ASVS 5.0.0 match. Add local/external
  `frame-ancestors` checks before claiming full coverage.
- `v5.0.0-3.4.7` - CSP reporting endpoint is not checked today. Add a direct
  runtime rule for `report-uri` / `report-to` if we decide this is valuable.
- `v5.0.0-3.5.1` through `v5.0.0-3.5.3` - CSRF and safe-method semantics are
  application behavior. Existing dangerous-method probes help, but they do not
  prove anti-forgery controls.
- `v5.0.0-3.5.8` - CORP is observable and `external.corp_missing` exists, but
  the rule cannot know whether the response is an authenticated resource.
- `v5.0.0-12.1.2` - forward secrecy and preference order require richer cipher
  evaluation than simple weak-pattern detection.
- `v5.0.0-12.1.4` - OCSP stapling is only partly represented for Nginx. Add
  cross-server local checks and/or external stapling probes before claiming
  general coverage.
- `v5.0.0-12.1.5` - ECH is not checked. Treat as `probe-depth` and likely low
  priority until server support is common enough for useful findings.
- `v5.0.0-13.4.7` - extension allowlisting is broader than current sensitive
  path probes. Existing rules cover common leaks, not a full allowlist model.
- `v5.0.0-16.1.1` through `v5.0.0-16.4.3` - application security logging
  inventory, event semantics, and log protection are mostly outside current
  web server config/probe visibility. Local access/error-log presence can be
  supporting evidence, not complete ASVS coverage.

## Initial Gap Backlog

These are starting candidates, not final claims that a specific benchmark
section requires the exact rule. Each candidate must be tied to a verified
standard section before implementation.

| ID | Area | Gap type | Priority | Candidate work |
| --- | --- | --- | --- | --- |
| STD-GAP-001 | ASVS 5.0.0 | covered | P1 | Review the first-pass ASVS candidates above, then add exact ASVS references to the dedicated `ASVS` column for already-covered TLS, HTTPS redirect, HSTS, cookie, CORS, security-header, and sensitive-path exposure rules. |
| STD-GAP-002 | Nginx CIS | covered | P1 | Fill CIS references for existing Nginx checks such as `server_tokens_on`, `autoindex_on`, logging, TLS protocol/cipher, request-size, and access-control rules after the NGINX 3.0.0 benchmark walk. |
| STD-GAP-003 | Nginx CIS | direct-rule | P2 | Validate and potentially add Nginx TLS hardening rules not currently represented, such as session ticket, OCSP stapling completeness, or DH parameter posture checks. |
| STD-GAP-004 | Nginx CIS | host-depth | P3 | Classify Nginx file ownership, permissions, package, service user, and filesystem layout recommendations as host-depth unless an explicit host mode is added. |
| STD-GAP-005 | Apache CIS | covered | P1 | Fill CIS references for existing Apache checks such as `server_tokens_not_prod`, `server_signature_not_off`, `trace_enable_not_off`, `options_indexes`, status/info exposure, request limits, and logging. |
| STD-GAP-006 | Apache CIS | direct-rule | P2 | Add Apache TLS directive checks for `SSLProtocol`, `SSLCipherSuite`, `SSLHonorCipherOrder`, stapling, and compression where the parser already exposes enough directive context. |
| STD-GAP-007 | Apache CIS | parser-depth | P2 | Improve module inventory and include/effective handling before adding rules that reason about enabled module sets beyond the existing CGI/status/info checks. |
| STD-GAP-008 | IIS / Windows Server | covered | P1 | Map existing IIS and universal TLS/SChannel registry checks to active Windows Server or Microsoft hardening references where the requirement is host policy rather than IIS XML. |
| STD-GAP-009 | IIS / vendor docs | direct-rule | P2 | Validate additional IIS XML checks around request filtering deny lists, handler exposure, authentication defaults, and response-header behavior against current Microsoft documentation. |
| STD-GAP-010 | IIS legacy CIS | research | P3 | Decide whether unsupported CIS IIS 7/8 documents should be used only as historical notes, not as primary compliance references. |
| STD-GAP-011 | External probes | covered | P1 | Add ASVS references to the dedicated `ASVS` column for observable runtime behavior: TLS protocol negotiation, weak cipher negotiation, certificate validity, security headers, dangerous methods, and exposed sensitive files. |
| STD-GAP-012 | Standards output | direct-rule | P2 | After references stabilize, add optional report grouping by standard (`--group-by standard` or JSON `standards`) without changing rule behavior. |
| STD-GAP-013 | ASVS 5.0.0 | direct-rule | P2 | Add CSP quality probes for `frame-ancestors`, `object-src`, `base-uri`, and reporting directives after deciding the desired strictness. |
| STD-GAP-014 | ASVS 5.0.0 | probe-depth | P3 | Extend TLS probing for forward secrecy, cipher preference, OCSP stapling, and ECH before claiming deeper V12 coverage. |

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
  scoped config case when the server supports inheritance; for probe-based or
  runtime rules, the scoped equivalent can be different observable runtime
  conditions (such as HTTP path, redirect target, endpoint mode, or probe
  result) or a controlled config fixture that changes the observed probe signal
  without relying on host inspection;
- `docs/rule-coverage.md` is updated in the same PR;
- false-positive risk is described when the source item depends on host state
  not visible to the current analyzer.

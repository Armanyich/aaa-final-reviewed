# Rule Coverage

This document is the inventory and (eventually) standards mapping for every
rule shipped by webconf-audit. It supports Stage 2 of the project roadmap
(standards-driven rule expansion) by giving us a single place to see what we
already cover and where the gaps are.

## How this file is generated

The inventory tables below are derived from the rule registry. To regenerate
them after adding or modifying rules, dump the registry to JSON:

```bash
webconf-audit list-rules --format json > rule-inventory.json
```

The JSON payload contains every RuleMeta field
(`rule_id`, `title`, `severity`, `description`, `recommendation`,
`category`, `server_type`, `input_kind`, `tags`, `condition`, `order`)
and is the source of truth for tooling. The tables here are kept in sync with
that output and may include hand-curated columns (CWE, OWASP, CIS) that the
CLI does not own.

A pytest sync check (`tests/test_rule_coverage_doc.py`) runs in CI and fails
if a registered rule is missing from this document, if the document mentions
an unknown rule, or if the `Total rules` / per-group `Count` numbers drift
from the registry. PRs that change the rule registry must also update this
file.

## Summary

Total rules: **183**

| Dimension | Counts |
| --- | --- |
| Category | local (103), external (69), universal (11) |
| Severity | high (12), medium (61), low (99), info (11) |
| Input kind | ast (69), probe (69), effective (27), normalized (11), htaccess (6), mixed (1) |

## Inventory tables

Columns:

- **Rule ID** -- canonical identifier in the registry.
- **Severity** -- default severity assigned to findings produced by the rule.
- **Input** -- RuleMeta.input_kind (data the runner consumes).
- **Tags** -- registry tags used for filtering (`webconf-audit list-rules --tag ...`).
- **CWE / OWASP / CIS** -- standards mapping. Filled per server family as
  Stage 2 step 3 progresses. A cell stays empty (`-`) when no honest mapping
  exists; CIS for universal rules delegates to the per-server tables because
  CIS benchmarks are vendor-specific.

### Universal Rules

Count: 11

Stage 2 step 3 mapping: **complete** for this group. CIS / vendor cells say
`_see vendor sections_` because each universal rule reduces to a
server-specific configuration check (Apache, Nginx, Lighttpd, or IIS) and the
matching CIS benchmark item lives in the corresponding server-family table.

| Rule ID | Severity | Input | Tags | CWE | OWASP | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- |
| `universal.tls_intent_without_config` | high | normalized | tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | _see vendor sections_ |
| `universal.weak_tls_protocol` | medium | normalized | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | _see vendor sections_ |
| `universal.weak_tls_ciphers` | medium | normalized | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | _see vendor sections_ |
| `universal.missing_hsts` | medium | normalized | headers, tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | _see vendor sections_ |
| `universal.missing_x_content_type_options` | low | normalized | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | _see vendor sections_ |
| `universal.missing_x_frame_options` | low | normalized | headers | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | _see vendor sections_ |
| `universal.missing_content_security_policy` | low | normalized | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | _see vendor sections_ |
| `universal.missing_referrer_policy` | low | normalized | headers | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | _see vendor sections_ |
| `universal.directory_listing_enabled` | medium | normalized | access | [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | _see vendor sections_ |
| `universal.server_identification_disclosed` | low | normalized | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | _see vendor sections_ |
| `universal.listen_on_all_interfaces` | info | normalized | network | - | - | _see vendor sections_ |

Mapping rationale (universal rules):

- `tls_intent_without_config` -- a listener advertises HTTPS but no TLS is
  configured, so traffic would travel in cleartext: CWE-319, OWASP A02
  (cryptographic failures).
- `weak_tls_protocol`, `weak_tls_ciphers` -- enabling SSLv2/SSLv3/TLSv1.0/1.1
  or RC4/DES/3DES/MD5 cipher suites is the textbook case of CWE-327
  (broken / risky cryptographic algorithm), which OWASP groups under A02.
- `missing_hsts` -- without HSTS a site can be downgraded to plain HTTP and
  expose credentials in cleartext (CWE-319). Practitioners normally treat the
  missing header itself as a misconfiguration (A05) rather than a primary
  crypto failure.
- `missing_x_content_type_options`, `missing_content_security_policy` -- both
  are protective response headers; their absence is best modelled as a
  generic protection-mechanism failure (CWE-693). OWASP A05 covers the
  hardening-headers category.
- `missing_x_frame_options` -- direct match for CWE-1021 (improper
  restriction of rendered UI layers / clickjacking).
- `missing_referrer_policy` -- the referrer header has nuanced semantics and
  no single CWE maps cleanly to "policy not set"; we leave CWE empty and keep
  OWASP A05 because the rule is a hardening-config check.
- `directory_listing_enabled` -- direct match for CWE-548 (exposure of
  information through directory listing). Categorised as A05 (misconfig)
  because the rule fires only when the operator explicitly enables listing.
- `server_identification_disclosed` -- CWE-200 (information exposure) is the
  honest weakness class; OWASP A05 covers it as a hardening item.
- `listen_on_all_interfaces` -- info-only finding describing a deployment
  hint, not a vulnerability. Both CWE and OWASP cells stay empty by design.

### Nginx (Local)

Count: 41

Stage 2 step 3 mapping: **CWE / OWASP complete** for this group. The CIS
column is empty even though a *CIS Nginx Benchmark* exists at
[cisecurity.org](https://www.cisecurity.org/benchmark/nginx) — exact section
numbers will be added in a separate gap-analysis PR (Stage 2 step 4) after a
full benchmark walk-through, so we do not write references that may drift
from the published version. Several rules are operational anti-patterns or
deprecated controls; their CWE/OWASP cells are intentionally empty (see
rationale).

| Rule ID | Severity | Input | Tags | CWE | OWASP | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- |
| `nginx.alias_without_trailing_slash` | low | ast | - | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) | - |
| `nginx.allow_all_with_deny_all` | low | ast | - | [CWE-863](https://cwe.mitre.org/data/definitions/863.html) | [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) | - |
| `nginx.autoindex_on` | medium | ast | - | [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `nginx.duplicate_listen` | low | ast | - | - | - | - |
| `nginx.executable_scripts_allowed_in_uploads` | medium | ast | - | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | [A04:2021](https://owasp.org/Top10/A04_2021-Insecure_Design/) | - |
| `nginx.if_in_location` | low | ast | - | - | - | - |
| `nginx.missing_access_log` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - |
| `nginx.missing_access_restrictions_on_sensitive_locations` | low | ast | - | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) | - |
| `nginx.missing_allowed_methods_restriction_for_uploads` | low | ast | - | [CWE-650](https://cwe.mitre.org/data/definitions/650.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `nginx.missing_auth_basic_user_file` | low | ast | - | [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | - |
| `nginx.missing_backup_file_deny` | low | ast | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `nginx.missing_client_body_timeout` | low | ast | - | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | - | - |
| `nginx.missing_client_header_timeout` | low | ast | - | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | - | - |
| `nginx.missing_client_max_body_size` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - |
| `nginx.missing_content_security_policy` | low | ast | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `nginx.missing_error_log` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - |
| `nginx.missing_hidden_files_deny` | low | ast | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `nginx.missing_hsts_header` | low | ast | headers, tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `nginx.missing_http2_on_tls_listener` | low | ast | - | - | - | - |
| `nginx.missing_http_method_restrictions` | low | ast | - | [CWE-650](https://cwe.mitre.org/data/definitions/650.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `nginx.missing_keepalive_timeout` | low | ast | - | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | - | - |
| `nginx.missing_limit_conn` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - |
| `nginx.missing_limit_conn_zone` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - |
| `nginx.missing_limit_req` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - |
| `nginx.missing_limit_req_zone` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - |
| `nginx.missing_log_format` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - |
| `nginx.missing_permissions_policy` | low | ast | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `nginx.missing_referrer_policy` | low | ast | headers | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `nginx.missing_send_timeout` | low | ast | - | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | - | - |
| `nginx.missing_server_name` | low | ast | - | - | - | - |
| `nginx.missing_ssl_certificate` | low | ast | - | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `nginx.missing_ssl_certificate_key` | low | ast | - | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `nginx.missing_ssl_ciphers` | low | ast | - | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `nginx.missing_ssl_prefer_server_ciphers` | low | ast | - | [CWE-757](https://cwe.mitre.org/data/definitions/757.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `nginx.missing_x_content_type_options` | low | ast | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `nginx.missing_x_frame_options` | low | ast | headers | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `nginx.missing_x_xss_protection` | low | ast | headers | - | - | - |
| `nginx.server_tokens_on` | low | ast | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `nginx.ssl_stapling_missing_resolver` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `nginx.ssl_stapling_without_verify` | low | ast | - | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `nginx.weak_ssl_protocols` | medium | ast | - | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |

Mapping rationale (nginx rules):

- `alias_without_trailing_slash` -- a misconfigured `alias` allows path
  traversal outside the intended root: CWE-22 (path traversal), OWASP A01.
- `allow_all_with_deny_all` -- conflicting `allow all` / `deny all` directives
  let nginx pick the first match, so the intended access rules can be
  bypassed: CWE-863 (incorrect authorization), OWASP A01.
- `autoindex_on` -- direct match for CWE-548; categorised as A05 because the
  default is safe and the operator must explicitly enable listing.
- `duplicate_listen`, `if_in_location`, `missing_http2_on_tls_listener`,
  `missing_server_name` -- operational anti-patterns and best-practice
  hints, not vulnerabilities; CWE/OWASP cells stay empty.
- `executable_scripts_allowed_in_uploads` -- upload directories that also
  serve PHP/CGI are the textbook CWE-434 (unrestricted upload of dangerous
  file types). Categorised as OWASP A04 (insecure design): the issue is the
  combination of upload + script execution, not a single misconfig.
- `missing_access_log`, `missing_error_log`, `missing_log_format` -- without
  logs you cannot detect or investigate attacks: CWE-778, OWASP A09.
- `missing_access_restrictions_on_sensitive_locations` -- /admin, /private,
  /backup left open to the public: CWE-284 (improper access control),
  OWASP A01.
- `missing_allowed_methods_restriction_for_uploads`,
  `missing_http_method_restrictions` -- not pinning the allowed HTTP methods
  exposes CWE-650 (trusting HTTP permission methods), tracked as
  OWASP A05.
- `missing_auth_basic_user_file` -- enabling `auth_basic` without
  `auth_basic_user_file` leaves the location effectively unauthenticated:
  CWE-287 (improper authentication), OWASP A07.
- `missing_backup_file_deny`, `missing_hidden_files_deny` -- direct match for
  CWE-538 (file/directory information exposure); OWASP A05.
- `missing_client_body_timeout`, `missing_client_header_timeout`,
  `missing_keepalive_timeout`, `missing_send_timeout` -- absence of
  per-connection timeouts lets slow-loris-style clients hold sockets open
  forever: CWE-400 (uncontrolled resource consumption). OWASP cells empty
  because the 2021 Top 10 has no clean home for DoS hardening.
- `missing_client_max_body_size`, `missing_limit_conn`, `missing_limit_conn_zone`,
  `missing_limit_req`, `missing_limit_req_zone` -- no upper bound / rate
  limit on bodies, connections, or requests: CWE-770 (allocation without
  limits or throttling). OWASP cells empty for the same reason.
- `missing_content_security_policy`, `missing_x_content_type_options`,
  `missing_permissions_policy` -- protective response headers; CWE-693
  (protection mechanism failure), OWASP A05.
- `missing_hsts_header` -- missing HSTS allows downgrade to HTTP:
  CWE-319, OWASP A05 (matches the universal HSTS rule's mapping).
- `missing_referrer_policy` -- as in the universal table, no clean CWE for
  "policy not set"; we only keep OWASP A05.
- `missing_ssl_certificate`, `missing_ssl_certificate_key` -- listening on
  443 with `ssl` but no cert / key configured leaves the listener unable to
  establish TLS, so HTTPS to it fails: CWE-319, OWASP A02. As with the
  lighttpd `ssl_pemfile_missing` rule, the failure mode is connection
  refusal, not silent downgrade.
- `missing_ssl_ciphers` -- relying on the OpenSSL default cipher list keeps
  weak suites available on older builds: CWE-327, OWASP A02.
- `missing_ssl_prefer_server_ciphers` -- letting the client drive cipher
  selection enables downgrade attacks: CWE-757 (less-secure algorithm during
  negotiation), OWASP A02.
- `missing_x_frame_options` -- direct match for CWE-1021 (clickjacking),
  OWASP A05.
- `missing_x_xss_protection` -- the X-XSS-Protection header is deprecated and
  modern browsers ignore it; we keep the rule for legacy hardening but leave
  CWE/OWASP empty rather than mapping to controls that no longer apply.
- `server_tokens_on` -- nginx version disclosure: CWE-200, OWASP A05.
- `ssl_stapling_missing_resolver` -- enabling `ssl_stapling` without a
  resolver silently disables stapling, but it is a configuration mistake
  rather than a vulnerability class; CWE empty, OWASP A05 (misconfig).
- `ssl_stapling_without_verify` -- accepting OCSP responses without
  validation is CWE-295 (improper certificate validation), OWASP A02.
- `weak_ssl_protocols` -- TLSv1.0 / TLSv1.1 / SSLv3 are textbook CWE-327,
  OWASP A02 (matches the universal `weak_tls_protocol` rule).

### Apache (Local)

Count: 27

Stage 2 step 3 mapping: **CWE / OWASP complete** for this group. As with
nginx, the CIS column stays empty even though a *CIS Apache HTTP Server
Benchmark* exists at
[cisecurity.org](https://www.cisecurity.org/benchmark/apache_http_server) —
specific section numbers will land with the Stage 2 step 4 gap-analysis PR.
Rules that are best-practice / organisational (e.g. demanding explicit
`AllowOverride`, requiring `ErrorDocument`) leave CWE empty when no clean
weakness class fits, and `htaccess_*` rules are typed to the override-driven
weakness they create rather than to ".htaccess" itself.

| Rule ID | Severity | Input | Tags | CWE | OWASP | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- |
| `apache.allowoverride_all_in_directory` | medium | ast | - | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.backup_temp_files_not_restricted` | low | ast | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.custom_log_missing` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - |
| `apache.directory_without_allowoverride` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.error_document_404_missing` | low | ast | - | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.error_document_500_missing` | low | ast | - | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.error_log_missing` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - |
| `apache.htaccess_auth_without_require` | medium | htaccess | htaccess | [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | - |
| `apache.htaccess_disables_security_headers` | medium | htaccess | htaccess, headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.htaccess_enables_cgi` | medium | htaccess | htaccess | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.htaccess_enables_directory_listing` | medium | htaccess | htaccess | [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.htaccess_contains_security_directive` | medium | htaccess | htaccess | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.htaccess_rewrite_without_limit` | low | htaccess | htaccess | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.htaccess_weakens_security` | high | mixed | htaccess | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.index_options_fancyindexing_enabled` | low | ast | - | [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.index_options_scanhtmltitles_enabled` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.limit_request_body_missing_or_invalid` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - |
| `apache.limit_request_fields_missing_or_invalid` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - |
| `apache.options_execcgi_enabled` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.options_includes_enabled` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.options_indexes` | medium | ast | - | [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.options_multiviews_enabled` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.server_info_exposed` | low | ast | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.server_signature_not_off` | low | ast | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.server_status_exposed` | low | ast | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.server_tokens_not_prod` | low | ast | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `apache.trace_enable_not_off` | low | ast | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |

Mapping rationale (apache rules):

- `allowoverride_all_in_directory` -- `AllowOverride All` lets any `.htaccess`
  file under the directory grant or weaken authorization, mod_rewrite, or
  options: CWE-732 (incorrect permission assignment for critical resource),
  OWASP A05.
- `backup_temp_files_not_restricted` -- no `<FilesMatch>` block denying
  `*.bak`, `*.swp`, `*.tmp` lets editors' temp files be served as static
  content: CWE-538 (file/directory information exposure), OWASP A05.
- `custom_log_missing`, `error_log_missing` -- absence of `CustomLog` /
  `ErrorLog` defeats incident response: CWE-778 (insufficient logging),
  OWASP A09.
- `directory_without_allowoverride` -- a `<Directory>` block without an
  explicit `AllowOverride` makes the override behaviour depend on
  inherited / default settings, which is a maintainability and review hazard
  rather than a weakness class. CWE empty, OWASP A05 (best-practice
  misconfig).
- `error_document_404_missing`, `error_document_500_missing` -- without a
  custom `ErrorDocument`, Apache renders the default page that may include
  build / module details: CWE-209 (information exposure through an error
  message), OWASP A05.
- `htaccess_auth_without_require` -- declaring `AuthType` / `AuthName`
  without a matching `Require` leaves the realm effectively open: CWE-287
  (improper authentication), OWASP A07.
- `htaccess_disables_security_headers` -- `Header unset` against security
  response headers turns the protection off: CWE-693 (protection mechanism
  failure), OWASP A05.
- `htaccess_enables_cgi`, `options_execcgi_enabled`, `options_includes_enabled`
  -- enabling CGI / SSI from `.htaccess` or `Options` is an attack-surface
  increase, not a textbook weakness class. CWE empty, OWASP A05.
- `htaccess_enables_directory_listing`, `index_options_fancyindexing_enabled`,
  `options_indexes` -- direct match for CWE-548 (directory listing); OWASP
  A05.
- `htaccess_contains_security_directive` -- moving security directives into
  `.htaccess` instead of the main config is a governance / review issue, not
  a weakness class. CWE empty, OWASP A05.
- `htaccess_rewrite_without_limit` -- `RewriteRule` without a guarding
  `RewriteCond` is a heuristic for rewrite logic that may run more broadly
  than intended; we keep CWE empty because the practical risk is
  case-by-case, OWASP A05 (best-practice misconfig).
- `htaccess_weakens_security` -- `.htaccess` re-enables `ServerSignature`
  after the main config disabled it: CWE-200 (information exposure),
  OWASP A05.
- `index_options_scanhtmltitles_enabled` -- enables Apache to scan HTML
  files for titles when rendering a directory listing; only matters once
  listing is already on, so we keep CWE empty and tag OWASP A05.
- `limit_request_body_missing_or_invalid`, `limit_request_fields_missing_or_invalid`
  -- absence of `LimitRequestBody` / `LimitRequestFields` lets clients send
  arbitrarily large bodies or header lists: CWE-770 (allocation of resources
  without limits or throttling). OWASP empty (no clean DoS-hardening home in
  the 2021 Top 10).
- `options_multiviews_enabled` -- content negotiation can expose unintended
  files (e.g. backup variants), but this is about default behaviour rather
  than a single weakness; CWE empty, OWASP A05.
- `server_info_exposed`, `server_status_exposed`,
  `server_signature_not_off`, `server_tokens_not_prod` -- all leak server
  build / module / runtime information: CWE-200 (information exposure),
  OWASP A05.
- `trace_enable_not_off` -- `TraceEnable On` keeps the HTTP `TRACE` method
  available, the classic vector for cross-site tracing (XST) which lets an
  attacker echo back `Authorization` / `Cookie` headers: CWE-200 (information
  exposure), OWASP A05.

### Lighttpd (Local)

Count: 15

Stage 2 step 3 mapping: **complete** for this group. The CIS column is empty
across the whole group: there is no official *CIS Lighttpd Benchmark*, so we
do not invent one. Where vendor guidance from
[lighttpd.net wiki](https://redmine.lighttpd.net/projects/lighttpd/wiki)
applies, it is mentioned in the rationale below rather than in a column
that would imply a benchmark mapping.

| Rule ID | Severity | Input | Tags | CWE | OWASP | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- |
| `lighttpd.access_log_missing` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - |
| `lighttpd.dir_listing_enabled` | medium | effective | - | [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `lighttpd.error_log_missing` | medium | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - |
| `lighttpd.max_connections_missing` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - |
| `lighttpd.max_request_size_missing` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - |
| `lighttpd.missing_strict_transport_security` | medium | effective | headers | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `lighttpd.missing_x_content_type_options` | medium | effective | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `lighttpd.mod_cgi_enabled` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `lighttpd.mod_status_public` | medium | effective | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `lighttpd.server_tag_not_blank` | low | effective | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `lighttpd.ssl_engine_not_enabled` | medium | effective | tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `lighttpd.ssl_honor_cipher_order_missing` | medium | effective | tls | [CWE-757](https://cwe.mitre.org/data/definitions/757.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `lighttpd.ssl_pemfile_missing` | high | ast | tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `lighttpd.url_access_deny_missing` | medium | ast | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `lighttpd.weak_ssl_cipher_list` | high | ast | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |

Mapping rationale (lighttpd rules):

- `access_log_missing`, `error_log_missing` -- without access/error logs an
  operator cannot detect or investigate attacks: textbook CWE-778
  (insufficient logging), grouped under OWASP A09 (security logging and
  monitoring failures).
- `dir_listing_enabled` -- direct match for CWE-548. Categorised as A05
  (misconfig) because lighttpd defaults are safe; the finding fires only
  when the operator explicitly enables `dir-listing.activate`.
- `max_connections_missing`, `max_request_size_missing` -- absence of
  `server.max-connections` / `server.max-request-size` lets clients exhaust
  connections or memory: CWE-770 (allocation of resources without limits).
  We leave the OWASP cell empty: denial-of-service hardening does not have
  a clean mapping in the 2021 Top 10, and forcing it under A05 would
  overstretch the category.
- `missing_strict_transport_security` -- without HSTS clients can be
  downgraded to plaintext (CWE-319). Tracked as A05 (hardening header
  misconfiguration), matching the universal HSTS rule's mapping.
- `missing_x_content_type_options` -- missing protective response header:
  CWE-693 (protection mechanism failure), OWASP A05.
- `mod_cgi_enabled` -- enabling `mod_cgi` is not a vulnerability per se, it
  is an attack-surface increase that violates least-privilege deployment.
  No single CWE maps cleanly, so the CWE cell stays empty; OWASP A05 covers
  it as a hardening item ("only enable modules you actually need").
- `mod_status_public`, `server_tag_not_blank` -- both leak server-internal
  information to unauthenticated clients: CWE-200 (information exposure),
  OWASP A05.
- `ssl_engine_not_enabled` -- a virtual host advertised over HTTPS but with
  `ssl.engine = "disable"` does not establish TLS correctly: CWE-319,
  OWASP A02.
- `ssl_honor_cipher_order_missing` -- letting the client pick the cipher
  exposes the server to downgrade attacks: CWE-757 (selection of
  less-secure algorithm during negotiation), OWASP A02.
- `ssl_pemfile_missing` -- TLS enabled but no certificate path configured:
  the listener cannot complete a TLS handshake, so HTTPS to that listener
  fails outright. We keep CWE-319 / OWASP A02 because the rule still flags a
  broken cryptographic deployment, but the failure mode is connection refusal,
  not an automatic downgrade to plaintext.
- `url_access_deny_missing` -- without `url.access-deny` for `.bak`, `.sql`,
  `.conf`, `.log`, the server can hand out backup/configuration files:
  CWE-538 (file and directory information exposure), OWASP A05.
- `weak_ssl_cipher_list` -- enabling RC4/DES/3DES/MD5/NULL/EXPORT cipher
  tokens is the textbook CWE-327 (broken / risky cryptographic algorithm),
  OWASP A02.

### IIS (Local)

Count: 20

Stage 2 step 3 mapping: **CWE / OWASP complete** for this group. As with
nginx and apache, the CIS column stays empty even though a *CIS Microsoft
IIS Benchmark* exists at
[cisecurity.org](https://www.cisecurity.org/benchmark/microsoft_iis) — the
section numbers will land with the Stage 2 step 4 gap-analysis PR. ASP.NET
debug / trace / detailed-error rules cluster around CWE-209 / CWE-489;
request-filtering rules cluster around CWE-176 (improper encoding
handling); attack-surface rules (`webdav_module_enabled`,
`cgi_handler_enabled`) leave CWE empty.

| Rule ID | Severity | Input | Tags | CWE | OWASP | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- |
| `iis.directory_browse_enabled` | medium | effective | - | [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `iis.http_errors_detailed` | medium | effective | - | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `iis.custom_errors_off` | medium | effective | - | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `iis.asp_script_error_sent_to_browser` | medium | effective | - | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `iis.compilation_debug_enabled` | medium | effective | - | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `iis.trace_enabled` | medium | effective | - | [CWE-215](https://cwe.mitre.org/data/definitions/215.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `iis.http_runtime_version_header_enabled` | low | effective | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `iis.request_filtering_allow_double_escaping` | medium | effective | - | [CWE-176](https://cwe.mitre.org/data/definitions/176.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `iis.request_filtering_allow_high_bit` | low | effective | - | [CWE-176](https://cwe.mitre.org/data/definitions/176.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `iis.ssl_not_required` | medium | effective | tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `iis.ssl_weak_cipher_strength` | low | effective | tls | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `iis.logging_not_configured` | medium | effective | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - |
| `iis.max_allowed_content_length_missing` | low | effective | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - |
| `iis.missing_hsts_header` | medium | effective | headers, tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `iis.forms_auth_require_ssl_missing` | medium | effective | tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `iis.session_state_cookieless` | medium | effective | - | [CWE-598](https://cwe.mitre.org/data/definitions/598.html) | [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | - |
| `iis.webdav_module_enabled` | medium | effective | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `iis.cgi_handler_enabled` | medium | effective | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `iis.custom_headers_expose_server` | low | effective | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `iis.anonymous_auth_enabled` | medium | effective | - | [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | - |

Mapping rationale (iis rules):

- `directory_browse_enabled` -- direct match for CWE-548 (directory listing);
  OWASP A05.
- `http_errors_detailed`, `custom_errors_off`,
  `asp_script_error_sent_to_browser` -- detailed-error / verbose-error
  configurations expose stack traces, file paths, and SQL fragments to
  unauthenticated users: CWE-209 (information exposure through an error
  message), OWASP A05.
- `compilation_debug_enabled` -- ASP.NET compiled in debug mode keeps
  symbols and timing-sensitive paths in the deployed binaries: CWE-489
  (active debug code), OWASP A05.
- `trace_enabled` -- ASP.NET request tracing exposes per-request payload to
  developers and, in misconfigured deployments, to attackers: CWE-215
  (insertion of sensitive information into debugging code), OWASP A05.
- `http_runtime_version_header_enabled`, `custom_headers_expose_server` --
  `X-AspNet-Version` and similar custom headers leak runtime / build info:
  CWE-200 (information exposure), OWASP A05.
- `request_filtering_allow_double_escaping`,
  `request_filtering_allow_high_bit` -- both relax IIS request-filtering
  rules around URL encoding so multi-encoded or non-ASCII characters slip
  through, which historically enabled path-traversal and filter-bypass
  attacks: CWE-176 (improper handling of Unicode encoding), OWASP A05.
- `ssl_not_required` -- a site that does not enforce `SslRequire` accepts
  plaintext HTTP for the same routes: CWE-319 (cleartext transmission of
  sensitive information), OWASP A02.
- `ssl_weak_cipher_strength` -- a `<security:access sslFlags=...>` value
  that does not pin a minimum cipher strength leaves weak ciphers
  acceptable: CWE-326 (inadequate encryption strength), OWASP A02.
- `logging_not_configured` -- no `<httpLogging>` / `<httpErrors>` logging
  defeats incident response: CWE-778, OWASP A09.
- `max_allowed_content_length_missing` -- no `maxAllowedContentLength`
  ceiling lets a client send arbitrarily large bodies: CWE-770. OWASP cell
  empty (no clean DoS-hardening home in the 2021 Top 10).
- `missing_hsts_header` -- matches the universal HSTS rule: CWE-319,
  OWASP A05 (misconfig).
- `forms_auth_require_ssl_missing` -- `<forms requireSSL="false">` lets the
  authentication ticket cookie travel in cleartext: CWE-319, OWASP A02.
- `session_state_cookieless` -- cookieless session state embeds the session
  identifier in the URL, leaking it via Referer headers, browser history,
  proxy logs, and copy/paste: CWE-598 (use of GET method with sensitive
  query strings), OWASP A07 (session management failure).
- `webdav_module_enabled`, `cgi_handler_enabled` -- enabling WebDAV or
  legacy CGI handlers is an attack-surface increase, not a textbook
  weakness class. CWE empty, OWASP A05.
- `anonymous_auth_enabled` -- the rule fires only when anonymous
  authentication is enabled *together with* another scheme. The anonymous
  module wins the auth handshake first, so authenticated checks downstream
  do not run: CWE-287 (improper authentication), OWASP A07.

### External (Probe-based)

Count: 69

Stage 2 step 3 mapping: **CWE / OWASP complete** for this group. The CIS
column is empty across the whole group on purpose: external probes are
black-box runtime checks that do not align with config-level CIS Benchmarks.
Their natural standards companions are the OWASP Cheat Sheet Series and
[OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
verification requirements, which we will reference in the Stage 2 step 4
gap-analysis PR rather than mid-table here. Info-only probes that describe
expected, public-by-design endpoints (`robots.txt`, `sitemap.xml`,
permissive 302 redirects, OPTIONS responses) leave both CWE and OWASP empty.

| Rule ID | Severity | Input | Tags | CWE | OWASP | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- |
| `external.nginx.version_disclosed_in_server_header` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.nginx.default_welcome_page` | medium | probe | - | [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.apache.version_disclosed_in_server_header` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.apache.mod_status_public` | medium | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.apache.etag_inode_disclosure` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.iis.aspnet_version_header_present` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.iis.detailed_error_page` | medium | probe | - | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.lighttpd.version_in_server_header` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.lighttpd.mod_status_public` | medium | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.cookie_missing_secure_on_https` | low | probe | - | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.cookie_missing_httponly` | low | probe | - | [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.cookie_missing_samesite` | low | probe | - | [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.cookie_samesite_none_without_secure` | low | probe | - | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.cors_wildcard_origin` | low | probe | - | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.cors_wildcard_with_credentials` | medium | probe | - | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.server_version_disclosed` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.x_powered_by_header_present` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.x_aspnet_version_header_present` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.x_frame_options_missing` | low | probe | - | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.x_frame_options_invalid` | low | probe | - | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.x_content_type_options_missing` | low | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.x_content_type_options_invalid` | low | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.content_security_policy_missing` | medium | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.content_security_policy_unsafe_inline` | medium | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.content_security_policy_unsafe_eval` | medium | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.referrer_policy_missing` | info | probe | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.referrer_policy_unsafe` | low | probe | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.permissions_policy_missing` | info | probe | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.coep_missing` | info | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.coop_missing` | info | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.corp_missing` | info | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.https_not_available` | medium | probe | - | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `external.http_not_redirected_to_https` | low | probe | - | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `external.hsts_header_missing` | low | probe | - | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.hsts_header_invalid` | medium | probe | - | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.hsts_max_age_too_short` | low | probe | - | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.hsts_missing_include_subdomains` | info | probe | - | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.http_redirect_not_permanent` | info | probe | - | - | - | - |
| `external.trace_method_allowed` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.allow_header_dangerous_methods` | medium | probe | - | [CWE-650](https://cwe.mitre.org/data/definitions/650.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.options_method_exposed` | info | probe | - | - | - | - |
| `external.dangerous_http_methods_enabled` | medium | probe | - | [CWE-650](https://cwe.mitre.org/data/definitions/650.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.trace_method_exposed_via_options` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.webdav_methods_exposed` | medium | probe | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.git_metadata_exposed` | high | probe | - | [CWE-540](https://cwe.mitre.org/data/definitions/540.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.server_status_exposed` | medium | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.server_info_exposed` | medium | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.nginx_status_exposed` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.env_file_exposed` | high | probe | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.htaccess_exposed` | medium | probe | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.htpasswd_exposed` | high | probe | - | [CWE-522](https://cwe.mitre.org/data/definitions/522.html) | [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | - |
| `external.wordpress_admin_panel_exposed` | low | probe | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.phpinfo_exposed` | medium | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.elmah_axd_exposed` | medium | probe | - | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.trace_axd_exposed` | high | probe | - | [CWE-215](https://cwe.mitre.org/data/definitions/215.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.web_config_exposed` | high | probe | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.robots_txt_exposed` | info | probe | - | - | - | - |
| `external.sitemap_xml_exposed` | info | probe | - | - | - | - |
| `external.svn_metadata_exposed` | medium | probe | - | [CWE-540](https://cwe.mitre.org/data/definitions/540.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.certificate_expired` | high | probe | - | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `external.certificate_expires_soon` | medium | probe | - | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `external.tls_certificate_self_signed` | medium | probe | - | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `external.tls_1_0_supported` | high | probe | - | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `external.tls_1_1_supported` | medium | probe | - | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `external.tls_1_3_not_supported` | low | probe | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.weak_cipher_suite` | high | probe | - | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `external.cert_chain_incomplete` | medium | probe | - | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |
| `external.cert_chain_length_unusual` | low | probe | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - |
| `external.cert_san_mismatch` | medium | probe | - | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - |

Mapping rationale (external probes), grouped by pattern:

- **Server fingerprinting** -- the per-server `*.version_disclosed_in_server_header`
  family (`external.nginx.*`, `external.apache.*`, `external.iis.*`,
  `external.lighttpd.*`), plus `external.server_version_disclosed`,
  `external.x_powered_by_header_present`,
  `external.x_aspnet_version_header_present`,
  `external.iis.aspnet_version_header_present`,
  `external.apache.etag_inode_disclosure`,
  `external.phpinfo_exposed`, `external.nginx_status_exposed`,
  `external.apache.mod_status_public`, `external.lighttpd.mod_status_public`,
  `external.server_info_exposed`, `external.server_status_exposed`,
  `external.trace_method_allowed`, `external.trace_method_exposed_via_options`
  -- all leak server / runtime / module information to unauthenticated
  clients: CWE-200, OWASP A05.
- `external.nginx.default_welcome_page` -- the unconfigured-default page
  proves the server still runs in a stock state: CWE-1188 (insecure default
  initialization of resource), OWASP A05.
- `external.iis.detailed_error_page`, `external.elmah_axd_exposed` -- public
  detailed error pages or error logs expose stack traces and SQL fragments:
  CWE-209 (information exposure through an error message), OWASP A05.
- `external.trace_axd_exposed` -- ASP.NET `trace.axd` exposes per-request
  payloads and developer-only data: CWE-215 (insertion of sensitive
  information into debugging code), OWASP A05.
- **Cookie hardening** (`cookie_missing_secure_on_https`,
  `cookie_samesite_none_without_secure`) -- direct match for CWE-614
  (sensitive cookie in HTTPS session without Secure attribute);
  (`cookie_missing_httponly`) -- CWE-1004; (`cookie_missing_samesite`) --
  CWE-1275. All under OWASP A05 (hardening misconfiguration). Cookie
  hardening also lives in OWASP A07 conceptually, but A05 is the more
  honest fit because the rules check transport configuration rather than
  authentication failure.
- **CORS** (`cors_wildcard_origin`, `cors_wildcard_with_credentials`) --
  CWE-942 (permissive cross-domain policy with untrusted domains),
  OWASP A05.
- **Hardening response headers**
  (`x_frame_options_missing`, `x_frame_options_invalid`) -- CWE-1021
  (clickjacking protection failure);
  (`x_content_type_options_missing/invalid`,
  `content_security_policy_missing`,
  `content_security_policy_unsafe_inline`,
  `content_security_policy_unsafe_eval`,
  `coep_missing`, `coop_missing`, `corp_missing`) -- CWE-693 (protection
  mechanism failure) because the protection control is absent or
  weakened. OWASP A05.
- `referrer_policy_*`, `permissions_policy_missing` -- as in the universal
  table, no clean CWE for "policy not set / unsafe"; we keep OWASP A05.
- **HTTPS / HSTS** (`https_not_available`, `http_not_redirected_to_https`,
  `hsts_header_missing`, `hsts_header_invalid`, `hsts_max_age_too_short`,
  `hsts_missing_include_subdomains`) -- without HTTPS or proper HSTS the
  channel is downgradeable to plaintext: CWE-319. The two transport
  rules (`https_not_available`, `http_not_redirected_to_https`) sit under
  A02 (cryptographic failures); the HSTS-policy rules are hardening
  misconfigurations under A05.
- `http_redirect_not_permanent` -- cosmetic / SEO-style finding (302
  instead of 301); no security weakness.
- **HTTP method exposure** (`allow_header_dangerous_methods`,
  `dangerous_http_methods_enabled`) -- CWE-650 (trusting HTTP permission
  methods on the server side), OWASP A05;
  (`webdav_methods_exposed`) -- attack-surface increase rather than a
  weakness class, CWE empty, OWASP A05;
  (`options_method_exposed`) -- info-level observation, no
  CWE/OWASP.
- **Sensitive paths** (`git_metadata_exposed`, `svn_metadata_exposed`) --
  CWE-540 (inclusion of sensitive information in source code);
  (`env_file_exposed`, `htaccess_exposed`, `web_config_exposed`) -- CWE-538
  (file/directory information exposure);
  (`htpasswd_exposed`) -- CWE-522 (insufficiently protected credentials),
  OWASP A07;
  (`external.wordpress_admin_panel_exposed`) -- operational guidance for an
  exposed WordPress admin panel, not a weakness class (CWE empty, OWASP A05);
  `robots_txt_exposed` and `sitemap_xml_exposed` are public-by-design and
  stay empty for both CWE and OWASP.
- **TLS protocols / ciphers** (`tls_1_0_supported`, `tls_1_1_supported`,
  `weak_cipher_suite`) -- CWE-327, OWASP A02. (`tls_1_3_not_supported`,
  `cert_chain_length_unusual`) -- operational gaps, not weakness classes;
  CWE empty, OWASP A05.
- **Certificate validity** (`certificate_expired`,
  `certificate_expires_soon`, `tls_certificate_self_signed`,
  `cert_chain_incomplete`, `cert_san_mismatch`) -- a public-facing server
  whose certificate cannot be validated by mainstream clients pushes those
  clients into either accepting an unsafe channel or refusing to connect:
  CWE-295 (improper certificate validation, used as the umbrella class for
  the server-side configuration error), OWASP A02.

## Standards mapping plan

Stage 2 step 3 of the roadmap is to map these rules to external standards
only where the mapping is honest:

- **CWE** for rules with a clear weakness class.
- **OWASP** for rules supporting an application security control.
- **CIS / vendor hardening** for rules that mirror configuration-specific
  guidance from CIS benchmarks or vendor hardening guides.

Progress:

- [x] Universal rules (11)
- [x] Nginx local rules (41) — CWE/OWASP filled; CIS pending Stage 2 step 4
- [x] Apache local rules (27) — CWE/OWASP filled; CIS pending Stage 2 step 4
- [x] Lighttpd local rules (15)
- [x] IIS local rules (20) — CWE/OWASP filled; CIS pending Stage 2 step 4
- [x] External (probe) rules (69) — CWE/OWASP filled; CIS not applicable (probes)

Stage 2 step 3 complete for CWE / OWASP. CIS section numbers and OWASP ASVS
references are deferred to Stage 2 step 4 (gap analysis), where each
benchmark is walked end-to-end so references match the published versions.

Each follow-up PR fills one server family at a time and only writes a CWE,
OWASP, or CIS reference when it is verifiable. Cells without an honest match
stay as `-`.

### Mapping conventions

- **CWE links** point at the canonical entry on
  [cwe.mitre.org](https://cwe.mitre.org/data/definitions/).
- **OWASP** uses the 2021 Top 10 categories
  ([A01](https://owasp.org/Top10/A01_2021-Broken_Access_Control/),
  [A02](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/),
  [A05](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/),
  ...). When a more specific Cheat Sheet or ASVS section applies it is
  noted alongside the Top 10 cell.
- **CIS / vendor hardening** points at a specific section of a CIS Benchmark
  (e.g. *CIS Apache HTTP Server 2.4 Benchmark* §7.6) or an official vendor
  hardening guide. Universal rules delegate to the per-server tables because
  the same conceptual check has different section numbers in each benchmark.
- Cells stay empty (`-`) when no honest match exists; we prefer an empty cell
  to a stretched mapping.

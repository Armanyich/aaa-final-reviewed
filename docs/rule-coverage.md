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
- **CWE / OWASP / CIS** -- standards mapping. These are intentionally empty
  during Stage 2 preparation; they will be filled in step 3 of Stage 2 only
  when the mapping for a given rule is honest and verifiable.

### Universal Rules

Count: 11

| Rule ID | Severity | Input | Tags | CWE | OWASP | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- |
| `universal.tls_intent_without_config` | high | normalized | tls | _TBD_ | _TBD_ | _TBD_ |
| `universal.weak_tls_protocol` | medium | normalized | tls | _TBD_ | _TBD_ | _TBD_ |
| `universal.weak_tls_ciphers` | medium | normalized | tls | _TBD_ | _TBD_ | _TBD_ |
| `universal.missing_hsts` | medium | normalized | headers, tls | _TBD_ | _TBD_ | _TBD_ |
| `universal.missing_x_content_type_options` | low | normalized | headers | _TBD_ | _TBD_ | _TBD_ |
| `universal.missing_x_frame_options` | low | normalized | headers | _TBD_ | _TBD_ | _TBD_ |
| `universal.missing_content_security_policy` | low | normalized | headers | _TBD_ | _TBD_ | _TBD_ |
| `universal.missing_referrer_policy` | low | normalized | headers | _TBD_ | _TBD_ | _TBD_ |
| `universal.directory_listing_enabled` | medium | normalized | access | _TBD_ | _TBD_ | _TBD_ |
| `universal.server_identification_disclosed` | low | normalized | disclosure | _TBD_ | _TBD_ | _TBD_ |
| `universal.listen_on_all_interfaces` | info | normalized | network | _TBD_ | _TBD_ | _TBD_ |

### Nginx (Local)

Count: 41

| Rule ID | Severity | Input | Tags | CWE | OWASP | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- |
| `nginx.alias_without_trailing_slash` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.allow_all_with_deny_all` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.autoindex_on` | medium | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.duplicate_listen` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.executable_scripts_allowed_in_uploads` | medium | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.if_in_location` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_access_log` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_access_restrictions_on_sensitive_locations` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_allowed_methods_restriction_for_uploads` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_auth_basic_user_file` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_backup_file_deny` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_client_body_timeout` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_client_header_timeout` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_client_max_body_size` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_content_security_policy` | low | ast | headers | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_error_log` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_hidden_files_deny` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_hsts_header` | low | ast | headers, tls | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_http2_on_tls_listener` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_http_method_restrictions` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_keepalive_timeout` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_limit_conn` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_limit_conn_zone` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_limit_req` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_limit_req_zone` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_log_format` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_permissions_policy` | low | ast | headers | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_referrer_policy` | low | ast | headers | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_send_timeout` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_server_name` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_ssl_certificate` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_ssl_certificate_key` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_ssl_ciphers` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_ssl_prefer_server_ciphers` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_x_content_type_options` | low | ast | headers | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_x_frame_options` | low | ast | headers | _TBD_ | _TBD_ | _TBD_ |
| `nginx.missing_x_xss_protection` | low | ast | headers | _TBD_ | _TBD_ | _TBD_ |
| `nginx.server_tokens_on` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.ssl_stapling_missing_resolver` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.ssl_stapling_without_verify` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `nginx.weak_ssl_protocols` | medium | ast | - | _TBD_ | _TBD_ | _TBD_ |

### Apache (Local)

Count: 27

| Rule ID | Severity | Input | Tags | CWE | OWASP | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- |
| `apache.allowoverride_all_in_directory` | medium | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `apache.backup_temp_files_not_restricted` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `apache.custom_log_missing` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `apache.directory_without_allowoverride` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `apache.error_document_404_missing` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `apache.error_document_500_missing` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `apache.error_log_missing` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `apache.htaccess_auth_without_require` | medium | htaccess | htaccess | _TBD_ | _TBD_ | _TBD_ |
| `apache.htaccess_disables_security_headers` | medium | htaccess | htaccess, headers | _TBD_ | _TBD_ | _TBD_ |
| `apache.htaccess_enables_cgi` | medium | htaccess | htaccess | _TBD_ | _TBD_ | _TBD_ |
| `apache.htaccess_enables_directory_listing` | medium | htaccess | htaccess | _TBD_ | _TBD_ | _TBD_ |
| `apache.htaccess_contains_security_directive` | medium | htaccess | htaccess | _TBD_ | _TBD_ | _TBD_ |
| `apache.htaccess_rewrite_without_limit` | low | htaccess | htaccess | _TBD_ | _TBD_ | _TBD_ |
| `apache.htaccess_weakens_security` | high | mixed | htaccess | _TBD_ | _TBD_ | _TBD_ |
| `apache.index_options_fancyindexing_enabled` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `apache.index_options_scanhtmltitles_enabled` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `apache.limit_request_body_missing_or_invalid` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `apache.limit_request_fields_missing_or_invalid` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `apache.options_execcgi_enabled` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `apache.options_includes_enabled` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `apache.options_indexes` | medium | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `apache.options_multiviews_enabled` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `apache.server_info_exposed` | low | ast | disclosure | _TBD_ | _TBD_ | _TBD_ |
| `apache.server_signature_not_off` | low | ast | disclosure | _TBD_ | _TBD_ | _TBD_ |
| `apache.server_status_exposed` | low | ast | disclosure | _TBD_ | _TBD_ | _TBD_ |
| `apache.server_tokens_not_prod` | low | ast | disclosure | _TBD_ | _TBD_ | _TBD_ |
| `apache.trace_enable_not_off` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |

### Lighttpd (Local)

Count: 15

| Rule ID | Severity | Input | Tags | CWE | OWASP | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- |
| `lighttpd.access_log_missing` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `lighttpd.dir_listing_enabled` | medium | effective | - | _TBD_ | _TBD_ | _TBD_ |
| `lighttpd.error_log_missing` | medium | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `lighttpd.max_connections_missing` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `lighttpd.max_request_size_missing` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `lighttpd.missing_strict_transport_security` | medium | effective | headers | _TBD_ | _TBD_ | _TBD_ |
| `lighttpd.missing_x_content_type_options` | medium | effective | headers | _TBD_ | _TBD_ | _TBD_ |
| `lighttpd.mod_cgi_enabled` | low | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `lighttpd.mod_status_public` | medium | effective | - | _TBD_ | _TBD_ | _TBD_ |
| `lighttpd.server_tag_not_blank` | low | effective | disclosure | _TBD_ | _TBD_ | _TBD_ |
| `lighttpd.ssl_engine_not_enabled` | medium | effective | tls | _TBD_ | _TBD_ | _TBD_ |
| `lighttpd.ssl_honor_cipher_order_missing` | medium | effective | tls | _TBD_ | _TBD_ | _TBD_ |
| `lighttpd.ssl_pemfile_missing` | high | ast | tls | _TBD_ | _TBD_ | _TBD_ |
| `lighttpd.url_access_deny_missing` | medium | ast | - | _TBD_ | _TBD_ | _TBD_ |
| `lighttpd.weak_ssl_cipher_list` | high | ast | tls | _TBD_ | _TBD_ | _TBD_ |

### IIS (Local)

Count: 20

| Rule ID | Severity | Input | Tags | CWE | OWASP | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- |
| `iis.directory_browse_enabled` | medium | effective | - | _TBD_ | _TBD_ | _TBD_ |
| `iis.http_errors_detailed` | medium | effective | - | _TBD_ | _TBD_ | _TBD_ |
| `iis.custom_errors_off` | medium | effective | - | _TBD_ | _TBD_ | _TBD_ |
| `iis.asp_script_error_sent_to_browser` | medium | effective | - | _TBD_ | _TBD_ | _TBD_ |
| `iis.compilation_debug_enabled` | medium | effective | - | _TBD_ | _TBD_ | _TBD_ |
| `iis.trace_enabled` | medium | effective | - | _TBD_ | _TBD_ | _TBD_ |
| `iis.http_runtime_version_header_enabled` | low | effective | disclosure | _TBD_ | _TBD_ | _TBD_ |
| `iis.request_filtering_allow_double_escaping` | medium | effective | - | _TBD_ | _TBD_ | _TBD_ |
| `iis.request_filtering_allow_high_bit` | low | effective | - | _TBD_ | _TBD_ | _TBD_ |
| `iis.ssl_not_required` | medium | effective | tls | _TBD_ | _TBD_ | _TBD_ |
| `iis.ssl_weak_cipher_strength` | low | effective | tls | _TBD_ | _TBD_ | _TBD_ |
| `iis.logging_not_configured` | medium | effective | - | _TBD_ | _TBD_ | _TBD_ |
| `iis.max_allowed_content_length_missing` | low | effective | - | _TBD_ | _TBD_ | _TBD_ |
| `iis.missing_hsts_header` | medium | effective | headers, tls | _TBD_ | _TBD_ | _TBD_ |
| `iis.forms_auth_require_ssl_missing` | medium | effective | tls | _TBD_ | _TBD_ | _TBD_ |
| `iis.session_state_cookieless` | medium | effective | - | _TBD_ | _TBD_ | _TBD_ |
| `iis.webdav_module_enabled` | medium | effective | - | _TBD_ | _TBD_ | _TBD_ |
| `iis.cgi_handler_enabled` | medium | effective | - | _TBD_ | _TBD_ | _TBD_ |
| `iis.custom_headers_expose_server` | low | effective | disclosure | _TBD_ | _TBD_ | _TBD_ |
| `iis.anonymous_auth_enabled` | medium | effective | - | _TBD_ | _TBD_ | _TBD_ |

### External (Probe-based)

Count: 69

| Rule ID | Severity | Input | Tags | CWE | OWASP | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- |
| `external.nginx.version_disclosed_in_server_header` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.nginx.default_welcome_page` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.apache.version_disclosed_in_server_header` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.apache.mod_status_public` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.apache.etag_inode_disclosure` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.iis.aspnet_version_header_present` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.iis.detailed_error_page` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.lighttpd.version_in_server_header` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.lighttpd.mod_status_public` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.cookie_missing_secure_on_https` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.cookie_missing_httponly` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.cookie_missing_samesite` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.cookie_samesite_none_without_secure` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.cors_wildcard_origin` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.cors_wildcard_with_credentials` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.server_version_disclosed` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.x_powered_by_header_present` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.x_aspnet_version_header_present` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.x_frame_options_missing` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.x_frame_options_invalid` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.x_content_type_options_missing` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.x_content_type_options_invalid` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.content_security_policy_missing` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.content_security_policy_unsafe_inline` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.content_security_policy_unsafe_eval` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.referrer_policy_missing` | info | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.referrer_policy_unsafe` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.permissions_policy_missing` | info | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.coep_missing` | info | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.coop_missing` | info | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.corp_missing` | info | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.https_not_available` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.http_not_redirected_to_https` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.hsts_header_missing` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.hsts_header_invalid` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.hsts_max_age_too_short` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.hsts_missing_include_subdomains` | info | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.http_redirect_not_permanent` | info | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.trace_method_allowed` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.allow_header_dangerous_methods` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.options_method_exposed` | info | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.dangerous_http_methods_enabled` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.trace_method_exposed_via_options` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.webdav_methods_exposed` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.git_metadata_exposed` | high | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.server_status_exposed` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.server_info_exposed` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.nginx_status_exposed` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.env_file_exposed` | high | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.htaccess_exposed` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.htpasswd_exposed` | high | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.wordpress_admin_panel_exposed` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.phpinfo_exposed` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.elmah_axd_exposed` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.trace_axd_exposed` | high | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.web_config_exposed` | high | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.robots_txt_exposed` | info | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.sitemap_xml_exposed` | info | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.svn_metadata_exposed` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.certificate_expired` | high | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.certificate_expires_soon` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.tls_certificate_self_signed` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.tls_1_0_supported` | high | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.tls_1_1_supported` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.tls_1_3_not_supported` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.weak_cipher_suite` | high | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.cert_chain_incomplete` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.cert_chain_length_unusual` | low | probe | - | _TBD_ | _TBD_ | _TBD_ |
| `external.cert_san_mismatch` | medium | probe | - | _TBD_ | _TBD_ | _TBD_ |

## Standards mapping plan

Stage 2 step 3 of the roadmap is to map these rules to external standards
only where the mapping is honest:

- **CWE** for rules with a clear weakness class.
- **OWASP** for rules supporting an application security control.
- **CIS / vendor hardening** for rules that mirror configuration-specific
  guidance from CIS benchmarks or vendor hardening guides.

The inventory above is populated; the standards columns will be filled in
subsequent PRs, one server family at a time, with explicit references in the
commit message or PR description.

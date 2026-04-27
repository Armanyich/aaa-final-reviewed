# Cleanup

## Tech debt

No open items.

## Watch later

### Nginx parser single-quoted strings
- Current tokenizer supports double-quoted strings, bare words, comments, and source locations.
- Real Nginx configurations can contain single-quoted directive arguments, for example `add_header Content-Security-Policy 'default-src self';`.
- Current behavior treats a single quote as a parse error: `Single-quoted strings are not supported in nginx config`.
- Future cleanup: support single-quoted arguments in `src/webconf_audit/local/nginx/parser/parser.py` while preserving line/column tracking and existing double-quoted string behavior.
- Add tokenizer, parser, and end-to-end `analyze_nginx_config()` tests for single-quoted values and unterminated single-quoted strings.

### IIS XML-only TLS visibility
- Current IIS normalizer in `src/webconf_audit/local/normalizers/iis_normalizer.py` extracts HTTPS bindings, `sslFlags`, security headers, and access-policy signals from XML configuration.
- Real IIS TLS protocol and cipher configuration is often controlled outside `web.config` / `applicationHost.config`, for example through Windows registry / SChannel settings.
- Current XML-only local analysis therefore cannot fully reconstruct effective IIS TLS protocol and cipher policy.
- Future cleanup: either keep this limitation explicitly documented in user-facing architecture/report text, or add an optional Windows-specific enrichment path for registry-backed TLS settings.

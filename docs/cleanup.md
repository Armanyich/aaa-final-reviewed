# Cleanup

## Tech debt

### Duplicate path-matching helpers
- Current code has duplicated path normalization / coverage logic in two places:
- `src/webconf_audit/local/apache_htaccess.py`
- `src/webconf_audit/local/rules/apache/allowoverride_all.py`
- This is not a functional bug right now, but it is technical debt.
- Risk: future drift if one helper changes and the second copy is not updated.
- Future cleanup: extract shared path-matching helpers into one common module.

## Watch later

### Self-match in `_find_effective_allowoverride()`
- Rechecked against the current `AllowOverride` / `.htaccess` test slice and still considered correct.
- The function can match the current block itself on exact path match.
- This does not create a false positive for restricted values like `FileInfo`.
- Reason: the rule fires only for direct `All`, inherited `All`, or missing effective `AllowOverride`.
- No immediate fix required, but keep this behavior in mind if the rule logic is expanded later.

### IIS `applicationHost` warning-path E2E coverage
- Current warning branches for discovered site-level `web.config` files are covered via helper-level tests.
- This is acceptable for now and not considered a functional gap.
- Future cleanup: add one end-to-end `applicationHost.config` test that exercises discovery plus warning propagation for unreadable or malformed child `web.config`.

### IIS modular rule import smoke coverage
- Current IIS modular-rule coverage exercises package-level loading through `registry.ensure_loaded(...)` plus CLI and local IIS end-to-end tests.
- This is acceptable for now and not considered a functional gap.
- Future cleanup: add one smoke test that imports each module from `src/webconf_audit/local/rules/iis/` individually to catch packaging or import regressions earlier.

### Nginx parser single-quoted strings
- Current tokenizer supports double-quoted strings, bare words, comments, and source locations.
- Real Nginx configurations can contain single-quoted directive arguments, for example `add_header Content-Security-Policy 'default-src self';`.
- Current behavior treats a single quote as a parse error: `Single-quoted strings are not supported in nginx config`.
- Future cleanup: support single-quoted arguments in `src/webconf_audit/local/nginx/parser/parser.py` while preserving line/column tracking and existing double-quoted string behavior.
- Add tokenizer, parser, and end-to-end `analyze_nginx_config()` tests for single-quoted values and unterminated single-quoted strings.

### Lighttpd semantic alignment with real server behavior
- Current Lighttpd analyzer is intentionally conservative, but it does not yet fully match documented Lighttpd config semantics.
- Current merge logic in `src/webconf_audit/local/lighttpd/effective.py` can accumulate `+=` across matched conditional scopes more broadly than Lighttpd itself.
- Future cleanup: narrow `+=` handling so it matches documented Lighttpd behavior for same-condition / same-nesting merges and does not over-accumulate across unrelated conditional scopes.
- Current condition parser/evaluator supports only a subset of Lighttpd syntax: `==`, `!=`, `=~`, `!~` and a limited set of variables such as `$HTTP["host"]`, `$HTTP["url"]`, `$HTTP["remoteip"]`, `$HTTP["scheme"]`, `$SERVER["socket"]`.
- Future cleanup: extend Lighttpd condition support in `src/webconf_audit/local/lighttpd/parser/parser.py` and `src/webconf_audit/local/lighttpd/conditions.py` to cover additional documented operators and fields, including `=^`, `=$`, `$REQUEST_HEADER[...]`, and other common request predicates.
- Current parser treats only plain `else { ... }` as a special branch shape; Lighttpd-specific `else <condition>`, `elseif`, `elsif`, and `else if` forms are not modeled precisely.
- Future cleanup: add explicit support for `else if`-style conditional chains so branch selection and effective merge order better match Lighttpd.
- Current variable expansion in `src/webconf_audit/local/lighttpd/variables.py` handles `var.*` references defined in config, but not documented `env.*` inputs or built-ins such as `var.PID` and `var.CWD`.
- Future cleanup: extend variable resolution to cover `env.*` and documented built-in variables with regression tests.
- Current analyzer skips `include_shell` by default unless `--execute-shell` is enabled. This is an intentional safety tradeoff, but it is still a divergence from real Lighttpd startup behavior.
- Future cleanup: keep the safe default, but document this divergence clearly in user-facing docs and add stronger tests for the explicit execution path.

### IIS XML-only TLS visibility
- Current IIS normalizer in `src/webconf_audit/local/normalizers/iis_normalizer.py` extracts HTTPS bindings, `sslFlags`, security headers, and access-policy signals from XML configuration.
- Real IIS TLS protocol and cipher configuration is often controlled outside `web.config` / `applicationHost.config`, for example through Windows registry / SChannel settings.
- Current XML-only local analysis therefore cannot fully reconstruct effective IIS TLS protocol and cipher policy.
- Future cleanup: either keep this limitation explicitly documented in user-facing architecture/report text, or add an optional Windows-specific enrichment path for registry-backed TLS settings.

# Cleanup

## Tech debt

No open items.

## Watch later

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

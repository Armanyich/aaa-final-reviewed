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

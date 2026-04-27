# Cleanup

## Tech debt

No open items.

## Watch later

### IIS XML-only TLS visibility
- Current IIS normalizer in `src/webconf_audit/local/normalizers/iis_normalizer.py` extracts HTTPS bindings, `sslFlags`, security headers, and access-policy signals from XML configuration.
- Real IIS TLS protocol and cipher configuration is often controlled outside `web.config` / `applicationHost.config`, for example through Windows registry / SChannel settings.
- Current XML-only local analysis therefore cannot fully reconstruct effective IIS TLS protocol and cipher policy.
- Future cleanup: either keep this limitation explicitly documented in user-facing architecture/report text, or add an optional Windows-specific enrichment path for registry-backed TLS settings.

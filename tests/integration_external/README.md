## External Integration Slice

This directory contains Docker-backed integration validation for the
`external` pipeline.

Scope:

- live `analyze-external` validation against stock `nginx`, `httpd`, and
  `lighttpd` containers
- a small custom Python responder for deterministic IIS-like signals and
  edge HTTP behaviors that are awkward to force from stock containers alone

This slice is intentionally separate from `demo/local_admin/`, which remains
local-mode validation only.

Typical commands:

- PowerShell: `.\.venv\Scripts\python.exe -m pytest -q tests/integration_external`
- POSIX shell: `python -m pytest -q tests/integration_external`
- `docker compose -p webconf_audit_external_it -f tests/integration_external/docker-compose.yml up -d --build`
- `docker compose -p webconf_audit_external_it -f tests/integration_external/docker-compose.yml down -v --remove-orphans`

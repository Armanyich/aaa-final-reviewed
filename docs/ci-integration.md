# CI Integration

`webconf-audit` can run as a CI gate with `--fail-on`. In gating mode the
command exits with:

- `0` when analysis completed and no active findings met the threshold.
- `1` when analysis produced an execution or configuration error.
- `2` when at least one active finding met the selected severity threshold.

All `analyze-*` commands support `--format json` for machine-readable reports.

## Suppressions

When `--fail-on` is used, `webconf-audit` reads `.webconf-audit-ignore.yml` from
the current working directory if it exists. Use `--suppressions <path>` to point
at a different file in CI or to apply suppressions during an interactive run.

Each suppression must include:

- `rule_id`
- either `fingerprint` or locator fields such as `source`, `line`, `xml_path`,
  `details`, or `scope`
- `reason`
- `expires` in `YYYY-MM-DD` format

Expired suppressions do not hide findings and are reported as analysis issues.

```yaml
suppressions:
  - rule_id: nginx.weak_ssl_protocols
    fingerprint: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    reason: Legacy TLS migration is tracked in SEC-123.
    expires: 2026-06-30

  - rule_id: nginx.server_tokens_on
    source: nginx.conf
    line: 12
    reason: Accepted for the internal staging endpoint until the shared image is rebuilt.
    expires: 2026-05-31
```

Suppressed findings are removed from the active finding count and are emitted in
JSON under `suppressed_findings`.

## GitHub Actions

```yaml
name: webconf-audit

on:
  pull_request:
  push:
    branches: [main, master]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install "webconf-audit @ git+https://github.com/Armanyich/aaa-final-reviewed.git@v0.1.0"
      - run: webconf-audit analyze-nginx nginx.conf --fail-on medium --format json > webconf-audit.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: webconf-audit-report
          path: webconf-audit.json
```

## GitLab CI

```yaml
webconf-audit:
  image: python:3.12
  script:
    - python -m pip install "webconf-audit @ git+https://github.com/Armanyich/aaa-final-reviewed.git@v0.1.0"
    - webconf-audit analyze-nginx nginx.conf --fail-on medium --format json > webconf-audit.json
  artifacts:
    when: always
    paths:
      - webconf-audit.json
```

## Azure DevOps

```yaml
trigger:
  - main

pool:
  vmImage: ubuntu-latest

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: "3.12"
  - script: |
      python -m pip install "webconf-audit @ git+https://github.com/Armanyich/aaa-final-reviewed.git@v0.1.0"
      webconf-audit analyze-nginx nginx.conf --fail-on medium --format json > webconf-audit.json
    displayName: Run webconf-audit
  - publish: webconf-audit.json
    artifact: webconf-audit-report
    condition: always()
```

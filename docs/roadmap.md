# Roadmap

This roadmap replaces the old cleanup-oriented planning. The project is moving
from cleanup work to productization: first make the tool reliable in its own
development workflow, then make it easy to run in other projects' CI, then add
clear change-oriented reporting, and only after that expand rule coverage
against security standards.

## Stage 1 - CI And Reporting Foundation

Stage 1 has a fixed order. Do not start standards-driven rule expansion until
all three milestones below are complete.

### 1. Project CI For This Repository

Goal: every pull request to this repository must automatically prove that
`webconf-audit` still works.

Implementation plan:

1. Add `.github/workflows/ci.yml`.
2. Run on `pull_request` and pushes to `master`.
3. Use the supported Python range, starting with Python 3.10 and the current
   development version used locally.
4. Install dependencies from the project metadata.
5. Run fast deterministic checks:
   - `ruff check .`
   - `python -m compileall -q src`
   - `pytest tests --ignore=tests/integration_external --ignore=tests/integration_local --ignore=tests/integration_rule_coverage -q`
   - `webconf-audit list-rules`
6. Add a separate manual or scheduled workflow for Docker-backed integration
   tests, because those depend on a live Docker environment.
7. Document the local equivalent command set in `README.md`.

Acceptance criteria:

- CI runs automatically on every PR.
- A normal code-only PR cannot merge with failing lint, unit tests, import
  compilation, or rule registry loading.
- Docker integration tests are available without making every PR depend on a
  local service stack.
- The workflow runs under the repository owner only and does not require
  secrets.

Status: implemented by `.github/workflows/ci.yml`,
`.github/workflows/docker-integration.yml`, the `dev` dependency group, and the
local command set documented in `README.md`.

### 2. CI Integration Features For Users

Goal: make `webconf-audit` usable as a CI gate in real repositories, not only as
an interactive local scanner.

Implementation plan:

1. Define stable finding fingerprints:
   - `rule_id`
   - `server_type`
   - normalized source path or target
   - normalized line/XML path/details where available
   - scope identifier where available
2. Add severity-based exit behavior:
   - `--fail-on medium|high|critical`
   - exit code `0` when no matching findings exist
   - exit code `2` when policy-blocking findings exist
   - exit code `1` for execution/configuration errors
3. Add a suppression file:
   - default path `.webconf-audit-ignore.yml`
   - each suppression must include `rule_id`, locator/fingerprint data,
     `reason`, and `expires`
   - expired suppressions must stop suppressing and emit an analysis issue
   - suppressions without a reason must be rejected
4. Add CI-oriented documentation:
   - GitHub Actions example
   - GitLab CI example
   - Azure DevOps example if the CLI shape is stable
5. Add a minimal SARIF or Markdown CI report only after fingerprints and
   suppressions are stable.

Acceptance criteria:

- Users can fail CI on unsuppressed findings at a chosen severity.
- Users can document accepted risk with an expiry date.
- Suppressed findings are counted separately from active findings.
- CI examples are copy-paste runnable for at least GitHub Actions.
- The default local interactive behavior remains unchanged unless CI flags are
  used.

Status: stable fingerprints and severity-based CI exit codes are implemented.
The suppression file and CI examples are covered by the suppression-file
milestone branch.

### 3. Baseline/Diff Reporting

Goal: make reports show what is new and what was fixed compared with a previous
known state.

Implementation plan:

1. Reuse the stable finding fingerprint from milestone 2.
2. Add baseline creation from a JSON report:
   - command or flag to write a baseline file
   - baseline stores finding fingerprints plus enough display metadata to be
     useful in review
3. Add diff mode:
   - current findings compared with a baseline
   - findings grouped as `new`, `unchanged`, `resolved`, and `suppressed`
4. Add CI policy over diff results:
   - `--fail-on-new medium|high|critical`
   - optionally keep `--fail-on` for all current unsuppressed findings
5. Improve text and JSON output:
   - text report gets a short diff summary
   - JSON report gets explicit arrays for `new_findings`, `resolved_findings`,
     `unchanged_findings`, and `suppressed_findings`
6. Add tests for fingerprint stability, renamed paths where possible, expired
   suppressions, and resolved findings.

Acceptance criteria:

- A repository with existing debt can keep CI green while blocking new issues.
- A cleanup PR can clearly show which findings disappeared.
- JSON output is machine-readable enough for downstream dashboards.
- Text output stays readable for humans and does not bury new findings.

## Stage 2 - Standards-Driven Rule Expansion

Stage 2 starts only after Stage 1 is complete.

Goal: expand rules deliberately using CWE, OWASP, CIS, and similar references,
instead of adding one-off checks opportunistically.

Process:

1. Generate a current rule inventory:
   - rule id
   - server type
   - severity
   - tags
   - data source required
   - current tests
2. Create `docs/rule-coverage.md`.
3. Map current rules to standards where the mapping is honest:
   - CWE where a rule has a clear weakness class
   - OWASP where a rule supports an application security control
   - CIS or vendor hardening guidance where a rule is configuration-specific
4. For candidate standards items, classify each gap:
   - direct rule can be added now
   - rule requires deeper parser/effective-config analysis
   - rule requires deeper external probing
   - rule is out of scope for this tool
5. Build a separate standards roadmap from that gap analysis.
6. Implement new work in small PRs:
   - first add parser/probe depth when needed
   - then add the rule
   - then add mapping metadata and tests

Acceptance criteria:

- Every new standards-driven rule has a clear source reference.
- Rules that require deeper analysis are not hacked around with weak string
  matching.
- Rule metadata can eventually power reports grouped by standard.
- The project keeps false positives lower priority than raw rule count.

## Current Priority

The next concrete task after merging milestone 1 is milestone 2: CI integration
features for users.

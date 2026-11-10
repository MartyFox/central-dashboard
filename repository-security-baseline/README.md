# Repository Security Baseline

> **Status:** draft, staged inside the IDP Handbook. The PoC shares the
> `repository-security-scanning` repository with the dashboard.
> Owner: _TBC (Platform Capability)_.

A drop-in GitHub Actions workflow that gives any repository a minimum security baseline:
known-vulnerable dependencies, committed secrets and (optionally) insecure configuration
are found on every pull request and on a weekly schedule, with no per-project setup.

## The problem

Many projects have no automated security scanning, especially where SonarQube or GitHub
Advanced Security is not available. When a major CVE lands (Log4Shell, `xz`, compromised
npm packages), teams cannot quickly answer "are we affected?". More code is being written
quickly, including AI-assisted code, so vulnerable dependencies and hard-coded secrets reach
the default branch unnoticed.

## The pattern

1. **Scan every change and on a schedule.** Pull requests catch new problems. The weekly
   run catches new CVEs published against code that has not changed.
2. **Match declared dependencies against public advisory data.** Lockfiles and manifests
   are compared with CVE / GHSA / OSV data. No code is executed, no AI is involved, and the
   project does not need to be built.
3. **Report first, then enforce.** Start in `report` mode to see the backlog without
   blocking anyone. Switch to `enforce` once it is triaged.
4. **Block only what is actionable.** By default a run is blocked by CRITICAL/HIGH
   vulnerabilities that have a fix, any committed secret, and CRITICAL/HIGH
   misconfigurations.
5. **Exceptions are explicit and expire.** Every accepted risk has a reason and an expiry
   date in version control.
6. **The scanner is part of the supply chain.** Pin it, verify it, and update it on
   purpose.

This implementation uses [Trivy](https://trivy.dev) (Apache-2.0) on GitHub Actions. The
same pattern applies to other CI systems and scanners (OSV-Scanner, Grype).

## What it does

| Check | Default | Finds |
|---|---|---|
| Vulnerable dependencies (`vuln`) | On | Packages in lockfiles/manifests with known CVEs (npm, pip, Maven, Gradle, Go, NuGet, Cargo, Composer, Ruby and more) |
| Secrets (`secret`) | On | Private keys, cloud credentials, tokens and similar committed to the repository |
| Misconfiguration (`misconfig`) | Opt-in | Insecure Dockerfiles, Terraform, Kubernetes manifests, Helm charts, CloudFormation |

Every run produces:

- a **job summary** with counts, the files that were scanned, and tables of findings
  (secret values are never shown);
- either **results artifacts** containing JSON/SARIF, or a **sanitised summary output**
  committed by the separate branch publisher;
- optionally, **GitHub code scanning alerts** (Security tab and pull request annotations).

## When to use it

- The repository has no dependency or secret scanning today.
- You need a fast, consistent answer to "does this repository use the vulnerable version?"
  across many repositories.
- You want a minimum bar that works the same way across teams and languages.

**Coexistence:** it does not replace SonarQube (code quality and SAST), Dependabot
(automatic update pull requests) or GitHub Advanced Security. If those already cover
dependency and secret scanning, you may not need this. If they only partly cover it, run
this in `report` mode alongside them.

**Not suitable** when you need source-code analysis (SAST), container image scanning of
built images, or licence compliance. Those are possible extensions, not part of the
baseline.

## Getting started

1. Copy [examples/security-baseline.yml](examples/security-baseline.yml) to
   `.github/workflows/security-baseline.yml` in your repository.
2. Replace `your-org/repository-security-scanning` with the repository publishing
   the reusable workflow and pin to a release commit SHA. For the shared PoC this is
   `your-org/repository-security-scanning`; the workflow must be at root
   `.github/workflows/`, not inside this component folder.
3. Open a pull request. Read the job summary.
4. Triage findings: upgrade, remove, or record an exception (see below).
5. Change `mode: report` to `mode: enforce` and make the check required in branch
   protection.

For GitHub code scanning alerts, use
[examples/security-baseline-with-code-scanning.yml](examples/security-baseline-with-code-scanning.yml)
instead. Code scanning needs a public repository or GitHub Code Security on
private/internal repositories.

### Choose runner and storage with configuration

The recommended caller example defaults to branch storage with remote caching off.
Set repository Actions variables after installing it:

```text
SECURITY_RUNNER           ["self-hosted","linux","x64"]
SECURITY_RESULTS_STORAGE  branch
SECURITY_RESULTS_BRANCH   security-results
SECURITY_RESULTS_PATH     security-summary.json
SECURITY_CACHE_DB         false
```

For hosted execution use `["ubuntu-24.04"]` (the runner default). For artifacts set
`SECURITY_RESULTS_STORAGE` to `artifacts`. No implementation edits are required.
Variables are not credentials; keep normal repository/organisation access controls.

The example's scan job stays `contents: read`. Its separate
[publish-results.yml](.github/workflows/publish-results.yml) job requests
`contents: write` on trusted default-branch push/schedule/manual runs only. It
creates a dedicated orphan branch, commits a small sanitised summary and never
force-pushes. Branch rules must allow that token's writes; no bypass is attempted.
PRs never publish summaries, and GitHub-token commits do not recursively trigger
normal push workflows. Do not configure a scan on the results branch.

If scanning fails before summary creation, the publisher records an explicit error
when it can run. When it cannot (cancellation, denied permissions or missing outputs),
the collector sees missing/mismatched results rather than the previous success.
Old runs/attempts cannot overwrite a newer published run.

Raw JSON/SARIF is deleted from runner temp after reporting/upload. Branch mode keeps
no scanner artifacts, including on PR runs; PR details remain in their job summaries.
Optional code-scanning upload requires artifacts mode. The code-scanning example
uses artifacts explicitly and supports the same runner variable.

## Costs, runners and result storage

**No paid scanner licence is needed, but hosted execution is not automatically free.**
Private/internal scans use the caller repository owner's Actions compute allowance,
not the central workflow owner's. Public standard runners are free under GitHub's
terms; do not make private code or findings public to obtain free execution.

Choose hosted/self-hosted runner labels and artifacts/branch storage through inputs
or the example's variables. Artifact mode retains JSON/SARIF for 30 days by default
and can incur storage charges even on self-hosted runners. Branch mode avoids those
uploads; the publisher adds a separate job whose runtime also counts if hosted.

Recommended zero-additional-spend approach: existing isolated self-hosted capacity
where suitable, or included hosted compute with verified hard-stop spending controls,
plus small sanitised Git summaries using branch mode. An alert
alone does not cap spend. If allowance runs out, scanning may stop; surface that gap.

The examples trigger on PR updates, default-branch pushes and a weekly schedule.
Each trigger consumes runtime. Weekly scanning is cheaper than daily but finds new
advisories later; PR scanning can run many times per PR and does not replace scheduled
scans of unchanged dependencies. For 50 repos and three minutes/scan:

| Policy | Approximate scan minutes/month |
|---|---:|
| Weekly (four scans/repo) | 600 |
| Daily (30 scans/repo) | 4,500 |
| PRs (20 triggering updates/repo) | 3,000 |

These are separate/additive workloads; pushes, retries and manual runs add more.
Database downloads and reporting count too. Prefer weekly plus PR checks initially,
measure usage, and agree the acceptable advisory detection window.

See the shared guide for [hosted, self-hosted and hybrid models](../README.md#deployment-models),
[cost estimates and controls](../README.md#cost-and-scan-frequency),
[results-branch design and permissions](../README.md#results-branch-versus-actions-artifacts)
and [shared-repo PoC wiring](../README.md#shared-repository-pages-deployment-proof-of-concept).
Self-hosted scanners require Linux x64 with Bash, curl, tar, sha256sum, jq and
mikefarah/yq v4. The workflow checks these before scanning; use supported runner/action
versions and isolated ephemeral workers for untrusted PRs. Publisher also needs a
supported Node.js 24 runtime, provided by setup-node.

### Visibility of findings

Keep internal results private. Public source can be cloned and scanned by anyone,
but publishing centralised current findings still reduces attackers' reconnaissance
effort. A results branch in a public repo is public too; there is no private branch
visibility setting. Never commit secrets, raw snippets or sensitive exception details.
See [public-results considerations](../README.md#are-public-scanner-results-a-security-concern).

### Inputs

| Input | Default | Description |
|---|---|---|
| `runner` | `["ubuntu-24.04"]` | JSON array of labels; self-hosted Linux x64 supported. |
| `results-storage` | `artifacts` | `artifacts` uploads reports; `branch` returns summary only. Recommended caller selects `branch`. |
| `artifact-retention-days` | `30` | 1..90, subject to repository limits; applies only to artifacts. |
| `cache-db` | `true` | Use GitHub database cache. Recommended caller selects `false`. |
| `mode` | `report` | `report` never fails the run. `enforce` fails on blocking findings or invalid exceptions. |
| `severity` | `CRITICAL,HIGH` | Severities that count as blocking. |
| `fail-on-unfixed` | `false` | Also block on vulnerabilities with no fixed version. |
| `scanners` | `vuln,secret` | Add `misconfig` for IaC and Dockerfile checks. |
| `scan-path` | `.` | Directory to scan, relative to the repository root. |
| `skip-dirs` | _(none)_ | Comma-separated directories or globs to skip, relative to `scan-path`. |
| `ignore-file` | `.trivyignore.yaml` | Exceptions file, relative to the repository root. |
| `max-exception-days` | `180` | Longest allowed time until an exception expires. |
| `db-repository` | _(Trivy default)_ | OCI mirror of the vulnerability database, for restricted networks. |
| `artifact-name` | `security-baseline-results` | Results artifact name. Change it if you call the workflow more than once in a run. |

Outputs: `summary` (JSON), `blocking-count`, `vulnerability-count`, `secret-count`,
`misconfiguration-count`, `artifact-name`.

The separate publisher accepts `runner`, `summary`, `scan-result`, `results-branch`
and `results-path`. The caller example wires scan outputs and job result automatically.

### Tests

Run `node --test tests/*.test.mjs` with Node.js 24+, Bash, jq and mikefarah/yq v4.
Tests execute the workflow's actual summary/publisher scripts with mocked GitHub
responses, including sanitisation, early failures, ordering, unsafe paths and denied
writes. The nested live fixture workflow tests actual Trivy on GitHub in a standalone
deployment. A hosted and self-hosted pilot is still required before production.

## Exceptions

Record accepted risks in `.trivyignore.yaml` at the repository root (see
[examples/.trivyignore.yaml](examples/.trivyignore.yaml)):

```yaml
vulnerabilities:
  - id: CVE-2024-12345
    paths:
      - package-lock.json
    statement: Vulnerable parser not reachable from our code. Accepted by J Smith, SEC-123.
    expired_at: 2027-03-31
```

- `statement` and `expired_at` are required. `expired_at` must be within
  `max-exception-days`.
- Expired entries stop suppressing findings automatically.
- Policy problems are warnings in `report` mode and fail the run in `enforce` mode.
- Exceptions go through normal code review, so there is an audit trail.

If a secret is found, **rotate it first**. Removing it from the code does not remove it
from Git history.

## Security of the accelerator itself

In March 2026 the `aquasecurity/trivy-action` and `setup-trivy` tags and Trivy v0.69.4 were
compromised ([GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)).
The scanner is a supply-chain risk, so this workflow:

- downloads a pinned Trivy release directly and verifies its SHA-256 before running it
  (no third-party wrapper actions);
- pins every action to a full commit SHA;
- runs the scan job with `contents: read` only, with checkout credentials not persisted;
- grants `security-events: write` only to a separate upload job that runs no scanner, and
  skips it for pull requests from forks;
- ignores repository-supplied `trivy.yaml`, `trivy-secret.yaml` and `.trivyignore` files,
  so a pull request cannot quietly turn scanning off (only the reviewed exceptions file is
  used);
- passes all inputs through environment variables and validates them.

## Limitations

- Only dependencies declared in supported lockfiles/manifests are checked. Without a
  lockfile, transitive dependencies may be missed. The job summary lists the files that
  were scanned so gaps are visible.
- Trivy's built-in secret rules skip paths containing `test` or `example` and Markdown
  files, to reduce noise from sample data.
- Results depend on advisory data quality. "No findings" does not mean "no
  vulnerabilities".
- Code scanning file links assume `scan-path` is `.`.
- Secret scanning only checks the current files, not Git history.

## Maintenance

**Owner:** _TBC_. The owner reviews Dependabot pull requests, updates Trivy, and responds to
scanner security advisories.

### Updating Trivy

1. Choose a release that is at least a few days old and has no open advisories.
2. Verify the release (GitHub immutable release attestation or the cosign signature on
   `checksums.txt`).
3. Take the `Linux-64bit.tar.gz` SHA-256 from the verified `checksums.txt`.
4. Update `TRIVY_VERSION` and `TRIVY_SHA256` together in
   [security-baseline.yml](.github/workflows/security-baseline.yml).
5. Confirm the self-test passes, then tag a new release.

Pinned actions are updated by Dependabot ([.github/dependabot.yml](.github/dependabot.yml)).
Review every update. Never auto-merge.

### Self-test

[self-test.yml](.github/workflows/self-test.yml) scans
[tests/fixtures/vulnerable-project](tests/fixtures/vulnerable-project), which contains
deliberately outdated packages, an obviously fake private key, an insecure Dockerfile, and
one valid and one expired exception. It checks that each type is detected, that the valid
exception suppresses its CVE and the expired one does not, and that secret values do not
appear in the results. It then scans the accelerator itself in `enforce` mode.

The fixture exception `CVE-2018-18074` expires on 2027-03-31. Move the date forward when it
gets close, or the self-test will start reporting a warning.

## Central reporting

The companion [Repository Security Dashboard](../repository-security-dashboard/README.md)
collects this workflow's existing artifacts from an explicit list of repositories.
It provides organisation-wide counts, freshness and run links through GitHub Pages.
No scanner changes or credentials in application repositories are required.

## Retirement

Retire or replace this accelerator if the organisation adopts a managed equivalent for all
repositories (for example, GitHub Advanced Security with dependency review and secret
scanning enforced by organisation policy). Callers then delete one workflow file.

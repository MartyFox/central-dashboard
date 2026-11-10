# Repository Security Dashboard

> Draft accelerator. Owner: TBC (Platform Capability). The PoC shares the
> `repository-security-scanning` repository with the Repository Security Baseline;
> future users can deploy this component independently.

Collect existing security results (artifacts or branch summaries) from an **explicit repository list** and
build a static GitHub Pages dashboard. No organisation discovery, new scanning,
AI, database, runtime backend or third-party JavaScript dependencies.

## What it does

1. Read [repositories.json](repositories.json), the complete allowlist.
2. Query only each listed repository and named caller workflow.
3. Select its newest eligible run on the configured/default branch.
4. Read the configured branch summary or named artifact, including failed enforcement runs.
5. Validate run identity/freshness, retain counts only, and build the static site.

The collector never triggers remote workflows or scans. Adding a repository to this
list controls collection only; install the baseline workflow in that repository first.

The page shows repository/team, severity counts, secrets, detected dependency/config
targets, scan freshness, latest run links and explicit missing/error states.
Optional CodeQL integration adds application counts, separate scan status/time/run
links and an application finding-type filter. Search and filters run locally in
the browser.

```text
Configured repository list -> GitHub API -> branch summaries / baseline artifacts
                                                     |
                                              sanitised data.json
                                                     |
                                          static GitHub Pages site
```

## Setup

1. For a standalone deployment, copy this folder's **contents**, including `.github`,
   into its own repository. For the shared PoC, keep the component folder and follow
   [root workflow and subfolder build wiring](../README.md#shared-repository-pages-deployment-proof-of-concept).
   Nested workflows do not run automatically, either in the handbook or the PoC repo.
2. Populate [repositories.json](repositories.json), using
   [examples/repositories.json](examples/repositories.json). Empty lists intentionally
   fail configuration validation. There is no wildcard or discovery mode.
3. Configure one authentication option below.
4. Enable **Settings -> Pages -> Build and deployment -> GitHub Actions**.
5. Run **Collect security results and build dashboard**, leaving `publish` unchecked.
   Check `preview` to retain a one-day `security-dashboard-preview` artifact for inspection.
6. Confirm the intended Pages audience and repository owners' approval. Run the
   workflow manually with `publish` checked to approve that deployment.

**A private source repository does not guarantee a private Pages site.** Repository
names, team names and vulnerability counts are sensitive information. Verify Pages
visibility before publishing. Private Pages requires a supported GitHub Enterprise
Cloud configuration. Add required reviewers to the `github-pages` environment for
an additional approval gate.

Scheduled runs collect daily **without deploying** or retaining preview artifacts
unless `DASHBOARD_PREVIEW` is `true`. Preview storage is opt-in.
Every Pages deployment requires the explicit manual `publish` input; no deployment
is performed by this local implementation. A published dashboard ages its scan
statuses in the browser, so old reports do not remain green indefinitely.

## Costs and deployment choices

Collection defaults to hosted `ubuntu-24.04`, reads configured artifacts/branch summaries,
and does not retain previews unless requested. Daily collection is about 30
builds/month; weekly is about four. It does not rescan source code, but still uses
runner time, API quota and storage. Polling faster than source scans adds limited value.
Manual Pages publication is separate from collection and must not be assumed to make
the collector's work free.

The source repo owner covers source scan execution/storage; the dashboard repo owner
covers collection/build usage. Both depend on existing plan allowances and billing
controls. Avoid buying Pages access-control upgrades merely for the PoC; use an
existing approved internal host if necessary.

**Recommended:** use existing self-hosted capacity where suitable, or included hosted
compute with enforceable stop-usage controls, and small Git-backed source summaries.
Self-hosting still has infrastructure/maintenance costs and does not remove any
remaining GitHub artifact storage charges.

Set Actions variable `DASHBOARD_RUNNER` to `["self-hosted","linux","x64"]` for
self-hosted execution, or `["ubuntu-24.04"]` for hosted. The manual workflow `runner`
input overrides it for that run; collector and deploy use the same choice. The test
workflow uses the variable. Existing runners need Node.js 24 support, Bash, unzip
and zip; shared-repo baseline contract tests also require jq and mikefarah/yq v4.
No implementation changes are required.

See [cost, frequency and budget guidance](../README.md#cost-and-scan-frequency)
and [hosted, self-hosted and hybrid models](../README.md#deployment-models).

### Artifact collection versus a results branch

Select `storage: branch` or `storage: artifacts` per repository in the JSON file.
Omitting `storage` preserves existing artifacts behaviour. Branch mode reads
`resultsBranch` (default `security-results`) and `resultsPath` (default
`security-summary.json`). A missing branch/file is a collection error, not a clean
result; a mismatched run ID/attempt is missing results. Neither falls back to artifacts.

Artifact App grants: **Actions: read + Metadata: read**. Branch collection adds
**Contents: read**, while retaining Actions read to check latest workflow health.
The collector requests Contents read only for installations with branch-mode repos.
Contents access covers the repository, not just one summary file. Source publishing
uses a separate trusted `contents: write` job; the dashboard remains read-only on
source repositories. Grant updates require owner approval.

See [the storage design and permission matrix](../README.md#results-branch-versus-actions-artifacts).
Pages Actions deployment uses a one-day deployment artifact, even in branch mode.

### Application scanning (CodeQL)

Enable the CodeQL job in the application's existing
[baseline caller](../repository-security-baseline/examples/security-baseline.yml)
by setting `CODEQL_LANGUAGES` (or passing languages directly). No separate consumer
workflow is needed. Then opt in per inventory entry:

```json
"codeql": {
  "workflow": "security-baseline.yml",
  "languages": ["go"]
}
```

Omit `codeql` to keep existing baseline-only behaviour. `workflow` names the
application's caller workflow; `languages` must match the JSON `languages` input it
passes to the central reusable CodeQL workflow. Analysis categories must be
`security-baseline/language:<language>`, as supplied by the example.

Add **Code scanning alerts: read** to the fine-grained PAT saved as
`DASHBOARD_READ_TOKEN`, or to the central GitHub App's repository permissions.
Keep existing **Actions: read**, **Metadata: read**, and branch-mode **Contents: read**.
Approve any App permission update at its installations. The collector requests
`security_events: read` only for owners with CodeQL-enabled inventory entries.
Credentials stay in the central repo; app workflows use their own `GITHUB_TOKEN`.

The collector checks the latest eligible configured caller on the configured/default
branch. With the combined caller, both scans share one run and its overall conclusion;
a failed job keeps that run non-passing even if another scanner produced counts.
CodeQL requires successful analyses for every configured
language at that run's commit and since that attempt started. Old commit/attempt
analyses cannot make a newer missing/failed scan appear clean. Analysis warnings or
zero rules show limited coverage. CodeQL counts are **open alerts**, excluding
dismissed alerts; alerts without a security severity use `UNKNOWN`. Alert details, source
paths and code snippets are never written to the static site.

The application column shows its own status, time and run link. Successful current
analyses explicitly show completion, rules run and open alerts (for example,
**Completed · 35 rules · 0 alerts**). Rule counts are summed across the latest
validated analysis for each configured language, not deduplicated across languages.
Missing, failed, pending, stale and limited-coverage scans retain their diagnostic
messages instead of a completion label. Overall repository
status reflects both scanners; a failed/missing app scan cannot leave an overall
green baseline result. Browser freshness checks age both scans independently.
Combined counts/totals are unavailable if any configured scanner's counts are
missing. Selecting a specific type still shows available counts for that scanner.
Unconfigured application scans show **Not configured**, not zero application findings.

Critical repositories have a red accent, tinted row and explicit severity label;
positive severity counts use distinct badges (critical red, high orange, medium
amber). Summary cards emphasise critical findings, secrets and incomplete coverage.
Repository highlighting uses the highest known severity across all finding types,
independent of filters, even when another scanner's counts are missing. Scan-health
badges remain separate: critical highlighting never hides stale/missing/error states,
and zero or unavailable counts are not given a positive severity highlight.
The results table scrolls within its own keyboard-focusable region on narrow
screens. Coverage guidance is available in **How to read these results**.

CodeQL alerts are read live at collection time and may change through triage between
scans. These counts are not Trivy policy-gate counts or proof of complete coverage.
For public repos, CodeQL and standard hosted runner execution are free; see
[scanner costs and setup](../repository-security-baseline/README.md#enable-infrastructure-and-application-checks)
for private-repo entitlement and storage/larger-runner caveats.

### Public results are an explicit disclosure decision

Anyone can scan public source with Trivy, but a dashboard makes current weak points
easier to find and correlate across repositories. Counts and names can themselves
be sensitive; public manifests do not prove production exposure. Do not publish
internal/private repo results without explicit permission and real access control.
A results branch has the visibility of its repo, while Pages visibility is configured
separately. Browser filters cannot hide sensitive data in a publicly served JSON file.
See [public-results risks and hosting alternatives](../README.md#are-public-scanner-results-a-security-concern).

### Repository list

```json
{
  "staleAfterHours": 192,
  "installations": {
    "your-org": "123456"
  },
  "repositories": [
    {
      "repository": "your-org/payments-api",
      "workflow": "security-baseline.yml",
      "storage": "branch",
      "resultsBranch": "security-results",
      "resultsPath": "security-summary.json",
      "team": "Payments"
    }
  ]
}
```

- `repository`: exact `owner/name`. Duplicate names, including case variants, fail.
- `workflow`: filename of the **caller workflow in the application repo**, not the
  remotely called reusable workflow. This avoids collecting another workflow's data.
- `storage`: `branch` or `artifacts` (default for existing configs).
- `resultsBranch` / `resultsPath`: branch-mode location, defaulting to
  `security-results` / `security-summary.json`.
- `artifact`: required for artifacts mode; exact artifact name. Defaults in the baseline are
  `security-baseline-results`, containing root-level `trivy-results.json`.
- `branch`: optional; otherwise fetch the repository's current default branch.
- `team`: optional label displayed on the dashboard.
- `staleAfterHours`: 1..8760; 192 hours allows eight days for weekly baseline scans.
- `installations`: owner-to-installation-ID mapping for GitHub App authentication.
  Keep IDs as strings. This configuration is versioned and reviewed with the repo list;
  it contains no credentials.

Runs from `push`, `schedule` and `workflow_dispatch` qualify. PR runs, including
same-repository PRs, are excluded. Results are not mixed across branches.
Deleting a repository from the list removes it on the next build. No source workflow
change is required for existing artifact users. Branch-mode users install the supplied
caller example with the publisher job once, then select modes using configuration.

### Authentication: GitHub App (recommended)

Create a GitHub App with repository permissions:

- **Actions: read**
- **Metadata: read** (required by GitHub)
- **Contents: read** for branch-mode repositories (not needed for artifact-only installations)

No webhook or code write access is needed. Use one GitHub App installed separately
by each repository owner (personal account or organisation), only on approved
repositories. The App must allow installation by those owners.

Configure dashboard repository variables under **Settings -> Secrets and variables
-> Actions -> Variables**:

- `DASHBOARD_APP_ID`

Keep the owner mapping in the `installations` field of
[repositories.json](repositories.json), alongside the repository list. For example:

```json
{
  "staleAfterHours": 192,
  "installations": {
    "your-org": "123456",
    "another-owner": "789012"
  },
  "repositories": [
    {
      "repository": "your-org/payments-api",
      "workflow": "security-baseline.yml",
      "artifact": "security-baseline-results"
    },
    {
      "repository": "another-owner/customer-web",
      "workflow": "security.yml",
      "artifact": "security-baseline-results"
    }
  ]
}
```

See the complete cross-owner [configuration example](examples/repositories.json).
Changes to owners and repos go through normal commits and PR review. Installation
IDs are not secrets. Each owner can find theirs in the URL when configuring the
installed App, for example `https://github.com/settings/installations/123456`.

Configure **one secret on the dashboard repository**:

- `DASHBOARD_APP_PRIVATE_KEY`: complete PEM private key for that App.

The collector validates that every listed owner has a mapping, checks that the
installation belongs to that owner, then mints a separate short-lived token per owner.
Each token is restricted to that owner's allowlisted repository names and read-only
permissions. Tokens are created when first needed, reused for that owner's repositories
and all revoked in a `finally` block, even if a revocation fails. An owner authentication
failure marks that owner's repositories as errors without stopping other owners.

Owner matching is case-insensitive. Unknown owners, invalid IDs and duplicate owners
or installation IDs fail configuration validation. Extra mapped owners cause no API
requests unless their repositories appear in the allowlist. No installation or repo
discovery is performed, and missing grants never trigger broader access.

**Existing single-owner setup still works:** keep `DASHBOARD_APP_INSTALLATION_ID`
instead of the mapping. Existing `DASHBOARD_APP_INSTALLATIONS` variables also remain
supported. Precedence is: file `installations`, then `DASHBOARD_APP_INSTALLATIONS`,
then single-owner `DASHBOARD_APP_INSTALLATION_ID`. To use a legacy variable, omit
`installations` from the file entirely. An empty or invalid file mapping fails rather
than falling back to a variable. Multiple owners require a mapping; a single
installation ID is never applied across owners.

### Alternative: fine-grained token

Set repository secret `DASHBOARD_READ_TOKEN` with read-only Actions and Metadata
access to exactly the selected repositories. It takes precedence over App settings.
Add Contents read if any selected repos use branch storage.
Observe organisation approval and token expiry policies. The normal workflow
`GITHUB_TOKEN` cannot read other private repositories and is not used as a fallback.
A fine-grained PAT is restricted to one resource owner; use the App installation
mapping above for private repositories across different owners.

## Status semantics

| Status | Meaning |
|---|---|
| Findings | Fresh, successful workflow with reported findings |
| No reported findings | Fresh, successful workflow, zero findings, at least one dependency/config target detected |
| Limited coverage | Zero findings but no dependency/config targets detected |
| Workflow failed | Latest workflow failed/cancelled; artifact counts may still be available |
| Scan pending | Newest eligible run has not completed; older counts are not substituted |
| Stale scan | Successful report older than configured threshold |
| Missing results | No eligible run, artifact or matching branch run/attempt, or ambiguous duplicate artifacts |
| Expired artifact | GitHub no longer retains the matching artifact |
| Collection error | Access, download, size, format or timestamp validation failed |

Unavailable counts are `-`, never zero. No previous successful result is substituted
when the newest run is pending or missing. This prevents stale success hiding a
failed scan. Re-run artifacts must have been created during the current attempt.
Counts on failed workflows are not treated as passing results.

Counts reflect Trivy's **post-exception findings at all severities**, not the baseline's
blocking policy. Branch summaries also store scope/scanners/policy metadata, but the
dashboard uses the same count presentation in both modes. JSON artifacts do not carry
all policy inputs, so the dashboard does not invent a blocking count or claim every
scanner ran. Target count is a coverage hint, not proof of complete coverage.
Suppressed findings and exception details are not reconstructed.

Organisation totals include all available reports, including stale/failed reports;
the fresh-report card shows collection coverage separately. No finding descriptions,
secret values, file paths or raw JSON/SARIF are published.

## Local development and tests

Requires Node.js 24+ and `unzip` (`zip` also required by tests). Both ZIP tools are
available on GitHub's Ubuntu runners. There are no npm dependencies to install.

```sh
npm run check
npm test
# Supply a scoped token through your shell or secret manager, never commit it.
npm run collect -- repositories.json dist
# Serve the built site locally, for example:
python3 -m http.server 8080 --directory dist
```

The collector reads `GH_TOKEN`, or `GH_APP_ID` and `GH_APP_PRIVATE_KEY` locally,
with installation mappings from the configuration file. Legacy `GH_APP_INSTALLATIONS`
(JSON mapping only) and `GH_APP_INSTALLATION_ID` (single owner) remain supported
when the file has no `installations` field.
Never put credentials into browser code or configuration.
Do not open the HTML directly using `file://`; the dashboard fetches relative JSON.
Preview artifacts should only be shared with authorised viewers.

Tests use fake API responses and fake secret values. They exercise allowlist-only
API calls, pagination, status transitions, branch selection, rerun artifacts,
ZIP handling, sanitisation, multi-owner App token routing and scope, token cleanup,
owner failures, site generation and filter behaviour.
Live cross-repository permissions and Pages deployment need a pilot GitHub repository.

## Reliability and maintenance

- One repo failing collection does not hide others: its row becomes a collection
  error, the collector logs a diagnostic and Actions emits a warning. Fatal config or
  authentication errors fail the build and prevent deployment.
- The collector checks at most 1,000 runs/artifacts per endpoint (10 pages). Exceeding
  the bound fails that repository explicitly; configure a dedicated caller workflow.
- ZIP downloads are bounded at 25 MiB, decompressed JSON at 20 MiB, and ZIP reads
  time out after 15 seconds. Only the exact JSON member is read to stdout; archives
  are not extracted into the workspace. Temporary raw downloads are removed.
- GitHub credentials are never forwarded to artifact storage URLs.
- Actions are pinned to full commit SHAs; review Dependabot updates. No auto-merge.
- Previews are opt-in and retain data for one day; Pages contains only the last manually
  approved publication. No historical trend database is maintained.
- Initial implementation supports github.com / GitHub Enterprise Cloud, not a
  custom GitHub Enterprise Server API host.

Retire this accelerator if a managed organisation-wide security dashboard replaces
the reporting need. The per-repository security baseline can remain independently.

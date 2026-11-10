# Repository Security Scanning

Two related accelerators, sharing one repository for the proof of concept:

- [Repository Security Baseline](repository-security-baseline/README.md): scan an
  application repository using a remotely called GitHub Actions workflow.
- [Repository Security Dashboard](repository-security-dashboard/README.md): collect
  existing results from an explicit repository list and publish a static dashboard.

Each component keeps its own implementation, configuration and README. Neither
requires AI or a paid scanner licence. **That does not make execution, storage or
private hosting automatically free.**

## Current implementation versus recommended deployment

| Area | Implemented today | Recommended for no additional spend |
|---|---|---|
| Execution | Hosted or self-hosted through runner inputs/variables | Existing isolated self-hosted capacity, or included hosted compute with enforced spending controls |
| Source results | Configurable artifacts or sanitised results-branch summary | Results branch; no retained source scan artifacts |
| Collection | Per-repo artifacts or branch mode; both check latest workflow health | Read allowlisted summaries and source workflow status |
| Dashboard | Daily builds; preview retention opt-in; manual Pages approval | Leave previews disabled; use existing hosting entitlement or serve internally |
| Runtime backend | None | None |

Choose modes with inputs/variables and versioned configuration, not implementation
edits. Hosted runners remain the default unless you configure self-hosted labels;
the recommended caller example selects branch storage by default. Existing direct
callers retain artifacts as their reusable-workflow default.

## Configuration-only choices

Install the [caller example](repository-security-baseline/examples/security-baseline.yml)
once in each application repo, replacing its central repository and release SHA.
Then set repository Actions variables:

| Variable | Default | Purpose |
|---|---|---|
| `SECURITY_RUNNER` | `["ubuntu-24.04"]` | Hosted labels, or `["self-hosted","linux","x64"]` |
| `SECURITY_RESULTS_STORAGE` | `branch` | `branch` or `artifacts` |
| `SECURITY_CACHE_DB` | `false` | Set `true` to use GitHub's remote database cache |
| `CODEQL_LANGUAGES` | unset | Optional SAST language JSON array, e.g. `["go"]`; unset skips CodeQL |
| `SECURITY_RESULTS_BRANCH` | `security-results` | Dedicated output branch, created on first trusted publication |
| `SECURITY_RESULTS_PATH` | `security-summary.json` | JSON file on that branch |

The scanner job stays read-only. The example's separate publisher requests
`contents: write` only for branch mode on the default branch. The reusable publisher
also rejects PR events. Repository/organisation rules must permit the branch write;
the workflow never bypasses protections or force-pushes.

On the dashboard repo set `DASHBOARD_RUNNER` to its hosted or self-hosted JSON labels.
Set each entry's `storage` in its versioned [configuration](repository-security-dashboard/examples/repositories.json).
Different repos may use different storage modes. Branch defaults are
`resultsBranch: security-results` and `resultsPath: security-summary.json`.
Approve the App's **Contents: read** grant for owners with branch-mode repos;
**Actions: read** remains required for latest-run health in both modes.

For hybrid deployment, choose self-hosted labels on source repos and hosted labels
on the dashboard (or vice versa). No new workflow code is needed. Optional Trivy
code-scanning upload still needs artifacts mode because its uploader consumes SARIF artifacts.
The reusable baseline additionally exposes `artifact-retention-days` and `cache-db`.
The code-scanning upload workflow has its own `runner` input.

### Infrastructure and application scanning

Enable Trivy infrastructure checks by passing `scanners: vuln,secret,misconfig`
in the application caller. The same
[baseline caller](repository-security-baseline/examples/security-baseline.yml)
includes an optional CodeQL job for SAST, chained **Trivy -> CodeQL -> publisher**.
The final publisher waits for both scanners, even if CodeQL is disabled or fails.
Set `CODEQL_LANGUAGES` to
`["go"]` or `["javascript-typescript","java-kotlin"]`, or pass the `languages`
input directly in that job. No second consumer workflow is needed. The implementation lives
centrally in the reusable `.github/workflows/codeql.yml`, alongside the Trivy
baseline. Consumers only own triggers, language selection and runner configuration.
Publish the central workflow first, then pin consumers to that commit SHA.
Existing pinned Trivy callers remain unchanged.

Opt in to CodeQL collection with `codeql: {"workflow":"security-baseline.yml","languages":["go"]}`
on the dashboard's inventory entry. Its central App/PAT additionally needs
**Code scanning alerts: read**. CodeQL uploads directly to GitHub code scanning,
so this integration works with branch storage and needs no source SARIF artifact.
Only counts and scan metadata reach the static dashboard. See
[scanner setup and costs](repository-security-baseline/README.md#enable-infrastructure-and-application-checks)
and [dashboard application integration](repository-security-dashboard/README.md#application-scanning-codeql).

## Shared repository Pages deployment: proof of concept

Yes. The `repository-security-scanning` repository can keep both component folders
and publish the dashboard built from its subfolder. GitHub Pages serves the selected
build output, not the repository's folder structure.

Expected repository layout after moving this folder's contents to the PoC repo:

```text
repository-security-scanning/
  .github/workflows/             # Active workflows must live here
  repository-security-baseline/
    README.md
    ...
  repository-security-dashboard/
    README.md
    scripts/
    site/
    repositories.json
    ...
  README.md
```

The nested `.github/workflows` files remain component templates. GitHub does not
discover them as active workflows, and reusable workflow files cannot be called
from nested component `.github` directories.

### Wire the PoC without flattening component code

In the new PoC repository, not the handbook:

1. Root workflows are supplied in this shared folder's `.github/workflows/`.
   They already use component-relative paths. To prepare them from templates for
   a clean distribution, run `node prepare-workflows.mjs shared`.
   The command is idempotent and refuses to overwrite a modified workflow;
   review/remove an outdated generated copy explicitly before regeneration.
2. Remote callers use
   `your-org/repository-security-scanning/.github/workflows/security-baseline.yml@<commit-sha>`
   and `publish-results.yml` at the same root. Do not include a component folder
   in this `uses` path.
3. Configure secrets/variables on the PoC repository and populate the dashboard's
   own versioned configuration. Select **Settings -> Pages -> GitHub Actions**.
4. Test collection with `publish` unchecked. Check `preview` only when you want a
   retained one-day preview artifact. Review the audience and output, then
   explicitly approve publication. No deployment happens from these instructions.

The shared root test workflow checks dashboard behaviour and baseline workflow
contracts. The baseline's nested live fixture self-test remains a standalone-repo
template, not an active shared workflow. A real GitHub pilot is still required.
`node prepare-workflows.mjs baseline` or `dashboard` prepares standalone component
workflows instead. The command accepts an optional output directory for packaging.

If using Dependabot in the shared repo, put its configuration in root `.github/`
and ensure it covers the active root workflows. Nested configurations are templates.

Default project-site address:
`https://<owner>.github.io/repository-security-scanning/`.
The dashboard already uses relative asset/data paths, suitable for this prefix.
There is **one Pages site per repository**: another Pages deployment from the same
repo replaces that site unless a single combined build deliberately includes both.
This is why the PoC should not deploy over the handbook's existing site.

Future users may deploy the components independently; the shared layout is not a
requirement for application repositories.

## Cost and scan frequency

### What "no additional spend" means

Trivy has no licence fee. Standard hosted runner compute in private/internal repos,
artifact retention, and some hosting/access-control options can still incur costs.
Included allowances are shared with other workloads under the billing account.
The source repo owner pays for source runs; the dashboard repo owner pays for
collection/build runs. Calling a central reusable workflow does not transfer billing.

**Recommended strategy:** use existing self-hosted capacity for private scanning
and collection where suitable, use small Git-backed summaries rather than retained
scan artifacts using branch mode, and use an existing approved hosting entitlement.
Self-hosting moves infrastructure and maintenance costs to your environment; it
does not eliminate them.

Where hosted runners are used, verify included allowances and configure applicable
**stop-usage budget controls**, not notification-only alerts. Coverage may stop when
allowances are exhausted. Budget features and enforcement depend on the billing
account and product; confirm them with its administrator. The workflows cannot
guarantee zero charges themselves. If no enforceable zero-spend setup is available,
do not enable paid hosted execution without approval.

### Daily, weekly and pull-request trade-offs

Illustration: 50 repositories, three runner minutes per scan, 30-day month.
Actual times include database download, checkout and reporting, not only scanning.

| Trigger policy | Approximate runs/month | Scan runner minutes/month |
|---|---:|---:|
| Weekly only (four runs per repo) | 200 | 600 |
| Daily only | 1,500 | 4,500 |
| PRs: 20 scan-triggering updates per repo | 1,000 | 3,000 |
| Weekly plus those PR updates | 1,200 | 3,600 |
| Daily plus those PR updates | 2,500 | 7,500 |

A PR can trigger several scans as commits are pushed. A default-branch push after
merge is another run; retries and manual runs add more. At an illustrative standard
Linux rate of $0.006/minute, 4,500 minutes represents $27 of compute before included
allowances. This is not a quote: rates, rounding and plan allowances can change.

Weekly scans reduce usage but may leave a newly published advisory undetected until
the next run. Daily scans shorten that window. PR checks find changes early but
cannot detect new advisories in unchanged code without a scheduled scan.

Start with **weekly plus PR checks**, measure usage and agree the detection window.
Reduce overlapping/redundant triggers where appropriate. Any future path filters
must preserve required-check behaviour and scheduled coverage; they are not currently
configured. Security exceptions must not be used to reduce compute costs.

Daily dashboard collection is roughly 30 builds/month; weekly is roughly four.
Collection does not rescan applications but still uses runtime and API quota.
Polling more frequently than source scans generally adds little value. Current
daily collection builds the site without retaining previews unless configured;
Pages updates need manual approval.

### Storage

Artifacts consume storage independently of runner choice. Baseline artifact retention
defaults to 30 days and is an input; dashboard previews are opt-in and retain one day.
At steady state, 50 repos with
one 1 MB artifact daily and 30-day retention hold roughly 1.5 GB before PR runs.
At $0.25/GB-month, that is about $0.38 before included storage, shared with GitHub
Packages. Shorter retention lowers storage but the collector must run before expiry.

Git-backed summaries avoid Actions artifact storage charges for those summaries.
They still consume normal Git repository storage, accumulate history and must respect
repository limits. Do not commit full scanner reports, secrets or one file per finding.
Pages deployment still uses a one-day deployment artifact. Self-hosting does not
waive artifact or hosting charges.

## Deployment models

| Model | Execution | Costs and responsibilities |
|---|---|---|
| Hosted | GitHub-hosted scans and collector; GitHub Pages | Least runner administration; private compute consumes allowance, artifacts consume storage, Pages entitlement and visibility must be checked |
| Self-hosted | Existing runners for scans/collector; existing internal static hosting | No GitHub-hosted runner compute for those jobs; you maintain machines, patching, isolation, network access and hosting |
| Hybrid | For example, self-hosted scans with hosted collector/Pages | Reduces hosted scan compute but collector, artifact storage and any paid hosting remain separate considerations |

Configure runner inputs/variables; no workflow editing is required. Self-hosted
scanner download is Linux x64 and scripts require Ubuntu-compatible tooling (`bash`, `curl`,
`tar`, `sha256sum`, `jq`, `yq`); dashboard needs Node.js 24+ and `unzip` (`zip` for
tests; baseline contract tests also require `yq`). Validate supported action runtime and runner versions. Pages build/upload
actions also have platform requirements.

Do not run untrusted fork PRs on persistent self-hosted runners with credentials or
internal-network access. Use isolated ephemeral workers and approval controls, or
keep untrusted PR execution on hosted runners within an approved allowance.

## Results branch versus Actions artifacts

### Implemented branch mode

- Commit one small versioned summary per configured scan scope to a dedicated
  branch such as `security-results` in the source repo, not its code branch.
- Include schema version, source commit, scan time, workflow run/attempt link,
  enabled scanners, scope/coverage, severity counts and scan success/failure.
  Never replace a failed/partial scan with a success-shaped empty result.
- Publish from trusted default-branch runs only, through a separate job with
  `contents: write`. PR runs stay read-only. Prevent result commits triggering
  recursive scans. Avoid force-pushes, bypass tokens or disabling protections.
- Preserve the source commit separately from the result commit. Do not let a
  stale previous summary mask a newer failed run. Check latest workflow status
  or publish explicit failure records when possible, and enforce freshness.
- Retain useful small-file history under an agreed policy. Removed values remain
  in Git history: sanitise before committing, not after.

### Permission model

| Operation | Artifact mode | Results-branch mode |
|---|---|---|
| Source scan checkout | `contents: read` | Same |
| Source result publisher | No Git write; artifact upload | Separate trusted job with `contents: write`, subject to branch rules |
| Central GitHub App on selected source repos | Actions: read, Metadata: read | Contents: read, Actions: read, Metadata: read |
| Optional code-scanning upload | `security-events: write` in separate job | Same if retained |
| Dashboard Pages deployment | `pages: write`, `id-token: write` in deploy job | Same when using Pages Actions deployment |

Installing the App is not enough: each owner grants it the selected repos, and the
versioned dashboard list selects which of those to collect. One App supports several
owners via separate installations. Updating App permissions may need owner approval;
the collector automatically requests Contents read only for installations with branch-mode repos.
Results-branch mode needs **Contents: read**, which grants access to repository
contents, not only a single results file; GitHub does not provide file-only App scopes.
Use a separate private reporting repository if that broader grant is unacceptable,
but that introduces a separately scoped publisher credential and more administration.

## Are public scanner results a security concern?

**Yes. Public source does not make publishing a vulnerability dashboard risk-free.**
Anyone who can clone a public repository can run free tools such as Trivy and inspect
public manifests. That does not justify making an indexed, current target list easier
to exploit: centralised results lower the effort of finding vulnerable repositories,
highlight unfixed findings and can reveal internal names or deployment context.

Dependency evidence in public source does not prove a vulnerability is reachable or
present in production. Conversely, private settings and runtime state are not generally
recoverable from a public clone. Do not publish production exposure claims, secret
values/snippets, internal infrastructure paths, exception rationales or credentials.

Default policy: keep internal/private-repository results access-controlled. An approved
public open-source project can choose transparent counts/advisories as part of its
disclosure policy, with explicit owner consent. Rotate exposed secrets immediately
and use responsible disclosure for newly discovered issues.

A results branch has the **same visibility as its repository**; a branch cannot be
made private inside a public repo. Private source repositories do not automatically
make Pages private. Client-side filtering, hidden links and JavaScript login screens
do not protect a published static JSON file.

Where private Pages is unavailable under an existing entitlement, use an existing
authenticated internal host or do not publish. Do not buy an upgrade or make security
results public merely to keep the PoC running.

## References and pricing checks

Reviewed 9 November 2026; check current terms before enabling execution:

- [GitHub Actions billing and allowances](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
- [Budgets and alerts](https://docs.github.com/en/billing/concepts/budgets-and-alerts)
- [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages)
- [Pages access control](https://docs.github.com/en/pages/getting-started-with-github-pages/changing-the-visibility-of-your-github-pages-site)
- [Self-hosted runner security](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)

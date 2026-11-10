import { readFile, mkdir, writeFile, copyFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { authentication, latestBranchRun } from './github.mjs';
import { readReport, summarise } from './report.mjs';
import { DashboardError } from './errors.mjs';
import { collectCodeQL, validateCodeQLConfig } from './codeql.mjs';

export function validateConfig(config) {
  if (!config || !Number.isInteger(config.staleAfterHours) || config.staleAfterHours < 1 ||
      config.staleAfterHours > 8760 || !Array.isArray(config.repositories) ||
      config.repositories.length < 1 || config.repositories.length > 500) {
    throw new DashboardError('Config needs staleAfterHours (1..8760) and 1..500 explicit repositories');
  }
  const seen = new Set();
  for (const entry of config.repositories) {
    if (!entry || !/^[a-zA-Z0-9][a-zA-Z0-9-]*\/[a-zA-Z0-9_.-]+$/.test(entry.repository ?? '') ||
        ['.', '..'].includes(entry.repository.split('/')[1]) ||
        !/^[a-zA-Z0-9_.-]+\.ya?ml$/.test(entry.workflow ?? '') ||
        !['artifacts', 'branch'].includes(entry.storage ?? 'artifacts') ||
        ((entry.storage ?? 'artifacts') === 'artifacts' &&
          (typeof entry.artifact !== 'string' || !entry.artifact.trim() || entry.artifact.length > 128)) ||
        (entry.storage === 'branch' && (
          typeof (entry.resultsBranch ?? 'security-results') !== 'string' ||
          !/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(entry.resultsBranch ?? 'security-results') ||
          (entry.resultsBranch ?? '').includes('..') ||
          !/^(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+\.json$/.test(entry.resultsPath ?? 'security-summary.json'))) ||
        (entry.branch !== undefined && (typeof entry.branch !== 'string' || !entry.branch.trim())) ||
        (entry.team !== undefined && (typeof entry.team !== 'string' || entry.team.length > 100))) {
      throw new DashboardError('Each repository needs owner/name, workflow filename and valid artifacts/branch storage settings; optional branch and team must be text');
    }
    const name = entry.repository.toLowerCase();
    if (entry.codeql !== undefined) validateCodeQLConfig(entry.codeql);
    if (seen.has(name)) throw new DashboardError(`Duplicate repository: ${entry.repository}`);
    seen.add(name);
  }
  return config;
}

function timestamp(value) {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) {
    throw new DashboardError('Missing or invalid scan timestamp');
  }
  return new Date(value).toISOString();
}

export async function collectRepository(entry, config, apiForRepository, now, unpack = readReport) {
  const row = { repository: entry.repository, team: entry.team ?? '', status: 'error', counts: null };
  try {
    const api = await apiForRepository(entry.repository);
    const base = `/repos/${entry.repository}`;
    const metadata = await api.json(base);
    const branch = entry.branch ?? metadata.default_branch;
    if (typeof branch !== 'string' || !branch) throw new DashboardError('Default branch unavailable');
    row.branch = branch;
    const latest = await latestBranchRun(api, entry.repository, entry.workflow, branch);
    if (!latest) return { ...row, status: 'missing', message: 'No eligible branch scan found' };
    if (!Number.isSafeInteger(latest.id) || latest.id < 1) throw new DashboardError('Invalid workflow run ID');
    row.runUrl = `https://github.com/${entry.repository}/actions/runs/${latest.id}`;
    row.attemptedAt = timestamp(latest.run_started_at ?? latest.created_at);
    row.runConclusion = latest.conclusion;
    if (latest.status !== 'completed') {
      return { ...row, status: 'pending', message: 'Latest scan has not completed' };
    }
    let summary;
    let scanResult = 'success';
    if (entry.storage === 'branch') {
      const resultsBranch = entry.resultsBranch ?? 'security-results';
      const resultsPath = entry.resultsPath ?? 'security-summary.json';
      const file = await api.json(`${base}/contents/${resultsPath}?ref=${encodeURIComponent(resultsBranch)}`);
      if (file.type !== 'file' || file.encoding !== 'base64' || typeof file.content !== 'string' ||
          !Number.isSafeInteger(file.size) || file.size < 0 || file.size > 256 * 1024 ||
          file.content.length > 350_000) throw new DashboardError('Invalid or oversized branch summary file');
      const record = JSON.parse(Buffer.from(file.content, 'base64').toString('utf8'));
      if (record.schemaVersion !== 1 || typeof record.repository !== 'string' ||
          record.repository.toLowerCase() !== entry.repository.toLowerCase() || record.branch !== branch) {
        throw new DashboardError('Branch summary belongs to a different source or schema');
      }
      if (!Number.isSafeInteger(latest.run_attempt) || latest.run_attempt < 1) {
        throw new DashboardError('Latest run has invalid attempt identity');
      }
      if (record.runId !== latest.id || record.runAttempt !== latest.run_attempt) {
        return { ...row, status: 'missing', message: 'Branch summary does not match latest workflow run and attempt' };
      }
      if (!['success', 'failure', 'cancelled', 'skipped'].includes(record.scanResult)) {
        throw new DashboardError('Invalid branch scan result');
      }
      scanResult = record.scanResult;
      if (record.scanOutcome === 'error' && record.summary === null) {
        return { ...row, status: 'failed', message: 'Latest scan failed before producing results' };
      }
      if (record.scanOutcome !== 'completed') throw new DashboardError('Invalid branch scan outcome');
      summary = validateSummary(record.summary);
      row.scannedAt = timestamp(record.summary.scannedAt);
    } else {
      const artifacts = [];
      for await (const page of api.pages(`${base}/actions/runs/${latest.id}/artifacts`, 'artifacts')) {
        artifacts.push(...page.filter(artifact => artifact.name === entry.artifact &&
          Date.parse(artifact.created_at) >= Date.parse(row.attemptedAt)));
      }
      if (artifacts.length !== 1) {
        return { ...row, status: 'missing', message: artifacts.length
          ? 'Multiple matching artifacts; check run configuration'
          : 'No results artifact for latest attempt; scan may have failed before upload' };
      }
      const artifact = artifacts[0];
      if (artifact.expired) return { ...row, status: 'expired', message: 'Results artifact has expired' };
      if (!Number.isSafeInteger(artifact.id) || artifact.id < 1) throw new DashboardError('Invalid artifact ID');
      if (!Number.isFinite(artifact.size_in_bytes) || artifact.size_in_bytes > 25 * 1024 * 1024) {
        throw new DashboardError('Invalid or oversized artifact');
      }
      const report = await unpack(await api.archive(`${base}/actions/artifacts/${artifact.id}/zip`));
      summary = summarise(report);
      row.scannedAt = timestamp(report.CreatedAt);
    }
    row.counts = summary.counts;
    row.detectedTargets = summary.detectedTargets;
    const age = now.getTime() - Date.parse(row.scannedAt);
    if (age < -300_000) throw new DashboardError('Scan timestamp is in the future');
    if (Date.parse(row.scannedAt) < Date.parse(row.attemptedAt) - 300_000) {
      throw new DashboardError('Report predates latest workflow attempt');
    }
    if (latest.conclusion !== 'success' || scanResult !== 'success') {
      return { ...row, status: 'failed', message: 'Latest workflow failed or was cancelled; counts are not a pass' };
    }
    if (age > config.staleAfterHours * 3600_000) {
      return { ...row, status: 'stale', message: 'Scan older than freshness threshold' };
    }
    const total = Object.values(row.counts).flatMap(Object.values).reduce((a, b) => a + b, 0);
    if (!total && !row.detectedTargets) {
      return { ...row, status: 'limited', message: 'No findings, but no dependency or configuration targets detected' };
    }
    return { ...row, status: total ? 'findings' : 'clear',
      message: total ? 'Findings reported; not a policy gate calculation' : 'No reported findings in detected targets' };
  } catch (error) {
    // Do not publish API response bodies, archive content, URLs or exception details.
    const diagnostic = error instanceof DashboardError ? error.message : 'Unexpected response or local I/O error';
    console.error(`${entry.repository}: ${diagnostic}`);
    return { ...row, counts: null, status: 'error',
      message: 'Collection failed; check Actions permissions, workflow name and artifact format' };
  }
}

export function validateSummary(summary) {
  if (!summary || !Number.isSafeInteger(summary.detectedTargets) || summary.detectedTargets < 0) {
    throw new DashboardError('Invalid branch summary coverage');
  }
  const counts = {};
  for (const type of ['vulnerabilities', 'secrets', 'misconfigurations']) {
    counts[type] = {};
    for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']) {
      const value = summary.counts?.[type]?.[severity];
      if (!Number.isSafeInteger(value) || value < 0) throw new DashboardError('Invalid branch summary count');
      counts[type][severity] = value;
    }
  }
  return { counts, detectedTargets: summary.detectedTargets };
}

export async function build(config, apiForRepository, output, now = new Date(), unpack = readReport) {
  validateConfig(config);
  const repositories = [];
  for (const entry of config.repositories) {
    const row = await collectRepository(entry, config, apiForRepository, now, unpack);
    if (entry.codeql) row.application = await collectCodeQL(entry, config, apiForRepository, now);
    repositories.push(row);
  }
  const data = { schemaVersion: 1, generatedAt: now.toISOString(),
    staleAfterHours: config.staleAfterHours, repositories };
  await mkdir(output, { recursive: true });
  const site = fileURLToPath(new URL('../site/', import.meta.url));
  for (const file of ['index.html', 'app.js', 'model.js', 'style.css']) {
    await copyFile(resolve(site, file), resolve(output, file));
  }
  await writeFile(resolve(output, '.nojekyll'), '');
  await writeFile(resolve(output, 'data.json'), `${JSON.stringify(data, null, 2)}\n`);
  return data;
}

async function main() {
  const config = validateConfig(JSON.parse(await readFile(process.argv[2] ?? 'repositories.json', 'utf8')));
  const auth = await authentication(config);
  let data;
  try {
    data = await build(config, auth.forRepository, resolve(process.argv[3] ?? 'dist'));
  } finally {
    await auth.revoke();
  }
  const errors = data.repositories.filter(row => row.status === 'error' || row.application?.status === 'error').length;
  console.log(`Collected ${data.repositories.length} configured repositories; ${errors} collection errors.`);
  // Publish explicit per-repository errors rather than leaving an old green dashboard online.
  if (errors && process.env.GITHUB_ACTIONS) {
    console.log(`::warning::${errors} repositories could not be collected; dashboard marks them as errors.`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    const diagnostic = error instanceof DashboardError ? error.message : 'Invalid JSON, response or local I/O failure';
    console.error(`Collector failed: ${diagnostic}`);
    process.exitCode = 1;
  });
}

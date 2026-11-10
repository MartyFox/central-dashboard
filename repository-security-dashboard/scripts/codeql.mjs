import { DashboardError } from './errors.mjs';
import { latestBranchRun } from './github.mjs';
import { SEVERITIES } from './report.mjs';

const LANGUAGES = ['c-cpp', 'csharp', 'go', 'java-kotlin', 'javascript-typescript', 'python', 'ruby', 'rust', 'swift'];
const categoryFor = language => `security-baseline/language:${language}`;

export function validateCodeQLConfig(config) {
  if (!config || !/^[a-zA-Z0-9_.-]+\.ya?ml$/.test(config.workflow ?? '') ||
      !Array.isArray(config.languages) || !config.languages.length ||
      config.languages.some(language => !LANGUAGES.includes(language)) ||
      new Set(config.languages).size !== config.languages.length) {
    throw new DashboardError('CodeQL needs a workflow filename and unique supported languages');
  }
}

export async function collectCodeQL(entry, config, apiForRepository, now) {
  const result = { status: 'error', counts: null };
  try {
    const api = await apiForRepository(entry.repository);
    const base = `/repos/${entry.repository}`;
    const branch = entry.branch ?? (await api.json(base)).default_branch;
    if (typeof branch !== 'string' || !branch) throw new DashboardError('CodeQL branch unavailable');
    const run = await latestBranchRun(api, entry.repository, entry.codeql.workflow, branch);
    if (!run) return { ...result, status: 'missing', message: 'No eligible CodeQL branch scan found' };
    if (!Number.isSafeInteger(run.id) || run.id < 1) throw new DashboardError('Invalid CodeQL run ID');
    result.runUrl = `https://github.com/${entry.repository}/actions/runs/${run.id}`;
    if (run.status !== 'completed') {
      return { ...result, status: 'pending', message: 'Latest CodeQL scan has not completed' };
    }
    if (run.conclusion !== 'success') {
      return { ...result, status: 'failed', message: 'Latest CodeQL workflow failed or was cancelled' };
    }
    const attempted = Date.parse(run.run_started_at ?? run.created_at);
    if (!Number.isFinite(attempted) || !/^[a-f0-9]{40}$/.test(run.head_sha ?? '')) {
      throw new DashboardError('Invalid CodeQL run timestamp or commit');
    }
    const ref = encodeURIComponent(`refs/heads/${branch}`);
    const expected = new Set(entry.codeql.languages.map(categoryFor));
    const analyses = new Map();
    for await (const page of api.pages(`${base}/code-scanning/analyses?tool_name=CodeQL&ref=${ref}`)) {
      for (const analysis of page) {
        if (!expected.has(analysis.category) || analysis.commit_sha !== run.head_sha) continue;
        const time = Date.parse(analysis.created_at);
        if (!Number.isFinite(time)) throw new DashboardError('Invalid CodeQL analysis timestamp');
        if (time < attempted || analyses.has(analysis.category)) continue;
        if (time > now.getTime() + 300_000) throw new DashboardError('CodeQL analysis timestamp is in the future');
        if (analysis.tool?.name !== 'CodeQL') throw new DashboardError('Unexpected analysis tool');
        analyses.set(analysis.category, analysis);
      }
      if (analyses.size === expected.size) break;
    }
    if (analyses.size !== expected.size) {
      return { ...result, status: 'missing', message: 'Missing CodeQL language analyses for latest run/attempt' };
    }
    const reports = [...analyses.values()];
    if (reports.some(analysis => analysis.error)) {
      return { ...result, status: 'failed', message: 'CodeQL reported an analysis error' };
    }
    if (reports.some(analysis => !Number.isSafeInteger(analysis.rules_count) || analysis.rules_count < 0)) {
      throw new DashboardError('Invalid CodeQL analysis rule count');
    }
    const counts = Object.fromEntries(SEVERITIES.map(severity => [severity, 0]));
    const seen = new Set();
    for await (const page of api.pages(`${base}/code-scanning/alerts?tool_name=CodeQL&state=open&ref=${ref}`)) {
      for (const alert of page) {
        const instance = alert.most_recent_instance;
        if (!expected.has(instance?.category)) continue;
        if (alert.state !== 'open' || alert.tool?.name !== 'CodeQL' ||
            instance.ref !== `refs/heads/${branch}` || instance.commit_sha !== run.head_sha ||
            !Number.isSafeInteger(alert.number) || alert.number < 1 || seen.has(alert.number)) {
          throw new DashboardError('CodeQL alert does not match latest analysis');
        }
        seen.add(alert.number);
        const severity = alert.rule?.security_severity_level?.toUpperCase() ?? 'UNKNOWN';
        if (!SEVERITIES.includes(severity)) throw new DashboardError('Invalid CodeQL severity');
        counts[severity]++;
      }
    }
    result.counts = counts;
    result.scannedAt = new Date(Math.min(...reports.map(analysis => Date.parse(analysis.created_at)))).toISOString();
    if (now.getTime() - Date.parse(result.scannedAt) > config.staleAfterHours * 3600_000) {
      return { ...result, status: 'stale', message: 'CodeQL scan older than freshness threshold' };
    }
    if (reports.some(analysis => analysis.warning || analysis.rules_count === 0)) {
      return { ...result, status: 'limited', message: 'CodeQL reported warnings or no analysis rules' };
    }
    const total = Object.values(counts).reduce((sum, value) => sum + value, 0);
    return { ...result, status: total ? 'findings' : 'clear',
      message: total ? 'Open CodeQL alerts; dismissed alerts excluded' : 'No open CodeQL alerts in configured languages' };
  } catch (error) {
    const diagnostic = error instanceof DashboardError ? error.message : 'Unexpected response or local I/O error';
    console.error(`${entry.repository} CodeQL: ${diagnostic}`);
    return { ...result, counts: null, status: 'error',
      message: 'CodeQL collection failed; check Code scanning alerts read access and workflow configuration' };
  }
}

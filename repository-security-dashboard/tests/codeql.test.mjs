import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { collectCodeQL } from '../scripts/codeql.mjs';
import { build, validateConfig } from '../scripts/collect.mjs';
import { GitHub } from '../scripts/github.mjs';
import { count, effectiveStatus, filterRows, totalCount } from '../site/model.js';

const now = new Date('2026-11-10T12:00:00Z');
const sha = 'a'.repeat(40);
const entry = { repository: 'acme/api', workflow: 'security-baseline.yml', artifact: 'baseline',
  codeql: { workflow: 'codeql.yml', languages: ['go'] } };
const config = { staleAfterHours: 192, repositories: [entry] };
const run = { id: 123, event: 'push', head_branch: 'main', head_sha: sha, status: 'completed',
  conclusion: 'success', run_started_at: '2026-11-10T10:00:00Z' };
const analysis = { category: 'security-baseline/language:go', commit_sha: sha,
  created_at: '2026-11-10T10:05:00Z', rules_count: 100, error: '', warning: '', tool: { name: 'CodeQL' } };
function alert(severity = 'high', number = 1) {
  return { number, state: 'open', tool: { name: 'CodeQL' },
    rule: { security_severity_level: severity, description: 'DO_NOT_PUBLISH' },
    most_recent_instance: { ref: 'refs/heads/main', category: analysis.category, commit_sha: sha,
      location: { path: 'DO_NOT_PUBLISH.go' }, message: { text: 'DO_NOT_PUBLISH' } } };
}
function fakeApi({ runs = [[run]], analyses = [[analysis]], alerts = [[alert()]], fail } = {}) {
  const calls = [];
  return {
    calls,
    async json(path) {
      calls.push(path);
      assert.equal(path, '/repos/acme/api');
      return { default_branch: 'main' };
    },
    async *pages(path, key) {
      calls.push(path);
      if (fail && path.includes('/code-scanning/')) throw fail;
      if (key === 'workflow_runs') {
        yield* path.includes('/security-baseline.yml/') ? [[run]] : runs;
      } else if (key === 'artifacts') {
        yield [{ id: 456, name: 'baseline', created_at: analysis.created_at, expired: false, size_in_bytes: 100 }];
      } else {
        assert.equal(key, undefined);
        assert.ok(path.includes('tool_name=CodeQL'));
        assert.ok(path.includes('ref=refs%2Fheads%2Fmain'));
        if (path.includes('/alerts?')) {
          assert.ok(path.includes('state=open'));
          yield* alerts;
        } else {
          yield* analyses;
        }
      }
    },
    async archive() { return Buffer.from('archive'); },
  };
}
const collect = (options = {}, settings = config, item = entry) =>
  collectCodeQL(item, settings, async () => fakeApi(options), now);
const zero = Object.fromEntries(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map(level => [level, 0]));
const baselineCounts = Object.fromEntries(['vulnerabilities', 'secrets', 'misconfigurations'].map(type =>
  [type, { ...zero }]));

test('CodeQL config is opt-in and requires unique supported languages and a workflow filename', () => {
  assert.equal(validateConfig(config), config);
  for (const codeql of [null, {}, false, { workflow: '../codeql.yml', languages: ['go'] },
    { workflow: 'codeql.yml', languages: [] }, { workflow: 'codeql.yml', languages: ['go', 'go'] },
    { workflow: 'codeql.yml', languages: ['unknown'] }]) {
    assert.throws(() => validateConfig({ ...config, repositories: [{ ...entry, codeql }] }), /CodeQL/);
  }
});

test('CodeQL projects only open-alert counts, severities, timestamps and a trusted run URL', async () => {
  const result = await collect({ alerts: [[alert(), alert(null, 2), alert('critical', 3)]] });
  assert.equal(result.status, 'findings');
  assert.equal(result.rulesCount, 100);
  assert.equal(result.message, 'Completed \u00b7 100 rules \u00b7 3 alerts');
  assert.deepEqual(result.counts, { ...zero, HIGH: 1, UNKNOWN: 1, CRITICAL: 1 });
  assert.equal(result.scannedAt, analysis.created_at.replace('Z', '.000Z'));
  assert.equal(result.runUrl, 'https://github.com/acme/api/actions/runs/123');
  assert.ok(!JSON.stringify(result).includes('DO_NOT_PUBLISH'));
});

test('zero alerts is clear only after successful current analyses for every configured language', async () => {
  const clear = await collect({ alerts: [[]], analyses: [[{ ...analysis, rules_count: 35 }]] });
  assert.equal(clear.status, 'clear');
  assert.equal(clear.rulesCount, 35);
  assert.equal(clear.message, 'Completed \u00b7 35 rules \u00b7 0 alerts');
  const multi = { ...entry, codeql: { ...entry.codeql, languages: ['go', 'javascript-typescript'] } };
  assert.equal((await collect({}, config, multi)).status, 'missing');
  const result = await collect({ analyses: [[analysis], [
    { ...analysis, category: 'security-baseline/language:javascript-typescript' },
  ]], alerts: [[]] }, config, multi);
  assert.equal(result.status, 'clear');
  assert.equal(result.rulesCount, 200);
  assert.equal(result.message, 'Completed \u00b7 200 rules \u00b7 0 alerts');
});

test('execution summary handles singular counts without marking incomplete scans completed', async () => {
  const single = await collect({ analyses: [[{ ...analysis, rules_count: 1 }]] });
  assert.equal(single.message, 'Completed \u00b7 1 rule \u00b7 1 alert');
  for (const options of [
    { runs: [[]] }, { runs: [[{ ...run, status: 'in_progress' }]] },
    { runs: [[{ ...run, conclusion: 'failure' }]] },
    { analyses: [[{ ...analysis, warning: 'warning' }]] },
    { analyses: [[{ ...analysis, rules_count: 0 }]] },
  ]) {
    const result = await collect(options);
    assert.ok(!result.message.startsWith('Completed'));
  }
  const stale = await collect({}, { ...config, staleAfterHours: 1 });
  assert.equal(stale.status, 'stale');
  assert.ok(!stale.message.startsWith('Completed'));
});

test('failed, pending, missing and previous-attempt analyses never become zero-shaped success', async () => {
  for (const [options, status] of [
    [{ runs: [[]] }, 'missing'],
    [{ runs: [[{ ...run, status: 'in_progress' }]] }, 'pending'],
    [{ runs: [[{ ...run, conclusion: 'failure' }]] }, 'failed'],
    [{ analyses: [[]] }, 'missing'],
    [{ analyses: [[{ ...analysis, commit_sha: 'b'.repeat(40) }]] }, 'missing'],
    [{ analyses: [[{ ...analysis, created_at: '2026-11-10T09:00:00Z' }]] }, 'missing'],
    [{ analyses: [[{ ...analysis, error: 'DO_NOT_PUBLISH' }]] }, 'failed'],
  ]) {
    const result = await collect(options);
    assert.equal(result.status, status);
    assert.equal(result.counts, null);
    assert.ok(!JSON.stringify(result).includes('DO_NOT_PUBLISH'));
  }
  assert.equal((await collect({ analyses: [[{ ...analysis, warning: 'DO_NOT_PUBLISH' }]] })).status, 'limited');
  assert.equal((await collect({ analyses: [[{ ...analysis, rules_count: 0 }]] })).status, 'limited');
  assert.equal((await collect({}, { ...config, staleAfterHours: 1 })).status, 'stale');
});

test('PRs and other branches are excluded; analysis/alert pages are followed', async () => {
  const api = fakeApi({
    runs: [[{ ...run, event: 'pull_request' }, { ...run, head_branch: 'feature' }], [run]],
    analyses: [[{ ...analysis, category: 'other' }], [analysis]],
    alerts: [[], [alert()]],
  });
  const result = await collectCodeQL(entry, config, async () => api, now);
  assert.equal(result.counts.HIGH, 1);
  assert.ok(api.calls.every(path => path.startsWith('/repos/acme/api')));
});

test('permissions/API failures and malformed or mismatched data remain explicit without raw errors', async () => {
  const mismatched = alert();
  mismatched.most_recent_instance.commit_sha = 'b'.repeat(40);
  for (const options of [
    { fail: new Error('DO_NOT_PUBLISH') },
    { runs: [[{ ...run, head_sha: 'invalid' }]] },
    { analyses: [[{ ...analysis, created_at: 'invalid' }]] },
    { analyses: [[{ ...analysis, created_at: '2026-11-11T00:00:00Z' }]] },
    { analyses: [[{ ...analysis, rules_count: undefined }]] },
    { alerts: [[alert('invalid')]] }, { alerts: [[mismatched]] },
    { alerts: [[alert(), alert()]] },
  ]) {
    const result = await collect(options);
    assert.equal(result.status, 'error');
    assert.equal(result.counts, null);
    assert.ok(!JSON.stringify(result).includes('DO_NOT_PUBLISH'));
  }
});

test('GitHub API supports paginated root arrays with the same bounded/error behavior', async () => {
  let requests = 0;
  const api = new GitHub('fake-token', async () => {
    requests++;
    return Response.json(requests === 1 ? Array(100).fill(analysis) : [analysis]);
  });
  const pages = [];
  for await (const page of api.pages('/repos/acme/api/code-scanning/analyses')) pages.push(page);
  assert.equal(pages.length, 2);
  assert.equal(requests, 2);
  const invalid = new GitHub('fake', async () => Response.json({ message: 'not an array' }));
  await assert.rejects(async () => {
    for await (const page of invalid.pages('/repos/acme/api/code-scanning/analyses')) assert.fail(page);
  }, /results array/);
});

test('application findings participate in counts, filters, freshness and overall status without hiding gaps', () => {
  const application = { status: 'findings', counts: { ...zero, HIGH: 2 }, scannedAt: analysis.created_at };
  const row = { repository: 'acme/api', team: '', status: 'clear', counts: baselineCounts,
    scannedAt: analysis.created_at, application };
  assert.equal(count(row, 'HIGH'), 2);
  assert.equal(count(row, 'HIGH', 'applications'), 2);
  assert.equal(count(row, 'HIGH', 'misconfigurations'), 0);
  assert.equal(effectiveStatus(row, 192, now.getTime()), 'findings');
  assert.equal(effectiveStatus(row, 1, now.getTime()), 'stale');
  assert.equal(filterRows([row], { type: 'applications', severity: 'HIGH' }, 192, now.getTime()).length, 1);
  const missing = { ...row, application: { status: 'missing', counts: null } };
  assert.equal(effectiveStatus(missing, 192, now.getTime()), 'missing');
  assert.equal(count(missing, 'HIGH'), null);
  assert.equal(count(missing, 'HIGH', 'applications'), null);
  assert.equal(count(missing, 'HIGH', 'vulnerabilities'), 0);
  assert.equal(totalCount([row, missing], 'HIGH'), null);
  assert.equal(count({ ...row, application: undefined }, 'HIGH', 'applications'), null);
  assert.equal(count({ ...row, counts: null }, 'HIGH', 'applications'), 2);
  assert.equal(effectiveStatus({ ...row, status: 'failed' }, 192, now.getTime()), 'failed');
});

test('build emits sanitised application data and independent failure states alongside baseline results', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'dashboard-codeql-'));
  const report = { SchemaVersion: 2, CreatedAt: analysis.created_at,
    Results: [{ Target: 'go.mod', Class: 'lang-pkgs' }] };
  try {
    const data = await build(config, async () => fakeApi(), directory, now, async () => report);
    assert.equal(data.repositories[0].status, 'clear');
    assert.equal(data.repositories[0].application.status, 'findings');
    assert.equal(data.repositories[0].application.rulesCount, 100);
    assert.equal(data.repositories[0].application.message, 'Completed \u00b7 100 rules \u00b7 1 alert');
    const json = await readFile(join(directory, 'data.json'), 'utf8');
    assert.ok(!json.includes('DO_NOT_PUBLISH'));
    const html = await readFile(join(directory, 'index.html'), 'utf8');
    assert.ok(html.includes('value="applications"'));
    assert.ok(html.includes('Application scan (CodeQL)'));
    const failed = await build(config, async () => fakeApi({ fail: new Error('DO_NOT_PUBLISH') }),
      directory, now, async () => report);
    assert.equal(failed.repositories[0].status, 'clear');
    assert.equal(failed.repositories[0].application.status, 'error');
    assert.equal(count(failed.repositories[0], 'CRITICAL'), null);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('combined caller collects both scanners from the same run and never hides overall workflow failure', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'dashboard-combined-'));
  const combined = { ...config, repositories: [{
    ...entry, codeql: { ...entry.codeql, workflow: entry.workflow },
  }] };
  const report = { SchemaVersion: 2, CreatedAt: analysis.created_at,
    Results: [{ Target: 'go.mod', Class: 'lang-pkgs' }] };
  try {
    const api = fakeApi();
    const data = await build(combined, async () => api, directory, now, async () => report);
    const row = data.repositories[0];
    assert.equal(row.status, 'clear');
    assert.equal(row.application.status, 'findings');
    assert.equal(row.runUrl, row.application.runUrl);
    assert.ok(!api.calls.some(path => path.includes('/workflows/codeql.yml/')));
    assert.equal(effectiveStatus(row, 192, now.getTime()), 'findings');

    const failedApi = fakeApi();
    const pages = failedApi.pages.bind(failedApi);
    failedApi.pages = async function* (path, key) {
      for await (const page of pages(path, key)) {
        yield key === 'workflow_runs' ? page.map(value => ({ ...value, conclusion: 'failure' })) : page;
      }
    };
    const failed = await build(combined, async () => failedApi, directory, now, async () => report);
    assert.equal(failed.repositories[0].status, 'failed');
    assert.equal(failed.repositories[0].application.status, 'failed');
    assert.equal(failed.repositories[0].application.counts, null);
    assert.equal(effectiveStatus(failed.repositories[0], 192, now.getTime()), 'failed');
  } finally { await rm(directory, { recursive: true, force: true }); }
});

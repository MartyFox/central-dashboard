import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { authentication } from '../scripts/github.mjs';
import { collectRepository, validateConfig } from '../scripts/collect.mjs';

const now = new Date('2026-11-09T12:00:00Z');
const entry = { repository: 'acme/api', workflow: 'security.yml', storage: 'branch' };
const config = { staleAfterHours: 192, repositories: [entry] };
const run = { id: 123, run_attempt: 2, status: 'completed', conclusion: 'success',
  head_branch: 'main', event: 'schedule', run_started_at: '2026-11-09T11:00:00Z' };
const counts = Object.fromEntries(['vulnerabilities', 'secrets', 'misconfigurations'].map(type =>
  [type, Object.fromEntries(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map(level => [level, 0]))]));
const record = {
  schemaVersion: 1, repository: 'acme/api', branch: 'main', runId: 123, runAttempt: 2,
  scanResult: 'success', scanOutcome: 'completed',
  summary: { counts, detectedTargets: 1, scannedAt: '2026-11-09T11:05:00Z' },
};
function apiFor(data, latest = run) {
  return async repository => {
    assert.equal(repository, entry.repository);
    return {
      async json(path) {
        if (path === '/repos/acme/api') return { default_branch: 'main' };
        assert.equal(path, '/repos/acme/api/contents/security-summary.json?ref=security-results');
        const content = Buffer.from(JSON.stringify(data));
        return { type: 'file', encoding: 'base64', content: content.toString('base64'), size: content.length };
      },
      async *pages(path, key) {
        assert.equal(key, 'workflow_runs');
        assert.equal(path, '/repos/acme/api/actions/workflows/security.yml/runs?branch=main');
        yield [latest];
      },
      archive() { assert.fail('Branch collection must not download any artifacts'); },
    };
  };
}
const collect = (data = record, latest = run) =>
  collectRepository(entry, config, apiFor(data, latest), now);

test('branch mode validates without an artifact name; rejects unsafe or unknown settings', () => {
  assert.equal(validateConfig(config), config);
  for (const invalid of [
    { storage: 'other' }, { resultsPath: '../secrets.json' },
    { resultsPath: 'result.txt' }, { resultsBranch: '../main' },
    { resultsBranch: 123 }, { resultsPath: 123 },
  ]) assert.throws(() => validateConfig({ ...config, repositories: [{ ...entry, ...invalid }] }));
});

test('branch summaries produce counts without publishing raw extra fields', async () => {
  const row = await collect({ ...record, secret: 'NEVER_PUBLISH',
    summary: { ...record.summary, rawFindings: 'NEVER_PUBLISH' } });
  assert.equal(row.status, 'clear');
  assert.equal(row.counts.vulnerabilities.HIGH, 0);
  assert.ok(!JSON.stringify(row).includes('NEVER_PUBLISH'));
});

test('branch run and attempt must match latest source workflow; old success cannot mask new failure', async () => {
  for (const update of [{ runId: 122 }, { runAttempt: 1 }]) {
    const row = await collect({ ...record, ...update }, { ...run, conclusion: 'failure' });
    assert.equal(row.status, 'missing');
    assert.equal(row.counts, null);
  }
  assert.equal((await collect(record, { ...run, status: 'in_progress' })).status, 'pending');
});

test('failure snapshots stay failed, including early failures without counts', async () => {
  const failed = await collect({ ...record, scanResult: 'failure' });
  assert.equal(failed.status, 'failed');
  const early = await collect({ ...record, scanOutcome: 'error', scanResult: 'failure', summary: null });
  assert.equal(early.status, 'failed');
  assert.equal(early.counts, null);
  assert.equal((await collect(record, { ...run, conclusion: 'failure' })).status, 'failed');
});

test('invalid branch source, schema, timestamp and counts fail explicitly', async () => {
  for (const bad of [
    { ...record, repository: 'someone/else' }, { ...record, schemaVersion: 99 },
    { ...record, branch: 'feature' }, { ...record, scanResult: 'unknown' },
    { ...record, summary: { ...record.summary, scannedAt: 'invalid' } },
    { ...record, summary: { ...record.summary, counts: { vulnerabilities: { HIGH: -1 } } } },
    { ...record, summary: { ...record.summary, detectedTargets: -1 } },
  ]) {
    const row = await collect(bad);
    assert.equal(row.status, 'error');
    assert.equal(row.counts, null);
  }
});

test('branch API failure, missing file or malformed content does not fall back to artifacts or old counts', async () => {
  const api = await apiFor(record)(entry.repository);
  api.json = async path => {
    if (path === '/repos/acme/api') return { default_branch: 'main' };
    return { type: 'file', encoding: 'base64', size: 999999, content: 'invalid' };
  };
  assert.equal((await collectRepository(entry, config, async () => api, now)).status, 'error');
  api.json = async () => { throw new Error('GitHub API HTTP 404'); };
  assert.equal((await collectRepository(entry, config, async () => api, now)).status, 'error');
});

test('mixed storage requests Contents read only for installations with branch repositories', async () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const mixed = { ...config, installations: { acme: '456', other: '789' },
    repositories: [entry, { repository: 'other/api', storage: 'artifacts' }] };
  const requests = [];
  const auth = await authentication(mixed, {
    GH_APP_ID: '123', GH_APP_PRIVATE_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  }, async (url, options) => {
    if (options.method === 'POST') {
      requests.push(JSON.parse(options.body));
      return Response.json({ token: 'fake-token' });
    }
    if (options.method === 'DELETE') return new Response(null, { status: 204 });
    return Response.json({ account: { login: url.includes('/456') ? 'acme' : 'other' } });
  });
  try {
    await auth.forRepository('acme/api');
    await auth.forRepository('other/api');
    assert.deepEqual(requests.map(request => request.permissions), [
      { actions: 'read', metadata: 'read', contents: 'read' },
      { actions: 'read', metadata: 'read' },
    ]);
  } finally { await auth.revoke(); }
});

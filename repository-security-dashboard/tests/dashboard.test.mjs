import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { build, collectRepository, validateConfig } from '../scripts/collect.mjs';
import { GitHub, authentication } from '../scripts/github.mjs';
import { readReport, summarise, MAX_ARCHIVE_BYTES } from '../scripts/report.mjs';
import { count, effectiveStatus, filterRows } from '../site/model.js';

const now = new Date('2026-11-03T10:00:00Z');
const entry = { repository: 'acme/payments', workflow: 'security-baseline.yml', artifact: 'security-baseline-results' };
const config = { staleAfterHours: 192, repositories: [entry] };
const run = {
  id: 123, event: 'push', head_branch: 'main', status: 'completed', conclusion: 'success',
  run_started_at: '2026-11-03T08:00:00Z',
};
const artifact = {
  id: 456, name: entry.artifact, created_at: '2026-11-03T08:10:00Z',
  expired: false, size_in_bytes: 3000,
};
function report() {
  return {
    SchemaVersion: 2, CreatedAt: '2026-11-03T08:05:00Z',
    Results: [
      { Target: 'package-lock.json', Class: 'lang-pkgs', Vulnerabilities: [
        { Severity: 'CRITICAL', VulnerabilityID: 'CVE-fixture', Description: 'DO_NOT_PUBLISH' },
        { Severity: 'UNKNOWN' },
      ] },
      { Target: 'config/key', Class: 'secret', Secrets: [
        { Severity: 'HIGH', Match: 'DO_NOT_PUBLISH_SECRET', Code: { Lines: ['DO_NOT_PUBLISH'] } },
      ] },
      { Target: 'Dockerfile', Class: 'config', Misconfigurations: [
        { Severity: 'MEDIUM', Status: 'FAIL' }, { Severity: 'HIGH', Status: 'PASS' },
      ] },
    ],
  };
}
function fakeApi({ runs = [[run]], artifacts = [[artifact]], defaultBranch = 'main' } = {}) {
  const calls = [];
  return {
    calls,
    async json(path) {
      calls.push(path);
      assert.equal(path, '/repos/acme/payments');
      return { default_branch: defaultBranch };
    },
    async *pages(path, key) {
      calls.push(path);
      yield* key === 'workflow_runs' ? runs : artifacts;
    },
    async archive(path) {
      calls.push(path);
      return Buffer.from('archive');
    },
  };
}
const collect = (api = fakeApi(), data = report(), settings = config) =>
  collectRepository(entry, settings, async () => api, now, async () => data);

test('requires a non-empty, explicit, duplicate-free allowlist', () => {
  assert.equal(validateConfig(config), config);
  for (const invalid of [
    { ...config, repositories: [] },
    { ...config, repositories: [entry, { ...entry, repository: 'ACME/PAYMENTS' }] },
    { ...config, repositories: [{ ...entry, workflow: '../workflow.yml' }] },
    { ...config, staleAfterHours: -1 },
    { ...config, repositories: [{ ...entry, repository: 'acme/*' }] },
    { ...config, repositories: [{ ...entry, repository: 'acme/..' }] },
    { ...config, repositories: [{ ...entry, branch: '' }] },
  ]) assert.throws(() => validateConfig(invalid));
});

test('collects only configured repository and workflow, excludes PRs and follows pages', async () => {
  const api = fakeApi({ runs: [
    [{ ...run, event: 'pull_request' }, { ...run, head_branch: 'feature' }],
    [run],
  ] });
  const result = await collect(api);
  assert.equal(result.status, 'findings');
  assert.equal(result.counts.vulnerabilities.CRITICAL, 1);
  assert.equal(result.counts.secrets.HIGH, 1);
  assert.equal(result.counts.misconfigurations.HIGH, 0);
  assert.equal(result.detectedTargets, 2);
  assert.equal(result.runUrl, 'https://github.com/acme/payments/actions/runs/123');
  assert.ok(api.calls.every(path => path.startsWith('/repos/acme/payments')));
  assert.ok(api.calls.some(path => path.includes('/workflows/security-baseline.yml/runs?branch=main')));
  assert.ok(!JSON.stringify(result).includes('DO_NOT_PUBLISH'));
});

test('supports explicit branch and alternate artifact names without changing baseline', async () => {
  const custom = { ...entry, branch: 'release/1', artifact: 'alternate' };
  const api = fakeApi({ runs: [[{ ...run, head_branch: 'release/1' }]],
    artifacts: [[{ ...artifact, name: 'alternate' }]] });
  const result = await collectRepository(custom, config, async () => api, now, async () => report());
  assert.equal(result.status, 'findings');
  assert.ok(api.calls.some(path => path.endsWith('branch=release%2F1')));
});

test('missing, expired, pending, stale and failed scans never appear clear', async () => {
  assert.equal((await collect(fakeApi({ runs: [[]] }))).status, 'missing');
  assert.equal((await collect(fakeApi({ artifacts: [[]] }))).status, 'missing');
  assert.equal((await collect(fakeApi({ artifacts: [[{ ...artifact, expired: true }]] }))).status, 'expired');
  const pending = await collect(fakeApi({ runs: [[{ ...run, status: 'in_progress' }]] }));
  assert.equal(pending.status, 'pending');
  assert.equal(pending.counts, null);
  const failed = await collect(fakeApi({ runs: [[{ ...run, conclusion: 'failure' }]] }));
  assert.equal(failed.status, 'failed');
  assert.notEqual(failed.counts, null);
  assert.equal((await collect(fakeApi(), report(), { ...config, staleAfterHours: 1 })).status, 'stale');
});

test('rejects duplicate artifacts and ignores artifacts from previous rerun attempts', async () => {
  assert.equal((await collect(fakeApi({ artifacts: [[artifact, artifact]] }))).status, 'missing');
  assert.equal((await collect(fakeApi({
    artifacts: [[{ ...artifact, created_at: '2026-11-02T08:10:00Z' }]],
  }))).status, 'missing');
});

test('empty detected target is limited coverage; clean detected target can be clear', async () => {
  assert.equal((await collect(fakeApi(), { ...report(), Results: [] })).status, 'limited');
  assert.equal((await collect(fakeApi(), {
    ...report(), Results: [{ Class: 'lang-pkgs', Target: 'requirements.txt' }],
  })).status, 'clear');
});

test('invalid report, timestamps, API or archive failure produces explicit unavailable counts', async () => {
  const bad = [
    { ...report(), SchemaVersion: 999 },
    { ...report(), Results: 'not-an-array' },
    { ...report(), CreatedAt: 'not-a-date' },
    { ...report(), CreatedAt: '2026-11-04T08:00:00Z' },
    { ...report(), CreatedAt: '2026-11-02T08:00:00Z' },
  ];
  for (const data of bad) {
    const row = await collect(fakeApi(), data);
    assert.equal(row.status, 'error');
    assert.equal(row.counts, null);
  }
  const api = fakeApi();
  api.json = async () => { throw new Error('sensitive API body DO_NOT_PUBLISH'); };
  const row = await collect(api);
  assert.equal(row.status, 'error');
  assert.ok(!JSON.stringify(row).includes('DO_NOT_PUBLISH'));
});

test('summary validates findings and never copies raw fields', () => {
  assert.ok(!JSON.stringify(summarise(report())).includes('DO_NOT_PUBLISH'));
  assert.throws(() => summarise({ SchemaVersion: 2, Results: [{ Secrets: [{ Severity: 'BOGUS' }] }] }));
  assert.throws(() => summarise({ SchemaVersion: 2, Results: [{ Vulnerabilities: {} }] }));
  assert.throws(() => summarise({ SchemaVersion: 2, Results: [{ Misconfigurations: [{ Status: 'WHAT' }] }] }));
});

test('ZIP reader reads exact JSON member without extracting other files', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'dashboard-zip-test-'));
  try {
    await writeFile(join(directory, 'trivy-results.json'), JSON.stringify(report()));
    await writeFile(join(directory, 'raw-secret.txt'), 'DO_NOT_PUBLISH');
    execFileSync('zip', ['-q', 'valid.zip', 'trivy-results.json', 'raw-secret.txt'], { cwd: directory });
    const parsed = await readReport(await readFile(join(directory, 'valid.zip')));
    assert.deepEqual(parsed, report());
    execFileSync('zip', ['-q', 'invalid.zip', 'raw-secret.txt'], { cwd: directory });
    await assert.rejects(readReport(await readFile(join(directory, 'invalid.zip'))), /exactly one/);
    await assert.rejects(readReport(Buffer.from('not a zip')));
    await assert.rejects(readReport(Buffer.alloc(MAX_ARCHIVE_BYTES + 1)), /exceeds/);
    await writeFile(join(directory, 'trivy-results.json'), ' '.repeat(20 * 1024 * 1024 + 1));
    execFileSync('zip', ['-q', 'oversized.zip', 'trivy-results.json'], { cwd: directory });
    await assert.rejects(readReport(await readFile(join(directory, 'oversized.zip'))), /size\/time limits/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('GitHub API paginates exact endpoint and surfaces HTTP failures', async () => {
  const calls = [];
  const api = new GitHub('fake-token', async (url, options) => {
    calls.push(url);
    assert.equal(options.headers.Authorization, 'Bearer fake-token');
    return Response.json({ workflow_runs: url.endsWith('page=1') ? Array(100).fill(run) : [run] });
  });
  const pages = [];
  for await (const page of api.pages('/repos/acme/payments/actions/runs?branch=main', 'workflow_runs')) pages.push(page);
  assert.equal(pages.length, 2);
  assert.equal(calls.length, 2);
  await assert.rejects(new GitHub('fake', async () => new Response('', { status: 403 })).json('/repos/acme/payments'), /HTTP 403/);
  await assert.rejects(api.request('//external'), /Invalid API path/);
});

test('artifact signed-URL fetch never forwards GitHub credentials', async () => {
  const calls = [];
  const api = new GitHub('fake-token', async (url, options) => {
    calls.push({ url: String(url), options });
    return calls.length === 1
      ? new Response(null, { status: 302, headers: { location: 'https://artifacts.example.invalid/archive' } })
      : new Response('zip');
  });
  assert.equal((await api.archive('/repos/acme/payments/actions/artifacts/456/zip')).toString(), 'zip');
  assert.equal(calls[0].options.headers.Authorization, 'Bearer fake-token');
  assert.equal(calls[1].options.headers, undefined);
  assert.equal(calls[1].options.redirect, 'error');
});

test('download enforces actual streamed archive size and rejects insecure redirects', async () => {
  let requests = 0;
  const api = new GitHub('fake-token', async () => {
    requests++;
    return requests === 1
      ? new Response(null, { status: 302, headers: { location: 'https://artifacts.example.invalid/archive' } })
      : new Response(Buffer.alloc(MAX_ARCHIVE_BYTES + 1));
  });
  await assert.rejects(api.archive('/repos/acme/payments/actions/artifacts/456/zip'), /exceeds/);
  const insecure = new GitHub('fake', async () =>
    new Response(null, { status: 302, headers: { location: 'http://example.invalid/archive' } }));
  await assert.rejects(insecure.archive('/repos/acme/payments/actions/artifacts/456/zip'), /Invalid artifact/);
});

test('pagination exhaustion is an error, never a false missing/clean result', async () => {
  let pages = 0;
  const api = new GitHub('fake', async () => {
    pages++;
    return Response.json({ workflow_runs: Array(100).fill(run) });
  });
  await assert.rejects(async () => {
    for await (const page of api.pages('/repos/acme/payments/actions/runs', 'workflow_runs')) {
      assert.equal(page.length, 100);
    }
  }, /pagination limit/);
  assert.equal(pages, 10);
});

test('GitHub App token is restricted to allowlisted repo names and read permissions', async () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const calls = [];
  const auth = await authentication(config, {
    GH_APP_ID: '123', GH_APP_INSTALLATION_ID: '456',
    GH_APP_PRIVATE_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  }, async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/app/installations/456')) return Response.json({ account: { login: 'ACME' } });
    return options.method === 'POST' ? Response.json({ token: 'installation-token' }) : new Response(null, { status: 204 });
  });
  const client = await auth.forRepository('acme/payments');
  assert.deepEqual(JSON.parse(calls[1].options.body), {
    repositories: ['payments'], permissions: { actions: 'read', metadata: 'read' },
  });
  assert.equal(client.token, 'installation-token');
  await auth.revoke();
  assert.equal(calls[2].options.method, 'DELETE');
  await assert.rejects(authentication(config, {}), /Set GH_TOKEN/);
  await assert.rejects(authentication({ repositories: [entry, { repository: 'other/repo' }] }, {
    GH_APP_ID: '123', GH_APP_INSTALLATION_ID: '456', GH_APP_PRIVATE_KEY: 'unused',
  }), /multiple owners/);
});

test('build emits complete static site with only sanitised counts', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'dashboard-build-test-'));
  try {
    const data = await build(config, async () => fakeApi(), directory, now, async () => report());
    const json = await readFile(join(directory, 'data.json'), 'utf8');
    assert.equal(data.repositories.length, 1);
    assert.ok(!json.includes('DO_NOT_PUBLISH'));
    for (const file of ['index.html', 'app.js', 'model.js', 'style.css', '.nojekyll']) {
      await readFile(join(directory, file));
    }
    assert.deepEqual(JSON.parse(json), data);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('50-repository build queries only explicit inventory, retains failures and removes excluded repos', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'dashboard-inventory-test-'));
  const inventory = { ...config, repositories: Array.from({ length: 50 }, (_, index) =>
    ({ ...entry, repository: `acme/app-${index}` })) };
  const calls = [];
  const api = {
    async json(path) {
      calls.push(path);
      if (path === '/repos/acme/app-1') throw new Error('DO_NOT_PUBLISH');
      return { default_branch: 'main' };
    },
    async *pages(path) {
      calls.push(path);
      yield [];
    },
  };
  try {
    const data = await build(inventory, async () => api, directory, now);
    assert.equal(data.repositories.length, 50);
    assert.equal(data.repositories.filter(row => row.status === 'error').length, 1);
    assert.equal(data.repositories.filter(row => row.status === 'missing').length, 49);
    assert.ok(calls.every(path => /^\/repos\/acme\/app-\d+(\/|$)/.test(path)));
    assert.equal(calls.length, 99);
    const reduced = await build({ ...inventory, repositories: [inventory.repositories[0]] }, async () => api, directory, now);
    assert.equal(reduced.repositories.length, 1);
    const json = await readFile(join(directory, 'data.json'), 'utf8');
    assert.ok(!json.includes('acme/app-1'));
    assert.ok(!json.includes('DO_NOT_PUBLISH'));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('dashboard filters type, severity and team; old published clear results become stale', async () => {
  const row = { ...await collect(), team: 'Payments team' };
  assert.equal(filterRows([row], { query: 'PAYMENTS TEAM' }, 192, now.getTime()).length, 1);
  assert.equal(filterRows([row], { type: 'secrets', severity: 'CRITICAL' }, 192, now.getTime()).length, 0);
  assert.equal(filterRows([row], { type: 'secrets', severity: 'HIGH' }, 192, now.getTime()).length, 1);
  assert.equal(count({ ...row, counts: null }, 'HIGH'), null);
  assert.equal(effectiveStatus(row, 1, now.getTime()), 'stale');
  assert.equal(effectiveStatus({ ...row, status: 'failed' }, 1, now.getTime()), 'failed');
  assert.equal(filterRows([row], { status: 'stale' }, 1, now.getTime()).length, 1);
});

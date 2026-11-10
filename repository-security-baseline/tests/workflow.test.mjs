import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const workflows = fileURLToPath(new URL('../.github/workflows/', import.meta.url));
function workflow(name) {
  return JSON.parse(execFileSync('yq', ['-o=json', '.', `${workflows}/${name}.yml`], { encoding: 'utf8' }));
}
const baseline = workflow('security-baseline');
const publisher = workflow('publish-results');
const step = name => baseline.jobs.scan.steps.find(value => value.name === name);
const publishStep = publisher.jobs.publish.steps.find(value => value.run);
const script = publishStep.run.split("<<'JS'\n")[1].trim().replace(/\nJS$/, '');
const execute = new (Object.getPrototypeOf(async function () {}).constructor)('fetch', 'process', script);
const fixedTime = '2026-11-09T12:00:00Z';
const env = {
  RESULTS_BRANCH: 'security-results', RESULTS_PATH: 'security-summary.json',
  SOURCE_REPOSITORY: 'acme/api', SOURCE_BRANCH: 'main', SOURCE_SHA: 'a'.repeat(40),
  RUN_ID: '123', RUN_ATTEMPT: '2', SCAN_RESULT: 'success', GH_TOKEN: 'fake-token',
};
const counts = Object.fromEntries(['vulnerabilities', 'secrets', 'misconfigurations'].map(type =>
  [type, Object.fromEntries(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map(level => [level, 0]))]));
const summary = { schemaVersion: 1, scannedAt: fixedTime, detectedTargets: 1, blockingCount: 0,
  scanners: ['vuln', 'secret'], scannerVersion: '0.76.1', mode: 'report',
  blockingSeverities: ['HIGH', 'CRITICAL'], failOnUnfixed: false,
  scope: '.', skipDirs: [], counts };
function fakeGitHub({ existing, ref = false, rejectWrite = false } = {}) {
  const calls = [];
  const fetcher = async (url, options) => {
    calls.push({ path: new URL(url).pathname, options });
    const path = new URL(url).pathname;
    assert.equal(options.headers.Authorization, 'Bearer fake-token');
    if (path.includes('/git/ref/')) {
      return ref ? Response.json({ object: { sha: 'parent' } }) : new Response(null, { status: 404 });
    }
    if (path.includes('/contents/')) {
      return existing
        ? Response.json({ encoding: 'base64', content: Buffer.from(JSON.stringify(existing)).toString('base64') })
        : new Response(null, { status: 404 });
    }
    if (options.method === 'GET') return Response.json({ tree: { sha: 'base-tree' } });
    if (rejectWrite) return new Response(null, { status: 403 });
    return Response.json({ sha: path.endsWith('/trees') ? 'tree' : 'commit' });
  };
  return { calls, fetcher };
}
async function publish(options = {}, github = fakeGitHub()) {
  let exitCode;
  await execute(github.fetcher, {
    env: { ...env, SUMMARY: JSON.stringify(summary), ...options },
    exit(code) { exitCode = code; throw new Error('test-process-exit'); },
  }).catch(error => { if (error.message !== 'test-process-exit') throw error; });
  return { ...github, exitCode };
}
function published(calls) {
  const tree = calls.find(call => call.path.endsWith('/git/trees'));
  return JSON.parse(JSON.parse(tree.options.body).tree[0].content);
}

test('runner and storage are inputs; scanner stays read-only and raw artifacts are conditional', () => {
  assert.equal(baseline.jobs.scan['runs-on'], '${{ fromJSON(inputs.runner) }}');
  assert.equal(baseline.permissions.contents, 'read');
  assert.equal(baseline.on.workflow_call.inputs['results-storage'].default, 'artifacts');
  assert.match(step('Upload results').if, /inputs.results-storage == 'artifacts'/);
  assert.equal(step('Upload results').with['retention-days'], '${{ inputs.artifact-retention-days }}');
  assert.equal(baseline.on.workflow_call.outputs.summary.value, '${{ jobs.scan.outputs.summary }}');
  assert.match(publisher.jobs.publish.if, /github\.ref == format/);
  assert.ok(!publisher.jobs.publish.if.includes('pull_request'));
  assert.equal(publisher.jobs.publish.permissions.contents, 'write');
  assert.ok(!publisher.jobs.publish.steps.some(step => step.uses?.startsWith('actions/checkout')));
  assert.match(step('Remove raw reports').if, /always/);
});

test('actual input script rejects unknown storage and invalid retention', () => {
  const valid = { ...process.env, MODE: 'report', SEVERITY: 'HIGH,CRITICAL', SCANNERS: 'vuln,secret',
    SCAN_PATH: '.', IGNORE_FILE: '.trivyignore.yaml', MAX_DAYS: '180', RESULTS_STORAGE: 'branch', RETENTION: '1' };
  assert.equal(spawnSync('bash', ['-c', step('Validate inputs').run], { env: valid }).status, 0);
  for (const change of [{ RESULTS_STORAGE: 'typo' }, { RETENTION: '0' }, { RETENTION: '91' }]) {
    assert.notEqual(spawnSync('bash', ['-c', step('Validate inputs').run], { env: { ...valid, ...change } }).status, 0);
  }
});

test('actual evaluation script emits schema/counts without raw findings; enforce fails on blocking results', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'baseline-summary-test-'));
  try {
    await mkdir(join(directory, 'security-baseline'));
    await writeFile(join(directory, 'security-baseline/trivy-results.json'), JSON.stringify({
      SchemaVersion: 2, CreatedAt: fixedTime, Results: [
        { Class: 'lang-pkgs', Target: 'requirements.txt', Vulnerabilities: [
          { Severity: 'CRITICAL', PkgName: 'demo', InstalledVersion: '1', FixedVersion: '2', VulnerabilityID: 'CVE-fixture' },
        ] },
        { Class: 'secret', Target: 'config/key', Secrets: [
          { Severity: 'HIGH', Title: 'Private key', StartLine: 1, Match: 'NEVER_PUBLISH_RAW_VALUE' },
        ] },
        { Class: 'config', Target: 'Dockerfile', Misconfigurations: [
          { Severity: 'HIGH', Status: 'FAIL', ID: 'AVD-fixture', Title: 'Insecure configuration' },
          { Severity: 'HIGH', Status: 'PASS' },
        ] },
      ],
    }));
    const local = { ...process.env, RUNNER_TEMP: directory,
      GITHUB_OUTPUT: join(directory, 'outputs'), GITHUB_STEP_SUMMARY: join(directory, 'summary.md'),
      MODE: 'enforce', SEVERITY: 'CRITICAL,HIGH', FAIL_ON_UNFIXED: 'false',
      SCANNERS: 'vuln,secret,misconfig', SCAN_PATH: '.', SKIP_DIRS: '', TRIVY_VERSION: '0.76.1' };
    execFileSync('bash', ['-c', step('Summarise and evaluate findings').run], { env: local });
    const outputs = await readFile(local.GITHUB_OUTPUT, 'utf8');
    const result = JSON.parse(outputs.split('\n').find(line => line.startsWith('summary=')).slice(8));
    assert.equal(result.counts.vulnerabilities.CRITICAL, 1);
    assert.equal(result.counts.secrets.HIGH, 1);
    assert.equal(result.counts.misconfigurations.HIGH, 1);
    assert.equal(result.detectedTargets, 2);
    assert.equal(result.blockingCount, 3);
    assert.ok(!outputs.includes('NEVER_PUBLISH_RAW_VALUE'));
    const enforced = spawnSync('bash', ['-c', step('Enforce').run], { env: { ...local, BLOCKING: '2' } });
    assert.equal(enforced.status, 1);
    assert.equal(spawnSync('bash', ['-c', step('Enforce').run], {
      env: { ...local, MODE: 'report', BLOCKING: '2' },
    }).status, 0);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('publisher creates orphan branch with only explicitly projected summary fields', async () => {
  const { calls } = await publish({ SUMMARY: JSON.stringify({ ...summary, rawSecret: 'NEVER_PUBLISH' }) });
  const record = published(calls);
  assert.equal(record.runId, 123);
  assert.equal(record.runAttempt, 2);
  assert.equal(record.scanOutcome, 'completed');
  assert.equal(record.summary.counts.secrets.HIGH, 0);
  assert.ok(!JSON.stringify(record).includes('NEVER_PUBLISH'));
  assert.deepEqual(JSON.parse(calls.find(call => call.path.endsWith('/git/commits')).options.body).parents, []);
  assert.equal(JSON.parse(calls.at(-1).options.body).ref, 'refs/heads/security-results');
});

test('publisher records early failure without zero-shaped counts', async () => {
  const { calls } = await publish({ SUMMARY: '', SCAN_RESULT: 'failure' });
  const record = published(calls);
  assert.equal(record.scanOutcome, 'error');
  assert.equal(record.scanResult, 'failure');
  assert.equal(record.summary, null);
});

test('publisher updates branch without force; retains latest run/attempt and respects write failures', async () => {
  const old = { schemaVersion: 1, repository: 'acme/api', branch: 'main', runId: 122, runAttempt: 1 };
  const { calls } = await publish({}, fakeGitHub({ ref: true, existing: old }));
  assert.deepEqual(JSON.parse(calls.at(-1).options.body), { sha: 'commit', force: false });
  assert.deepEqual(JSON.parse(calls.find(call => call.path.endsWith('/git/commits')).options.body).parents, ['parent']);
  for (const existing of [{ ...old, runId: 124 }, { ...old, runId: 123, runAttempt: 2 }]) {
    const result = await publish({}, fakeGitHub({ ref: true, existing }));
    assert.equal(result.exitCode, 0);
    assert.ok(result.calls.every(call => call.options.method === 'GET'));
  }
  await assert.rejects(publish({}, fakeGitHub({ rejectWrite: true })), /HTTP 403/);
});

test('publisher rejects unsafe paths, default-branch writes and malformed summaries before API calls', async () => {
  for (const update of [
    { RESULTS_BRANCH: 'main' }, { RESULTS_BRANCH: '../main' },
    { RESULTS_PATH: '.github/workflows/malicious.json' }, { RESULTS_PATH: '../secret.json' },
    { SUMMARY: JSON.stringify({ ...summary, counts: {} }) },
    { SCAN_RESULT: 'unknown' },
  ]) {
    const api = fakeGitHub();
    await assert.rejects(publish(update, api));
    assert.equal(api.calls.length, 0);
  }
});

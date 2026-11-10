import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { collectRepository } from '../repository-security-dashboard/scripts/collect.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
function workflow(name) {
  return JSON.parse(execFileSync('yq', ['-o=json', '.', join(root, `.github/workflows/${name}.yml`)], { encoding: 'utf8' }));
}
test('real workflow summary -> publisher Git content -> branch collector preserves exact counts without artifacts', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'security-roundtrip-'));
  try {
    await mkdir(join(directory, 'security-baseline'));
    await writeFile(join(directory, 'security-baseline/trivy-results.json'), JSON.stringify({
      SchemaVersion: 2, CreatedAt: '2026-11-09T12:05:00Z', Results: [
        { Class: 'lang-pkgs', Target: 'requirements.txt', Vulnerabilities: [
          { Severity: 'CRITICAL', PkgName: 'demo', InstalledVersion: '1', FixedVersion: '2', VulnerabilityID: 'CVE-fixture' },
        ] },
        { Class: 'secret', Target: 'key', Secrets: [
          { Severity: 'HIGH', Title: 'Private key', StartLine: 1, Match: 'NEVER_PUBLISH_RAW_VALUE' },
        ] },
      ],
    }));
    const scan = workflow('security-baseline').jobs.scan.steps.find(step => step.id === 'evaluate');
    const env = {
      ...process.env, RUNNER_TEMP: directory, GITHUB_OUTPUT: join(directory, 'outputs'),
      GITHUB_STEP_SUMMARY: join(directory, 'summary.md'), MODE: 'enforce', SEVERITY: 'CRITICAL,HIGH',
      FAIL_ON_UNFIXED: 'false', SCANNERS: 'vuln,secret', SCAN_PATH: '.', SKIP_DIRS: '', TRIVY_VERSION: '0.76.1',
    };
    execFileSync('bash', ['-c', scan.run], { env });
    const outputs = await readFile(env.GITHUB_OUTPUT, 'utf8');
    const summary = outputs.split('\n').find(line => line.startsWith('summary=')).slice(8);
    const publisher = workflow('publish-results').jobs.publish.steps.find(step => step.run).run;
    const source = publisher.split("<<'JS'\n")[1].trim().replace(/\nJS$/, '');
    const execute = new (Object.getPrototypeOf(async function () {}).constructor)('fetch', 'process', source);
    let content;
    await execute(async (url, options) => {
      if (options.method === 'GET') return new Response(null, { status: 404 });
      if (url.endsWith('/git/trees')) content = JSON.parse(options.body).tree[0].content;
      return Response.json({ sha: 'fake-commit' });
    }, { env: {
      SUMMARY: summary, SCAN_RESULT: 'failure', RESULTS_BRANCH: 'security-results',
      RESULTS_PATH: 'security-summary.json', SOURCE_REPOSITORY: 'acme/api', SOURCE_BRANCH: 'main',
      SOURCE_SHA: 'a'.repeat(40), RUN_ID: '123', RUN_ATTEMPT: '1', GH_TOKEN: 'fake-token',
    } });
    assert.ok(!content.includes('NEVER_PUBLISH_RAW_VALUE'));
    const api = {
      async json(path) {
        return path === '/repos/acme/api' ? { default_branch: 'main' } :
          { type: 'file', encoding: 'base64', content: Buffer.from(content).toString('base64'), size: Buffer.byteLength(content) };
      },
      async *pages(path, key) {
        assert.equal(key, 'workflow_runs');
        yield [{ id: 123, run_attempt: 1, event: 'schedule', head_branch: 'main', status: 'completed',
          conclusion: 'failure', run_started_at: '2026-11-09T12:00:00Z' }];
      },
      archive() { assert.fail('No artifact should be involved'); },
    };
    const entry = { repository: 'acme/api', workflow: 'security-baseline.yml', storage: 'branch' };
    const row = await collectRepository(entry, { staleAfterHours: 192 }, async () => api, new Date('2026-11-09T13:00:00Z'));
    assert.equal(row.status, 'failed');
    assert.equal(row.counts.vulnerabilities.CRITICAL, 1);
    assert.equal(row.counts.secrets.HIGH, 1);
    assert.equal(row.detectedTargets, 1);
    assert.equal(JSON.parse(content).summary.blockingCount, 2);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

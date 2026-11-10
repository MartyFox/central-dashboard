import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const path = fileURLToPath(new URL('../.github/workflows/codeql.yml', import.meta.url));
const workflow = JSON.parse(execFileSync('yq', ['-o=json', '.', path], { encoding: 'utf8' }));
const callerPath = fileURLToPath(new URL('../examples/security-baseline.yml', import.meta.url));
const caller = JSON.parse(execFileSync('yq', ['-o=json', '.', callerPath], { encoding: 'utf8' }));

test('reusable CodeQL takes consumer languages and runner inputs with least permissions and no raw artifact uploads', () => {
  assert.deepEqual(Object.keys(workflow.on), ['workflow_call']);
  const inputs = workflow.on.workflow_call.inputs;
  assert.equal(inputs.languages.required, true);
  assert.equal(inputs.languages.type, 'string');
  assert.equal(inputs.runner.default, '["ubuntu-24.04"]');
  assert.equal(inputs['go-version-file'].default, 'go.mod');
  assert.equal(workflow.permissions.contents, 'read');
  const job = workflow.jobs.analyze;
  assert.equal(job.permissions['security-events'], 'write');
  assert.equal(job.permissions.contents, 'read');
  assert.ok(!job.permissions.actions);
  assert.equal(job['runs-on'], '${{ fromJSON(inputs.runner) }}');
  assert.equal(job.needs, 'validate');
  assert.equal(job.strategy.matrix.language, '${{ fromJSON(needs.validate.outputs.languages) }}');
  assert.equal(job.strategy['fail-fast'], false);
  const init = job.steps.find(step => step.uses?.includes('codeql-action/init@'));
  assert.equal(init.with.queries, 'security-extended');
  assert.equal(init.with['build-mode'], 'autobuild');
  assert.ok(job.steps.some(step => step.uses?.includes('codeql-action/autobuild@')));
  const analyze = job.steps.find(step => step.uses?.includes('codeql-action/analyze@'));
  assert.equal(analyze.with.category, 'security-baseline/language:${{ matrix.language }}');
  assert.equal(analyze.with['wait-for-processing'], true);
  const setup = job.steps.find(step => step.uses?.startsWith('actions/setup-go@'));
  assert.equal(setup.if, "matrix.language == 'go'");
  assert.equal(setup.with['go-version-file'], '${{ inputs.go-version-file }}');
  assert.equal(setup.with.cache, false);
  assert.ok(!job.steps.some(step => step.uses?.includes('upload-artifact')));
  for (const step of job.steps.filter(step => step.uses)) assert.match(step.uses, /@[a-f0-9]{40}$/);
});

test('consumer owns triggers and language selection, not scanner implementation', async () => {
  assert.deepEqual(Object.keys(caller.on), ['pull_request', 'push', 'schedule', 'workflow_dispatch']);
  assert.deepEqual(caller.on.push.branches, ['main']);
  assert.deepEqual(Object.keys(caller.jobs), ['security-baseline', 'codeql', 'publish']);
  const job = caller.jobs.codeql;
  assert.match(job.uses, /\/.github\/workflows\/codeql.yml@/);
  assert.equal(job.with.languages, '${{ vars.CODEQL_LANGUAGES }}');
  assert.equal(job.if, "vars.CODEQL_LANGUAGES != ''");
  assert.equal(job.permissions['security-events'], 'write');
  assert.equal(caller.permissions.contents, 'read');
  assert.equal(caller.jobs['security-baseline'].permissions, undefined);
  assert.equal(caller.jobs.publish.needs, 'security-baseline');
  assert.equal(caller.jobs.publish.permissions.contents, 'write');
  assert.equal(job.needs, undefined);
  assert.ok(!job.steps);
  assert.ok(!job.strategy);
  assert.match(job.with.runner, /vars.SECURITY_RUNNER/);
  const text = await readFile(path, 'utf8');
  assert.ok(!text.includes('secrets.'));
  assert.ok(!text.includes('pull_request_target'));
});

test('combined consumer example is the only normal baseline caller and allows dashboard collection from the same run', async () => {
  const inventory = JSON.parse(await readFile(new URL('../../repository-security-dashboard/repositories.json', import.meta.url), 'utf8'));
  const hive = inventory.repositories.find(entry => entry.repository === 'MartyFox/hive');
  assert.equal(hive.codeql.workflow, hive.workflow);
  assert.equal(hive.workflow, 'security-baseline.yml');
  await assert.rejects(readFile(new URL('../examples/codeql.yml', import.meta.url)), { code: 'ENOENT' });
});

test('actual input validator accepts supported mixed languages and rejects malformed/empty/duplicate/unknown selection', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'codeql-inputs-'));
  try {
    const step = workflow.jobs.validate.steps[0];
    assert.equal(step.env.LANGUAGES, '${{ inputs.languages }}');
    const output = join(directory, 'outputs');
    for (const languages of [['go'], ['javascript-typescript', 'java-kotlin'], ['python', 'ruby', 'rust']]) {
      execFileSync('bash', ['-c', step.run], {
        env: { ...process.env, LANGUAGES: JSON.stringify(languages), GITHUB_OUTPUT: output },
      });
    }
    const lines = (await readFile(output, 'utf8')).trim().split('\n');
    assert.equal(lines.length, 3);
    assert.deepEqual(JSON.parse(lines[1].slice('languages='.length)), ['javascript-typescript', 'java-kotlin']);
    for (const languages of ['invalid', 'null', '{}', '[]', '["go","go"]', '["typescript"]', '[1]']) {
      const result = spawnSync('bash', ['-c', step.run], {
        env: { ...process.env, LANGUAGES: languages, GITHUB_OUTPUT: output }, encoding: 'utf8',
      });
      assert.equal(result.status, 1);
      assert.match(result.stderr, /::error::languages must be/);
    }
    assert.equal((await readFile(output, 'utf8')).trim().split('\n').length, 3);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const script = join(root, 'prepare-workflows.mjs');
test('shared packaging matches supplied workflows and wires component paths without editing implementation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'security-packaging-'));
  try {
    execFileSync(process.execPath, [script, 'shared', directory]);
    execFileSync(process.execPath, [script, 'shared', directory]);
    for (const file of ['security-baseline.yml', 'publish-results.yml', 'upload-code-scanning.yml', 'dashboard.yml', 'test.yml']) {
      const generated = await readFile(join(directory, '.github/workflows', file), 'utf8');
      assert.equal(generated, await readFile(join(root, '.github/workflows', file), 'utf8'));
      if (file === 'dashboard.yml') {
        assert.ok(generated.includes('working-directory: repository-security-dashboard'));
        assert.ok(generated.includes('path: repository-security-dashboard/dist/'));
        assert.ok(generated.includes('vars.DASHBOARD_RUNNER'));
        assert.ok(generated.includes("vars.DASHBOARD_PREVIEW == 'true'"));
      }
    }
    const target = join(directory, '.github/workflows/dashboard.yml');
    await writeFile(target, 'user modification\n');
    const modified = spawnSync(process.execPath, [script, 'shared', directory]);
    assert.notEqual(modified.status, 0);
    assert.equal(await readFile(target, 'utf8'), 'user modification\n');
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('standalone dashboard packaging preserves root paths and does not install baseline jobs', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'security-standalone-'));
  try {
    execFileSync(process.execPath, [script, 'dashboard', directory]);
    const generated = await readFile(join(directory, '.github/workflows/dashboard.yml'), 'utf8');
    assert.ok(generated.includes('working-directory: .'));
    assert.ok(generated.includes('path: dist/'));
    const standaloneTest = await readFile(join(directory, '.github/workflows/test.yml'), 'utf8');
    assert.ok(!standaloneTest.includes('repository-security-baseline'));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { authentication } from '../scripts/github.mjs';
import { build } from '../scripts/collect.mjs';

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const env = {
  GH_APP_ID: '123',
  GH_APP_PRIVATE_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  GH_APP_INSTALLATIONS: JSON.stringify({ alice: '456', bob: '789', unused: '999' }),
};
const config = {
  staleAfterHours: 192,
  repositories: ['Alice/api', 'alice/web', 'bob/api'].map(repository => ({
    repository, workflow: 'security-baseline.yml', artifact: 'security-baseline-results',
  })),
};

function mockGitHub({ failOwner, wrongOwner, failRevoke = false } = {}) {
  const calls = [];
  const fetcher = async (url, options) => {
    calls.push({ path: new URL(url).pathname, options });
    const path = new URL(url).pathname;
    const match = path.match(/^\/app\/installations\/(456|789)(\/access_tokens)?$/);
    if (match) {
      const owner = match[1] === '456' ? 'alice' : 'bob';
      if (owner === failOwner) return new Response(null, { status: 403 });
      if (!match[2]) return Response.json({ account: { login: wrongOwner ?? owner } });
      return Response.json({ token: `fake-${owner}-token` });
    }
    if (path === '/installation/token') {
      const failed = failRevoke && options.headers.Authorization === 'Bearer fake-alice-token';
      return new Response(null, { status: failed ? 500 : 204 });
    }
    const owner = path.split('/')[2].toLowerCase();
    assert.equal(options.headers.Authorization, `Bearer fake-${owner}-token`);
    if (path.includes('/actions/workflows/')) return Response.json({ workflow_runs: [] });
    return Response.json({ default_branch: 'main' });
  };
  return { calls, fetcher };
}

test('multiple owners get isolated, allowlist-scoped tokens with one cached client per owner', async () => {
  const { calls, fetcher } = mockGitHub();
  const auth = await authentication(config, env, fetcher);
  assert.equal(calls.length, 0);
  const [alice, sameAlice, bob] = await Promise.all([
    auth.forRepository('Alice/api'), auth.forRepository('alice/web'), auth.forRepository('bob/api'),
  ]);
  assert.equal(alice, sameAlice);
  assert.notEqual(alice, bob);
  await alice.json('/repos/Alice/api');
  await bob.json('/repos/bob/api');
  const minted = calls.filter(call => call.options.method === 'POST');
  assert.equal(minted.length, 2);
  assert.deepEqual(minted.map(call => [call.path, JSON.parse(call.options.body)]), [
    ['/app/installations/456/access_tokens', {
      repositories: ['api', 'web'], permissions: { actions: 'read', metadata: 'read' },
    }],
    ['/app/installations/789/access_tokens', {
      repositories: ['api'], permissions: { actions: 'read', metadata: 'read' },
    }],
  ]);
  assert.ok(!calls.some(call => call.path.includes('999')));
  const count = calls.length;
  await assert.rejects(auth.forRepository('alice/not-allowlisted'), /allowlist/);
  await assert.rejects(auth.forRepository('unknown/api'), /allowlist/);
  assert.equal(calls.length, count);
  await auth.revoke();
  assert.deepEqual(calls.filter(call => call.options.method === 'DELETE')
    .map(call => call.options.headers.Authorization).sort(), [
    'Bearer fake-alice-token', 'Bearer fake-bob-token',
  ]);
});

test('installation map validates before any API call; owner matching is case-insensitive', async () => {
  const invalid = [
    'invalid JSON', 'null', '[]', '{}',
    '{"alice":"456"}',
    '{"alice":"456","bob":789}',
    '{"alice":"0","bob":"789"}',
    '{"alice":"456","bob":"456"}',
    '{"alice":"456","ALICE":"999","bob":"789"}',
    '{"alice":"456","bob":"789","bad/owner":"999"}',
  ];
  for (const mapping of invalid) {
    await assert.rejects(authentication(config, { ...env, GH_APP_INSTALLATIONS: mapping }, () => {
      assert.fail('Invalid configuration must not call GitHub');
    }), /installation|Installation|GH_APP_INSTALLATIONS/);
  }
  const { fetcher } = mockGitHub();
  const auth = await authentication(config, {
    ...env, GH_APP_INSTALLATIONS: '{"ALICE":"456","BOB":"789"}',
  }, fetcher);
  await auth.forRepository('ALICE/API');
  await auth.revoke();
});

test('explicit installation map takes precedence over legacy single-installation variable', async () => {
  const { calls, fetcher } = mockGitHub();
  const auth = await authentication(config, { ...env, GH_APP_INSTALLATION_ID: '999' }, fetcher);
  await auth.forRepository('Alice/api');
  assert.equal(calls[0].path, '/app/installations/456');
  await auth.revoke();
});

test('versioned file mapping supports multiple owners without installation variables', async () => {
  const { calls, fetcher } = mockGitHub();
  const { GH_APP_INSTALLATIONS, ...credentials } = env;
  const fileConfig = { ...config, installations: { ALICE: '456', bob: '789' } };
  const auth = await authentication(fileConfig, credentials, fetcher);
  await auth.forRepository('Alice/api');
  await auth.forRepository('bob/api');
  assert.deepEqual(calls.filter(call => call.options.method === 'POST').map(call => call.path), [
    '/app/installations/456/access_tokens', '/app/installations/789/access_tokens',
  ]);
  await auth.revoke();
});

test('file mapping takes precedence over installation variables without merging or fallback', async () => {
  const { calls, fetcher } = mockGitHub();
  const auth = await authentication({ ...config, installations: { alice: '456', bob: '789' } }, {
    ...env, GH_APP_INSTALLATIONS: 'invalid JSON', GH_APP_INSTALLATION_ID: '999',
  }, fetcher);
  await auth.forRepository('bob/api');
  assert.equal(calls[0].path, '/app/installations/789');
  await auth.revoke();
  for (const installations of [null, [], {}, { alice: '456' },
    { alice: 456, bob: '789' }, { alice: '456', bob: '456' }]) {
    await assert.rejects(authentication({ ...config, installations }, env, () => {
      assert.fail('Invalid file mapping must not call GitHub or fall back to variables');
    }), /Installation|installation/);
  }
});

test('installation must belong to configured owner before minting a token', async () => {
  const { calls, fetcher } = mockGitHub({ wrongOwner: 'someone-else' });
  const auth = await authentication(config, env, fetcher);
  await assert.rejects(auth.forRepository('Alice/api'), /does not belong/);
  await assert.rejects(auth.forRepository('alice/web'), /does not belong/);
  assert.equal(calls.length, 1);
  await auth.revoke();
  assert.ok(!calls.some(call => call.options.method === 'POST' || call.options.method === 'DELETE'));
});

test('all tokens are revoked even when one revocation fails', async () => {
  const { calls, fetcher } = mockGitHub({ failRevoke: true });
  const auth = await authentication(config, env, fetcher);
  await auth.forRepository('Alice/api');
  await auth.forRepository('bob/api');
  await assert.rejects(auth.revoke(), /all revocations were attempted/);
  assert.equal(calls.filter(call => call.options.method === 'DELETE').length, 2);
});

test('owner authentication failures remain explicit without stopping other owners or leaking settings', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'dashboard-multi-owner-'));
  const { calls, fetcher } = mockGitHub({ failOwner: 'alice' });
  const auth = await authentication(config, env, fetcher);
  try {
    const data = await build(config, auth.forRepository, directory);
    assert.deepEqual(data.repositories.map(row => row.status), ['error', 'error', 'missing']);
    assert.ok(data.repositories.every(row => row.counts === null));
    assert.equal(calls.filter(call => call.path === '/app/installations/456').length, 1);
    assert.ok(calls.some(call => call.path === '/repos/bob/api'));
    const json = await readFile(join(directory, 'data.json'), 'utf8');
    for (const excluded of ['fake-alice-token', 'fake-bob-token', 'PRIVATE KEY', 'GH_APP_INSTALLATIONS']) {
      assert.ok(!json.includes(excluded));
    }
  } finally {
    await auth.revoke();
    await rm(directory, { recursive: true, force: true });
  }
  assert.equal(calls.filter(call => call.options.method === 'DELETE').length, 1);
});

test('build routes cross-owner workflow and artifact requests with the correct installation token', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'dashboard-owner-artifacts-'));
  const calls = [];
  const now = new Date('2026-11-04T10:00:00Z');
  const { fetcher: appFetcher } = mockGitHub();
  const auth = await authentication(config, env, async (url, options) => {
    const parsed = new URL(url);
    if (parsed.pathname.startsWith('/app/') || parsed.pathname === '/installation/token') {
      return appFetcher(url, options);
    }
    if (parsed.hostname === 'artifacts.example.invalid') {
      assert.equal(options.headers, undefined);
      return new Response('fake ZIP');
    }
    const path = parsed.pathname;
    calls.push(path);
    const owner = path.split('/')[2].toLowerCase();
    assert.equal(options.headers.Authorization, `Bearer fake-${owner}-token`);
    if (path.endsWith('/zip')) {
      return new Response(null, { status: 302,
        headers: { location: 'https://artifacts.example.invalid/download' } });
    }
    if (path.endsWith('/artifacts')) {
      return Response.json({ artifacts: [{
        id: 2, name: 'security-baseline-results', expired: false, size_in_bytes: 8,
        created_at: '2026-11-04T09:10:00Z',
      }] });
    }
    if (path.endsWith('/runs')) {
      return Response.json({ workflow_runs: [{
        id: 1, event: 'schedule', head_branch: 'main', status: 'completed', conclusion: 'success',
        run_started_at: '2026-11-04T09:00:00Z',
      }] });
    }
    return Response.json({ default_branch: 'main' });
  });
  try {
    const data = await build(config, auth.forRepository, directory, now, async () => ({
      SchemaVersion: 2, CreatedAt: '2026-11-04T09:05:00Z',
      Results: [{ Class: 'lang-pkgs', Target: 'requirements.txt',
        Vulnerabilities: [{ Severity: 'HIGH' }] }],
    }));
    assert.deepEqual(data.repositories.map(row => row.status), ['findings', 'findings', 'findings']);
    assert.ok(data.repositories.every(row => row.counts.vulnerabilities.HIGH === 1));
    for (const { repository } of config.repositories) {
      assert.deepEqual(calls.filter(path => path.startsWith(`/repos/${repository}/`) ||
        path === `/repos/${repository}`), [
        `/repos/${repository}`,
        `/repos/${repository}/actions/workflows/security-baseline.yml/runs`,
        `/repos/${repository}/actions/runs/1/artifacts`,
        `/repos/${repository}/actions/artifacts/2/zip`,
      ]);
    }
    assert.equal(calls.length, 12);
  } finally {
    await auth.revoke();
    await rm(directory, { recursive: true, force: true });
  }
});

test('PAT takes precedence, remains allowlist-bound, and is never revoked by the collector', async () => {
  const calls = [];
  const auth = await authentication(config, { GH_TOKEN: 'fake-pat', GH_APP_INSTALLATIONS: 'invalid' },
    async (url, options) => {
      calls.push(url);
      assert.equal(options.headers.Authorization, 'Bearer fake-pat');
      return Response.json({ default_branch: 'main' });
    });
  const alice = await auth.forRepository('Alice/api');
  const bob = await auth.forRepository('bob/api');
  assert.equal(alice, bob);
  await alice.json('/repos/Alice/api');
  await bob.json('/repos/bob/api');
  await assert.rejects(auth.forRepository('alice/not-allowlisted'), /allowlist/);
  await auth.revoke();
  assert.equal(calls.length, 2);
});

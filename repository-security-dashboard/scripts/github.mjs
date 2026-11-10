import { createSign } from 'node:crypto';
import { MAX_ARCHIVE_BYTES } from './report.mjs';
import { DashboardError } from './errors.mjs';

const API = 'https://api.github.com';

export class GitHub {
  constructor(token, fetcher = fetch) {
    if (!token) throw new DashboardError('Set GH_TOKEN or configure GitHub App credentials');
    this.token = token;
    this.fetcher = fetcher;
  }

  async request(path, options = {}) {
    if (!path.startsWith('/') || path.startsWith('//')) throw new DashboardError('Invalid API path');
    let response;
    try {
      response = await this.fetcher(`${API}${path}`, {
        ...options,
        headers: {
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
          ...options.headers,
          Authorization: `Bearer ${this.token}`,
        },
        redirect: 'manual',
        signal: AbortSignal.timeout(60_000),
      });
    } catch {
      throw new DashboardError('GitHub API network request failed');
    }
    if (!response.ok && response.status !== 302) {
      throw new DashboardError(`GitHub API HTTP ${response.status}`);
    }
    return response;
  }

  async json(path, options) {
    return (await this.request(path, options)).json();
  }

  async *pages(path, key) {
    for (let page = 1; page <= 10; page++) {
      const data = await this.json(`${path}${path.includes('?') ? '&' : '?'}per_page=100&page=${page}`);
      if (!Array.isArray(data[key])) throw new DashboardError(`GitHub API missing ${key}`);
      yield data[key];
      if (data[key].length < 100) return;
    }
    throw new DashboardError('GitHub pagination limit reached; narrow the configured workflow');
  }

  async archive(path) {
    const response = await this.request(path);
    if (response.status !== 302) throw new DashboardError('Expected GitHub artifact download redirect');
    const location = new URL(response.headers.get('location'));
    if (location.protocol !== 'https:' || location.username || location.password) {
      throw new DashboardError('Invalid artifact download URL');
    }
    // Signed artifact URL is fetched without the GitHub token.
    let download;
    try {
      download = await this.fetcher(location, { signal: AbortSignal.timeout(60_000), redirect: 'error' });
    } catch {
      throw new DashboardError('Artifact download network request failed');
    }
    if (!download.ok) throw new DashboardError(`Artifact download HTTP ${download.status}`);
    const chunks = [];
    let size = 0;
    for await (const chunk of download.body) {
      size += chunk.length;
      if (size > MAX_ARCHIVE_BYTES) {
        throw new DashboardError('Artifact exceeds 25 MiB limit');
      }
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  }
}

export async function authentication(config, env = process.env, fetcher = fetch) {
  const allowed = new Set(config.repositories.map(entry => entry.repository.toLowerCase()));
  function ownerFor(repository) {
    if (!allowed.has(repository.toLowerCase())) {
      throw new DashboardError('Repository is not in the configured allowlist');
    }
    return repository.split('/')[0].toLowerCase();
  }
  if (env.GH_TOKEN) {
    const api = new GitHub(env.GH_TOKEN, fetcher);
    return {
      forRepository: async repository => { ownerFor(repository); return api; },
      revoke: async () => {},
    };
  }
  const { GH_APP_ID: appId, GH_APP_INSTALLATION_ID: installation, GH_APP_PRIVATE_KEY: key } = env;
  if (!/^[1-9]\d*$/.test(appId ?? '') || !key) {
    throw new DashboardError('Set GH_TOKEN or GH_APP_ID, GH_APP_PRIVATE_KEY and an installation configuration');
  }
  const repositoriesByOwner = new Map();
  for (const { repository } of config.repositories) {
    const [owner, name] = repository.split('/');
    const names = repositoriesByOwner.get(owner.toLowerCase()) ?? [];
    names.push(name);
    repositoriesByOwner.set(owner.toLowerCase(), names);
  }
  const installations = new Map();
  if (config.installations !== undefined || env.GH_APP_INSTALLATIONS) {
    let mapping = config.installations;
    if (mapping === undefined) {
      try {
        mapping = JSON.parse(env.GH_APP_INSTALLATIONS);
      } catch {
        throw new DashboardError('GH_APP_INSTALLATIONS must be a JSON object mapping owners to installation ID strings');
      }
    }
    if (!mapping || typeof mapping !== 'object' || Array.isArray(mapping)) {
      throw new DashboardError('Installation configuration must be a JSON object mapping owners to installation ID strings');
    }
    const ids = new Set();
    for (const [owner, id] of Object.entries(mapping)) {
      const normalised = owner.toLowerCase();
      if (!/^[a-zA-Z0-9][a-zA-Z0-9-]*$/.test(owner) ||
          typeof id !== 'string' || !/^[1-9]\d*$/.test(id) ||
          installations.has(normalised) || ids.has(id)) {
        throw new DashboardError('Installation mapping needs unique owners and unique positive installation ID strings');
      }
      installations.set(normalised, id);
      ids.add(id);
    }
  } else {
    if (repositoriesByOwner.size !== 1 || !/^[1-9]\d*$/.test(installation ?? '')) {
      throw new DashboardError('Set config.installations or GH_APP_INSTALLATIONS for multiple owners, or GH_APP_INSTALLATION_ID for one owner');
    }
    installations.set(repositoriesByOwner.keys().next().value, installation);
  }
  for (const owner of repositoriesByOwner.keys()) {
    if (!installations.has(owner)) throw new DashboardError(`No GitHub App installation configured for owner ${owner}`);
  }

  const clients = new Map();
  const issued = [];
  async function createClient(owner) {
    // Sign a fresh JWT per owner so later installations do not use an expired App JWT.
    const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const payload = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({ iat: now - 60, exp: now + 540, iss: appId })}`;
    const signer = createSign('RSA-SHA256');
    signer.update(payload);
    const jwt = `${payload}.${signer.sign(key, 'base64url')}`;
    const app = new GitHub(jwt, fetcher);
    const id = installations.get(owner);
    const details = await app.json(`/app/installations/${id}`);
    if (typeof details.account?.login !== 'string' || details.account.login.toLowerCase() !== owner) {
      throw new DashboardError(`Configured GitHub App installation does not belong to owner ${owner}`);
    }
    const result = await app.json(`/app/installations/${id}/access_tokens`, {
      method: 'POST',
      body: JSON.stringify({
        repositories: repositoriesByOwner.get(owner),
        permissions: {
          actions: 'read', metadata: 'read',
          ...(config.repositories.some(entry =>
            entry.repository.split('/')[0].toLowerCase() === owner && entry.storage === 'branch')
            ? { contents: 'read' } : {}),
        },
      }),
    });
    if (typeof result.token !== 'string' || !result.token) throw new DashboardError('GitHub App token missing');
    const client = new GitHub(result.token, fetcher);
    issued.push(client);
    return client;
  }
  return {
    forRepository: async repository => {
      const owner = ownerFor(repository);
      // Cache rejected promises too: one broken installation must not be retried per repo.
      if (!clients.has(owner)) clients.set(owner, createClient(owner));
      return clients.get(owner);
    },
    revoke: async () => {
      const results = await Promise.allSettled(
        issued.map(client => client.request('/installation/token', { method: 'DELETE' })),
      );
      if (results.some(result => result.status === 'rejected')) {
        throw new DashboardError('Failed to revoke one or more GitHub App installation tokens; all revocations were attempted');
      }
    },
  };
}

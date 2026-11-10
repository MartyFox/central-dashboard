import { execFile } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { DashboardError } from './errors.mjs';

const exec = promisify(execFile);
export const MAX_ARCHIVE_BYTES = 25 * 1024 * 1024;
const MAX_REPORT_BYTES = 20 * 1024 * 1024;
export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

export async function readReport(archive) {
  if (archive.length > MAX_ARCHIVE_BYTES) throw new DashboardError('Artifact exceeds 25 MiB limit');
  const directory = await mkdtemp(join(tmpdir(), 'security-dashboard-'));
  try {
    const path = join(directory, 'artifact.zip');
    await writeFile(path, archive, { mode: 0o600 });
    const options = { timeout: 15_000, maxBuffer: MAX_REPORT_BYTES };
    const { stdout: listing } = await exec('unzip', ['-Z1', path], options);
    const entries = listing.trim().split('\n');
    // Read one exact member to stdout; never extract paths supplied by another repo.
    if (entries.filter(name => name === 'trivy-results.json').length !== 1) {
      throw new DashboardError('Artifact must contain exactly one root trivy-results.json');
    }
    const { stdout } = await exec('unzip', ['-p', path, 'trivy-results.json'], options);
    return JSON.parse(stdout);
  } catch (error) {
    if (error instanceof DashboardError) throw error;
    throw new DashboardError('Unable to read valid Trivy JSON from ZIP within size/time limits');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

export function summarise(report) {
  if (!report || report.SchemaVersion !== 2 || !Array.isArray(report.Results)) {
    throw new DashboardError('Expected Trivy SchemaVersion 2 with a Results array');
  }
  const counts = Object.fromEntries(
    ['vulnerabilities', 'secrets', 'misconfigurations'].map(type => [
      type, Object.fromEntries(SEVERITIES.map(severity => [severity, 0])),
    ]),
  );
  const targets = new Set();
  for (const result of report.Results) {
    if (!result || typeof result !== 'object') throw new DashboardError('Invalid Trivy result');
    if (['lang-pkgs', 'os-pkgs', 'config'].includes(result.Class)) {
      if (typeof result.Target !== 'string') throw new DashboardError('Invalid Trivy target');
      targets.add(`${result.Class}:${result.Target}`);
    }
    for (const [field, type] of [
      ['Vulnerabilities', 'vulnerabilities'], ['Secrets', 'secrets'],
      ['Misconfigurations', 'misconfigurations'],
    ]) {
      const findings = result[field] ?? [];
      if (!Array.isArray(findings)) throw new DashboardError(`Invalid Trivy ${field}`);
      for (const finding of findings) {
        if (!finding || typeof finding !== 'object') throw new DashboardError('Invalid finding');
        if (field === 'Misconfigurations') {
          if (!['FAIL', 'PASS', 'EXCEPTION'].includes(finding.Status)) {
            throw new DashboardError('Invalid misconfiguration status');
          }
          if (finding.Status !== 'FAIL') continue;
        }
        if (!SEVERITIES.includes(finding.Severity)) throw new DashboardError('Invalid finding severity');
        counts[type][finding.Severity]++;
      }
    }
  }
  return { counts, detectedTargets: targets.size };
}

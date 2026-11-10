import test from 'node:test';
import assert from 'node:assert/strict';
import { highestSeverity, count, effectiveStatus } from '../site/model.js';

const levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
function row(type = 'vulnerabilities', severity = 'CRITICAL', value = 2) {
  const counts = Object.fromEntries(['vulnerabilities', 'secrets', 'misconfigurations'].map(category =>
    [category, Object.fromEntries(levels.map(level => [level, 0]))]));
  counts[type][severity] = value;
  return { status: value ? 'findings' : 'clear', counts, scannedAt: '2026-11-10T12:00:00Z' };
}

test('repository risk uses highest positive severity from all baseline finding types', () => {
  for (const type of ['vulnerabilities', 'secrets', 'misconfigurations']) {
    for (const severity of levels) assert.equal(highestSeverity(row(type, severity)), severity);
  }
  const mixed = row('vulnerabilities', 'LOW');
  mixed.counts.misconfigurations.HIGH = 1;
  mixed.counts.secrets.CRITICAL = 1;
  assert.equal(highestSeverity(mixed), 'CRITICAL');
});

test('application risk participates even when baseline is missing; missing counts never imply clear', () => {
  const application = { status: 'findings', counts: Object.fromEntries(levels.map(level =>
    [level, level === 'CRITICAL' ? 1 : 0])) };
  assert.equal(highestSeverity({ counts: null, application }), 'CRITICAL');
  assert.equal(highestSeverity({ counts: null, application: { counts: null } }), null);
  assert.equal(highestSeverity(row('vulnerabilities', 'HIGH', 0)), null);
});

test('known critical risk remains visible when combined totals unavailable, without overriding scan health', () => {
  const incomplete = { ...row(), application: { status: 'error', counts: null } };
  assert.equal(count(incomplete, 'CRITICAL'), null);
  assert.equal(highestSeverity(incomplete), 'CRITICAL');
  assert.equal(effectiveStatus(incomplete, 192, Date.parse('2026-11-10T13:00:00Z')), 'error');
  assert.equal(count(incomplete, 'CRITICAL', 'applications'), null);
  const stale = row();
  assert.equal(highestSeverity(stale), 'CRITICAL');
  assert.equal(effectiveStatus(stale, 1, Date.parse('2026-11-11T13:00:00Z')), 'stale');
});

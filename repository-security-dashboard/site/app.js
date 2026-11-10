import { SEVERITIES, STATUSES, count, effectiveStatus, filterRows } from './model.js';

const byId = id => document.getElementById(id);
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function date(value) {
  return value ? new Date(value).toLocaleString() : 'Not available';
}
for (const [value, label] of Object.entries(STATUSES)) {
  const option = element('option', label);
  option.value = value;
  byId('status').append(option);
}
for (const severity of SEVERITIES) {
  const option = element('option', severity);
  option.value = severity;
  byId('severity').append(option);
}

let data;
function render() {
  const now = Date.now();
  const options = Object.fromEntries(['query', 'status', 'type', 'severity'].map(id => [id, byId(id).value]));
  const rows = filterRows(data.repositories, options, data.staleAfterHours, now);
  const totals = byId('totals');
  totals.replaceChildren();
  const fresh = data.repositories.filter(row =>
    ['clear', 'findings', 'limited'].includes(effectiveStatus(row, data.staleAfterHours, now))).length;
  const critical = data.repositories.reduce((sum, row) => sum + (count(row, 'CRITICAL') ?? 0), 0);
  const secretCount = data.repositories.reduce((sum, row) =>
    sum + SEVERITIES.reduce((total, level) => total + (count(row, level, 'secrets') ?? 0), 0), 0);
  for (const [label, value] of [
    ['Configured repositories', data.repositories.length], ['Fresh reports', `${fresh}/${data.repositories.length}`],
    ['Reported critical findings', critical], ['Reported secrets', secretCount],
  ]) {
    const card = element('div', undefined, 'card');
    card.append(element('strong', String(value)), element('span', label));
    totals.append(card);
  }
  byId('updated').textContent = `Collected ${date(data.generatedAt)}. Scan freshness limit: ${data.staleAfterHours} hours. Totals include available older reports.`;
  byId('shown').textContent = `${rows.length} of ${data.repositories.length} repositories shown`;
  const body = byId('rows');
  body.replaceChildren();
  for (const row of rows) {
    const tr = element('tr');
    const repo = element('th');
    repo.scope = 'row';
    repo.append(element('span', row.repository));
    if (row.team) repo.append(element('small', row.team));
    repo.append(element('small', row.branch ?? 'Branch unavailable'));
    const status = effectiveStatus(row, data.staleAfterHours, now);
    const statusCell = element('td');
    statusCell.append(element('span', STATUSES[status], `badge ${status}`));
    statusCell.append(element('small', status === 'stale' ? 'Report older than freshness threshold' : row.message));
    tr.append(repo, statusCell);
    for (const severity of SEVERITIES) tr.append(element('td', String(count(row, severity, options.type) ?? '-')));
    const secrets = row.counts
      ? SEVERITIES.reduce((sum, level) => sum + count(row, level, 'secrets'), 0) : '-';
    tr.append(element('td', String(secrets)), element('td', String(row.detectedTargets ?? '-')),
      element('td', date(row.scannedAt)));
    const linkCell = element('td');
    if (row.runUrl) {
      const expected = `https://github.com/${row.repository}/actions/runs/`;
      if (row.runUrl.startsWith(expected) && /^\d+$/.test(row.runUrl.slice(expected.length))) {
        const link = element('a', 'View run');
        link.href = row.runUrl;
        linkCell.append(link);
      }
    }
    tr.append(linkCell);
    body.append(tr);
  }
}

try {
  const response = await fetch('./data.json', { cache: 'no-store' });
  if (!response.ok) throw new Error(`Data request failed (HTTP ${response.status})`);
  data = await response.json();
  if (data.schemaVersion !== 1 || !Array.isArray(data.repositories) ||
      !Number.isInteger(data.staleAfterHours) || !Number.isFinite(Date.parse(data.generatedAt))) {
    throw new Error('Unsupported dashboard data format');
  }
  render();
  for (const id of ['query', 'status', 'type', 'severity']) byId(id).addEventListener('input', render);
  setInterval(render, 60_000);
} catch (error) {
  byId('updated').textContent = 'Dashboard unavailable. No security status can be inferred.';
  byId('error').hidden = false;
  byId('error').textContent = `Unable to load dashboard: ${error.message}`;
}

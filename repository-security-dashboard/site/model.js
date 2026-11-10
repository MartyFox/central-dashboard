export const TYPES = ['vulnerabilities', 'secrets', 'misconfigurations'];
export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
export const STATUSES = {
  clear: 'No reported findings', findings: 'Findings', limited: 'Limited coverage',
  stale: 'Stale scan', missing: 'Missing results', expired: 'Expired artifact',
  pending: 'Scan pending', failed: 'Workflow failed', error: 'Collection error',
};

export function effectiveStatus(row, staleAfterHours, now = Date.now()) {
  if (['clear', 'findings', 'limited'].includes(row.status) &&
      now - Date.parse(row.scannedAt) > staleAfterHours * 3600_000) return 'stale';
  return row.status;
}

export function count(row, severity, type = 'all') {
  if (!row.counts) return null;
  return (type === 'all' ? TYPES : [type])
    .reduce((sum, category) => sum + row.counts[category][severity], 0);
}

export function filterRows(rows, { query = '', status = '', type = 'all', severity = '' } = {},
  staleAfterHours = 192, now = Date.now()) {
  return rows.filter(row => {
    if (!`${row.repository} ${row.team}`.toLowerCase().includes(query.toLowerCase())) return false;
    if (status && effectiveStatus(row, staleAfterHours, now) !== status) return false;
    if (severity) return (count(row, severity, type) ?? 0) > 0;
    if (type !== 'all') return SEVERITIES.some(level => (count(row, level, type) ?? 0) > 0);
    return true;
  });
}

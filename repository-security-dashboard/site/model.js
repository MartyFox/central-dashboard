export const TYPES = ['vulnerabilities', 'secrets', 'misconfigurations', 'applications'];
export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
export const STATUSES = {
  clear: 'No reported findings', findings: 'Findings', limited: 'Limited coverage',
  stale: 'Stale scan', missing: 'Missing results', expired: 'Expired artifact',
  pending: 'Scan pending', failed: 'Workflow failed', error: 'Collection error',
};

export function effectiveStatus(row, staleAfterHours, now = Date.now()) {
  const statuses = [row, ...(row.application ? [row.application] : [])].map(scan =>
    ['clear', 'findings', 'limited'].includes(scan.status) &&
      now - Date.parse(scan.scannedAt) > staleAfterHours * 3600_000 ? 'stale' : scan.status);
  return ['error', 'failed', 'pending', 'missing', 'expired', 'stale', 'limited', 'findings', 'clear']
    .find(status => statuses.includes(status));
}

export function count(row, severity, type = 'all') {
  if (type === 'applications') return row.application?.counts?.[severity] ?? null;
  if (!row.counts) return null;
  const categories = type === 'all' ? TYPES.filter(category => category !== 'applications') : [type];
  const baseline = categories.reduce((sum, category) => sum + row.counts[category][severity], 0);
  if (type !== 'all' || !row.application) return baseline;
  const application = count(row, severity, 'applications');
  return application === null ? null : baseline + application;
}

export function totalCount(rows, severity, type = 'all') {
  const counts = rows.map(row => count(row, severity, type));
  return counts.some(value => value === null) ? null : counts.reduce((sum, value) => sum + value, 0);
}

export function highestSeverity(row) {
  return SEVERITIES.find(severity =>
    TYPES.some(type => (count(row, severity, type) ?? 0) > 0)) ?? null;
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

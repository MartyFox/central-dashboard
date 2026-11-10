import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Generate active root workflows from component templates without hand-editing paths.
const root = fileURLToPath(new URL('.', import.meta.url));
const mode = process.argv[2] ?? 'shared';
if (!['shared', 'baseline', 'dashboard'].includes(mode)) {
  throw new Error('Usage: node prepare-workflows.mjs shared|baseline|dashboard [output-directory]');
}
const output = resolve(process.argv[3] ?? (mode === 'shared' ? root : `${root}/repository-security-${mode}`));
const destination = resolve(output, '.github/workflows');
await mkdir(destination, { recursive: true });
const files = [
  ...(mode !== 'dashboard' ? ['security-baseline.yml', 'publish-results.yml', 'upload-code-scanning.yml', 'codeql.yml'] : []),
  ...(mode !== 'baseline' ? ['dashboard.yml', 'test.yml'] : []),
];
for (const file of files) {
  const component = ['dashboard.yml', 'test.yml'].includes(file) ? 'dashboard' : 'baseline';
  let template = await readFile(`${root}/repository-security-${component}/.github/workflows/${file}`, 'utf8');
  if (mode === 'shared' && component === 'dashboard') {
    template = template.replace('working-directory: .', 'working-directory: repository-security-dashboard')
      .replaceAll('path: dist/', 'path: repository-security-dashboard/dist/');
    if (file === 'test.yml') {
      template += '      - name: Test baseline workflow contracts and packaging\n        run: node --test ../repository-security-baseline/tests/*.test.mjs ../tests/*.test.mjs\n';
    }
  }
  const target = resolve(destination, file);
  let existing;
  try { existing = await readFile(target, 'utf8'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (existing !== undefined && existing !== template) {
    throw new Error(`Refusing to overwrite modified workflow: ${target}. Review and remove it explicitly before regenerating.`);
  }
  await writeFile(target, template);
  console.log(`Prepared ${target}`);
}

import fs from 'node:fs';
import path from 'node:path';

const rootDir = path.resolve(new URL('..', import.meta.url).pathname);
const packageLockPath = path.join(rootDir, 'package-lock.json');
const generatedDir = path.join(rootDir, 'src', 'generated');
const generatedFilePath = path.join(generatedDir, 'licenses.ts');

const packageLock = JSON.parse(fs.readFileSync(packageLockPath, 'utf8'));
const packages = packageLock.packages || {};

const entries = [];

for (const packagePath of Object.keys(packages)) {
  if (!packagePath || !packagePath.startsWith('node_modules/')) {
    continue;
  }

  const absolutePackageDir = path.join(rootDir, packagePath);
  const packageJsonPath = path.join(absolutePackageDir, 'package.json');
  if (!fs.existsSync(packageJsonPath)) {
    continue;
  }

  const manifest = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  const repositoryValue = typeof manifest.repository === 'string'
    ? manifest.repository
    : manifest.repository?.url;
  const homepageValue = typeof manifest.homepage === 'string' ? manifest.homepage : undefined;
  const licenseValue = typeof manifest.license === 'string'
    ? manifest.license
    : manifest.license?.type || 'UNKNOWN';

  entries.push({
    name: manifest.name || packagePath.replace(/^node_modules\//, ''),
    version: manifest.version || '0.0.0',
    license: licenseValue,
    repository: repositoryValue,
    homepage: homepageValue,
  });
}

entries.sort((left, right) => {
  if (left.name !== right.name) {
    return left.name.localeCompare(right.name);
  }
  return left.version.localeCompare(right.version);
});

fs.mkdirSync(generatedDir, { recursive: true });
fs.writeFileSync(
  generatedFilePath,
  [
    'export interface ThirdPartyLicense {',
    '  name: string;',
    '  version: string;',
    '  license: string;',
    '  repository?: string;',
    '  homepage?: string;',
    '}',
    '',
    `export const THIRD_PARTY_LICENSES: ThirdPartyLicense[] = ${JSON.stringify(entries, null, 2)};`,
    '',
  ].join('\n'),
);

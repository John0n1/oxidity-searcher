import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, '..');
const distDir = path.resolve(projectRoot, 'dist');
const downloadsDir = path.resolve(projectRoot, '..', '..', 'artifacts', 'downloads');
const zipPath = path.resolve(downloadsDir, 'oxidity-wallet-extension.zip');
const packageJson = JSON.parse(readFileSync(path.resolve(projectRoot, 'package.json'), 'utf8'));

mkdirSync(downloadsDir, { recursive: true });

if (!existsSync(path.resolve(distDir, 'home.html')) && existsSync(path.resolve(distDir, 'index.html'))) {
  writeFileSync(
    path.resolve(distDir, 'home.html'),
    readFileSync(path.resolve(distDir, 'index.html')),
  );
}

writeFileSync(
  path.resolve(distDir, 'manifest.json'),
  JSON.stringify(
    {
      manifest_version: 3,
      name: 'Oxidity Wallet',
      version: packageJson.version || '1.0.0',
      description: 'Oxidity Wallet for Chrome.',
      action: {
        default_title: 'Oxidity Wallet',
        default_popup: 'home.html',
      },
      permissions: ['storage'],
      host_permissions: [
        'http://127.0.0.1:9555/*',
        'https://wallet.oxidity.io/*',
        'https://oxidity.io/*',
      ],
      web_accessible_resources: [
        {
          resources: ['assets/*'],
          matches: ['<all_urls>'],
        },
      ],
    },
    null,
    2,
  ),
);

rmSync(zipPath, { force: true });
execFileSync('zip', ['-rq', zipPath, '.'], { cwd: distDir, stdio: 'inherit' });

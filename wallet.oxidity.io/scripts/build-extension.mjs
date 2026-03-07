import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const baseDir = join(root, 'dist-extension-base');
const outputDir = join(root, 'dist-extension');
const packageJson = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

if (!existsSync(baseDir)) {
  throw new Error('dist-extension-base does not exist. Run the Vite extension build first.');
}

rmSync(outputDir, { recursive: true, force: true });
mkdirSync(outputDir, { recursive: true });
cpSync(baseDir, outputDir, { recursive: true });

const manifest = {
  manifest_version: 3,
  name: 'Oxidity Wallet',
  short_name: 'Oxidity',
  version: packageJson.version,
  description:
    'Self-custody Ethereum wallet with private-ready execution and Oxidity business onboarding hooks.',
  action: {
    default_title: 'Oxidity Wallet',
    default_popup: 'index.html',
  },
  icons: {
    128: 'favicon.png',
  },
  permissions: ['storage'],
  host_permissions: ['https://wallet.oxidity.io/*', 'https://oxidity.io/*'],
  content_security_policy: {
    extension_pages: "script-src 'self'; object-src 'self'",
  },
};

writeFileSync(join(outputDir, 'manifest.json'), JSON.stringify(manifest, null, 2));

const zipFile = join(root, 'public', 'downloads', 'oxidity-wallet-extension.zip');
mkdirSync(join(root, 'public', 'downloads'), { recursive: true });

try {
  execFileSync('zip', ['-qr', zipFile, '.'], { cwd: outputDir, stdio: 'ignore' });
  console.log(`Created ${zipFile}`);
} catch {
  console.warn('zip command unavailable; extension ZIP not generated');
}

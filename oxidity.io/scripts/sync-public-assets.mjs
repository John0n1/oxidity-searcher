import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(__dirname, '..');
const publicDir = path.join(appRoot, 'public');
const canonicalKeyPath = path.join(publicDir, 'pgp.asc');
const mirroredKeyPaths = [
  path.join(publicDir, 'publickey.asc'),
  path.join(publicDir, '.well-known', 'publickey.asc'),
];

async function main() {
  const canonicalKey = await readFile(canonicalKeyPath, 'utf8');

  for (const outputPath of mirroredKeyPaths) {
    await mkdir(path.dirname(outputPath), { recursive: true });
    await writeFile(outputPath, canonicalKey);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

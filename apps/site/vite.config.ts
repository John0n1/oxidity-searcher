import fs from 'fs';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

const walletPackageJson = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, '../wallet/package.json'), 'utf8'),
) as { version?: string };

export default defineConfig(() => {
  return {
    define: {
      __OXIDITY_WALLET_VERSION__: JSON.stringify(walletPackageJson.version || '0.0.0'),
    },
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      hmr: process.env.DISABLE_HMR !== 'true',
    },
  };
});

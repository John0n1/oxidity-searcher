import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { defineConfig } from 'vite';

export default defineConfig(({ mode }) => {
  const isExtension = mode === 'extension';

  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },
    base: isExtension ? './' : '/',
    build: {
      outDir: isExtension ? 'dist-extension-base' : 'dist',
      sourcemap: true,
    },
    server: {
      host: '0.0.0.0',
      port: isExtension ? 3002 : 3001,
    },
  };
});

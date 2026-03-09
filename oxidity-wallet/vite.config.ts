import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { defineConfig } from 'vite';

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    build: {
      rollupOptions: {
        input: {
          index: path.resolve(__dirname, 'index.html'),
          home: path.resolve(__dirname, 'home.html'),
        },
        output: {
          manualChunks(id) {
            if (id.includes('node_modules/ethers')) {
              return 'vendor-ethers';
            }
            if (id.includes('node_modules/motion') || id.includes('node_modules/lucide-react')) {
              return 'vendor-motion';
            }
            if (
              id.includes('node_modules/@capacitor')
              || id.includes('node_modules/@aparajita')
            ) {
              return 'vendor-native';
            }
            if (id.includes('node_modules/react-markdown')) {
              return 'vendor-markdown';
            }
            if (id.includes('node_modules/react') || id.includes('node_modules/zustand')) {
              return 'vendor-react';
            }
          },
        },
      },
    },
    server: {
      hmr: process.env.DISABLE_HMR !== 'true',
    },
  };
});

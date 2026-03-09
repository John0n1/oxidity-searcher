import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'io.oxidity.wallet',
  appName: 'Oxidity Wallet',
  webDir: 'dist',
  server: {
    androidScheme: 'https',
  },
};

export default config;

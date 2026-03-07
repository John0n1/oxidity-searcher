import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'io.oxidity.wallet',
  appName: 'Oxidity Wallet',
  webDir: 'dist',
  android: {
    path: 'android',
  },
};

export default config;

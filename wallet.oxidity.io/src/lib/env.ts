const normalize = (value: string | undefined, fallback: string) => {
  const trimmed = value?.trim();
  return trimmed && trimmed.length > 0 ? trimmed : fallback;
};

export const walletEnv = {
  apiBase: normalize(import.meta.env.VITE_WALLET_API_BASE, '/api'),
  supportEmail: normalize(import.meta.env.VITE_WALLET_SUPPORT_EMAIL, 'support@oxidity.io'),
  downloadExtensionUrl: normalize(
    import.meta.env.VITE_WALLET_DOWNLOAD_EXTENSION_URL,
    'https://wallet.oxidity.io/downloads/oxidity-wallet-extension.zip'
  ),
  downloadAndroidUrl: normalize(
    import.meta.env.VITE_WALLET_DOWNLOAD_ANDROID_URL,
    'https://wallet.oxidity.io/downloads/oxidity-wallet-debug.apk'
  ),
  businessUrl: 'https://oxidity.io/partners?requested=wallet',
  docsUrl: 'https://oxidity.io/developers',
  statusUrl: 'https://oxidity.io/status',
};

export type RuntimeTarget = 'web' | 'extension' | 'android';

declare global {
  interface Window {
    Capacitor?: {
      getPlatform?: () => string;
      isNativePlatform?: () => boolean;
    };
  }
}

export function getRuntimeTarget(): RuntimeTarget {
  if (typeof chrome !== 'undefined' && chrome?.runtime?.id) {
    return 'extension';
  }

  const platform = window.Capacitor?.getPlatform?.();
  if (platform === 'android') {
    return 'android';
  }

  return 'web';
}

export function isNativeLikeRuntime(): boolean {
  return getRuntimeTarget() !== 'web';
}

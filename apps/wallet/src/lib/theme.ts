export type ThemeMode = 'dark' | 'midnight';

const THEME_STORAGE_KEY = 'oxidity.theme.mode';

export function readThemeMode(): ThemeMode {
  if (typeof window === 'undefined') {
    return 'dark';
  }

  return window.localStorage.getItem(THEME_STORAGE_KEY) === 'midnight' ? 'midnight' : 'dark';
}

export function applyThemeMode(mode: ThemeMode): void {
  if (typeof document !== 'undefined') {
    document.documentElement.dataset.oxidityTheme = mode;
  }

  if (typeof window !== 'undefined') {
    window.localStorage.setItem(THEME_STORAGE_KEY, mode);
  }
}

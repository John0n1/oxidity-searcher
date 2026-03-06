function normalizeZero(value: number): number {
  return Math.abs(value) < 1e-9 ? 0 : value;
}

export function formatUsd(value: number, maximumFractionDigits = 2): string {
  const safeValue = normalizeZero(value);
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    maximumFractionDigits,
  }).format(safeValue);
}

export function formatCompactNumber(value: number): string {
  return new Intl.NumberFormat('en-US', {
    notation: 'compact',
    maximumFractionDigits: 2,
  }).format(value);
}

export function formatEth(value: number, maximumFractionDigits = 3): string {
  const safeValue = normalizeZero(value);
  return `${new Intl.NumberFormat('en-US', {
    minimumFractionDigits: 0,
    maximumFractionDigits,
  }).format(safeValue)} ETH`;
}

export function shortHash(hash: string): string {
  if (hash.length <= 14) return hash;
  return `${hash.slice(0, 10)}...${hash.slice(-4)}`;
}

export function formatRelativeTime(isoTime: string): string {
  const date = new Date(isoTime);
  const now = Date.now();
  const seconds = Math.max(1, Math.floor((now - date.getTime()) / 1000));

  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

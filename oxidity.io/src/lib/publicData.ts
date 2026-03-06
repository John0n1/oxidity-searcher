import type { PublicData, PublicDataResult } from './types';

const apiBase = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

export const APP_CONFIG = {
  rpcUrl: import.meta.env.VITE_PUBLIC_RPC_URL || 'https://rpc.oxidity.io',
  apiBaseUrl: apiBase,
  supportEmail: import.meta.env.VITE_SUPPORT_EMAIL || 'ops@oxidity.io',
  bookingUrl: import.meta.env.VITE_BOOKING_URL || '',
};

function normalize(data: PublicData): PublicData {
  return {
    ...data,
    generatedAt: data.generatedAt || new Date().toISOString(),
    activity: [...(data.activity || [])],
    transactions: [...(data.transactions || [])],
    services: [...(data.services || [])],
    incidents: [...(data.incidents || [])],
    policy: {
      retainedBps: data.policy?.retainedBps ?? 1000,
      perTxGasCapEth: data.policy?.perTxGasCapEth ?? 0.05,
      perDayGasCapEth: data.policy?.perDayGasCapEth ?? 0.5,
    },
  };
}

function looksValidData(value: unknown): value is PublicData {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const maybe = value as Partial<PublicData>;
  return Boolean(maybe.stats && Array.isArray(maybe.activity) && Array.isArray(maybe.transactions));
}

function endpointCandidates(): string[] {
  const candidates = [apiBase ? `${apiBase}/api/public/summary` : '', '/api/public/summary'].filter(Boolean);
  return Array.from(new Set(candidates));
}

function partnerEndpointCandidates(): string[] {
  const candidates = [apiBase ? `${apiBase}/api/partner/summary` : '', '/api/partner/summary'].filter(Boolean);
  return Array.from(new Set(candidates));
}

async function fetchWithTimeout(
  url: string,
  timeoutMs: number,
  externalSignal?: AbortSignal,
  init?: RequestInit,
): Promise<Response> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);

  if (externalSignal) {
    externalSignal.addEventListener('abort', () => controller.abort(), { once: true });
  }

  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    window.clearTimeout(timer);
  }
}

function emptyTemplate(): PublicData {
  return {
    generatedAt: new Date().toISOString(),
    stats: {
      sponsoredTxCount: 0,
      gasRefundedEth: 0,
      mevReturnedUsd: 0,
      avgInclusionSeconds: 0,
    },
    activity: [],
    transactions: [],
    services: [
      {
        name: 'Pipeline Health',
        status: 'degraded',
        uptimePct: 0,
        latencyMs: 0,
      },
      {
        name: 'Bundle Submission',
        status: 'degraded',
        uptimePct: 0,
        latencyMs: 0,
      },
      {
        name: 'Risk Filtering',
        status: 'degraded',
        uptimePct: 0,
        latencyMs: 0,
      },
    ],
    incidents: [],
    policy: {
      retainedBps: 1000,
      perTxGasCapEth: 0.05,
      perDayGasCapEth: 0.5,
    },
  };
}

function isSparsePublicData(data: PublicData): boolean {
  const serviceSignal = data.services.some((service) => service.uptimePct > 0 || service.latencyMs > 0);
  const flowSignal =
    data.activity.length > 0 ||
    data.transactions.length > 0 ||
    data.stats.sponsoredTxCount > 0 ||
    Math.abs(data.stats.gasRefundedEth) > 0.000001 ||
    Math.abs(data.stats.mevReturnedUsd) > 0.01;

  return !serviceSignal && !flowSignal;
}

export async function loadPublicData(externalSignal?: AbortSignal): Promise<PublicDataResult> {
  const candidates = endpointCandidates();
  if (candidates.length === 0) {
    throw new Error('No public summary endpoint configured');
  }
  let lastError = '';

  for (const endpoint of candidates) {
    try {
      const response = await fetchWithTimeout(endpoint, 2500, externalSignal);
      if (!response.ok) {
        lastError = `HTTP ${response.status} at ${endpoint}`;
        continue;
      }

      const payload = await response.json();
      if (!looksValidData(payload)) {
        lastError = `Invalid payload shape at ${endpoint}`;
        continue;
      }

      const data = normalize(payload);
      if (isSparsePublicData(data)) {
        return {
          source: 'degraded',
          endpoint,
          data,
          error: 'Live telemetry is available but currently empty or degraded.',
        };
      }

      return {
        source: 'live',
        endpoint,
        data,
      };
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        throw error;
      }

      lastError = `${endpoint}: ${error instanceof Error ? error.message : String(error)}`;
    }
  }

  return {
    source: 'degraded',
    endpoint: candidates[0],
    data: emptyTemplate(),
    error: lastError || 'No public endpoint responded',
  };
}

export async function loadPartnerData(
  accessToken: string,
  externalSignal?: AbortSignal,
): Promise<PublicDataResult> {
  const token = accessToken.trim();
  if (!token) {
    throw new Error('Missing partner access token');
  }

  const candidates = partnerEndpointCandidates();
  if (candidates.length === 0) {
    throw new Error('No partner summary endpoint configured');
  }
  let lastError = '';

  for (const endpoint of candidates) {
    try {
      const response = await fetchWithTimeout(endpoint, 2500, externalSignal, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      if (!response.ok) {
        if (response.status === 401) {
          throw new Error('Unauthorized: invalid partner access token');
        }
        lastError = `HTTP ${response.status} at ${endpoint}`;
        continue;
      }

      const payload = await response.json();
      if (!looksValidData(payload)) {
        lastError = `Invalid payload shape at ${endpoint}`;
        continue;
      }

      return {
        source: 'live',
        endpoint,
        data: normalize(payload),
      };
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        throw error;
      }

      lastError = `${endpoint}: ${error instanceof Error ? error.message : String(error)}`;
    }
  }

  throw new Error(lastError || 'No partner endpoint responded');
}

export function calculateSplit(expectedMevUsd: number, gasCostUsd: number, retainedBps: number) {
  const gross = Math.max(0, expectedMevUsd);
  const gas = Math.max(0, gasCostUsd);
  const netBeforeRetained = Math.max(0, gross - gas);
  const retained = netBeforeRetained * (retainedBps / 10_000);
  const rebate = Math.max(0, netBeforeRetained - retained);

  return {
    gross,
    gas,
    netBeforeRetained,
    retained,
    rebate,
    sponsored: netBeforeRetained > 0,
  };
}

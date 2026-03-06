import { APP_CONFIG } from './publicData';

export interface OnboardingSubmissionInput {
  name: string;
  email: string;
  organization: string;
  teamType: string;
  volumeBand: string;
  journeyStage: string;
  timeline: string;
  requestedTrack: string;
  primaryNeed: string;
  recommendedPath: string;
  notes: string;
  sourcePage?: string;
  intakePacket: string;
}

export interface OnboardingSubmissionResult {
  status: 'ok';
  requestId: number;
  createdAt: string;
  message: string;
}

function endpointCandidates(): string[] {
  const base = APP_CONFIG.apiBaseUrl.replace(/\/$/, '');
  const candidates = [base ? `${base}/api/onboarding/request` : '', '/api/onboarding/request'].filter(Boolean);
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

export async function submitOnboardingRequest(
  payload: OnboardingSubmissionInput,
  externalSignal?: AbortSignal,
): Promise<OnboardingSubmissionResult> {
  const candidates = endpointCandidates();
  let lastError = 'No onboarding endpoint responded';

  for (const endpoint of candidates) {
    try {
      const response = await fetchWithTimeout(endpoint, 5000, externalSignal, {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const isJson = response.headers.get('content-type')?.includes('application/json') ?? false;
      const responseBody = isJson ? await response.json().catch(() => null) : null;

      if (!response.ok) {
        const message =
          responseBody && typeof responseBody.message === 'string'
            ? responseBody.message
            : responseBody && typeof responseBody.error === 'string'
              ? responseBody.error
              : `HTTP ${response.status}`;
        lastError = `${endpoint}: ${message}`;
        continue;
      }

      if (!responseBody || typeof responseBody.requestId !== 'number' || typeof responseBody.createdAt !== 'string') {
        lastError = `${endpoint}: invalid response payload`;
        continue;
      }

      return responseBody as OnboardingSubmissionResult;
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        throw error;
      }
      lastError = `${endpoint}: ${error instanceof Error ? error.message : String(error)}`;
    }
  }

  throw new Error(lastError);
}

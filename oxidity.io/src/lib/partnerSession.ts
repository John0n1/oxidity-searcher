export interface PartnerSession {
  email: string;
  accessToken: string;
  accountType: 'Partner';
  expiresAt: string;
}

const STORAGE_KEY = 'mitander.partner.session.v1';

export function readPartnerSession(): PartnerSession | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as PartnerSession;
    if (
      !parsed ||
      typeof parsed.email !== 'string' ||
      typeof parsed.accessToken !== 'string' ||
      parsed.accountType !== 'Partner' ||
      typeof parsed.expiresAt !== 'string'
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function savePartnerSession(session: PartnerSession) {
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
}

export function clearPartnerSession() {
  window.localStorage.removeItem(STORAGE_KEY);
}

export function isPartnerSessionExpired(session: PartnerSession): boolean {
  const expires = Date.parse(session.expiresAt);
  if (!Number.isFinite(expires)) {
    return true;
  }
  return Date.now() >= expires;
}

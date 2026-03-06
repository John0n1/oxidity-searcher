import { useCallback, useEffect, useRef, useState } from 'react';
import { loadPartnerData } from '../lib/publicData';
import type { PublicDataResult } from '../lib/types';

const DEFAULT_POLL_MS = 20_000;

export function usePartnerData(accessToken: string | null, pollMs = DEFAULT_POLL_MS) {
  const [result, setResult] = useState<PublicDataResult | null>(null);
  const [loading, setLoading] = useState(Boolean(accessToken));
  const [error, setError] = useState<string | null>(null);
  const inFlightRef = useRef(false);

  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      if (!accessToken || inFlightRef.current) {
        return;
      }

      inFlightRef.current = true;
      try {
        const next = await loadPartnerData(accessToken, signal);
        setResult(next);
        setError(next.error ?? null);
        setLoading(false);
      } catch (err) {
        if (err instanceof DOMException && err.name === 'AbortError') {
          return;
        }

        setError(err instanceof Error ? err.message : String(err));
        setLoading(false);
      } finally {
        inFlightRef.current = false;
      }
    },
    [accessToken],
  );

  useEffect(() => {
    if (!accessToken) {
      setResult(null);
      setError(null);
      setLoading(false);
      return;
    }

    const aborter = new AbortController();
    setLoading(true);
    void refresh(aborter.signal);

    const timer = window.setInterval(() => {
      void refresh(aborter.signal);
    }, pollMs);

    return () => {
      aborter.abort();
      window.clearInterval(timer);
    };
  }, [accessToken, pollMs, refresh]);

  return {
    result,
    loading,
    error,
    refresh,
  };
}

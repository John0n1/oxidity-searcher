import { useCallback, useEffect, useRef, useState } from 'react';
import { loadPublicData } from '../lib/publicData';
import type { PublicDataResult } from '../lib/types';

const DEFAULT_POLL_MS = 20_000;

export function usePublicData(pollMs = DEFAULT_POLL_MS) {
  const [result, setResult] = useState<PublicDataResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const inFlightRef = useRef(false);

  const refresh = useCallback(async (signal?: AbortSignal) => {
    if (inFlightRef.current) {
      return;
    }

    inFlightRef.current = true;
    try {
      const next = await loadPublicData(signal);
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
  }, []);

  useEffect(() => {
    const aborter = new AbortController();
    void refresh(aborter.signal);

    const timer = window.setInterval(() => {
      void refresh(aborter.signal);
    }, pollMs);

    return () => {
      aborter.abort();
      window.clearInterval(timer);
    };
  }, [pollMs, refresh]);

  return {
    result,
    loading,
    error,
    refresh,
  };
}

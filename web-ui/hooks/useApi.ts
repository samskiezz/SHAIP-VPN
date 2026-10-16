import { useCallback, useState } from 'react';
import { getToken } from '@/lib/api';

export interface ApiState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
}

/** Fetch helper that attaches the stored bearer token and tracks state. */
export function useApi<T>() {
  const [state, setState] = useState<ApiState<T>>({ data: null, loading: false, error: null });

  const call = useCallback(async (input: RequestInfo, init?: RequestInit): Promise<T | null> => {
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const tok = getToken();
      const resp = await fetch(input, {
        ...init,
        headers: {
          'Content-Type': 'application/json',
          ...(tok ? { Authorization: `Bearer ${tok}` } : {}),
          ...(init?.headers ?? {}),
        },
      });
      if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}`);
      const data = (await resp.json()) as T;
      setState({ data, loading: false, error: null });
      return data;
    } catch (e) {
      setState({ data: null, loading: false, error: e instanceof Error ? e.message : 'error' });
      return null;
    }
  }, []);

  return { ...state, call };
}

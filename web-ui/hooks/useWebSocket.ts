import { useEffect, useRef, useState } from 'react';

/** Auto-reconnecting WebSocket with exponential backoff. */
export function useWebSocket<T>(url: string) {
  const [data, setData] = useState<T | null>(null);
  const [status, setStatus] = useState<'connecting' | 'open' | 'closed'>('connecting');
  const ref = useRef<WebSocket | null>(null);

  useEffect(() => {
    let alive = true;
    let backoff = 500;
    const connect = () => {
      const ws = new WebSocket(url);
      ref.current = ws;
      setStatus('connecting');
      ws.onopen = () => {
        backoff = 500;
        setStatus('open');
      };
      ws.onmessage = (e) => {
        try {
          setData(JSON.parse(e.data) as T);
        } catch {
          /* ignore malformed frames */
        }
      };
      ws.onclose = () => {
        setStatus('closed');
        if (!alive) return;
        setTimeout(connect, backoff);
        backoff = Math.min(backoff * 2, 10000);
      };
    };
    connect();
    return () => {
      alive = false;
      ref.current?.close();
    };
  }, [url]);

  return { data, status };
}

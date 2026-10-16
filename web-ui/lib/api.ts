// Thin client for the PQANON-CP/1 control plane.

export const API_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

// The session token lives in sessionStorage: it is gone when the tab closes,
// so a shared or borrowed computer doesn't stay signed in to the account.

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.sessionStorage.getItem("token");
}

export function setToken(token: string) {
  window.sessionStorage.setItem("token", token);
}

export function clearToken() {
  window.sessionStorage.removeItem("token");
}

/** Group a 16-digit account number in fours, as it is shown. */
export function formatAccount(n: string): string {
  return n.replace(/\D/g, "").replace(/(\d{4})(?=\d)/g, "$1 ");
}

type Options = {
  method?: string;
  body?: unknown;
  auth?: boolean;
};

export async function api<T>(path: string, opts: Options = {}): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (opts.auth !== false) {
    const tok = getToken();
    if (tok) headers.Authorization = `Bearer ${tok}`;
  }
  const res = await fetch(`${API_URL}${path}`, {
    method: opts.method ?? "GET",
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (!res.ok) {
    let message = res.statusText;
    try {
      const data = await res.json();
      if (data?.error) message = data.error;
    } catch {
      /* ignore */
    }
    throw new Error(message);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

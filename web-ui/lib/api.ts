// Thin client for the PQANON-CP/1 control plane.
import { apiRequestURL } from "./transport";

export const API_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

// The hosted preview (web-ui/preview) runs the control plane itself in the
// page, compiled to WebAssembly, and installs window.pqanonAPI; requests then
// go to it instead of the network.
type InPageAPI = (
  method: string,
  path: string,
  authorization: string,
  body: string,
) => Promise<{ status: number; body: string }>;

function inPageAPI(): InPageAPI | null {
  if (typeof window === "undefined") return null;
  const f = (window as unknown as { pqanonAPI?: InPageAPI }).pqanonAPI;
  return typeof f === "function" ? f : null;
}

// The session token lives in sessionStorage: it is gone when the tab closes,
// so a shared or borrowed computer doesn't stay signed in to the account. In
// the preview, whose accounts last only as long as the page, it stays in
// memory; so it does wherever storage is blocked.
let memoryToken: string | null = null;

function storage(): Storage | null {
  if (typeof window === "undefined" || inPageAPI()) return null;
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

export function getToken(): string | null {
  try {
    return storage()?.getItem("token") ?? memoryToken;
  } catch {
    return memoryToken;
  }
}

export function setToken(token: string) {
  memoryToken = token;
  try {
    storage()?.setItem("token", token);
  } catch {
    /* kept in memory */
  }
}

export function clearToken() {
  memoryToken = null;
  try {
    storage()?.removeItem("token");
  } catch {
    /* nothing stored */
  }
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
  const method = opts.method ?? "GET";
  const body = opts.body ? JSON.stringify(opts.body) : undefined;

  let status: number;
  let text: string;
  const local = inPageAPI();
  if (local) {
    const r = await local(method, path, headers.Authorization ?? "", body ?? "");
    status = r.status;
    text = r.body;
  } else {
    const url = apiRequestURL(API_URL, path,
      typeof window === "undefined" ? undefined : window.location.href);
    const res = await fetch(url, {
      method, headers, body,
      redirect: "error", // never forward a password/body to a redirected origin
      referrerPolicy: "no-referrer",
      cache: "no-store",
      credentials: "omit", // bearer auth only; no ambient tracking cookies
    });
    status = res.status;
    text = await res.text();
  }

  if (status < 200 || status >= 300) {
    let message = `request failed (${status})`;
    try {
      const data = JSON.parse(text);
      if (data?.error) message = data.error;
    } catch {
      /* not JSON */
    }
    throw new Error(message);
  }
  if (status === 204 || text === "") return undefined as T;
  return JSON.parse(text) as T;
}

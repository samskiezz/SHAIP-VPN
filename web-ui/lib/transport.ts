/** Refuse remote cleartext before constructing a credential-bearing request. */
export function apiRequestURL(base: string, path: string, pageURL?: string): string {
  if (!path.startsWith("/api/") || /[\\\r\n#]/.test(path)) {
    throw new Error("Invalid control-plane request path.");
  }
  let endpoint: URL;
  try {
    endpoint = new URL(base || "/", pageURL);
  } catch {
    throw new Error("Configure an HTTPS control-plane URL.");
  }
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw new Error("Control-plane URLs cannot contain credentials, queries or fragments.");
  }
  const loopback = (host: string) => ["localhost", "127.0.0.1", "[::1]"].includes(host);
  const localPage = pageURL ? loopback(new URL(pageURL).hostname) : false;
  if (endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" && loopback(endpoint.hostname) && localPage)) {
    throw new Error("Remote account requests require HTTPS. Cleartext is restricted to local development.");
  }
  return endpoint.href.replace(/\/$/, "") + path;
}

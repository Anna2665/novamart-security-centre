/** Address of the API server. Empty = same origin (the normal `python run.py` setup). Set VITE_API_URL at build time when the pages are hosted separately (e.g. Netlify + Render). */
export const API_BASE: string = (((import.meta as any).env?.VITE_API_URL as string | undefined) ?? "").trim().replace(/\/+$/, "");

let token: string | null = null;
try { token = sessionStorage.getItem("cg_token"); } catch { /* storage unavailable */ }

export class ApiError extends Error {
  status: number;
  body: any;
  constructor(status: number, body: any) {
    super(typeof body?.detail === "string" ? body.detail : `Request failed (${status})`);
    this.status = status;
    this.body = body;
  }
}

export const getToken = () => token;
export function setToken(t: string | null) {
  token = t;
  try { t ? sessionStorage.setItem("cg_token", t) : sessionStorage.removeItem("cg_token"); } catch { /* ignore */ }
}

let onUnauthorized: () => void = () => {};
export const setUnauthorizedHandler = (fn: () => void) => { onUnauthorized = fn; };

export async function api<T = any>(path: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api${path}`, { method: opts.method ?? (opts.body !== undefined ? "POST" : "GET"), headers, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined });
  } catch {
    throw new ApiError(0, { detail: "Cannot reach the NovaMart server. Is the backend running?" });
  }
  let data: any = null;
  try { data = await res.json(); } catch { /* empty */ }
  if (!res.ok) {
    if (res.status === 401 && token && !path.startsWith("/auth/")) onUnauthorized();
    const detail = Array.isArray(data?.detail) ? data.detail.map((d: any) => d.msg).join("; ") : data?.detail;
    throw new ApiError(res.status, { ...(data ?? {}), detail });
  }
  return data as T;
}

export const get = <T = any>(p: string) => api<T>(p);
export const post = <T = any>(p: string, body: unknown = {}) => api<T>(p, { method: "POST", body });
export const put = <T = any>(p: string, body: unknown = {}) => api<T>(p, { method: "PUT", body });

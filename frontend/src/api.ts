export type Row = Record<string, any>;

let token: string | null = null;
try { token = sessionStorage.getItem("v3token"); } catch { /* storage unavailable */ }
export const setToken = (t: string | null) => {
  token = t;
  try { t ? sessionStorage.setItem("v3token", t) : sessionStorage.removeItem("v3token"); } catch { /* ignore */ }
};
export const hasToken = () => !!token;
let onUnauthorized: () => void = () => {};
export const setUnauthorizedHandler = (f: () => void) => { onUnauthorized = f; };

export class ApiError extends Error { constructor(public status: number, msg: string) { super(msg); } }

async function raw(method: string, path: string, body?: unknown): Promise<Response> {
  const r = await fetch(path, {
    method,
    headers: { ...(body !== undefined ? { "Content-Type": "application/json" } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (r.status === 401 && token && !path.includes("/auth/login")) onUnauthorized();
  return r;
}

async function req<T = any>(method: string, path: string, body?: unknown): Promise<T> {
  const r = await raw(method, path, body);
  if (!r.ok) {
    let msg = r.statusText;
    try { const j = await r.json(); msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch { /* not json */ }
    throw new ApiError(r.status, msg);
  }
  return r.json();
}

export const api = {
  get: <T = any>(p: string) => req<T>("GET", p),
  post: <T = any>(p: string, b?: unknown) => req<T>("POST", p, b ?? {}),
  put: <T = any>(p: string, b?: unknown) => req<T>("PUT", p, b ?? {}),
  patch: <T = any>(p: string, b?: unknown) => req<T>("PATCH", p, b ?? {}),
  del: <T = any>(p: string) => req<T>("DELETE", p),
  async download(path: string, filename: string) {
    const r = await raw("GET", path);
    if (!r.ok) throw new ApiError(r.status, "download failed");
    const url = URL.createObjectURL(await r.blob());
    const a = document.createElement("a"); a.href = url; a.download = filename; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  },
};
export const qs = (o: Record<string, unknown>) => {
  const p = new URLSearchParams();
  Object.entries(o).forEach(([k, v]) => { if (v !== undefined && v !== "" && v !== null) p.set(k, String(v)); });
  const s = p.toString();
  return s ? `?${s}` : "";
};

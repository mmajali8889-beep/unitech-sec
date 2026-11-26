import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { api, hasToken, Row, setToken, setUnauthorizedHandler } from "./api";
import { Locale, translate } from "./i18n";

type Toast = { id: number; kind: "ok" | "err"; msg: string };
interface Ctx {
  user: Row | null; setUser: (u: Row | null) => void; locale: Locale; setLocale: (l: Locale) => void; theme: "dark" | "light"; toggleTheme: () => void;
  t: (k: string) => string; can: (p: string) => boolean; toast: (msg: string, kind?: "ok" | "err") => void; toasts: Toast[]; booting: boolean; logout: () => void;
}
const C = createContext<Ctx>(null as unknown as Ctx);
export const useApp = () => useContext(C);

const safeGet = (k: string) => { try { return localStorage.getItem(k); } catch { return null; } };
const safeSet = (k: string, v: string) => { try { localStorage.setItem(k, v); } catch { /* ignore */ } };

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<Row | null>(null);
  const [booting, setBooting] = useState(hasToken());
  const [locale, setLoc] = useState<Locale>((safeGet("v3locale") as Locale) || "en");
  const [theme, setTheme] = useState<"dark" | "light">((safeGet("v3theme") as "dark" | "light") || "dark");
  const [toasts, setToasts] = useState<Toast[]>([]);

  useEffect(() => {
    document.documentElement.lang = locale;
    document.documentElement.dir = locale === "ar" ? "rtl" : "ltr";
    safeSet("v3locale", locale);
  }, [locale]);
  useEffect(() => { document.documentElement.classList.toggle("dark", theme === "dark"); safeSet("v3theme", theme); }, [theme]);

  const logout = useCallback(() => { api.post("/api/auth/logout").catch(() => {}); setToken(null); setUser(null); }, []);
  useEffect(() => { setUnauthorizedHandler(() => { setToken(null); setUser(null); }); }, []);
  useEffect(() => {
    if (!hasToken()) return;
    api.get("/api/auth/me").then((u) => { setUser(u); if (u.locale) setLoc(u.locale); }).catch(() => setToken(null)).finally(() => setBooting(false));
  }, []);

  const toast = useCallback((msg: string, kind: "ok" | "err" = "ok") => {
    const id = Date.now() + Math.random();
    setToasts((x) => [...x, { id, kind, msg }]);
    setTimeout(() => setToasts((x) => x.filter((i) => i.id !== id)), 5000);
  }, []);

  const value = useMemo<Ctx>(() => ({
    user, setUser, locale, setLocale: (l) => { setLoc(l); if (user) api.put("/api/auth/preferences", { locale: l }).catch(() => {}); },
    theme, toggleTheme: () => setTheme((x) => (x === "dark" ? "light" : "dark")), t: (k) => translate(locale, k),
    can: (p) => !!user && (user.permissions.includes("*") || user.permissions.includes(p)), toast, toasts, booting, logout,
  }), [user, locale, theme, toasts, booting, toast, logout]);
  return <C.Provider value={value}>{children}</C.Provider>;
}

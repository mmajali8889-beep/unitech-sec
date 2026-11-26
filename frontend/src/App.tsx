import React, { useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { Activity, BarChart3, Bot, CalendarClock, ClipboardList, Container, Cpu, FileSearch, FileText, FolderGit2, HeartPulse, History, KeyRound, LogOut, Menu, Moon, Radar, ScanLine, Settings as Cog, ShieldAlert, Sun, Users as UsersIcon, Bug, Languages } from "lucide-react";
import { api, setToken } from "./api";
import { useApp } from "./ctx";
import { Field, Notice } from "./ui";
import Dashboard from "./pages/Dashboard";
import Projects from "./pages/Projects";
import { FileScanner, ScanCenter } from "./pages/Scan";
import { FindingsView } from "./pages/Findings";
import Beko from "./pages/Beko";
import Live from "./pages/Live";
import HistoryPage from "./pages/History";
import Schedules from "./pages/Schedules";
import Reports from "./pages/Reports";
import { Audit, Engines, Health } from "./pages/Admin";
import { UsersPage, SettingsPage } from "./pages/Users";

function Login() {
  const { t, setUser, setLocale, locale } = useApp();
  const [u, setU] = useState(""); const [p, setP] = useState(""); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true); setErr("");
    try {
      const r = await api.post("/api/auth/login", { username: u, password: p });
      setToken(r.token);
      const me = await api.get("/api/auth/me");
      setUser(me); if (me.locale) setLocale(me.locale);
    } catch (x: any) { setErr(x.message); } finally { setBusy(false); }
  };
  return (
    <main className="flex min-h-screen items-center justify-center p-4">
      <form onSubmit={submit} className="card fade-in w-full max-w-sm space-y-4" aria-labelledby="login-title">
        <div className="flex items-center gap-2"><ShieldAlert className="text-brand-500" /><h1 id="login-title" className="text-lg font-bold">{t("app")}</h1></div>
        {err && <Notice tone="err">{err}</Notice>}
        <Field label={t("username")}><input className="input" autoComplete="username" value={u} onChange={(e) => setU(e.target.value)} required /></Field>
        <Field label={t("password")}><input className="input" type="password" autoComplete="current-password" value={p} onChange={(e) => setP(e.target.value)} required /></Field>
        <button className="btn-primary w-full justify-center" disabled={busy}>{busy ? t("signingIn") : t("login")}</button>
        <button type="button" className="btn-ghost w-full justify-center" onClick={() => setLocale(locale === "en" ? "ar" : "en")}><Languages size={16} />{locale === "en" ? "العربية" : "English"}</button>
      </form>
    </main>
  );
}

function ChangePassword() {
  const { t, setUser, logout } = useApp();
  const [cur, setCur] = useState(""); const [nw, setNw] = useState(""); const [err, setErr] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    try { await api.post("/api/auth/change-password", { current_password: cur, new_password: nw }); setUser(await api.get("/api/auth/me")); } catch (x: any) { setErr(x.message); }
  };
  return (
    <main className="flex min-h-screen items-center justify-center p-4">
      <form onSubmit={submit} className="card w-full max-w-sm space-y-4">
        <Notice tone="warn">{t("mustChange")}</Notice>{err && <Notice tone="err">{err}</Notice>}
        <Field label={t("currentPassword")}><input className="input" type="password" value={cur} onChange={(e) => setCur(e.target.value)} required /></Field>
        <Field label={t("newPassword")}><input className="input" type="password" value={nw} onChange={(e) => setNw(e.target.value)} required /></Field>
        <div className="flex gap-2"><button className="btn-primary">{t("save")}</button><button type="button" className="btn-ghost" onClick={logout}>{t("logout")}</button></div>
      </form>
    </main>
  );
}

const NAV: [string, string, React.ReactNode][] = [
  ["/", "nav.dashboard", <BarChart3 size={18} />], ["/projects", "nav.projects", <FolderGit2 size={18} />], ["/scan", "nav.scan", <Radar size={18} />],
  ["/files", "nav.files", <FileSearch size={18} />], ["/source", "nav.source", <FileText size={18} />], ["/secrets", "nav.secrets", <KeyRound size={18} />],
  ["/deps", "nav.deps", <ClipboardList size={18} />], ["/docker", "nav.docker", <Container size={18} />], ["/vulns", "nav.vulns", <Bug size={18} />],
  ["/beko", "nav.beko", <Bot size={18} />], ["/live", "nav.live", <Activity size={18} />], ["/history", "nav.history", <History size={18} />],
  ["/schedules", "nav.schedules", <CalendarClock size={18} />], ["/reports", "nav.reports", <ScanLine size={18} />], ["/health", "nav.health", <HeartPulse size={18} />],
  ["/engines", "nav.engines", <Cpu size={18} />], ["/audit", "nav.audit", <ShieldAlert size={18} />], ["/users", "nav.users", <UsersIcon size={18} />], ["/settings", "nav.settings", <Cog size={18} />],
];

function Shell() {
  const { t, user, logout, theme, toggleTheme, locale, setLocale, toasts } = useApp();
  const [open, setOpen] = useState(false);
  return (
    <div className="flex min-h-screen">
      <aside className={`fixed inset-y-0 start-0 z-40 w-64 transform overflow-y-auto border-e border-slate-200 bg-white p-3 transition-transform dark:border-slate-800 dark:bg-slate-900 lg:static lg:!translate-x-0 ${open ? "translate-x-0" : "ltr:-translate-x-full rtl:translate-x-full"}`} aria-label="Primary">
        <div className="mb-4 flex items-center gap-2 px-2 pt-1"><ShieldAlert className="text-brand-500" /><span className="font-bold">{t("app")}</span></div>
        <nav className="space-y-0.5">
          {NAV.map(([to, k, icon]) => (
            <NavLink key={to} to={to} end={to === "/"} onClick={() => setOpen(false)}
              className={({ isActive }) => `flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors ${isActive ? "bg-brand-600 text-white" : "hover:bg-slate-100 dark:hover:bg-slate-800"}`}>{icon}{t(k)}</NavLink>
          ))}
        </nav>
      </aside>
      {open && <div className="fixed inset-0 z-30 bg-black/40 lg:hidden" onClick={() => setOpen(false)} />}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex items-center gap-2 border-b border-slate-200 bg-white/90 px-4 py-2 backdrop-blur dark:border-slate-800 dark:bg-slate-900/90">
          <button className="btn-ghost lg:hidden" aria-label="menu" onClick={() => setOpen(true)}><Menu size={18} /></button>
          <div className="flex-1 truncate text-xs text-slate-500">{t("readOnly")}</div>
          <button className="btn-ghost" onClick={() => setLocale(locale === "en" ? "ar" : "en")} aria-label={t("language")}><Languages size={16} />{locale === "en" ? "ع" : "EN"}</button>
          <button className="btn-ghost" onClick={toggleTheme} aria-label={t("theme")}>{theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}</button>
          <span className="hidden text-sm sm:inline">{user!.username} · {user!.role}</span>
          <button className="btn-ghost" onClick={logout} aria-label={t("logout")}><LogOut size={16} /></button>
        </header>
        <main className="fade-in flex-1 p-4 sm:p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/projects" element={<Projects />} />
            <Route path="/scan" element={<ScanCenter />} />
            <Route path="/files" element={<FileScanner />} />
            <Route path="/source" element={<FindingsView category="source" title={t("nav.source")} />} />
            <Route path="/secrets" element={<FindingsView category="secrets" title={t("nav.secrets")} />} />
            <Route path="/deps" element={<FindingsView category="dependency" title={t("nav.deps")} note="Offline manifest hygiene. CVE scanners (pip-audit, OSV, npm audit) stay disabled until verified - see Security Engines." />} />
            <Route path="/docker" element={<FindingsView category="docker" title={t("nav.docker")} />} />
            <Route path="/vulns" element={<FindingsView title={t("nav.vulns")} triage />} />
            <Route path="/beko" element={<Beko />} />
            <Route path="/live" element={<Live />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/schedules" element={<Schedules />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/health" element={<Health />} />
            <Route path="/engines" element={<Engines />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/users" element={<UsersPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        </main>
      </div>
      <div className="fixed bottom-4 end-4 z-50 space-y-2" aria-live="polite">
        {toasts.map((x) => <div key={x.id} className={`fade-in rounded-lg px-4 py-2 text-sm text-white shadow-lg ${x.kind === "err" ? "bg-red-600" : "bg-emerald-600"}`}>{x.msg}</div>)}
      </div>
    </div>
  );
}

export default function App() {
  const { user, booting } = useApp();
  if (booting) return <div className="p-10 text-center">…</div>;
  if (!user) return <Login />;
  if (user.must_change_password) return <ChangePassword />;
  return <Shell />;
}

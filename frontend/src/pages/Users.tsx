import { useState } from "react";
import { api, Row } from "../api";
import { useApp } from "../ctx";
import { Empty, Field, fmtTime, Modal, Notice, PageHeader, Spinner, Table, useAction, useLoad } from "../ui";

const ROLE_HELP: Record<string, string> = { admin: "Full control", analyst: "Register projects, run/cancel scans, triage, reports, schedules, BEKO", viewer: "Read-only dashboards, findings and reports", auditor: "Read-only + audit logs" };

export function UsersPage() {
  const { t, can, user } = useApp();
  const { data, loading, reload } = useLoad(() => api.get("/api/users"), [], 0);
  const { busy, run } = useAction();
  const [show, setShow] = useState(false); const [f, setF] = useState({ username: "", display_name: "", role: "viewer", password: "" });
  const [reset, setReset] = useState<Row | null>(null); const [pw, setPw] = useState("");
  if (!can("users:manage")) return <Notice tone="warn">Administrator permission required.</Notice>;
  return (
    <>
      <PageHeader title={t("nav.users")}><button className="btn-primary" onClick={() => setShow(true)}>{t("create")}</button></PageHeader>
      <div className="card mb-4 text-xs"><ul className="grid gap-1 sm:grid-cols-2">{Object.entries(ROLE_HELP).map(([r, d]) => <li key={r}><b>{r}</b> — {d}</li>)}</ul></div>
      {loading ? <Spinner /> : !data?.length ? <Empty /> : (
        <Table head={[t("username"), t("name"), t("role"), t("active"), "Last login", t("actions")]}>
          {data.map((u: Row) => <tr key={u.id}><td className="td">{u.username}</td><td className="td">{u.display_name}</td>
            <td className="td"><select className="input w-auto py-1" aria-label={`${t("role")} ${u.username}`} value={u.role} onChange={async (e) => { await run(() => api.patch(`/api/users/${u.id}`, { role: e.target.value }), t("saved")); reload(true); }}>{Object.keys(ROLE_HELP).map((r) => <option key={r}>{r}</option>)}</select></td>
            <td className="td"><input type="checkbox" aria-label={t("active")} checked={!!u.active} disabled={u.username === user!.username} onChange={async (e) => { await run(() => api.patch(`/api/users/${u.id}`, { active: e.target.checked })); reload(true); }} /></td>
            <td className="td text-xs">{fmtTime(u.last_login)}</td><td className="td"><button className="btn-ghost py-1" onClick={() => { setReset(u); setPw(""); }}>Reset password</button></td></tr>)}
        </Table>)}
      {show && <Modal title={t("create")} onClose={() => setShow(false)}><div className="space-y-3">
        <Field label={t("username")}><input className="input" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></Field>
        <Field label={t("name")}><input className="input" value={f.display_name} onChange={(e) => setF({ ...f, display_name: e.target.value })} /></Field>
        <Field label={t("role")}><select className="input" value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>{Object.keys(ROLE_HELP).map((r) => <option key={r}>{r}</option>)}</select></Field>
        <Field label={`${t("password")} (12+, upper/lower/digit — user must change at first login)`}><input className="input" type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></Field>
        <button className="btn-primary" disabled={busy} onClick={async () => { if (await run(() => api.post("/api/users", f), t("saved"))) { setShow(false); reload(true); } }}>{t("create")}</button></div></Modal>}
      {reset && <Modal title={`Reset password: ${reset.username}`} onClose={() => setReset(null)}><div className="space-y-3">
        <Field label={t("newPassword")}><input className="input" type="password" value={pw} onChange={(e) => setPw(e.target.value)} /></Field>
        <button className="btn-primary" disabled={busy} onClick={async () => { if (await run(() => api.patch(`/api/users/${reset.id}`, { password: pw }), t("saved"))) setReset(null); }}>{t("save")}</button></div></Modal>}
    </>
  );
}

export function SettingsPage() {
  const { t, can, locale, setLocale, theme, toggleTheme } = useApp();
  const { data, reload } = useLoad(() => (can("settings:read") ? api.get("/api/settings") : Promise.resolve(null)), []);
  const keys = useLoad(() => (can("settings:write") ? api.get("/api/integrations/keys") : Promise.resolve([])), []);
  const { busy, run } = useAction();
  const [form, setForm] = useState<Row | null>(null); const [newKey, setNewKey] = useState<string | null>(null);
  const v = form ?? data;
  const save = async () => { if (await run(() => api.put("/api/settings", form), t("saved"))) { setForm(null); reload(true); } };
  const set = (k: string, val: any) => setForm({ ...(form ?? data), [k]: val });
  return (
    <>
      <PageHeader title={t("nav.settings")} />
      <div className="card mb-4 flex flex-wrap items-center gap-4 text-sm">
        <span>{t("language")}: <button className="btn-ghost ms-2" onClick={() => setLocale(locale === "en" ? "ar" : "en")}>{locale === "en" ? "العربية" : "English"}</button></span>
        <span>{t("theme")}: <button className="btn-ghost ms-2" onClick={toggleTheme}>{theme}</button></span></div>
      {v && can("settings:write") ? (
        <div className="card mb-4 space-y-3">
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={v.store_snippets} onChange={(e) => set("store_snippets", e.target.checked)} />{t("stored")}</label>
          <div className="grid gap-3 sm:grid-cols-2"><Field label="BEKO / Ollama URL (loopback only)"><input className="input font-mono" value={v.beko_url} onChange={(e) => set("beko_url", e.target.value)} /></Field>
            <Field label="BEKO model"><input className="input font-mono" value={v.beko_model} onChange={(e) => set("beko_model", e.target.value)} /></Field></div>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={v.notifications_enabled} onChange={(e) => set("notifications_enabled", e.target.checked)} />{t("webhook")}</label>
          <div className="grid gap-3 sm:grid-cols-2"><Field label="URL"><input className="input font-mono" value={v.webhook_url} onChange={(e) => set("webhook_url", e.target.value)} /></Field>
            <Field label={`Secret header ${v.webhook_secret_set ? "(set — leave blank to keep)" : ""}`}><input className="input" type="password" onChange={(e) => set("webhook_secret", e.target.value)} /></Field></div>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={v.only_on_findings} onChange={(e) => set("only_on_findings", e.target.checked)} />Only notify when findings exist</label>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={v.n8n_enabled} onChange={(e) => set("n8n_enabled", e.target.checked)} />{t("n8n")} (X-API-Key authenticated, off by default)</label>
          <button className="btn-primary" disabled={busy || !form} onClick={save}>{t("save")}</button>
        </div>) : null}
      {can("settings:write") && (
        <div className="card"><div className="mb-2 flex items-center justify-between"><h2 className="font-semibold">{t("apiKeys")}</h2>
          <button className="btn-ghost" onClick={async () => { const r = await run(() => api.post("/api/integrations/keys", { name: `n8n-${Date.now() % 100000}` })); if (r) { setNewKey(r.key); keys.reload(true); } }}>{t("create")}</button></div>
          {newKey && <Notice tone="warn">Copy now (shown once): <code className="break-all">{newKey}</code></Notice>}
          <ul className="space-y-1 text-sm">{(keys.data ?? []).map((k: Row) => <li key={k.id} className="flex justify-between"><span>{k.name} {k.revoked ? "(revoked)" : ""}</span>{!k.revoked && <button className="btn-ghost py-1" onClick={async () => { await run(() => api.del(`/api/integrations/keys/${k.id}`)); keys.reload(true); }}>{t("delete")}</button>}</li>)}</ul></div>)}
    </>
  );
}

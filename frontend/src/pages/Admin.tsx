import { useState } from "react";
import { api, qs, Row } from "../api";
import { useApp } from "../ctx";
import { Empty, fmtTime, Notice, PageHeader, Spinner, Stat, Table, useAction, useLoad } from "../ui";

export function Health() {
  const { t } = useApp();
  const { data: h, loading } = useLoad(() => api.get("/api/system/health"), [], 5000);
  if (loading && !h) return <Spinner />;
  if (!h) return <Empty />;
  return (
    <>
      <PageHeader title={t("nav.health")} sub={`v${h.version} · ${h.bind}`} />
      <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Database" value={h.database.ok ? "OK" : "ERR"} tone={h.database.ok ? "#059669" : "#dc2626"} />
        <Stat label="Queue" value={`${h.queue.queued ?? 0} / ${h.queue.running ?? 0}`} />
        <Stat label="BEKO / Ollama" value={h.beko.reachable ? (h.beko.model_available ? "OK" : "no model") : "offline"} tone={h.beko.reachable ? "#059669" : "#d97706"} />
        <Stat label="Scheduler" value={h.scheduler.enabled ? "ON" : "OFF"} />
      </div>
      <h2 className="mb-2 font-semibold">Agents</h2>
      {!h.agents.length ? <Notice tone="warn">{t("noAgent")}</Notice> : (
        <Table head={[t("name"), "Host", "Version", "Status", "Last heartbeat", "Approved roots", "Ext. engines"]}>
          {h.agents.map((a: Row) => <tr key={a.id}><td className="td">{a.name}</td><td className="td">{a.hostname}</td><td className="td">{a.version}</td>
            <td className="td"><b className={a.online ? "text-emerald-600" : "text-red-600"}>{a.revoked ? "revoked" : a.online ? "online" : "offline"}</b>{a.status?.active_job ? ` · job #${a.status.active_job}` : ""}</td>
            <td className="td text-xs">{fmtTime(a.last_seen)}</td><td className="td font-mono text-xs">{a.roots.join(", ")}</td><td className="td text-xs">{a.external_engines.join(", ") || "—"}</td></tr>)}
        </Table>)}
    </>
  );
}

export function Engines() {
  const { t, can } = useApp();
  const { data, loading, reload } = useLoad(() => api.get("/api/capabilities"), []);
  const { run } = useAction();
  if (loading && !data) return <Spinner />;
  return (
    <>
      <PageHeader title={t("nav.engines")} />
      <Notice>Deterministic scanners are separate from BEKO AI analysis. Planned CVE scanners remain disabled until their installation and compatibility are verified on the agent host.</Notice>
      <Table head={[t("name"), "Kind", t("available"), t("enabled"), "Rules", "Limitations"]}>
        {data?.engines.map((e: Row) => (
          <tr key={e.id}><td className="td"><b>{e.name}</b><div className="font-mono text-xs text-slate-500">{e.id}</div></td><td className="td text-xs">{e.kind}</td>
            <td className="td">{e.available ? "✓" : "✗"}</td>
            <td className="td"><input type="checkbox" aria-label={`${t("enabled")} ${e.id}`} checked={e.enabled} disabled={!can("settings:write") || !e.available} onChange={async (ev) => { await run(() => api.patch(`/api/engines/${e.id}`, { enabled: ev.target.checked })); reload(true); }} /></td>
            <td className="td">{e.rules.length ? <details><summary className="cursor-pointer text-xs">{e.rules.length}</summary><ul className="mt-1 text-xs">{e.rules.map((r: Row) => <li key={r.id}><code>{r.id}</code> {r.title}</li>)}</ul></details> : "—"}</td>
            <td className="td text-xs">{e.limitations?.map((l: string) => <div key={l}>• {l}</div>)}</td></tr>))}
      </Table>
      <h2 className="mb-2 mt-6 font-semibold">Legacy V2 components</h2>
      <Table head={[t("name"), "Kind", "Status"]}>{data?.legacy.map((l: Row) => <tr key={l.id}><td className="td">{l.name}</td><td className="td text-xs">{l.kind}</td><td className="td text-xs">{l.note}</td></tr>)}</Table>
    </>
  );
}

export function Audit() {
  const { t } = useApp();
  const [f, setF] = useState({ action: "", outcome: "" }); const [page, setPage] = useState(0);
  const { data, loading } = useLoad(() => api.get(`/api/audit${qs({ ...f, limit: 50, offset: page * 50 })}`), [f, page], 10000);
  const [v, setV] = useState<Row | null>(null);
  const { run } = useAction();
  return (
    <>
      <PageHeader title={t("nav.audit")}><button className="btn-ghost" onClick={async () => setV(await run(() => api.get("/api/audit/verify")) ?? null)}>{t("verify")}</button></PageHeader>
      {v && <Notice tone={v.valid ? "info" : "err"}>{v.valid ? `✓ chain intact (${v.checked} entries)` : `✗ chain broken at entry #${v.broken_at}`}</Notice>}
      <div className="card mb-3 flex gap-2"><input className="input" placeholder="action prefix (e.g. scan.)" aria-label="action" value={f.action} onChange={(e) => { setF({ ...f, action: e.target.value }); setPage(0); }} />
        <select className="input w-auto" aria-label="outcome" value={f.outcome} onChange={(e) => { setF({ ...f, outcome: e.target.value }); setPage(0); }}><option value="">outcome</option>{["ok", "denied", "error", "locked", "rate_limited"].map((o) => <option key={o}>{o}</option>)}</select></div>
      {loading && !data ? <Spinner /> : !data?.items.length ? <Empty /> : (
        <Table head={["#", "Time", "Actor", t("role"), "Action", "Target", "IP", "Outcome"]}>
          {data.items.map((a: Row) => <tr key={a.id}><td className="td">{a.id}</td><td className="td text-xs">{fmtTime(a.ts)}</td><td className="td">{a.actor}</td><td className="td text-xs">{a.role}</td><td className="td font-mono text-xs">{a.action}</td><td className="td text-xs">{a.target}</td><td className="td text-xs">{a.ip}</td><td className={`td text-xs font-semibold ${a.outcome === "ok" ? "text-emerald-600" : "text-red-600"}`}>{a.outcome}</td></tr>)}
        </Table>)}
      <div className="mt-3 flex gap-2"><button className="btn-ghost" disabled={page === 0} onClick={() => setPage(page - 1)}>‹</button><button className="btn-ghost" disabled={(page + 1) * 50 >= (data?.total ?? 0)} onClick={() => setPage(page + 1)}>›</button></div>
    </>
  );
}

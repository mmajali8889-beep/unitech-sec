import { useEffect, useRef, useState } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { api, Row } from "../api";
import { useApp } from "../ctx";
import { Empty, fmtTime, PageHeader, StateBadge, useAction, useLoad } from "../ui";

export default function Live() {
  const { t, can } = useApp();
  const [sp, setSp] = useSearchParams();
  const [job, setJob] = useState<string>(sp.get("job") ?? "");
  const active = useLoad(() => api.get("/api/scans?limit=20"), [], 3000);
  const [events, setEvents] = useState<Row[]>([]);
  const [meta, setMeta] = useState<Row | null>(null);
  const after = useRef(0);
  const { run } = useAction();
  useEffect(() => { setEvents([]); after.current = 0; setMeta(null); }, [job]);
  useEffect(() => {
    if (!job) return;
    let stop = false;
    const tick = async () => {
      try {
        const r = await api.get(`/api/scans/${job}/events?after=${after.current}`);
        const j = await api.get(`/api/scans/${job}`);
        if (stop) return;
        if (r.events.length) { after.current = r.events[r.events.length - 1].id; setEvents((e) => [...e, ...r.events]); }
        setMeta(j);
      } catch { /* transient */ }
    };
    tick(); const i = setInterval(tick, 1200);
    return () => { stop = true; clearInterval(i); };
  }, [job]);
  const running = (active.data?.items ?? []).filter((j: Row) => ["queued", "running"].includes(j.state));
  return (
    <>
      <PageHeader title={t("nav.live")} />
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="card"><h2 className="mb-2 font-semibold">{t("running")}</h2>
          {!running.length ? <Empty /> : <ul className="space-y-1">{running.map((j: Row) => <li key={j.id}><button className="w-full rounded px-2 py-1 text-start text-sm hover:bg-slate-100 dark:hover:bg-slate-800" onClick={() => { setJob(String(j.id)); setSp({ job: String(j.id) }); }}>#{j.id} {j.project_name ?? "ad-hoc"} <StateBadge s={j.state} /></button></li>)}</ul>}
          <h3 className="mb-1 mt-4 text-xs font-semibold uppercase text-slate-500">{t("nav.history")}</h3>
          <ul className="space-y-1">{(active.data?.items ?? []).slice(0, 6).map((j: Row) => <li key={j.id}><button className="text-sm underline" onClick={() => setJob(String(j.id))}>#{j.id}</button> <StateBadge s={j.state} /></li>)}</ul></div>
        <div className="card lg:col-span-2">
          {!meta ? <Empty text="Select a scan" /> : <>
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2"><div className="text-sm"><b>#{meta.id}</b> {meta.project_name ?? meta.adhoc_path} · <StateBadge s={meta.state} /></div>
              <div className="flex gap-2">{["queued", "running"].includes(meta.state) && can("scans:cancel") && <button className="btn-danger" onClick={() => run(() => api.post(`/api/scans/${meta.id}/cancel`), t("cancelled"))}>{t("cancel")}</button>}
                {!["queued", "running"].includes(meta.state) && <Link className="btn-primary" to={`/vulns?job=${meta.id}`}>{t("nav.vulns")}</Link>}</div></div>
            <div className="mb-1 h-3 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800" role="progressbar" aria-valuenow={Math.round(meta.progress * 100)} aria-valuemin={0} aria-valuemax={100}>
              <div className="h-full bg-brand-500 transition-all duration-500" style={{ width: `${Math.round(meta.progress * 100)}%` }} /></div>
            <div className="mb-3 text-xs text-slate-500">{Math.round(meta.progress * 100)}% · {meta.files_scanned} files · {t("riskScore")}: {meta.risk_score}</div>
            {meta.error && <div className="mb-2 text-sm text-red-600">{meta.error}</div>}
            <div className="max-h-96 overflow-auto rounded-lg bg-slate-900 p-3 font-mono text-xs text-slate-100" dir="ltr" aria-live="polite">
              {events.map((e) => <div key={e.id} className={e.level === "error" ? "text-red-400" : e.level === "warning" ? "text-amber-300" : ""}>{fmtTime(e.ts).split(",").pop()} [{e.kind}] {e.message}</div>)}</div>
          </>}
        </div>
      </div>
    </>
  );
}

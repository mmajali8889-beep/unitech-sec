import { useState } from "react";
import { api, Row } from "../api";
import { useApp } from "../ctx";
import { Empty, fmtTime, Notice, PageHeader, Spinner, useAction, useLoad } from "../ui";

export default function Beko() {
  const { t, can } = useApp();
  const status = useLoad(() => api.get("/api/beko/status"), [], 20000);
  const scans = useLoad(() => api.get("/api/scans?limit=100"), []);
  const [job, setJob] = useState("");
  const an = useLoad(() => (job ? api.get(`/api/beko/analyses?job_id=${job}`) : Promise.resolve(null)), [job], job ? 4000 : 0);
  const { busy, run } = useAction();
  const s = status.data;
  const done = (scans.data?.items ?? []).filter((j: Row) => ["completed", "partial"].includes(j.state));
  return (
    <>
      <PageHeader title={t("nav.beko")} />
      <Notice tone="warn">{t("unverifiedAI")}</Notice>
      <div className="card mb-4 text-sm">
        {status.loading && !s ? <Spinner /> : s && <ul className="space-y-1"><li>Endpoint: <code>{s.endpoint}</code></li><li>Model: <code>{s.model}</code></li>
          <li>Ollama: <b className={s.reachable ? "text-emerald-600" : "text-red-600"}>{s.reachable ? "online" : "offline"}</b> · model available: <b>{s.model_available ? t("yes") : t("no")}</b></li>
          {!s.reachable && <li className="text-amber-600">Scanner results remain fully available while Ollama is offline.</li>}</ul>}
      </div>
      <div className="card mb-4 flex flex-wrap items-end gap-3">
        <label className="block text-sm"><span className="mb-1 block">{t("nav.history")}</span><select className="input min-w-64" value={job} onChange={(e) => setJob(e.target.value)}><option value="">—</option>{done.map((j: Row) => <option key={j.id} value={j.id}>#{j.id} · {j.project_name ?? "ad-hoc"} · {t(j.state)}</option>)}</select></label>
        {can("beko:run") && <button className="btn-primary" disabled={!job || busy} onClick={async () => { await run(() => api.post("/api/beko/analyse", { job_id: Number(job) }), "BEKO started"); setTimeout(() => an.reload(true), 1500); }}>{t("runAI")}</button>}
      </div>
      {an.data && (
        <>
          <details className="card mb-3 text-xs"><summary className="cursor-pointer font-semibold">Data sent to the model (aggregated rule metadata only)</summary><pre className="mt-2 overflow-auto" dir="ltr">{JSON.stringify(an.data.sent_metadata_preview, null, 2)}</pre></details>
          {!an.data.items.length ? <Empty /> : an.data.items.map((a: Row) => (
            <div key={a.id} className="card mb-3">
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500"><span>{a.model} · {fmtTime(a.created_at)} · <b>{a.state}</b></span>
                {a.state === "ok" && (a.human_reviewed ? <span className="text-emerald-600">✓ {a.reviewed_by}</span> : can("findings:triage") && <button className="btn-ghost py-1" onClick={async () => { await run(() => api.post(`/api/beko/analyses/${a.id}/review`)); an.reload(true); }}>{t("markReviewed")}</button>)}</div>
              {a.state === "ok" ? <><Notice tone="warn">{a.disclaimer}</Notice><pre className="whitespace-pre-wrap text-sm">{a.content}</pre></> : <Notice tone="err">{a.error}</Notice>}
            </div>))}
        </>)}
    </>
  );
}

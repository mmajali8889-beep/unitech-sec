import { useState } from "react";
import { api, Row } from "../api";
import { useApp } from "../ctx";
import { Empty, fmtTime, PageHeader, Spinner, Table, useAction, useLoad } from "../ui";

export default function Reports() {
  const { t, can } = useApp();
  const scans = useLoad(() => api.get("/api/scans?limit=100"), []);
  const reports = useLoad(() => api.get("/api/reports"), []);
  const [job, setJob] = useState(""); const [fmt, setFmt] = useState("html");
  const { busy, run } = useAction();
  const done = (scans.data?.items ?? []).filter((j: Row) => !["queued", "running"].includes(j.state));
  return (
    <>
      <PageHeader title={t("nav.reports")} />
      {can("reports:create") && <div className="card mb-4 flex flex-wrap items-end gap-3">
        <label className="block text-sm"><span className="mb-1 block">{t("nav.history")}</span><select className="input min-w-64" value={job} onChange={(e) => setJob(e.target.value)}><option value="">—</option>{done.map((j: Row) => <option key={j.id} value={j.id}>#{j.id} · {j.project_name ?? "ad-hoc"} · {t(j.state)}</option>)}</select></label>
        <label className="block text-sm"><span className="mb-1 block">{t("format")}</span><select className="input" value={fmt} onChange={(e) => setFmt(e.target.value)}>{["html", "json", "sarif", "pdf"].map((f) => <option key={f}>{f}</option>)}</select></label>
        <button className="btn-primary" disabled={!job || busy} onClick={async () => { if (await run(() => api.post("/api/reports", { job_id: Number(job), format: fmt }), t("saved"))) reports.reload(true); }}>{t("generate")}</button></div>}
      {reports.loading && !reports.data ? <Spinner /> : !reports.data?.length ? <Empty /> : (
        <Table head={["#", t("project"), "Scan", t("format"), "SHA-256", t("created"), t("actions")]}>
          {reports.data.map((r: Row) => <tr key={r.id}><td className="td">{r.id}</td><td className="td">{r.project_name ?? "ad-hoc"}</td><td className="td">#{r.job_id}</td><td className="td uppercase">{r.format}</td>
            <td className="td font-mono text-xs">{r.sha256.slice(0, 12)}…</td><td className="td text-xs">{fmtTime(r.created_at)}</td>
            <td className="td"><button className="btn-ghost py-1" onClick={() => run(() => api.download(`/api/reports/${r.id}/download`, `unitech-report-job${r.job_id}.${r.format}`))}>{t("download")}</button></td></tr>)}
        </Table>)}
    </>
  );
}

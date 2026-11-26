import { useState } from "react";
import { Link } from "react-router-dom";
import { api, qs, Row } from "../api";
import { useApp } from "../ctx";
import { Empty, fmtTime, Modal, PageHeader, Spinner, StateBadge, Table, useLoad } from "../ui";

export default function History() {
  const { t } = useApp();
  const [state, setState] = useState(""); const [project, setProject] = useState(""); const [page, setPage] = useState(0);
  const projects = useLoad(() => api.get("/api/projects"), []);
  const { data, loading } = useLoad(() => api.get(`/api/scans${qs({ state, project_id: project, limit: 25, offset: page * 25 })}`), [state, project, page], 5000);
  const [cmp, setCmp] = useState<Row | null>(null);
  return (
    <>
      <PageHeader title={t("nav.history")} />
      <div className="card mb-3 flex flex-wrap gap-2">
        <select className="input w-auto" aria-label={t("state")} value={state} onChange={(e) => { setState(e.target.value); setPage(0); }}><option value="">{t("state")}: {t("all")}</option>{["queued", "running", "completed", "partial", "failed", "cancelled"].map((s) => <option key={s} value={s}>{t(s)}</option>)}</select>
        <select className="input w-auto" aria-label={t("project")} value={project} onChange={(e) => { setProject(e.target.value); setPage(0); }}><option value="">{t("project")}: {t("all")}</option>{projects.data?.map((p: Row) => <option key={p.id} value={p.id}>{p.name}</option>)}</select>
      </div>
      {loading && !data ? <Spinner /> : !data?.items.length ? <Empty /> : (
        <Table head={["#", t("project"), t("target"), t("state"), t("riskScore"), t("openFindings"), t("created"), t("actions")]}>
          {data.items.map((j: Row) => (
            <tr key={j.id}><td className="td">{j.id}</td><td className="td">{j.project_name ?? "ad-hoc"}</td><td className="td text-xs">{j.target_kind}</td><td className="td"><StateBadge s={j.state} /></td>
              <td className="td">{j.risk_score}</td><td className="td">{j.summary?.total ?? "—"}</td><td className="td text-xs">{fmtTime(j.created_at)}</td>
              <td className="td flex gap-2"><Link className="btn-ghost py-1" to={`/vulns?job=${j.id}`}>{t("nav.vulns")}</Link>
                {["completed", "partial"].includes(j.state) && <button className="btn-ghost py-1" onClick={async () => setCmp({ job: j.id, ...(await api.get(`/api/scans/${j.id}/compare`)) })}>{t("compare")}</button>}</td></tr>))}
        </Table>)}
      <div className="mt-3 flex gap-2"><button className="btn-ghost" disabled={page === 0} onClick={() => setPage(page - 1)}>‹</button><button className="btn-ghost" disabled={(page + 1) * 25 >= (data?.total ?? 0)} onClick={() => setPage(page + 1)}>›</button></div>
      {cmp && <Modal title={`#${cmp.job} ↔ #${cmp.base ?? "—"}`} onClose={() => setCmp(null)}>
        {!cmp.base ? <Empty text={cmp.note} /> : <div className="space-y-3 text-sm"><div>{t("riskScore")} Δ <b>{cmp.risk_delta > 0 ? "+" : ""}{cmp.risk_delta}</b> · {t("unchanged")}: {cmp.unchanged}</div>
          <div><b className="text-red-600">{t("newF")} ({cmp.new.length})</b><ul className="ms-4 list-disc text-xs">{cmp.new.slice(0, 30).map((f: Row) => <li key={f.id}>{f.rule_id} {f.file}:{f.line}</li>)}</ul></div>
          <div><b className="text-emerald-600">{t("fixed")} ({cmp.fixed.length})</b><ul className="ms-4 list-disc text-xs">{cmp.fixed.slice(0, 30).map((f: Row) => <li key={f.id}>{f.rule_id} {f.file}:{f.line}</li>)}</ul></div></div>}
      </Modal>}
    </>
  );
}

import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, qs, Row } from "../api";
import { useApp } from "../ctx";
import { Empty, Field, Modal, Notice, PageHeader, SEV, SevBadge, Spinner, Table, useAction, useLoad } from "../ui";

const STATUSES = ["open", "triaged", "accepted", "false_positive", "fixed"];

export function FindingsView({ category, title, note, triage = false }: { category?: string; title: string; note?: string; triage?: boolean }) {
  const { t, can } = useApp();
  const [sp] = useSearchParams();
  const [f, setF] = useState({ severity: "", status: "", verification: "", q: "", project_id: "" });
  const [page, setPage] = useState(0);
  const jobId = sp.get("job") ?? "";
  const projects = useLoad(() => api.get("/api/projects"), []);
  const { data, loading, reload } = useLoad(() => api.get(`/api/findings${qs({ category, job_id: jobId, ...f, limit: 50, offset: page * 50 })}`), [category, jobId, f, page]);
  const [sel, setSel] = useState<Row | null>(null);
  const [st, setSt] = useState("open"); const [note2, setNote] = useState("");
  const { busy, run } = useAction();
  const save = async () => { if (await run(() => api.patch(`/api/findings/${sel!.id}`, { status: st, note: note2 }), t("saved"))) { setSel(null); reload(); } };
  const set = (k: string, v: string) => { setPage(0); setF({ ...f, [k]: v }); };
  return (
    <>
      <PageHeader title={title} sub={jobId ? `#${jobId}` : undefined} />
      {note && <Notice>{note}</Notice>}
      <div className="card mb-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
        <input className="input" placeholder={t("search")} aria-label={t("search")} value={f.q} onChange={(e) => set("q", e.target.value)} />
        <select className="input" aria-label={t("severity")} value={f.severity} onChange={(e) => set("severity", e.target.value)}><option value="">{t("severity")}: {t("all")}</option>{SEV.map((s) => <option key={s} value={s}>{t(s)}</option>)}</select>
        <select className="input" aria-label={t("status")} value={f.status} onChange={(e) => set("status", e.target.value)}><option value="">{t("status")}: {t("all")}</option>{STATUSES.map((s) => <option key={s} value={s}>{t(s)}</option>)}</select>
        <select className="input" aria-label={t("verification")} value={f.verification} onChange={(e) => set("verification", e.target.value)}><option value="">{t("verification")}: {t("all")}</option><option value="deterministic">deterministic</option><option value="heuristic">heuristic</option></select>
        <select className="input" aria-label={t("project")} value={f.project_id} onChange={(e) => set("project_id", e.target.value)}><option value="">{t("project")}: {t("all")}</option>{projects.data?.map((p: Row) => <option key={p.id} value={p.id}>{p.name}</option>)}</select>
      </div>
      {data && <div className="mb-2 flex flex-wrap gap-2 text-xs">{SEV.map((s) => <span key={s}><SevBadge s={s} /> {data.severity_counts[s] ?? 0}</span>)}<span className="text-slate-500">· {data.total}</span></div>}
      {loading && !data ? <Spinner /> : !data?.items.length ? <Empty /> : (
        <>
          <Table head={[t("severity"), t("rule"), "Title", `${t("file")}:${t("line")}`, t("project"), t("verification"), t("status")]}>
            {data.items.map((x: Row) => (
              <tr key={x.id} className="cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50" onClick={() => { setSel(x); setSt(x.status); setNote(x.status_note); }} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && setSel(x)}>
                <td className="td"><SevBadge s={x.severity} /></td><td className="td font-mono text-xs">{x.rule_id}</td><td className="td">{x.title}</td>
                <td className="td font-mono text-xs">{x.file}:{x.line}</td><td className="td">{x.project_name ?? "—"}</td>
                <td className="td text-xs">{x.verification}</td><td className="td text-xs">{t(x.status)}</td>
              </tr>))}
          </Table>
          <div className="mt-3 flex items-center gap-2"><button className="btn-ghost" disabled={page === 0} onClick={() => setPage(page - 1)}>‹</button><span className="text-sm">{page + 1}</span><button className="btn-ghost" disabled={(page + 1) * 50 >= data.total} onClick={() => setPage(page + 1)}>›</button></div>
        </>)}
      {sel && (
        <Modal title={`${sel.rule_id} · ${sel.title}`} onClose={() => setSel(null)}>
          <dl className="space-y-2 text-sm">
            <div><SevBadge s={sel.severity} /> <span className="ms-2 text-xs">{sel.engine} · {sel.cwe}</span></div>
            <div className="font-mono text-xs">{sel.file}:{sel.line}</div>
            {sel.snippet && <pre className="overflow-auto rounded bg-slate-100 p-2 text-xs dark:bg-slate-800" dir="ltr">{sel.snippet}</pre>}
            <div><b>{t("remediation")}:</b> {sel.remediation}</div>
            <div><b>{t("verification")}:</b> {sel.verification}</div>
          </dl>
          {can("findings:triage") && (triage || true) && (
            <div className="mt-4 space-y-2 border-t border-slate-200 pt-3 dark:border-slate-800">
              <Field label={t("status")}><select className="input" value={st} onChange={(e) => setSt(e.target.value)}>{STATUSES.map((s) => <option key={s} value={s}>{t(s)}</option>)}</select></Field>
              <Field label={t("note")}><input className="input" maxLength={500} value={note2} onChange={(e) => setNote(e.target.value)} /></Field>
              <button className="btn-primary" disabled={busy} onClick={save}>{t("save")}</button>
            </div>)}
        </Modal>)}
    </>
  );
}

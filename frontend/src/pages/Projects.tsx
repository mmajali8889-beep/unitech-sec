import { useState } from "react";
import { Folder, File as FileIcon, ArrowUp, Trash2, Search, Plus } from "lucide-react";
import { Link } from "react-router-dom";
import { api, Row } from "../api";
import { useApp } from "../ctx";
import { Empty, Field, fmtTime, Modal, Notice, PageHeader, Spinner, Table, useAction, useLoad } from "../ui";

export function DirBrowser({ onPick, filesToo = false }: { onPick: (path: string, type: string) => void; filesToo?: boolean }) {
  const { t } = useApp();
  const [path, setPath] = useState("");
  const { data, loading, error } = useLoad(() => api.get(`/api/browse?path=${encodeURIComponent(path)}`), [path]);
  return (
    <div>
      {error && <Notice tone="err">{error}</Notice>}
      {loading && <Spinner />}
      {data && (
        <>
          <div className="mb-2 flex items-center gap-2 text-xs text-slate-500">
            {!data.roots && <button className="btn-ghost" onClick={() => setPath(data.parent || "")} aria-label="up"><ArrowUp size={14} /></button>}
            <span className="truncate">{data.path || t("browse")}</span>
          </div>
          <ul className="max-h-72 divide-y divide-slate-100 overflow-auto rounded-lg border border-slate-200 dark:divide-slate-800 dark:border-slate-800">
            {data.entries.map((e: Row) => (
              <li key={e.path} className="flex items-center justify-between px-3 py-1.5 text-sm">
                <button className="flex min-w-0 items-center gap-2 truncate text-start" onClick={() => (e.type === "dir" ? setPath(e.path) : filesToo && onPick(e.path, "file"))}>
                  {e.type === "dir" ? <Folder size={15} className="text-amber-500" /> : <FileIcon size={15} />}<span className="truncate">{e.name}</span></button>
                {(e.type === "dir" || filesToo) && <button className="btn-ghost py-1 text-xs" onClick={() => onPick(e.path, e.type)}>{t("target")}</button>}
              </li>
            ))}
            {!data.entries.length && <li><Empty /></li>}
          </ul>
        </>
      )}
    </div>
  );
}

export default function Projects() {
  const { t, can } = useApp();
  const { data, loading, reload } = useLoad(() => api.get("/api/projects"), []);
  const { busy, run } = useAction();
  const [showReg, setShowReg] = useState(false);
  const [disc, setDisc] = useState<Row[] | null>(null);
  const [form, setForm] = useState({ name: "", path: "", kind: "generic" });
  const register = async () => { if (await run(() => api.post("/api/projects", form), t("saved"))) { setShowReg(false); setForm({ name: "", path: "", kind: "generic" }); reload(); } };
  return (
    <>
      <PageHeader title={t("nav.projects")}>
        {can("projects:write") && <>
          <button className="btn-ghost" disabled={busy} onClick={async () => { const r = await run(() => api.post("/api/projects/discover", {})); if (r) setDisc(r.candidates); }}><Search size={16} />{t("discover")}</button>
          <button className="btn-primary" onClick={() => setShowReg(true)}><Plus size={16} />{t("register")}</button></>}
      </PageHeader>
      {loading ? <Spinner /> : !data?.length ? <Empty /> : (
        <Table head={[t("name"), t("path"), "Type", t("riskScore"), "Last scan", t("actions")]}>
          {data.map((p: Row) => (
            <tr key={p.id} className={p.active ? "" : "opacity-50"}>
              <td className="td font-medium">{p.name}</td><td className="td font-mono text-xs">{p.canonical_path}</td><td className="td">{p.kind}</td>
              <td className="td">{p.risk_score ?? "—"}</td><td className="td">{fmtTime(p.last_scan_at)}</td>
              <td className="td flex gap-2"><Link className="btn-ghost py-1" to={`/scan?project=${p.id}`}>{t("startScan")}</Link>
                {can("projects:write") && p.active ? <button className="btn-ghost py-1" aria-label={t("delete")} onClick={async () => { if (confirm(`${t("delete")} ${p.name}? (${"registration only, files untouched"})`)) { await run(() => api.del(`/api/projects/${p.id}`)); reload(); } }}><Trash2 size={14} /></button> : null}</td>
            </tr>))}
        </Table>)}
      {disc && (
        <Modal title={t("discover")} onClose={() => setDisc(null)}>
          {!disc.length ? <Empty /> : <ul className="divide-y divide-slate-100 dark:divide-slate-800">{disc.map((c) => (
            <li key={c.path} className="flex items-center justify-between py-2 text-sm"><div><b>{c.name}</b> <span className="text-xs text-slate-500">{c.kind} · {c.markers.join(", ")}</span><div className="font-mono text-xs">{c.path}</div></div>
              {c.registered ? <span className="text-xs text-emerald-600">✓</span> : <button className="btn-ghost" onClick={() => { setForm({ name: c.name, path: c.path, kind: c.kind }); setDisc(null); setShowReg(true); }}>{t("register")}</button>}</li>))}</ul>}
        </Modal>)}
      {showReg && (
        <Modal title={t("register")} onClose={() => setShowReg(false)}>
          <div className="space-y-3">
            <Field label={t("name")}><input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
            <Field label={t("path")}><input className="input font-mono" value={form.path} onChange={(e) => setForm({ ...form, path: e.target.value })} /></Field>
            <DirBrowser onPick={(p, ty) => ty === "dir" && setForm((f) => ({ ...f, path: p, name: f.name || p.split(/[\\/]/).pop() || "" }))} />
            <button className="btn-primary" disabled={busy || !form.name || !form.path} onClick={register}>{t("register")}</button>
          </div>
        </Modal>)}
    </>
  );
}

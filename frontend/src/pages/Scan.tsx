import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, Row } from "../api";
import { useApp } from "../ctx";
import { Field, Notice, PageHeader, Spinner, useAction, useLoad } from "../ui";
import { DirBrowser } from "./Projects";

function EnginePicker({ engines, sel, setSel }: { engines: Row[]; sel: string[]; setSel: (s: string[]) => void }) {
  return (
    <fieldset className="grid gap-2 sm:grid-cols-2">
      {engines.map((e) => {
        const usable = e.available && e.enabled;
        return (
          <label key={e.id} className={`flex items-start gap-2 rounded-lg border p-2 text-sm ${usable ? "cursor-pointer border-slate-300 dark:border-slate-700" : "cursor-not-allowed border-dashed opacity-50"}`}>
            <input type="checkbox" disabled={!usable} checked={sel.includes(e.id)} onChange={(ev) => setSel(ev.target.checked ? [...sel, e.id] : sel.filter((x) => x !== e.id))} />
            <span><b>{e.name}</b>{!usable && <span className="block text-xs text-amber-600">{e.kind === "planned" || !e.available ? "not available" : "disabled"}</span>}<span className="block text-xs text-slate-500">{e.limitations?.[0]}</span></span>
          </label>);
      })}
    </fieldset>);
}

export function ScanCenter() {
  const { t } = useApp();
  const nav = useNavigate();
  const [sp] = useSearchParams();
  const projects = useLoad(() => api.get("/api/projects"), []);
  const caps = useLoad(() => api.get("/api/capabilities"), []);
  const [pid, setPid] = useState<string>(sp.get("project") ?? "");
  const [sel, setSel] = useState<string[]>([]);
  const [mode, setMode] = useState<"project" | "files">("project");
  const [files, setFiles] = useState("");
  const [beko, setBeko] = useState(false);
  const { busy, run } = useAction();
  useEffect(() => { if (caps.data && !sel.length) setSel(caps.data.engines.filter((e: Row) => e.available && e.enabled).map((e: Row) => e.id)); }, [caps.data]);
  const start = async () => {
    const body: Row = { project_id: Number(pid), engines: sel, beko };
    if (mode === "files") body.targets = files.split("\n").map((x) => x.trim()).filter(Boolean);
    const r = await run(() => api.post("/api/scans", body), t("queued"));
    if (r) nav(`/live?job=${r.id}`);
  };
  if (projects.loading || caps.loading) return <Spinner />;
  return (
    <>
      <PageHeader title={t("nav.scan")} sub={t("readOnly")} />
      {caps.data?.agents_online === 0 && <Notice tone="warn">{t("noAgent")}</Notice>}
      <div className="card space-y-4">
        <Field label={t("project")}><select className="input" value={pid} onChange={(e) => setPid(e.target.value)}><option value="">—</option>{projects.data?.filter((p: Row) => p.active).map((p: Row) => <option key={p.id} value={p.id}>{p.name}</option>)}</select></Field>
        <div className="flex gap-4 text-sm"><label><input type="radio" checked={mode === "project"} onChange={() => setMode("project")} /> {t("wholeProject")}</label><label><input type="radio" checked={mode === "files"} onChange={() => setMode("files")} /> {t("selectedFiles")}</label></div>
        {mode === "files" && <textarea className="input font-mono" rows={4} value={files} onChange={(e) => setFiles(e.target.value)} placeholder="app/main.py" />}
        <div><h2 className="mb-2 text-sm font-semibold">{t("engines")}</h2><EnginePicker engines={caps.data?.engines ?? []} sel={sel} setSel={setSel} /></div>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={beko} onChange={(e) => setBeko(e.target.checked)} />{t("runAI")} <span className="text-xs text-slate-500">(sanitized metadata only)</span></label>
        <button className="btn-primary" disabled={busy || !pid || !sel.length || (mode === "files" && !files.trim())} onClick={start}>{t("startScan")}</button>
      </div>
    </>);
}

export function FileScanner() {
  const { t, can } = useApp();
  const nav = useNavigate();
  const caps = useLoad(() => api.get("/api/capabilities"), []);
  const [path, setPath] = useState("");
  const [kind, setKind] = useState("");
  const [sel, setSel] = useState<string[]>([]);
  const { busy, run } = useAction();
  useEffect(() => { if (caps.data && !sel.length) setSel(caps.data.engines.filter((e: Row) => e.available && e.enabled).map((e: Row) => e.id)); }, [caps.data]);
  const start = async () => { const r = await run(() => api.post("/api/scans", { adhoc_path: path, engines: sel }), t("queued")); if (r) nav(`/live?job=${r.id}`); };
  return (
    <>
      <PageHeader title={t("nav.files")} sub={t("readOnly")} />
      {caps.data?.agents_online === 0 && <Notice tone="warn">{t("noAgent")}</Notice>}
      {!can("browse") ? <Notice tone="warn">Your role cannot browse directories.</Notice> : (
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="card"><h2 className="mb-2 font-semibold">{t("browse")}</h2><DirBrowser filesToo onPick={(p, ty) => { setPath(p); setKind(ty); }} /></div>
          <div className="card space-y-3">
            <Field label={t("target")}><input className="input font-mono" readOnly value={path} placeholder="…" /></Field>
            {kind && <div className="text-xs text-slate-500">{kind}</div>}
            <EnginePicker engines={caps.data?.engines ?? []} sel={sel} setSel={setSel} />
            <button className="btn-primary" disabled={busy || !path || !sel.length} onClick={start}>{t("startScan")}</button>
          </div>
        </div>)}
    </>);
}

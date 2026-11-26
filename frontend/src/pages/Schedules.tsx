import { useState } from "react";
import { Trash2 } from "lucide-react";
import { api, Row } from "../api";
import { useApp } from "../ctx";
import { Empty, Field, fmtTime, PageHeader, Spinner, Table, useAction, useLoad } from "../ui";

export default function Schedules() {
  const { t, can } = useApp();
  const list = useLoad(() => api.get("/api/schedules"), [], 10000);
  const projects = useLoad(() => api.get("/api/projects"), []);
  const caps = useLoad(() => api.get("/api/capabilities"), []);
  const { busy, run } = useAction();
  const [f, setF] = useState({ name: "", project_id: "", mode: "daily", interval: "60", daily: "02:00", beko: false });
  const [eng, setEng] = useState<string[]>(["secrets", "source", "config", "docker", "authz", "taint", "deps"]);
  const create = async () => {
    const body: Row = { name: f.name, project_id: Number(f.project_id), engines: eng, beko: f.beko };
    if (f.mode === "daily") body.daily_at = f.daily; else body.interval_minutes = Number(f.interval);
    if (await run(() => api.post("/api/schedules", body), t("saved"))) { setF({ ...f, name: "" }); list.reload(); }
  };
  return (
    <>
      <PageHeader title={t("nav.schedules")} />
      {can("schedules:write") && (
        <div className="card mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Field label={t("name")}><input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
          <Field label={t("project")}><select className="input" value={f.project_id} onChange={(e) => setF({ ...f, project_id: e.target.value })}><option value="">—</option>{projects.data?.filter((p: Row) => p.active).map((p: Row) => <option key={p.id} value={p.id}>{p.name}</option>)}</select></Field>
          <Field label="Mode"><select className="input" value={f.mode} onChange={(e) => setF({ ...f, mode: e.target.value })}><option value="daily">{t("dailyAt")}</option><option value="interval">{t("interval")}</option></select></Field>
          {f.mode === "daily" ? <Field label={t("dailyAt")}><input className="input" value={f.daily} onChange={(e) => setF({ ...f, daily: e.target.value })} /></Field> : <Field label={t("interval")}><input className="input" type="number" min={5} value={f.interval} onChange={(e) => setF({ ...f, interval: e.target.value })} /></Field>}
          <div className="sm:col-span-2 lg:col-span-4 flex flex-wrap gap-3 text-sm">{(caps.data?.engines ?? []).filter((e: Row) => e.available && e.enabled).map((e: Row) => <label key={e.id}><input type="checkbox" checked={eng.includes(e.id)} onChange={(ev) => setEng(ev.target.checked ? [...eng, e.id] : eng.filter((x) => x !== e.id))} /> {e.id}</label>)}
            <label><input type="checkbox" checked={f.beko} onChange={(e) => setF({ ...f, beko: e.target.checked })} /> BEKO</label></div>
          <div><button className="btn-primary" disabled={busy || !f.name || !f.project_id || !eng.length} onClick={create}>{t("create")}</button></div>
        </div>)}
      {list.loading && !list.data ? <Spinner /> : !list.data?.length ? <Empty /> : (
        <Table head={[t("name"), t("project"), "When", t("engines"), "Next", "Last", t("enabled"), t("actions")]}>
          {list.data.map((s: Row) => (
            <tr key={s.id}><td className="td">{s.name}</td><td className="td">{s.project_name}</td><td className="td text-xs">{s.daily_at ? `daily ${s.daily_at}` : `every ${s.interval_minutes} min`}</td><td className="td text-xs">{s.engines.join(", ")}</td>
              <td className="td text-xs">{fmtTime(s.next_run)}</td><td className="td text-xs">{fmtTime(s.last_run)}</td>
              <td className="td"><input type="checkbox" aria-label={t("enabled")} checked={!!s.enabled} disabled={!can("schedules:write")} onChange={async (e) => { await run(() => api.patch(`/api/schedules/${s.id}`, { enabled: e.target.checked })); list.reload(true); }} /></td>
              <td className="td">{can("schedules:write") && <button className="btn-ghost py-1" aria-label={t("delete")} onClick={async () => { await run(() => api.del(`/api/schedules/${s.id}`)); list.reload(true); }}><Trash2 size={14} /></button>}</td></tr>))}
        </Table>)}
    </>
  );
}

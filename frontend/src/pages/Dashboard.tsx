import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis, Legend } from "recharts";
import { api } from "../api";
import { useApp } from "../ctx";
import { Empty, PageHeader, SEV, SEV_COLOR, Spinner, Stat, StateBadge, useLoad } from "../ui";

export default function Dashboard() {
  const { t } = useApp();
  const { data: d, loading, reload } = useLoad(() => api.get("/api/dashboard"), [], 15000);
  if (loading && !d) return <Spinner />;
  if (!d) return <Empty />;
  const sev = SEV.map((s) => ({ name: t(s), key: s, value: d.severity[s] ?? 0 })).filter((x) => x.value > 0);
  return (
    <>
      <PageHeader title={t("nav.dashboard")}><button className="btn-ghost" onClick={() => reload()}>{t("refresh")}</button></PageHeader>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Stat label={t("openFindings")} value={d.totals.open_findings} tone={d.totals.open_findings ? SEV_COLOR.high : undefined} />
        <Stat label={t("nav.projects")} value={d.totals.projects} /><Stat label={t("scans")} value={d.totals.scans} />
        <Stat label={t("agentsOnline")} value={d.totals.agents_online} tone={d.totals.agents_online ? "#059669" : SEV_COLOR.critical} /><Stat label={t("nav.schedules")} value={d.totals.schedules} />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <div className="card"><h2 className="mb-2 font-semibold">{t("severity")}</h2>
          {sev.length ? <ResponsiveContainer width="100%" height={240}><PieChart><Pie data={sev} dataKey="value" nameKey="name" innerRadius={50} outerRadius={85} label>{sev.map((s) => <Cell key={s.key} fill={SEV_COLOR[s.key]} />)}</Pie><Tooltip /><Legend /></PieChart></ResponsiveContainer> : <Empty />}</div>
        <div className="card lg:col-span-2"><h2 className="mb-2 font-semibold">{t("riskScore")}</h2>
          {d.risk_trend.length ? <ResponsiveContainer width="100%" height={240}><LineChart data={d.risk_trend}><CartesianGrid strokeDasharray="3 3" opacity={0.3} /><XAxis dataKey="day" /><YAxis domain={[0, 100]} /><Tooltip /><Line type="monotone" dataKey="risk" stroke="#2f7cf6" strokeWidth={2} /></LineChart></ResponsiveContainer> : <Empty />}</div>
        <div className="card lg:col-span-2"><h2 className="mb-2 font-semibold">{t("rule")}</h2>
          {d.top_rules.length ? <ResponsiveContainer width="100%" height={260}><BarChart data={d.top_rules} layout="vertical" margin={{ left: 20 }}><CartesianGrid strokeDasharray="3 3" opacity={0.3} /><XAxis type="number" allowDecimals={false} /><YAxis type="category" dataKey="rule_id" width={70} /><Tooltip /><Bar dataKey="n">{d.top_rules.map((r: any) => <Cell key={r.rule_id} fill={SEV_COLOR[r.severity]} />)}</Bar></BarChart></ResponsiveContainer> : <Empty />}</div>
        <div className="card"><h2 className="mb-2 font-semibold">{t("nav.projects")}</h2>
          <ul className="space-y-2">{d.projects_at_risk.length ? d.projects_at_risk.map((p: any) => (
            <li key={p.id} className="flex items-center justify-between text-sm"><span>{p.name}</span>{p.job_id ? <Link className="font-semibold text-brand-500" to={`/vulns?job=${p.job_id}`}>{p.risk_score}/100</Link> : <span className="text-slate-400">—</span>}</li>)) : <Empty />}</ul>
          <div className="mt-3 flex flex-wrap gap-1">{Object.entries(d.job_states).map(([s, n]) => <span key={s} className="text-xs"><StateBadge s={s} /> {n as number}</span>)}</div></div>
      </div>
    </>
  );
}

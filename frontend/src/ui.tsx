import React, { useCallback, useEffect, useRef, useState } from "react";
import { Loader2 } from "lucide-react";
import { useApp } from "./ctx";

export const SEV = ["critical", "high", "medium", "low", "info"] as const;
export const SEV_COLOR: Record<string, string> = { critical: "#dc2626", high: "#ea580c", medium: "#d97706", low: "#2563eb", info: "#6b7280" };
export const fmtTime = (ts?: number | null) => (ts ? new Date(ts * 1000).toLocaleString() : "—");

export function SevBadge({ s }: { s: string }) {
  const { t } = useApp();
  return <span className="inline-block rounded-full px-2 py-0.5 text-xs font-semibold text-white" style={{ background: SEV_COLOR[s] ?? "#6b7280" }}>{t(s)}</span>;
}

const STATE_STYLE: Record<string, string> = {
  queued: "bg-slate-200 text-slate-800 dark:bg-slate-700 dark:text-slate-100", running: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-100",
  completed: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-100", partial: "bg-amber-100 text-amber-900 dark:bg-amber-900 dark:text-amber-100",
  failed: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100", cancelled: "bg-zinc-200 text-zinc-700 dark:bg-zinc-700 dark:text-zinc-200",
};
export function StateBadge({ s }: { s: string }) {
  const { t } = useApp();
  return <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${STATE_STYLE[s] ?? ""}`}>{t(s)}</span>;
}

export function PageHeader({ title, children, sub }: { title: string; sub?: string; children?: React.ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div><h1 className="text-xl font-bold sm:text-2xl">{title}</h1>{sub && <p className="text-sm text-slate-500">{sub}</p>}</div>
      <div className="flex flex-wrap items-center gap-2">{children}</div>
    </div>
  );
}

export function Stat({ label, value, tone }: { label: string; value: React.ReactNode; tone?: string }) {
  return <div className="card"><div className="text-xs uppercase tracking-wide text-slate-500">{label}</div><div className="mt-1 text-3xl font-bold" style={tone ? { color: tone } : undefined}>{value}</div></div>;
}

export const Spinner = () => <Loader2 className="inline animate-spin" size={18} aria-label="loading" />;
export const Empty = ({ text }: { text?: string }) => { const { t } = useApp(); return <div className="p-8 text-center text-sm text-slate-500">{text ?? t("empty")}</div>; };
export const Notice = ({ children, tone = "info" }: { children: React.ReactNode; tone?: "info" | "warn" | "err" }) => (
  <div role="status" className={`mb-3 rounded-lg border px-3 py-2 text-sm ${tone === "warn" ? "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-100" : tone === "err" ? "border-red-300 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-950 dark:text-red-100" : "border-blue-200 bg-blue-50 text-blue-900 dark:border-blue-900 dark:bg-blue-950 dark:text-blue-100"}`}>{children}</div>
);

export function Table({ head, children }: { head: string[]; children: React.ReactNode }) {
  return (
    <div className="card overflow-x-auto p-0">
      <table className="w-full min-w-[640px]">
        <thead className="border-b border-slate-200 dark:border-slate-800"><tr>{head.map((h) => <th key={h} className="th" scope="col">{h}</th>)}</tr></thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{children}</tbody>
      </table>
    </div>
  );
}

export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <label className="block text-sm"><span className="mb-1 block text-slate-600 dark:text-slate-300">{label}</span>{children}</label>;
}

export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { ref.current?.focus(); const k = (e: KeyboardEvent) => e.key === "Escape" && onClose(); window.addEventListener("keydown", k); return () => window.removeEventListener("keydown", k); }, [onClose]);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={onClose}>
      <div ref={ref} tabIndex={-1} role="dialog" aria-modal="true" aria-label={title} className="card fade-in max-h-[85vh] w-full max-w-2xl overflow-auto" onClick={(e) => e.stopPropagation()}>
        <div className="mb-3 flex items-center justify-between"><h2 className="text-lg font-semibold">{title}</h2><button className="btn-ghost" onClick={onClose} aria-label="close">✕</button></div>
        {children}
      </div>
    </div>
  );
}

/** Data loader hook with refresh + error toast. */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[] = [], intervalMs = 0) {
  const { toast } = useApp();
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try { setData(await fn()); setError(null); } catch (e: any) { setError(e.message); if (!quiet) toast(e.message, "err"); } finally { setLoading(false); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { run(); }, [run]);
  useEffect(() => { if (!intervalMs) return; const i = setInterval(() => run(true), intervalMs); return () => clearInterval(i); }, [run, intervalMs]);
  return { data, loading, error, reload: run, setData };
}

export function useAction() {
  const { toast } = useApp();
  const [busy, setBusy] = useState(false);
  const run = async <T,>(fn: () => Promise<T>, ok?: string): Promise<T | undefined> => {
    setBusy(true);
    try { const r = await fn(); if (ok) toast(ok); return r; } catch (e: any) { toast(e.message, "err"); } finally { setBusy(false); }
  };
  return { busy, run };
}

import type { ReactNode } from "react";

const glass =
  "rounded-2xl border border-white/10 bg-slate-900/60 text-white shadow-xl backdrop-blur-xl transition-all duration-200 ease-in-out";

export function MetricRing({
  label,
  value,
  detail,
}: {
  label: string;
  value: number;
  detail: string;
}) {
  const pct = Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : 0;
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const dash = (pct / 100) * circumference;

  return (
    <article className={`${glass} p-5 hover:-translate-y-0.5`}>
      <div className="flex items-center gap-4">
        <svg viewBox="0 0 96 96" className="h-20 w-20 shrink-0" aria-hidden="true">
          <circle cx="48" cy="48" r={radius} fill="none" className="stroke-white/12" strokeWidth="8" />
          <circle
            cx="48"
            cy="48"
            r={radius}
            fill="none"
            stroke="currentColor"
            className="text-debian"
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={`${dash} ${circumference - dash}`}
            transform="rotate(-90 48 48)"
          />
          <text x="48" y="53" textAnchor="middle" className="fill-white" fontSize="14" fontWeight="600">
            {Math.round(pct)}%
          </text>
        </svg>
        <div className="min-w-0">
          <div className="text-xs tracking-wide text-white/60 uppercase">{label}</div>
          <div className="mt-1 truncate text-sm">{detail}</div>
        </div>
      </div>
    </article>
  );
}

export function StatusPill({
  tone,
  children,
}: {
  tone: "ok" | "bad" | "idle";
  children: ReactNode;
}) {
  const dot =
    tone === "ok"
      ? "bg-emerald-400 shadow-[0_0_12px] shadow-emerald-400 animate-pulse"
      : tone === "bad"
        ? "bg-rose-500 shadow-[0_0_12px] shadow-rose-500 animate-pulse"
        : "bg-white/40";
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-white transition-all duration-200 ease-in-out">
      <span className={`h-2 w-2 rounded-full ${dot}`} />
      {children}
    </span>
  );
}

export function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

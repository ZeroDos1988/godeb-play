import { useEffect, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { STATUS_COLORS, type ChartPoint, type ChartMarker } from "@/components/LineChart.tsx";
import { useGet } from "@/lib/useAsync.ts";
import * as ui from "@/components/ui.ts";

export type Status = "ok" | "info" | "warning" | "critical";

export type Finding = { id: string; status: Status; title: string; detail?: string };

export type SeriesInfo = { name: string; unit: string; label: string; value: number };

export type Summary = {
  time: number;
  status: Status;
  findings: Finding[] | null;
  series: SeriesInfo[] | null;
  checked: number;
  host: { uptime: number; cores: number; memTotal: number };
  interval: number;
};

export type RangeData = { from: number; to: number; step: number; series: Record<string, ChartPoint[]> };

export type MonitorEvent = { time: number; source: string; level: Status; text: string };

export const RANGES = ["1h", "6h", "24h", "7d", "30d", "1y"] as const;
export type RangeName = (typeof RANGES)[number];

export const button = ui.button;

export const input = ui.input;

// usePolling reloads every ms while mounted.
export function usePolling(reload: () => void, ms: number) {
  useEffect(() => {
    const id = window.setInterval(reload, ms);
    return () => window.clearInterval(id);
  }, [reload, ms]);
}

export function useSeries(names: string[], range: RangeName) {
  const query = useGet<RangeData>(`/api/plugins/monitor/series?names=${encodeURIComponent(names.join(","))}&range=${range}`);
  usePolling(query.reload, range === "1h" || range === "6h" ? 30_000 : 120_000);
  return query;
}

export function useEvents(range: RangeName): MonitorEvent[] {
  const query = useGet<{ events: MonitorEvent[] }>(`/api/plugins/monitor/events?range=${range}`);
  usePolling(query.reload, 60_000);
  return query.data?.events ?? [];
}

// useMarkers returns the events as chart markers; filter keeps events whose
// source starts with it (e.g. "steam:enshrouded").
export function useMarkers(range: RangeName, filter?: string): ChartMarker[] {
  return toMarkers(useEvents(range), filter);
}

export function toMarkers(events: MonitorEvent[], filter?: string): ChartMarker[] {
  return events
    .filter((e) => !filter || e.source.startsWith(filter))
    .map((e) => ({ time: e.time, text: e.text, level: e.level }));
}

export function useTimeFormat(range: RangeName) {
  const { i18n } = useTranslation();
  const long = range === "7d" || range === "30d" || range === "1y";
  const fmt = new Intl.DateTimeFormat(i18n.language, long ? { day: "2-digit", month: "2-digit" } : { hour: "2-digit", minute: "2-digit" });
  const full = new Intl.DateTimeFormat(i18n.language, { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
  return { axis: (t: number) => fmt.format(t * 1000), full: (t: number) => full.format(t * 1000) };
}

export function StatusIcon({ status }: { status: Status }) {
  // Shape plus color, so the state never depends on color alone.
  const color = STATUS_COLORS[status];
  const path =
    status === "ok"
      ? "M7 12.5l3.2 3.2L17 9"
      : status === "critical"
        ? "M8.5 8.5l7 7M15.5 8.5l-7 7"
        : status === "warning"
          ? "M12 7.5v5.5M12 16.5h.01"
          : "M12 11v5M12 7.5h.01";
  return (
    <svg viewBox="0 0 24 24" className="h-5 w-5 shrink-0" aria-hidden="true">
      <circle cx="12" cy="12" r="10" fill={color} opacity="0.2" />
      <circle cx="12" cy="12" r="10" fill="none" stroke={color} strokeWidth="1.6" />
      <path d={path} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-2xl border border-white/10 bg-slate-900/60 p-4 text-white backdrop-blur-xl ${className}`}>{children}</div>
  );
}

export function RangePicker({ value, onChange }: { value: RangeName; onChange: (r: RangeName) => void }) {
  const { t } = useTranslation();
  return (
    <div className="flex flex-wrap gap-1" role="radiogroup" aria-label={t("monitor.range")}>
      {RANGES.map((r) => (
        <button
          key={r}
          type="button"
          role="radio"
          aria-checked={value === r}
          onClick={() => onChange(r)}
          className={`rounded-xl px-3 py-1 text-xs transition-all duration-200 ${
            value === r ? "bg-white/15 font-semibold text-white" : "text-white/60 hover:bg-white/5"
          }`}
        >
          {t(`monitor.ranges.${r}`)}
        </button>
      ))}
    </div>
  );
}

export function formatUptime(seconds: number, t: (k: string, o?: Record<string, unknown>) => string) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return t("monitor.uptimeDays", { d, h });
  if (h > 0) return t("monitor.uptimeHours", { h, m });
  return t("monitor.uptimeMinutes", { m });
}

// useBaseline loads the usual value per hour for up to eight single series
// (only up to 7 days; longer ranges get none).
export function useBaseline(names: string[], range: RangeName): Record<string, ChartPoint[]> {
  const short = range === "1h" || range === "6h" || range === "24h" || range === "7d";
  const list = names.slice(0, 8);
  const path = short && list.length > 0 ? `/api/plugins/monitor/baseline?names=${encodeURIComponent(list.join(","))}&range=${range}` : "";
  const query = useGet<{ series: Record<string, ChartPoint[] | null> }>(path || "/api/plugins/monitor/baseline?names=cpu&range=1h");
  if (!path || !query.data) return {};
  const out: Record<string, ChartPoint[]> = {};
  for (const [k, v] of Object.entries(query.data.series)) out[k] = v ?? [];
  return out;
}

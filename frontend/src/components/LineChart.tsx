import { useEffect, useMemo, useRef, useState, type PointerEvent } from "react";

// Categorical slots for the dark surface, validated in this order (CVD and
// contrast against slate-900). Assign by series position, never cycle.
export const SERIES_COLORS = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"];

// Status colors are reserved for health, never for a series.
export const STATUS_COLORS = { ok: "#0ca30c", info: "#3987e5", warning: "#fab219", critical: "#d03b3b" } as const;

export type ChartPoint = [number, number, number]; // unix seconds, avg, max

export type ChartSeries = {
  key: string;
  label: string;
  points: ChartPoint[];
};

export type ChartMarker = { time: number; text: string; level: string };

type Props = {
  title: string;
  series: ChartSeries[];
  unit: string;
  from: number;
  to: number;
  step: number;
  markers?: ChartMarker[];
  // reference is the usual value (baseline), drawn as a dashed neutral line.
  reference?: ChartPoint[];
  referenceLabel?: string;
  max?: number; // fixed upper bound, e.g. 100 for percent
  height?: number;
  formatTime: (t: number) => string;
  emptyText: string;
};

const PAD = { top: 12, right: 12, bottom: 24, left: 52 };

export function formatValue(v: number, unit: string): string {
  if (!Number.isFinite(v)) return "–";
  if (unit === "%") return `${v.toFixed(v < 10 ? 1 : 0)} %`;
  if (unit === "B/s" || unit === "B") {
    const units = ["B", "KB", "MB", "GB", "TB"];
    let x = Math.abs(v);
    let i = 0;
    while (x >= 1000 && i < units.length - 1) {
      x /= 1000;
      i++;
    }
    const s = `${x.toFixed(x < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
    return unit === "B/s" ? `${s}/s` : s;
  }
  if (unit === "s") return `${v.toFixed(0)} s`;
  return Math.abs(v) < 10 && v % 1 !== 0 ? v.toFixed(2) : v.toFixed(0);
}

// niceMax rounds the top of the axis up to 1, 2 or 5 times a power of ten
// (in the unit's own base for bytes it still reads well in decimal units).
function niceMax(v: number): number {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 5, 10]) {
    if (m * p >= v) return m * p;
  }
  return 10 * p;
}

export function LineChart({ title, series, unit, from, to, step, markers = [], reference, referenceLabel, max, height = 180, formatTime, emptyText }: Props) {
  const wrap = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(600);
  const [hover, setHover] = useState<number | null>(null);

  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width;
      if (w) setWidth(Math.max(260, w));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const hasData = series.some((s) => s.points.length > 0);
  const top = useMemo(() => {
    if (max !== undefined) return max;
    let m = 0;
    for (const s of series) for (const p of s.points) m = Math.max(m, p[1]);
    for (const p of reference ?? []) m = Math.max(m, p[1]);
    return niceMax(m * 1.1);
  }, [series, max, reference]);

  const plotW = width - PAD.left - PAD.right;
  const plotH = height - PAD.top - PAD.bottom;
  const x = (t: number) => PAD.left + ((t - from) / Math.max(1, to - from)) * plotW;
  const y = (v: number) => PAD.top + plotH - (Math.min(v, top) / top) * plotH;

  // Break the line where samples are missing (service stopped, gap > 2 steps).
  function path(points: ChartPoint[], gap = step) {
    let d = "";
    let last = -Infinity;
    for (const p of points) {
      const cmd = p[0] - last > gap * 2.5 ? "M" : "L";
      d += `${cmd}${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`;
      last = p[0];
    }
    return d;
  }

  // Crosshair snaps to the nearest step of the window.
  function onMove(e: PointerEvent<SVGSVGElement>) {
    const rect = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * width;
    if (px < PAD.left || px > width - PAD.right) {
      setHover(null);
      return;
    }
    const t = from + ((px - PAD.left) / plotW) * (to - from);
    setHover(Math.round(t / step) * step);
  }

  const ticks = [0, 0.5, 1].map((f) => f * top);
  const xTicks = width < 420 ? [0, 1] : [0, 1 / 3, 2 / 3, 1];
  const hoverRows =
    hover === null
      ? []
      : series.map((s, i) => {
          let best: ChartPoint | undefined;
          for (const p of s.points) {
            if (Math.abs(p[0] - hover) <= step && (!best || Math.abs(p[0] - hover) < Math.abs(best[0] - hover))) best = p;
          }
          return { s, i, p: best };
        });
  const hoverMarkers = hover === null ? [] : markers.filter((m) => Math.abs(m.time - hover) <= Math.max(step, (to - from) / 120));
  const tipLeft = hover !== null && x(hover) > width / 2;

  return (
    <figure className="rounded-2xl border border-white/10 bg-slate-900/60 p-3 text-white backdrop-blur-xl">
      <figcaption className="flex flex-wrap items-center justify-between gap-2 px-1 text-sm font-medium">
        <span>{title}</span>
        {series.length > 1 || (reference && reference.length > 0) ? (
          <span className="flex flex-wrap gap-3 text-xs font-normal text-white/70">
            {series.map((s, i) => (
              <span key={s.key} className="inline-flex items-center gap-1.5">
                <span className="inline-block h-0.5 w-3 rounded" style={{ background: SERIES_COLORS[i % SERIES_COLORS.length] }} />
                {s.label}
              </span>
            ))}
            {reference && reference.length > 0 ? (
              <span className="inline-flex items-center gap-1.5">
                <span className="inline-block w-3 border-t border-dashed border-white/60" />
                {referenceLabel}
              </span>
            ) : null}
          </span>
        ) : null}
      </figcaption>
      <div ref={wrap} className="relative mt-2">
        {!hasData ? (
          <p className="flex items-center justify-center text-sm text-white/50" style={{ height }}>
            {emptyText}
          </p>
        ) : (
          <>
            <svg
              viewBox={`0 0 ${width} ${height}`}
              width="100%"
              height={height}
              role="img"
              aria-label={title}
              className="touch-pan-y"
              onPointerMove={onMove}
              onPointerLeave={() => setHover(null)}
            >
              {ticks.map((v) => (
                <g key={v}>
                  <line x1={PAD.left} x2={width - PAD.right} y1={y(v)} y2={y(v)} className="stroke-white/8" />
                  <text x={PAD.left - 6} y={y(v) + 4} textAnchor="end" fontSize="10" className="fill-white/50">
                    {formatValue(v, unit)}
                  </text>
                </g>
              ))}
              {xTicks.map((f) => {
                const t = from + f * (to - from);
                return (
                  <text
                    key={f}
                    x={x(t)}
                    y={height - 6}
                    textAnchor={f === 0 ? "start" : f === 1 ? "end" : "middle"}
                    fontSize="10"
                    className="fill-white/50"
                  >
                    {formatTime(t)}
                  </text>
                );
              })}
              {markers.map((m, i) => (
                <line
                  key={`${m.time}-${i}`}
                  x1={x(m.time)}
                  x2={x(m.time)}
                  y1={PAD.top}
                  y2={PAD.top + plotH}
                  style={{ stroke: m.level === "critical" ? STATUS_COLORS.critical : m.level === "warning" ? STATUS_COLORS.warning : "color-mix(in oklab, var(--color-white) 35%, transparent)" }}
                  strokeDasharray="3 3"
                />
              ))}
              {reference && reference.length > 0 ? (
                <path d={path(reference, 3600)} fill="none" className="stroke-white/55" strokeWidth="1.5" strokeDasharray="5 4" />
              ) : null}
              {series.map((s, i) => (
                <path
                  key={s.key}
                  d={path(s.points)}
                  fill="none"
                  stroke={SERIES_COLORS[i % SERIES_COLORS.length]}
                  strokeWidth="2"
                  strokeLinejoin="round"
                  strokeLinecap="round"
                />
              ))}
              {hover !== null ? (
                <>
                  <line x1={x(hover)} x2={x(hover)} y1={PAD.top} y2={PAD.top + plotH} className="stroke-white/40" />
                  {hoverRows.map(({ s, i, p }) =>
                    p ? (
                      <circle
                        key={s.key}
                        cx={x(p[0])}
                        cy={y(p[1])}
                        r="4"
                        fill={SERIES_COLORS[i % SERIES_COLORS.length]}
                        className="stroke-slate-900"
                        strokeWidth="2"
                      />
                    ) : null,
                  )}
                </>
              ) : null}
            </svg>
            {hover !== null ? (
              <div
                className="pointer-events-none absolute top-1 z-10 max-w-[16rem] rounded-xl border border-white/10 bg-slate-950/90 px-3 py-2 text-xs shadow-xl"
                style={tipLeft ? { right: width - x(hover) + 8 } : { left: x(hover) + 8 }}
              >
                <div className="mb-1 text-white/60">{formatTime(hover)}</div>
                {hoverRows.map(({ s, i, p }) => (
                  <div key={s.key} className="flex items-center gap-2">
                    <span className="inline-block h-0.5 w-3 shrink-0 rounded" style={{ background: SERIES_COLORS[i % SERIES_COLORS.length] }} />
                    <span className="font-semibold text-white">{p ? formatValue(p[1], unit) : "–"}</span>
                    <span className="truncate text-white/60">{s.label}</span>
                  </div>
                ))}
                {hoverMarkers.map((m, i) => (
                  <div key={i} className="mt-1 border-t border-white/10 pt-1 text-white/80">
                    {m.text}
                  </div>
                ))}
              </div>
            ) : null}
          </>
        )}
      </div>
    </figure>
  );
}

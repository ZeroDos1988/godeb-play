import { useTranslation } from "react-i18next";
import { LineChart, formatValue, type ChartMarker, type ChartSeries } from "@/components/LineChart.tsx";
import {
  Card,
  StatusIcon,
  formatUptime,
  useBaseline,
  useMarkers,
  useSeries,
  useTimeFormat,
  type RangeData,
  type RangeName,
  type Summary,
} from "./shared.tsx";

type Props = { summary: Summary | null; range: RangeName };

// pick returns the series of data whose name matches, in the given order.
export function pick(data: RangeData | null, names: { key: string; label: string }[]): ChartSeries[] {
  return names.map((n) => ({ key: n.key, label: n.label, points: data?.series[n.key] ?? [] }));
}

// groups collects "<prefix>:<name>:<suffix>" names, e.g. net:eth0:rx -> eth0.
export function groups(summary: Summary | null, prefix: string): string[] {
  const out = new Set<string>();
  for (const s of summary?.series ?? []) {
    if (!s.name.startsWith(prefix + ":")) continue;
    const parts = s.name.split(":");
    if (parts.length >= 3) out.add(parts.slice(1, -1).join(":"));
  }
  return [...out].sort();
}

export function StatusBanner({ summary }: { summary: Summary }) {
  const { t } = useTranslation();
  const findings = summary.findings ?? [];
  return (
    <Card>
      <div className="flex items-center gap-3">
        <StatusIcon status={summary.status} />
        <div className="min-w-0">
          <div className="text-lg font-semibold">{t(`monitor.status.${summary.status}`)}</div>
          <div className="text-xs text-white/60">
            {summary.checked ? t("monitor.checkedAt", { time: new Date(summary.checked * 1000).toLocaleTimeString() }) : t("monitor.notChecked")}
          </div>
        </div>
      </div>
      {findings.length > 0 ? (
        <ul className="mt-3 space-y-2">
          {findings.map((f) => (
            <li key={f.id} className="flex gap-3 rounded-xl bg-white/5 px-3 py-2 text-sm">
              <StatusIcon status={f.status} />
              <div className="min-w-0">
                <div className="font-medium break-words">{f.title}</div>
                {f.detail ? <div className="text-xs break-words text-white/60">{f.detail}</div> : null}
              </div>
            </li>
          ))}
        </ul>
      ) : null}
    </Card>
  );
}

function Tile({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <Card>
      <div className="text-xs tracking-wide text-white/60 uppercase">{label}</div>
      <div className="mt-1 text-2xl font-semibold tracking-tight">{value}</div>
      {sub ? <div className="mt-1 text-xs text-white/50">{sub}</div> : null}
    </Card>
  );
}

export function latest(summary: Summary | null, name: string): number | undefined {
  return summary?.series?.find((s) => s.name === name)?.value;
}

export function SystemTab({ summary, range }: Props) {
  const { t } = useTranslation();
  const fmt = useTimeFormat(range);
  const markers = useMarkers(range);
  const ifaces = groups(summary, "net");
  const disks = groups(summary, "io");
  const mounts = (summary?.series ?? []).filter((s) => s.name.startsWith("disk:")).map((s) => s.name);

  const base = useBaseline(["cpu"], range);
  const data = useSeries(["cpu", "cpu.iowait", "mem", "swap", "load1", "disk:*", "net:*", "io:*"], range);
  const d = data.data;
  const common = {
    from: d?.from ?? 0,
    to: d?.to ?? 0,
    step: d?.step ?? 10,
    markers,
    formatTime: fmt.axis,
    emptyText: t("monitor.noData"),
  };

  if (!summary) return null;
  const cpu = latest(summary, "cpu");
  const mem = latest(summary, "mem");
  const load = latest(summary, "load1");

  return (
    <div className="space-y-4">
      <StatusBanner summary={summary} />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Tile label={t("monitor.cpu")} value={cpu !== undefined ? formatValue(cpu, "%") : "–"} sub={t("monitor.cores", { count: summary.host.cores })} />
        <Tile label={t("monitor.mem")} value={mem !== undefined ? formatValue(mem, "%") : "–"} sub={formatValue(summary.host.memTotal, "B")} />
        <Tile label={t("monitor.load")} value={load !== undefined ? load.toFixed(2) : "–"} />
        <Tile label={t("monitor.uptime")} value={formatUptime(summary.host.uptime, t)} />
      </div>

      {data.error ? <p className="text-sm text-debian">{data.error}</p> : null}
      <div className={`grid gap-4 lg:grid-cols-2 ${data.loading ? "opacity-60 transition-opacity" : ""}`}>
        <LineChart
          {...common}
          title={t("monitor.cpu")}
          unit="%"
          max={100}
          reference={base["cpu"]}
          referenceLabel={t("monitor.usual")}
          series={pick(d, [
            { key: "cpu", label: t("monitor.cpuUsed") },
            { key: "cpu.iowait", label: t("monitor.iowait") },
          ])}
        />
        <LineChart
          {...common}
          title={t("monitor.mem")}
          unit="%"
          max={100}
          series={pick(d, [
            { key: "mem", label: t("monitor.mem") },
            ...(latest(summary, "swap") !== undefined ? [{ key: "swap", label: t("monitor.swap") }] : []),
          ])}
        />
        <LineChart {...common} title={t("monitor.load")} unit="" series={pick(d, [{ key: "load1", label: t("monitor.load") }])} />
        <LineChart
          {...common}
          title={t("monitor.disk")}
          unit="%"
          max={100}
          series={pick(
            d,
            mounts.map((m) => ({ key: m, label: m.slice(5) })),
          )}
        />
        {ifaces.map((i) => (
          <NetChart key={i} title={t("monitor.net", { name: i })} prefix={`net:${i}`} rx="rx" tx="tx" data={d} common={common} />
        ))}
        {disks.map((disk) => (
          <LineChart
            key={disk}
            {...common}
            title={t("monitor.io", { name: disk })}
            unit="B/s"
            series={pick(d, [
              { key: `io:${disk}:read`, label: t("monitor.read") },
              { key: `io:${disk}:write`, label: t("monitor.write") },
            ])}
          />
        ))}
      </div>
      <EventList range={range} formatTime={fmt.full} markers={markers} />
    </div>
  );
}

type Common = {
  from: number;
  to: number;
  step: number;
  markers: ChartMarker[];
  formatTime: (t: number) => string;
  emptyText: string;
};

export function NetChart({ title, prefix, data, common }: { title: string; prefix: string; rx: string; tx: string; data: RangeData | null; common: Common }) {
  const { t } = useTranslation();
  return (
    <LineChart
      {...common}
      title={title}
      unit="B/s"
      series={pick(data, [
        { key: `${prefix}:rx`, label: t("monitor.rx") },
        { key: `${prefix}:tx`, label: t("monitor.tx") },
      ])}
    />
  );
}

export function EventList({ markers, formatTime }: { range: RangeName; markers: ChartMarker[]; formatTime: (t: number) => string }) {
  const { t } = useTranslation();
  const list = [...markers].reverse().slice(0, 50);
  return (
    <Card>
      <h2 className="text-sm font-semibold">{t("monitor.events")}</h2>
      {list.length === 0 ? (
        <p className="mt-2 text-sm text-white/50">{t("monitor.noEvents")}</p>
      ) : (
        <ul className="mt-2 divide-y divide-white/10 text-sm">
          {list.map((e, i) => (
            <li key={`${e.time}-${i}`} className="flex flex-wrap gap-x-3 py-1.5">
              <span className="font-mono text-xs text-white/50">{formatTime(e.time)}</span>
              <span className="min-w-0 break-words">{e.text}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

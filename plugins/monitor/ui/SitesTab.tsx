import { useTranslation } from "react-i18next";
import { LineChart, formatValue } from "@/components/LineChart.tsx";
import { StatusPill } from "@/components/Metrics.tsx";
import { useGet } from "@/lib/useAsync.ts";
import { pick } from "./SystemTab.tsx";
import { Card, StatusIcon, formatUptime, usePolling, useSeries, useTimeFormat, type Finding, type RangeName, type Status } from "./shared.tsx";

type SiteGame = { id: string; up: boolean; players: number; slots: number };
type SiteStatus = { host: string; time: number; status: Status; findings: Finding[]; values: Record<string, number>; games: SiteGame[]; uptime: number };
type Site = { name: string; address: string; reachable: boolean; lastSeen: number; error?: string; status?: SiteStatus };
export type SitesResponse = { hub: boolean; sites: Site[] };

export function useSites() {
  const q = useGet<SitesResponse>("/api/plugins/monitor/sites");
  usePolling(q.reload, 30_000);
  return q;
}

export function SitesTab({ data, range }: { data: SitesResponse | null; range: RangeName }) {
  const { t } = useTranslation();
  if (!data) return null;
  if (data.sites.length === 0) return <p className="text-sm text-white/60">{t("monitor.sites.none")}</p>;
  return (
    <div className="space-y-6">
      {data.sites.map((s) => (
        <SiteCard key={s.name} site={s} range={range} />
      ))}
    </div>
  );
}

function seriesName(name: string) {
  return name.toLowerCase().replace(/[^a-z0-9._/-]/g, "_").slice(0, 60);
}

function SiteCard({ site, range }: { site: Site; range: RangeName }) {
  const { t } = useTranslation();
  const fmt = useTimeFormat(range);
  const n = seriesName(site.name);
  const data = useSeries([`site:${n}:*`], range);
  const d = data.data;
  const st = site.status;
  const common = { from: d?.from ?? 0, to: d?.to ?? 0, step: d?.step ?? 10, formatTime: fmt.axis, emptyText: t("monitor.noData") };
  const gameKeys = Object.keys(d?.series ?? {}).filter((k) => k.startsWith(`site:${n}:game:`));

  return (
    <section className="space-y-3">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex items-center gap-3">
            <StatusIcon status={!site.reachable ? "critical" : (st?.status ?? "ok")} />
            <div>
              <h2 className="text-lg font-semibold">{site.name}</h2>
              <div className="font-mono text-xs text-white/50">
                {site.address}
                {st?.host ? ` · ${st.host}` : ""}
              </div>
            </div>
          </div>
          <StatusPill tone={site.reachable ? "ok" : "bad"}>{site.reachable ? t("monitor.sites.reachable") : t("monitor.sites.unreachable")}</StatusPill>
        </div>
        {!site.reachable && site.error ? <p className="mt-2 text-xs break-words text-amber-200">{site.error}</p> : null}
        {st ? (
          <>
            <div className="mt-3 grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
              <Value label={t("monitor.cpu")} value={st.values.cpu !== undefined ? formatValue(st.values.cpu, "%") : "–"} />
              <Value label={t("monitor.mem")} value={st.values.mem !== undefined ? formatValue(st.values.mem, "%") : "–"} />
              <Value label={t("monitor.disk")} value={st.values.disk !== undefined ? formatValue(st.values.disk, "%") : "–"} />
              <Value label={t("monitor.uptime")} value={formatUptime(st.uptime, t)} />
            </div>
            {st.games.length > 0 ? (
              <ul className="mt-3 space-y-1 text-sm">
                {st.games.map((g) => (
                  <li key={g.id} className="flex flex-wrap items-center gap-2">
                    <StatusPill tone={g.up ? "ok" : "idle"}>{g.id}</StatusPill>
                    {g.up ? t("monitor.sites.players", { players: g.players, slots: g.slots }) : t("monitor.games.stopped")}
                  </li>
                ))}
              </ul>
            ) : null}
            {st.findings.length > 0 ? (
              <ul className="mt-3 space-y-1">
                {st.findings.map((f) => (
                  <li key={f.id} className="flex items-center gap-2 text-sm">
                    <StatusIcon status={f.status} />
                    <span className="min-w-0 break-words">{f.title}</span>
                  </li>
                ))}
              </ul>
            ) : null}
          </>
        ) : null}
      </Card>
      <div className={`grid gap-4 lg:grid-cols-2 ${data.loading ? "opacity-60 transition-opacity" : ""}`}>
        <LineChart
          {...common}
          title={t("monitor.sites.load")}
          unit="%"
          max={100}
          series={pick(d, [
            { key: `site:${n}:cpu`, label: t("monitor.cpu") },
            { key: `site:${n}:mem`, label: t("monitor.mem") },
          ])}
        />
        {gameKeys.length > 0 ? (
          <LineChart
            {...common}
            title={t("monitor.games.playersChart")}
            unit=""
            series={pick(
              d,
              gameKeys.slice(0, 8).map((k) => ({ key: k, label: k.split(":")[3] ?? k })),
            )}
          />
        ) : null}
      </div>
    </section>
  );
}

function Value({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs text-white/50">{label}</div>
      <div className="font-semibold">{value}</div>
    </div>
  );
}

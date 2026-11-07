import { useState } from "react";
import { useTranslation } from "react-i18next";
import { DataTable } from "@/components/PanelFrame.tsx";
import { LineChart, formatValue } from "@/components/LineChart.tsx";
import { useGet } from "@/lib/useAsync.ts";
import { groups, latest, pick } from "./SystemTab.tsx";
import { button, useBaseline, useMarkers, usePolling, useSeries, useTimeFormat, type RangeName, type Summary } from "./shared.tsx";

type Connection = {
  proto: string;
  direction: "in" | "out" | "forward";
  remote: string;
  local: string;
  port: number;
  service?: string;
  name?: string;
  state?: string;
  bytes: number;
  packets: number;
};

type Remote = { remote: string; name?: string; connections: number; bytes: number; services: string[] };

type Connections = {
  total: number;
  accounting: boolean;
  connections: Connection[];
  remotes: Remote[];
  mocked: boolean;
  detail?: string;
};

// Peers with the most traffic first; the palette has eight slots, so a
// chart never shows more than eight series.
function topPeers(summary: Summary | null, dir: "rx" | "tx", n: number): string[] {
  return groups(summary, "wg")
    .map((p) => ({ p, v: latest(summary, `wg:${p}:${dir}`) ?? 0 }))
    .sort((a, b) => b.v - a.v)
    .slice(0, n)
    .map((x) => x.p);
}

export function NetworkTab({ summary, range }: { summary: Summary | null; range: RangeName }) {
  const { t } = useTranslation();
  const fmt = useTimeFormat(range);
  const markers = useMarkers(range);
  const data = useSeries(["svc:*", "wg:*", "wg.online"], range);
  const d = data.data;
  const common = {
    from: d?.from ?? 0,
    to: d?.to ?? 0,
    step: d?.step ?? 10,
    markers,
    formatTime: fmt.axis,
    emptyText: t("monitor.noData"),
  };
  const services = groups(summary, "svc");
  const label = (name: string) => summary?.series?.find((s) => s.name === `svc:${name}:in`)?.label ?? name;
  const rxPeers = topPeers(summary, "rx", 8);
  const base = useBaseline(
    services.map((s) => `svc:${s}:in`),
    range,
  );
  const txPeers = topPeers(summary, "tx", 8);

  return (
    <div className="space-y-6">
      <section>
        <h2 className="mb-3 text-sm font-semibold">{t("monitor.network.services")}</h2>
        {services.length === 0 ? (
          <p className="text-sm text-white/60">{t("monitor.network.noAccounting")}</p>
        ) : (
          <div className={`grid gap-4 lg:grid-cols-2 ${data.loading ? "opacity-60 transition-opacity" : ""}`}>
            {services.map((s) => (
              <LineChart
                key={s}
                {...common}
                title={label(s)}
                unit="B/s"
                height={150}
                reference={base[`svc:${s}:in`]}
                referenceLabel={t("monitor.usualIn")}
                series={pick(d, [
                  { key: `svc:${s}:in`, label: t("monitor.network.in") },
                  { key: `svc:${s}:out`, label: t("monitor.network.out") },
                ])}
              />
            ))}
          </div>
        )}
      </section>

      {groups(summary, "wg").length > 0 || latest(summary, "wg.online") !== undefined ? (
        <section>
          <h2 className="mb-3 text-sm font-semibold">{t("monitor.network.wireguard")}</h2>
          <div className="grid gap-4 lg:grid-cols-2">
            <LineChart {...common} title={t("monitor.network.online")} unit="" series={pick(d, [{ key: "wg.online", label: t("monitor.network.online") }])} />
            <LineChart
              {...common}
              title={t("monitor.network.fromPeers")}
              unit="B/s"
              series={pick(
                d,
                rxPeers.map((p) => ({ key: `wg:${p}:rx`, label: p })),
              )}
            />
            <LineChart
              {...common}
              title={t("monitor.network.toPeers")}
              unit="B/s"
              series={pick(
                d,
                txPeers.map((p) => ({ key: `wg:${p}:tx`, label: p })),
              )}
            />
          </div>
        </section>
      ) : null}

      <LiveConnections />
    </div>
  );
}

function LiveConnections() {
  const { t } = useTranslation();
  const query = useGet<Connections>("/api/plugins/monitor/connections");
  usePolling(query.reload, 10_000);
  const [details, setDetails] = useState(false);
  const c = query.data;

  return (
    <section>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold">
          {t("monitor.network.live")}
          {c ? <span className="ml-2 font-normal text-white/50">{t("monitor.network.total", { count: c.total })}</span> : null}
        </h2>
        <button type="button" className={button} onClick={() => setDetails((v) => !v)}>
          {details ? t("monitor.network.byRemote") : t("monitor.network.allConnections")}
        </button>
      </div>
      {query.error ? <p className="text-sm text-debian">{query.error}</p> : null}
      {c?.mocked ? (
        <p className="mb-3 rounded-2xl border border-amber-300/20 bg-amber-950/30 px-4 py-3 text-sm text-amber-100">
          {t("panel.mocked")} {c.detail}
        </p>
      ) : null}
      {c && !c.accounting ? <p className="mb-3 text-xs text-white/50">{t("monitor.network.noBytes")}</p> : null}
      {c && !details ? (
        <DataTable
          head={[t("monitor.network.remote"), t("monitor.network.connections"), t("monitor.network.servicesCol"), ...(c.accounting ? [t("monitor.network.bytes")] : [])]}
        >
          {c.remotes.map((r) => (
            <tr key={r.remote}>
              <td className="px-3 py-2">
                <div className="font-mono text-xs">{r.remote}</div>
                {r.name ? <div className="text-xs text-white/60">{r.name}</div> : null}
              </td>
              <td className="px-3 py-2">{r.connections}</td>
              <td className="px-3 py-2 text-xs">{r.services.join(", ")}</td>
              {c.accounting ? <td className="px-3 py-2 text-xs">{formatValue(r.bytes, "B")}</td> : null}
            </tr>
          ))}
        </DataTable>
      ) : null}
      {c && details ? (
        <DataTable
          head={[
            t("monitor.network.direction"),
            t("monitor.network.remote"),
            t("monitor.network.service"),
            t("monitor.network.target"),
            ...(c.accounting ? [t("monitor.network.bytes")] : []),
          ]}
        >
          {c.connections.map((x, i) => (
            <tr key={`${x.remote}-${x.port}-${i}`}>
              <td className="px-3 py-2 text-xs">{t(`monitor.network.dir.${x.direction}`)}</td>
              <td className="px-3 py-2">
                <div className="font-mono text-xs">{x.remote}</div>
                {x.name ? <div className="text-xs text-white/60">{x.name}</div> : null}
              </td>
              <td className="px-3 py-2 text-xs">
                {x.service ?? `${x.proto}/${x.port}`}
                {x.state ? <span className="ml-1 text-white/40">{x.state}</span> : null}
              </td>
              <td className="px-3 py-2 font-mono text-xs">{x.local}</td>
              {c.accounting ? <td className="px-3 py-2 text-xs">{formatValue(x.bytes, "B")}</td> : null}
            </tr>
          ))}
        </DataTable>
      ) : null}
    </section>
  );
}

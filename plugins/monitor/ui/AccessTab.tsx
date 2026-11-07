import { useTranslation } from "react-i18next";
import { DataTable } from "@/components/PanelFrame.tsx";
import { useGet } from "@/lib/useAsync.ts";
import { Card, StatusIcon, usePolling, useTimeFormat, type RangeName } from "./shared.tsx";

type Entry = { time: number; kind: "ssh" | "login" | "logout" | "action" | "ban"; ok: boolean; user?: string; ip?: string; name?: string; detail?: string };
type Source = { ip: string; name?: string; count: number; ports?: string[] };
type Access = {
  entries: Entry[];
  stats: { sshOk: number; sshFailed: number; loginOk: number; loginFailed: number; actions: number; bans: number; blocks: number };
  topBlocked: Source[];
  topFailed: Source[];
  notes?: string[];
  mocked: boolean;
};

// The journal is read on demand, so the access view goes back at most 7 days.
function accessRange(range: RangeName): "1h" | "6h" | "24h" | "7d" {
  return range === "30d" || range === "1y" ? "7d" : range;
}

function Stat({ label, ok, bad }: { label: string; ok?: number; bad?: number }) {
  const { t } = useTranslation();
  return (
    <Card>
      <div className="text-xs tracking-wide text-white/60 uppercase">{label}</div>
      <div className="mt-1 flex flex-wrap items-baseline gap-x-3 text-sm">
        {ok !== undefined ? (
          <span>
            <span className="text-2xl font-semibold">{ok}</span> {t("monitor.access.ok")}
          </span>
        ) : null}
        {bad !== undefined ? (
          <span className={bad > 0 ? "text-amber-200" : "text-white/60"}>
            <span className="text-2xl font-semibold">{bad}</span> {t("monitor.access.failed")}
          </span>
        ) : null}
      </div>
    </Card>
  );
}

export function AccessTab({ range }: { range: RangeName }) {
  const { t } = useTranslation();
  const r = accessRange(range);
  const fmt = useTimeFormat("24h");
  const query = useGet<Access>(`/api/plugins/monitor/access?range=${r}`);
  usePolling(query.reload, 60_000);
  const a = query.data;

  return (
    <div className={`space-y-6 ${query.loading ? "opacity-70 transition-opacity" : ""}`}>
      {r !== range ? <p className="text-xs text-white/50">{t("monitor.access.clamped")}</p> : null}
      {query.error ? <p className="text-sm text-debian">{query.error}</p> : null}
      {a?.mocked ? (
        <p className="rounded-2xl border border-amber-300/20 bg-amber-950/30 px-4 py-3 text-sm text-amber-100">
          {t("panel.mocked")} {(a.notes ?? []).join(" ")}
        </p>
      ) : null}
      {a ? (
        <>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Stat label={t("monitor.access.ssh")} ok={a.stats.sshOk} bad={a.stats.sshFailed} />
            <Stat label={t("monitor.access.godeb")} ok={a.stats.loginOk} bad={a.stats.loginFailed} />
            <Stat label={t("monitor.access.actions")} ok={a.stats.actions} />
            <Card>
              <div className="text-xs tracking-wide text-white/60 uppercase">{t("monitor.access.defense")}</div>
              <div className="mt-1 text-sm">
                <span className="text-2xl font-semibold">{a.stats.bans}</span> {t("monitor.access.bans")}
                <span className="ml-3 text-2xl font-semibold">{a.stats.blocks}</span> {t("monitor.access.blocks")}
              </div>
            </Card>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <section>
              <h2 className="mb-2 text-sm font-semibold">{t("monitor.access.topFailed")}</h2>
              {a.topFailed.length === 0 ? (
                <p className="text-sm text-white/50">{t("monitor.access.none")}</p>
              ) : (
                <DataTable head={[t("monitor.network.remote"), t("monitor.access.count")]}>
                  {a.topFailed.map((s) => (
                    <tr key={s.ip}>
                      <td className="px-3 py-2 font-mono text-xs">
                        {s.ip}
                        {s.name ? <span className="ml-2 font-sans text-white/60">{s.name}</span> : null}
                      </td>
                      <td className="px-3 py-2">{s.count}</td>
                    </tr>
                  ))}
                </DataTable>
              )}
            </section>
            <section>
              <h2 className="mb-2 text-sm font-semibold">{t("monitor.access.topBlocked")}</h2>
              {a.topBlocked.length === 0 ? (
                <p className="text-sm text-white/50">{t("monitor.access.noBlocks")}</p>
              ) : (
                <DataTable head={[t("monitor.network.remote"), t("monitor.access.count"), t("monitor.access.ports")]}>
                  {a.topBlocked.map((s) => (
                    <tr key={s.ip}>
                      <td className="px-3 py-2 font-mono text-xs">{s.ip}</td>
                      <td className="px-3 py-2">{s.count}</td>
                      <td className="px-3 py-2 text-xs">{(s.ports ?? []).join(", ")}</td>
                    </tr>
                  ))}
                </DataTable>
              )}
            </section>
          </div>

          <section>
            <h2 className="mb-2 text-sm font-semibold">{t("monitor.access.timeline")}</h2>
            {a.entries.length === 0 ? (
              <p className="text-sm text-white/50">{t("monitor.access.none")}</p>
            ) : (
              <ul className="space-y-1">
                {a.entries.map((e, i) => (
                  <li key={`${e.time}-${i}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-xl bg-slate-900/60 px-3 py-2 text-sm">
                    <StatusIcon status={e.ok ? "ok" : e.kind === "ban" ? "info" : "warning"} />
                    <span className="font-mono text-xs text-white/50">{fmt.full(e.time)}</span>
                    <span className="font-medium">{t(`monitor.access.kind.${e.kind}`)}</span>
                    {e.user ? <span className="text-white/80">{e.user}</span> : null}
                    {e.ip ? <span className="font-mono text-xs text-white/60">{e.ip}</span> : null}
                    {e.name ? <span className="text-xs text-white/60">({e.name})</span> : null}
                    {e.detail ? <span className="min-w-0 text-xs break-all text-white/50">{e.detail}</span> : null}
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      ) : null}
    </div>
  );
}

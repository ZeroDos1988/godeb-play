import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { DataTable, PanelFrame } from "@/components/PanelFrame.tsx";
import { api } from "@/lib/api.ts";
import type { CommandEnvelope } from "@/lib/types.ts";
import { useGet } from "@/lib/useAsync.ts";
import * as ui from "@/components/ui.ts";
import { More } from "@/components/Section.tsx";
import { AutoRebootForm, RebootCard, useReboot } from "./Reboot.tsx";

type Service = {
  unit: string;
  load: string;
  active: string;
  sub: string;
  description: string;
};

type ServiceList = CommandEnvelope & { services: Service[] };

type ServerInfo = {
  hostname: string;
  os: string;
  kernel: string;
  uptime: number;
  load: number[];
  cpus: number;
  memTotal: number;
  memUsed: number;
};

type ServiceView = {
  unit: string;
  key: string;
  group: string;
  name: string;
  active: string;
  sub: string;
  enabled: string;
  since?: number;
  memory: number;
  cpu: number;
  critical?: boolean;
  locked?: boolean;
};

type Overview = CommandEnvelope & {
  server: ServerInfo;
  services: ServiceView[];
};

type Action = "start" | "stop" | "restart";

const action =
  "inline-flex min-h-11 items-center justify-center rounded-lg border border-white/15 bg-white/5 px-3 text-xs text-white transition-all duration-200 ease-in-out enabled:hover:bg-white/15 disabled:opacity-40 md:min-h-8";

// The services page follows HestiaCP: the server's key figures, then the
// services that matter with status, uptime, CPU and memory, then (second
// tab) every loaded unit.
export default function Panel() {
  const { t } = useTranslation();
  const [tab, setTab] = useState<"server" | "all">("server");
  const tabs = (
    <div className="inline-flex rounded-xl border border-white/10 bg-slate-900/60 p-1 text-sm text-white backdrop-blur-xl">
      {(["server", "all"] as const).map((id) => (
        <button
          key={id}
          type="button"
          aria-pressed={tab === id}
          onClick={() => setTab(id)}
          className={`min-h-9 rounded-lg px-3 transition-all duration-200 ease-in-out ${tab === id ? "bg-white/15 font-medium" : "text-white/70 hover:text-white"}`}
        >
          {t(`systemd.tab.${id}`)}
        </button>
      ))}
    </div>
  );
  return tab === "server" ? <ServerServices tabs={tabs} /> : <AllUnits tabs={tabs} />;
}

function useAction(reload: () => void) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  async function run(unit: string, act: Action) {
    setBusy(`${unit}:${act}`);
    setError("");
    try {
      await api("/api/plugins/systemd/action", {
        method: "POST",
        body: JSON.stringify({ unit, action: act }),
      });
      reload();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("systemd.failed"));
    } finally {
      setBusy("");
    }
  }
  return { busy, error, run };
}

function ServerServices({ tabs }: { tabs: ReactNode }) {
  const { t } = useTranslation();
  const query = useGet<Overview>("/api/plugins/systemd/overview");
  const { reload } = query;
  const { busy, error, run } = useAction(reload);
  const reboot = useReboot();
  const reloadReboot = reboot.reload;

  // CPU is measured between two polls, so the page refreshes itself.
  useEffect(() => {
    const id = window.setInterval(() => {
      reload();
      reloadReboot();
    }, 10000);
    return () => window.clearInterval(id);
  }, [reload, reloadReboot]);

  function confirmAndRun(s: ServiceView, act: Action) {
    if (
      s.critical &&
      act !== "start" &&
      !window.confirm(
        t(`systemd.confirm.${act}`, {
          name: t(`services.${s.key}.name`, { defaultValue: s.name }),
        }),
      )
    ) {
      return;
    }
    void run(s.unit, act);
  }

  const data = query.data;
  return (
    <PanelFrame
      tabs={tabs}
      title={t("systemd.title")}
      description={t("systemd.overviewDescription")}
      command={data?.command}
      mocked={data?.mocked}
      detail={data?.detail}
      loading={query.loading && !data}
      error={query.error}
      onRefresh={reload}
    >
      {data ? (
        <>
          {reboot.data ? <RebootCard status={reboot.data} onChanged={reloadReboot} /> : null}
          {error ? <p className="mb-4 text-sm text-debian">{error}</p> : null}
          <ServiceTable
            services={data.services.filter((s) => !unused(s))}
            busy={busy}
            onAction={confirmAndRun}
          />
          {data.services.some(unused) ? (
            <More title={t("systemd.unused", { count: data.services.filter(unused).length })}>
              <ServiceTable services={data.services.filter(unused)} busy={busy} onAction={confirmAndRun} />
            </More>
          ) : null}
          {reboot.data ? (
            <More title={t("systemd.reboot.autoTitle")}>
              <AutoRebootForm settings={reboot.data.settings} onSaved={reloadReboot} />
            </More>
          ) : null}
        </>
      ) : null}
    </PanelFrame>
  );
}

// unused: stopped and not started at boot, e.g. the port forwarding on a
// home VM. Units that cut the admin off when stopped stay visible.
function unused(s: ServiceView) {
  return s.active !== "active" && s.active !== "failed" && s.enabled !== "enabled" && !s.critical;
}

// Fixed columns like the service list of HestiaCP: the values line up no
// matter how many buttons a row has.
const columns =
  "md:grid md:grid-cols-[minmax(0,1fr)_7rem_7rem_9rem_12rem] md:items-center md:gap-4";

function ServiceTable({
  services,
  busy,
  onAction,
}: {
  services: ServiceView[];
  busy: string;
  onAction: (s: ServiceView, a: Action) => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="overflow-hidden rounded-2xl border border-white/10 bg-slate-900/60 text-white backdrop-blur-xl">
      <div className={`hidden border-b border-white/10 px-4 py-2.5 text-[11px] tracking-wide text-white/50 uppercase ${columns}`}>
        <span>{t("systemd.service")}</span>
        <span>{t("systemd.status")}</span>
        <span>{t("systemd.uptime")}</span>
        <span>{t("systemd.resources")}</span>
        <span className="text-end">{t("systemd.actions")}</span>
      </div>
      <ul className="divide-y divide-white/10">
        {services.map((s) => (
          <ServiceRow key={s.unit} service={s} busy={busy} onAction={(act) => onAction(s, act)} />
        ))}
      </ul>
    </div>
  );
}

function ServiceRow({
  service: s,
  busy,
  onAction,
}: {
  service: ServiceView;
  busy: string;
  onAction: (a: Action) => void;
}) {
  const { t } = useTranslation();
  const running = s.active === "active";
  // Oneshot units (ufw, wg-quick) stay active without a process.
  const oneshot = running && s.sub === "exited";
  const failed = s.active === "failed";
  const dot = running ? "bg-emerald-400" : failed ? "bg-rose-400" : s.critical ? "bg-amber-400" : "bg-white/30";
  const name = t(`services.${s.key}.name`, { defaultValue: s.unit });
  const desc = t(`services.${s.key}.description`, { defaultValue: s.name });
  const working = busy.startsWith(`${s.unit}:`);
  const state = oneshot
    ? t("systemd.activeOneshot")
    : running
      ? t("systemd.running")
      : failed
        ? t("systemd.failedState")
        : t("systemd.stopped");
  const stateTone = running ? "text-emerald-300" : failed ? "text-rose-300" : s.critical ? "text-amber-200" : "text-white/60";
  return (
    <li className={`grid grid-cols-2 gap-x-4 gap-y-2 px-4 py-3 transition-all duration-200 hover:bg-white/5 ${columns}`}>
      <div className="col-span-2 flex min-w-0 items-start gap-3 md:col-span-1">
        <span className={`mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full ${dot}`} aria-hidden />
        <div className="min-w-0">
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="font-medium">{name}</span>
            <span className="truncate font-mono text-[11px] text-white/40">{s.unit}</span>
          </div>
          <div className="truncate text-xs text-white/60">{desc}</div>
        </div>
      </div>
      <Cell label={t("systemd.status")} value={state} tone={stateTone} />
      <Cell
        label={t("systemd.uptime")}
        value={running && s.since ? duration(Math.max(0, Date.now() / 1000 - s.since), t) : "–"}
      />
      <Cell
        label={t("systemd.resources")}
        value={
          running && !oneshot
            ? `${s.cpu >= 0 ? `${s.cpu.toFixed(1)} %` : "…"} · ${s.memory >= 0 ? bytes(s.memory) : "–"}`
            : "–"
        }
      />
      <div className="flex items-center justify-end gap-1.5 md:col-auto">
        {s.locked ? (
          <span className="text-xs text-white/40">{t("systemd.locked")}</span>
        ) : (
          <>
            <button type="button" className={action} disabled={working || !running} onClick={() => onAction("restart")}>
              {t("systemd.restart")}
            </button>
            {running ? (
              <button type="button" className={`${action} w-16 text-rose-300`} disabled={working} onClick={() => onAction("stop")}>
                {t("systemd.stop")}
              </button>
            ) : (
              <button type="button" className={`${action} w-16 text-emerald-300`} disabled={working} onClick={() => onAction("start")}>
                {t("systemd.start")}
              </button>
            )}
          </>
        )}
      </div>
    </li>
  );
}

// Cell is one value of a row; the label only shows on phones, where the
// header row is hidden.
function Cell({ label, value, tone = "" }: { label: string; value: string; tone?: string }) {
  return (
    <div className="min-w-0 text-sm">
      <div className="text-[10px] tracking-wide text-white/40 uppercase md:hidden">{label}</div>
      <div className={`truncate ${tone}`}>{value}</div>
    </div>
  );
}

function AllUnits({ tabs }: { tabs: ReactNode }) {
  const { t } = useTranslation();
  const query = useGet<ServiceList>("/api/plugins/systemd/services");
  const [filter, setFilter] = useState("");
  const { busy, error, run } = useAction(query.reload);

  const services = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    const all = query.data?.services ?? [];
    if (!needle) {
      return all;
    }
    return all.filter(
      (s) =>
        s.unit.toLowerCase().includes(needle) ||
        s.description.toLowerCase().includes(needle),
    );
  }, [filter, query.data]);

  return (
    <PanelFrame
      tabs={tabs}
      title={t("systemd.allTitle")}
      description={t("systemd.description")}
      command={query.data?.command}
      mocked={query.data?.mocked}
      detail={query.data?.detail}
      loading={query.loading}
      error={query.error}
      onRefresh={query.reload}
    >
      <label className="mb-4 block max-w-sm text-sm">
        <span className="mb-1 block text-xs tracking-wide text-muted uppercase">
          {t("systemd.filter")}
        </span>
        <input
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          placeholder="ssh"
          className={`${ui.input} font-mono`}
        />
      </label>
      {error ? <p className="mb-4 text-sm text-debian">{error}</p> : null}
      {query.data ? (
        <DataTable
          head={[
            t("systemd.unit"),
            t("systemd.active"),
            t("systemd.sub"),
            t("systemd.descriptionCol"),
            "",
          ]}
        >
          {services.map((service) => (
            <tr key={service.unit}>
              <td className="px-3 py-2 font-mono text-xs">{service.unit}</td>
              <td
                className={`px-3 py-2 ${service.active === "active" ? "text-emerald-300" : "text-white/50"}`}
              >
                {service.active}
              </td>
              <td className="px-3 py-2">{service.sub}</td>
              <td className="px-3 py-2">{service.description}</td>
              <td className="space-x-3 px-3 py-2 text-right whitespace-nowrap">
                {(["start", "restart", "stop"] as const).map((act) => (
                  <button
                    key={act}
                    type="button"
                    disabled={busy !== ""}
                    onClick={() => void run(service.unit, act)}
                    className={`text-xs transition-all duration-200 ease-in-out enabled:hover:underline disabled:opacity-50 ${act === "stop" ? "text-rose-300" : act === "start" ? "text-emerald-300" : "text-white/80"}`}
                  >
                    {t(`systemd.${act}`)}
                  </button>
                ))}
              </td>
            </tr>
          ))}
        </DataTable>
      ) : null}
    </PanelFrame>
  );
}

function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 10 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

function duration(
  seconds: number,
  t: (k: string, o?: Record<string, unknown>) => string,
): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return t("systemd.dur.dh", { d, h });
  if (h > 0) return t("systemd.dur.hm", { h, m });
  return t("systemd.dur.m", { m });
}

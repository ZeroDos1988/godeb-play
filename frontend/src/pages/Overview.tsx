import { useEffect, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { formatBytes } from "@/components/Metrics.tsx";
import { Help } from "@/components/Help.tsx";
import { PluginIcon } from "@/components/Icons.tsx";
import * as ui from "@/components/ui.ts";
import { api } from "@/lib/api.ts";
import { useGet } from "@/lib/useAsync.ts";
import type { PluginMeta, SystemInfo } from "@/lib/types.ts";

type Level = "ok" | "info" | "warning" | "critical";
// Fix is the one-click action of a finding: POST body to an existing route.
type Fix = { action: string; path: string; body?: unknown };
type Health = {
  status: Level;
  findings: { id: string; status: string; title: string; fix?: Fix }[] | null;
  series: { name: string; value: number }[] | null;
};
type DoctorReport = {
  findings: { area: string; level: string; text: string; page?: string; fix?: Fix }[];
  fails: number;
  warns: number;
};
type Upgrades = { packages: unknown[]; security: number; settings?: { autoSecurity?: boolean } };
type Jails = { jails?: { name: string; currentlyBanned: number; totalBanned: number }[] };
type Services = {
  server?: { uptime: number; load: number[]; cpus: number };
  services: { unit: string; key: string; name: string; active: string; locked?: boolean }[];
};
type Peers = { peers?: { live?: boolean }[]; interface?: { up?: boolean } };
type Certs = { certificates?: { name: string; notAfter: string }[] };

// The overview refreshes itself; doctor and the plugin cards only when the
// page opens or on demand.
const REFRESH_MS = 10_000;
const CERT_WARN_DAYS = 21;

const dot: Record<Level, string> = {
  ok: "bg-emerald-500",
  info: "bg-emerald-500",
  warning: "bg-amber-400",
  critical: "bg-rose-500 animate-pulse",
};
const rank: Level[] = ["ok", "info", "warning", "critical"];
const worst = (...levels: Level[]) => rank[Math.max(...levels.map((l) => rank.indexOf(l)))];

// Overview is the dashboard: one line whether the server needs anything,
// then one tile per area that matters (load, updates, bans, tunnel,
// services, certificates, game servers). A tile only shows when its
// plugin is switched on.
export function Overview() {
  const { t, i18n } = useTranslation();
  const system = useGet<SystemInfo>("/api/system");
  const health = useGet<Health>("/api/plugins/monitor/summary");
  const doctor = useGet<DoctorReport>("/api/doctor");
  const apt = useGet<Upgrades>("/api/plugins/apt/upgradable");
  const bans = useGet<Jails>("/api/plugins/fail2ban/status");
  const services = useGet<Services>("/api/plugins/systemd/overview");
  const peers = useGet<Peers>("/api/plugins/wireguard/peers");
  const certs = useGet<Certs>("/api/plugins/certbot/certificates");
  // Findings only link to pages of plugins that are switched on.
  const enabled = new Set((useGet<{ plugins: PluginMeta[] }>("/api/plugins").data?.plugins ?? []).map((p) => p.id));
  const pageLink = (page?: string) => (page && enabled.has(page) ? `#/${page}` : undefined);

  const reloadSystem = system.reload;
  const reloadHealth = health.reload;
  useEffect(() => {
    const id = window.setInterval(() => {
      reloadSystem();
      reloadHealth();
    }, REFRESH_MS);
    return () => window.clearInterval(id);
  }, [reloadSystem, reloadHealth]);

  const reloadDoctor = doctor.reload;
  const refresh = () => {
    reloadDoctor();
    reloadHealth();
  };

  const info = system.data;
  const series = (name: string) => health.data?.series?.find((s) => s.name === name)?.value;
  const cpu = series("cpu") ?? info?.cpu ?? 0;

  const doctorIssues = (doctor.data?.findings ?? []).filter((f) => f.level === "FAIL" || f.level === "WARN");
  // The doctor's reboot finding carries the button; skip the monitor's twin.
  const doctorReboot = doctorIssues.some((f) => f.page === "systemd" && f.fix?.path.includes("/reboot"));
  const monitorIssues = (health.data?.findings ?? []).filter(
    (f) => f.status !== "info" && !(doctorReboot && f.id === "reboot"),
  );
  const issueCount = monitorIssues.length + doctorIssues.length;
  const status = worst(
    health.data?.status ?? "ok",
    doctor.data?.fails ? "critical" : doctorIssues.length ? "warning" : "ok",
  );

  const pending = apt.data?.packages.length ?? 0;
  const banned = (bans.data?.jails ?? []).reduce((sum, j) => sum + j.currentlyBanned, 0);
  const svc = services.data?.services ?? [];
  const stopped = svc.filter((s) => s.active !== "active");
  const peerList = peers.data?.peers ?? [];
  const certList = (certs.data?.certificates ?? [])
    .map((c) => ({ ...c, days: daysUntil(c.notAfter) }))
    .sort((a, b) => a.days - b.days);
  const expiring = certList.filter((c) => c.days < CERT_WARN_DAYS);
  const expired = certList.filter((c) => c.days < 0);

  return (
    <section>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h1 className="text-2xl font-semibold tracking-tight">{t("overview.title")}</h1>
        {info ? (
          <p className="text-sm text-muted">
            {info.os} · {t("overview.kernel")} {info.kernel}
          </p>
        ) : null}
      </div>

      {system.error ? (
        <p className="mt-6 rounded-2xl border border-rose-400/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          {t("overview.unreachable", { error: system.error })}
        </p>
      ) : null}

      {/* State: quiet while the server runs on its own, a short list as
          soon as something needs a look. */}
      <article className={`${ui.card} mt-5`}>
        <div className="flex flex-wrap items-center gap-3">
          <span className={`h-3 w-3 shrink-0 rounded-full ${dot[status]}`} aria-hidden="true" />
          <p className="flex min-w-0 flex-1 items-center gap-2 text-lg font-semibold">
            {issueCount === 0
              ? doctor.loading && !doctor.data
                ? t("common.loading")
                : t("overview.allGood")
              : t("overview.attention", { count: issueCount })}
            <Help>{t("overview.doctorHint")}</Help>
          </p>
          <button
            type="button"
            className={`${ui.button} w-11 px-0 text-lg md:w-10`}
            disabled={doctor.loading}
            title={t("overview.doctorOpen")}
            aria-label={t("overview.doctorOpen")}
            onClick={refresh}
          >
            <span aria-hidden className={doctor.loading ? "animate-spin" : ""}>
              ↻
            </span>
          </button>
        </div>
        {issueCount > 0 ? (
          <ul className="mt-4 divide-y divide-white/10 border-t border-white/10 text-sm">
            {monitorIssues.map((f) => (
              <Issue
                key={f.id}
                level={f.status === "critical" ? "critical" : "warning"}
                area={t("monitor.tile")}
                text={f.title}
                href="#/monitor"
                fix={f.fix}
                onFixed={refresh}
              />
            ))}
            {doctorIssues.slice(0, 10).map((f, i) => (
              <Issue
                key={`${f.area}-${i}`}
                level={f.level === "FAIL" ? "critical" : "warning"}
                area={f.area}
                text={f.text}
                href={pageLink(f.page)}
                fix={f.fix}
                onFixed={refresh}
              />
            ))}
          </ul>
        ) : null}
      </article>

      <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {info ? (
          <Tile icon="server" title={t("overview.system")} href={services.data ? "#/systemd" : undefined}>
            <Bar label={t("overview.cpu")} value={cpu} detail={`${Math.round(cpu)} %`} />
            <Bar
              label={t("overview.ram")}
              value={percent(info.memUsed, info.memTotal)}
              detail={`${formatBytes(info.memUsed)} / ${formatBytes(info.memTotal)}`}
            />
            <Bar
              label={t("overview.disk")}
              value={percent(info.diskUsed, info.diskTotal)}
              detail={`${formatBytes(info.diskUsed)} / ${formatBytes(info.diskTotal)}`}
            />
            {services.data?.server ? (
              <dl className="mt-1 grid grid-cols-2 gap-2 text-sm">
                <div>
                  <dt className="text-xs text-white/55">{t("overview.load")}</dt>
                  <dd className="font-mono">{services.data.server.load.map((l) => l.toFixed(2)).join(" · ")}</dd>
                </div>
                <div>
                  <dt className="text-xs text-white/55">{t("overview.uptime")}</dt>
                  <dd>{uptime(services.data.server.uptime, t)}</dd>
                </div>
              </dl>
            ) : null}
          </Tile>
        ) : null}

        {apt.data ? (
          <Tile
            icon="upgrade"
            title={t("overview.updates")}
            href="#/apt"
            value={pending === 0 ? t("overview.upToDate") : t("overview.pending", { count: pending })}
            tone={apt.data.security > 0 ? "critical" : pending > 0 ? "warning" : "ok"}
          >
            {apt.data.security > 0 ? (
              <p className="text-sm text-rose-300">{t("overview.securityPending", { count: apt.data.security })}</p>
            ) : null}
            <p className="text-sm text-white/60">
              {apt.data.settings?.autoSecurity ? t("overview.autoSecurityOn") : t("overview.autoSecurityOff")}
            </p>
          </Tile>
        ) : null}

        {bans.data ? (
          <Tile
            icon="lock"
            title="Fail2ban"
            href="#/fail2ban"
            value={banned === 0 ? t("overview.noneBlocked") : t("overview.blockedCount", { count: banned })}
            tone={banned > 0 ? "info" : "ok"}
          >
            <ul className="space-y-1 text-sm">
              {(bans.data.jails ?? []).map((j) => (
                <li key={j.name} className="flex justify-between gap-3">
                  <span className="font-mono text-white/80">{j.name}</span>
                  <span className="text-white/60">{t("overview.jailLine", { now: j.currentlyBanned, total: j.totalBanned })}</span>
                </li>
              ))}
            </ul>
          </Tile>
        ) : null}

        {peers.data ? (
          <Tile
            icon="network"
            title={t("overview.tunnel")}
            href="#/wireguard"
            value={peers.data.interface?.up ? t("overview.tunnelUp") : t("overview.tunnelDown")}
            tone={peers.data.interface?.up ? "ok" : "warning"}
          >
            <p className="text-sm text-white/60">
              {t("overview.peersLine", { live: peerList.filter((p) => p.live).length, total: peerList.length })}
            </p>
          </Tile>
        ) : null}

        {services.data ? (
          <Tile
            icon="cogs"
            title={t("overview.services")}
            href="#/systemd"
            value={t("overview.servicesLine", { running: svc.length - stopped.length, total: svc.length })}
            tone={stopped.length > 0 ? "warning" : "ok"}
          >
            {stopped.length > 0 ? (
              <ul className="space-y-1 text-sm">
                {stopped.map((s) => (
                  <li key={s.unit} className="flex justify-between gap-3">
                    <span>{t(`services.${s.key}.name`, { defaultValue: s.name })}</span>
                    <span className="text-amber-200">{s.active}</span>
                  </li>
                ))}
              </ul>
            ) : null}
          </Tile>
        ) : null}

        {certList.length > 0 ? (
          <Tile
            icon="certificate"
            title={t("overview.certs")}
            href="#/certbot"
            value={
              expired.length > 0
                ? t("overview.certsExpired", { count: expired.length })
                : expiring.length > 0
                  ? t("overview.certsExpiring", { count: expiring.length })
                  : t("overview.certsOk", { count: certList.length })
            }
            tone={expiring.some((c) => c.days < 7) ? "critical" : expiring.length > 0 ? "warning" : "ok"}
          >
            <p className="text-sm text-white/60">
              {t("overview.certNext", {
                name: certList[0].name,
                date: new Date(certList[0].notAfter).toLocaleDateString(i18n.language),
              })}
            </p>
          </Tile>
        ) : null}

      </div>

      {info?.mocked ? (
        <p className="mt-4 rounded-2xl border border-amber-300/20 bg-amber-950/30 px-4 py-3 text-sm text-amber-100">
          {t("overview.sample")}
          {info.detail ? ` ${info.detail}` : ""}
        </p>
      ) : null}
    </section>
  );
}

// Tile is one area of the dashboard: icon, title, the headline value with
// a coloured dot, details below. The whole header links to the page.
function Tile({
  icon,
  title,
  href,
  value,
  tone,
  children,
}: {
  icon: string;
  title: string;
  href?: string;
  value?: string;
  tone?: Level;
  children?: ReactNode;
}) {
  const head = (
    <div className="flex items-center gap-2 text-sm font-medium text-white/70">
      <PluginIcon name={icon} />
      <span className="flex-1">{title}</span>
      {href ? (
        <span aria-hidden className="text-white/40 transition-all duration-200 group-hover:translate-x-0.5 group-hover:text-brand-cyan">
          →
        </span>
      ) : null}
    </div>
  );
  return (
    <article className={`${ui.card} flex flex-col gap-3`}>
      {href ? (
        <a href={href} className="group -m-1 rounded-xl p-1">
          {head}
        </a>
      ) : (
        head
      )}
      {value ? (
        <p className="flex items-center gap-2 text-xl font-semibold tracking-tight">
          {tone ? <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${dot[tone]}`} aria-hidden /> : null}
          {value}
        </p>
      ) : null}
      {children}
    </article>
  );
}

// Bar is a labelled usage bar; amber from 75 %, red from 90 %.
function Bar({ label, value, detail }: { label: string; value: number; detail: string }) {
  const pct = Math.max(0, Math.min(100, value));
  const color = pct >= 90 ? "bg-rose-500" : pct >= 75 ? "bg-amber-400" : "bg-brand-cyan";
  return (
    <div>
      <div className="flex justify-between gap-3 text-sm">
        <span className="text-white/70">{label}</span>
        <span className="font-mono text-xs text-white/60">{detail}</span>
      </div>
      <div className="mt-1 h-2 overflow-hidden rounded-full bg-white/10">
        <div className={`h-full rounded-full ${color} transition-all duration-500`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function Issue({
  level,
  area,
  text,
  href,
  fix,
  onFixed,
}: {
  level: Level;
  area: string;
  text: string;
  href?: string;
  fix?: Fix;
  onFixed: () => void;
}) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function run(f: Fix) {
    setBusy(true);
    setError("");
    try {
      await api(f.path, { method: "POST", body: f.body === undefined ? undefined : JSON.stringify(f.body) });
      onFixed();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("fix.failed"));
    } finally {
      setBusy(false);
    }
  }

  const body = (
    <>
      <span className={`h-2 w-2 shrink-0 rounded-full ${dot[level]}`} aria-hidden />
      <span className="w-16 shrink-0 truncate text-xs text-white/55 sm:w-24">{area}</span>
      <span className="min-w-0 flex-1 break-words">{text}</span>
      {href ? (
        <span aria-hidden className="text-white/40 transition-all duration-200 group-hover:translate-x-0.5 group-hover:text-brand-cyan">
          →
        </span>
      ) : null}
    </>
  );
  return (
    <li className="py-1">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        {href ? (
          <a href={href} className="group -mx-2 flex min-h-11 min-w-0 basis-full items-center gap-3 rounded-lg px-2 py-1 transition-all duration-200 hover:bg-white/5 sm:flex-1 sm:basis-0">
            {body}
          </a>
        ) : (
          <div className="flex min-h-11 min-w-0 basis-full items-center gap-3 py-1 sm:flex-1 sm:basis-0">{body}</div>
        )}
        {fix ? (
          <button type="button" className={`${ui.button} ms-auto mb-1 sm:mb-0`} disabled={busy} onClick={() => void run(fix)}>
            {busy ? t("fix.working") : t(`fix.${fix.action}`, { defaultValue: t("fix.generic") })}
          </button>
        ) : null}
      </div>
      {error ? <p className="ps-5 pb-1 text-xs break-words text-debian">{error}</p> : null}
    </li>
  );
}

function percent(used: number, total: number) {
  return total ? (used / total) * 100 : 0;
}

function daysUntil(date: string) {
  const ms = new Date(date).getTime() - Date.now();
  return Number.isNaN(ms) ? Infinity : Math.floor(ms / 86_400_000);
}

function uptime(seconds: number, t: (key: string, opts?: Record<string, unknown>) => string) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return days > 0 ? t("overview.uptimeDays", { days, hours }) : t("overview.uptimeHours", { hours });
}

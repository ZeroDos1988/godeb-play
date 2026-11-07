import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { DataTable, PanelFrame } from "@/components/PanelFrame.tsx";
import { api } from "@/lib/api.ts";
import type { CommandEnvelope } from "@/lib/types.ts";
import { useGet } from "@/lib/useAsync.ts";
import * as ui from "@/components/ui.ts";
import { Help } from "@/components/Help.tsx";

type AptPackage = {
  name: string;
  suite: string;
  version: string;
  arch: string;
  from: string;
  security: boolean;
};

type AptSettings = {
  autoCheck: boolean;
  interval: number;
  autoSecurity: boolean;
};

type AptJob = {
  action: "check" | "security" | "upgrade";
  trigger: string;
  started: string;
  finished?: string;
  ok: boolean;
  error?: string;
  installed?: string[];
  running: boolean;
  log: string[];
};

type AptStatus = CommandEnvelope & {
  packages: AptPackage[];
  security: number;
  settings: AptSettings;
  job?: AptJob;
  lastCheck?: string;
  nextCheck?: string;
};

const base = "/api/plugins/apt";
const card = `${ui.card} mb-6`;
const button = ui.button;

export default function Panel() {
  const { t } = useTranslation();
  const query = useGet<AptStatus>(`${base}/upgradable`);
  const data = query.data;
  const packages = data?.packages ?? [];
  const running = data?.job?.running ?? false;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // Follow a running job; GoDeb may restart itself during an upgrade, so
  // failed polls are expected for a few seconds and the loop keeps going.
  const { reload } = query;
  useEffect(() => {
    if (!running && !busy) {
      return;
    }
    const id = window.setInterval(reload, 3000);
    return () => window.clearInterval(id);
  }, [running, busy, reload]);

  async function start(action: "check" | "security" | "upgrade") {
    setBusy(true);
    setError("");
    try {
      await api(`${base}/${action}`, { method: "POST" });
      reload();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("apt.failed"));
    } finally {
      setBusy(false);
    }
  }

  const security = packages.filter((p) => p.security);
  return (
    <PanelFrame
      title={t("apt.title")}
      description={t("apt.description")}
      command={data?.command}
      mocked={data?.mocked}
      detail={data?.detail}
      loading={query.loading && !data}
      error={running ? "" : query.error}
      onRefresh={reload}
    >
      {data ? (
        <>
          <AutoCard
            settings={data.settings}
            lastCheck={data.lastCheck}
            nextCheck={data.nextCheck}
            onSaved={reload}
          />

          <section className={card}>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                className={button}
                disabled={running || busy}
                onClick={() => void start("check")}
              >
                {t("apt.checkNow")}
              </button>
              <button
                type="button"
                className={button}
                disabled={running || busy || security.length === 0}
                onClick={() => void start("security")}
              >
                {t("apt.installSecurity", { count: security.length })}
              </button>
              <button
                type="button"
                className={ui.primary}
                disabled={running || busy || packages.length === 0}
                onClick={() => void start("upgrade")}
              >
                {t("apt.upgradeAll", { count: packages.length })}
              </button>
              {error ? (
                <span className="text-sm text-rose-300">{error}</span>
              ) : null}
            </div>
            {packages.some((p) => p.name === "godeb") ? (
              <p className="mt-3 text-xs text-white/60">{t("apt.selfHint")}</p>
            ) : null}
          </section>

          {data.job ? (
            <JobCard job={data.job} offline={running && query.error !== ""} />
          ) : null}

          {packages.length === 0 ? (
            <p className="text-sm text-muted">{t("apt.empty")}</p>
          ) : (
            <DataTable
              head={[
                t("apt.package"),
                t("apt.suite"),
                t("apt.installed"),
                t("apt.available"),
                t("apt.arch"),
              ]}
            >
              {packages.map((pkg) => (
                <tr key={`${pkg.name}-${pkg.arch}-${pkg.version}`}>
                  <td className="px-3 py-2 font-mono text-xs">
                    {pkg.name}
                    {pkg.security ? (
                      <span className="ms-2 rounded-full border border-amber-300/40 bg-amber-400/10 px-2 py-0.5 font-sans text-[11px] text-amber-200">
                        {t("apt.securityBadge")}
                      </span>
                    ) : null}
                  </td>
                  <td className="px-3 py-2">{pkg.suite}</td>
                  <td className="px-3 py-2 font-mono text-xs">{pkg.from}</td>
                  <td className="px-3 py-2 font-mono text-xs">{pkg.version}</td>
                  <td className="px-3 py-2">{pkg.arch}</td>
                </tr>
              ))}
            </DataTable>
          )}
        </>
      ) : null}
    </PanelFrame>
  );
}

function AutoCard({
  settings,
  lastCheck,
  nextCheck,
  onSaved,
}: {
  settings: AptSettings;
  lastCheck?: string;
  nextCheck?: string;
  onSaved: () => void;
}) {
  const { t, i18n } = useTranslation();
  const [form, setForm] = useState(settings);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const dirty =
    form.autoCheck !== settings.autoCheck ||
    form.interval !== settings.interval ||
    form.autoSecurity !== settings.autoSecurity;
  const time = (iso?: string) =>
    iso
      ? new Date(iso).toLocaleTimeString(i18n.language, {
          hour: "2-digit",
          minute: "2-digit",
        })
      : "–";

  useEffect(
    () => setForm(settings),
    [settings.autoCheck, settings.interval, settings.autoSecurity],
  );

  async function save() {
    setBusy(true);
    setError("");
    try {
      await api(`${base}/settings`, {
        method: "POST",
        body: JSON.stringify(form),
      });
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2000);
      onSaved();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("apt.failed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className={card}>
      <h2 className="text-sm font-semibold">{t("apt.autoTitle")}</h2>
      <div className="mt-3 space-y-3 text-sm">
        <label className="flex flex-wrap items-center gap-2">
          <input
            type="checkbox"
            className="h-4 w-4"
            checked={form.autoCheck}
            onChange={(e) => setForm({ ...form, autoCheck: e.target.checked })}
          />
          <span>{t("apt.autoCheckBefore")}</span>
          <input
            type="number"
            min={5}
            max={1440}
            inputMode="numeric"
            value={form.interval}
            disabled={!form.autoCheck}
            onChange={(e) =>
              setForm({ ...form, interval: Number(e.target.value) || 0 })
            }
            aria-label={t("apt.interval")}
            className={`${ui.input} w-20! shrink-0 text-center`}
          />
          <span>{t("apt.autoCheckAfter")}</span>
        </label>
        <label className="flex items-start gap-2">
          <input
            type="checkbox"
            className="mt-1 h-4 w-4"
            checked={form.autoSecurity}
            disabled={!form.autoCheck}
            onChange={(e) =>
              setForm({ ...form, autoSecurity: e.target.checked })
            }
          />
          <span className="flex items-center gap-2">
            {t("apt.autoSecurity")}
            <Help>{t("apt.autoSecurityHint")}</Help>
          </span>
        </label>
        <p className="text-xs text-white/60">
          {t("apt.lastCheck", { time: time(lastCheck) })}
          {settings.autoCheck && nextCheck
            ? ` · ${t("apt.nextCheck", { time: time(nextCheck) })}`
            : ""}
        </p>
        {dirty || saved || error ? (
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              className={button}
              disabled={busy || !dirty}
              onClick={() => void save()}
            >
              {saved ? t("apt.saved") : t("apt.save")}
            </button>
            {error ? (
              <span className="text-sm text-debian">{error}</span>
            ) : null}
          </div>
        ) : null}
      </div>
    </section>
  );
}

function JobCard({ job, offline }: { job: AptJob; offline: boolean }) {
  const { t, i18n } = useTranslation();
  const when = (iso?: string) =>
    iso ? new Date(iso).toLocaleString(i18n.language) : "";
  const who =
    job.trigger === "auto"
      ? t("apt.byAuto")
      : t("apt.byUser", { name: job.trigger });
  let state = "";
  let tone = "text-white/70";
  if (job.running) {
    state = t("apt.running");
    tone = "text-amber-200";
  } else if (job.ok) {
    state = job.installed?.length
      ? t("apt.doneInstalled", { list: job.installed.join(", ") })
      : t("apt.done");
    tone = "text-emerald-300";
  } else {
    state = job.error ?? t("apt.failed");
    tone = "text-rose-300";
  }
  return (
    <details open={job.running || !job.ok} className={`${card} group`}>
      <summary className="flex cursor-pointer list-none flex-wrap items-baseline gap-x-3 gap-y-1 text-sm">
        <span className="font-semibold">{t(`apt.actions.${job.action}`)}</span>
        <span className="text-xs text-white/50">
          {when(job.started)} · {who}
        </span>
        <span className={`basis-full text-sm ${tone}`}>{state}</span>
      </summary>
      {offline ? (
        <p className="mt-2 text-xs text-amber-200">{t("apt.restarting")}</p>
      ) : null}
      {job.log.length > 0 ? (
        <pre className="mt-3 max-h-80 overflow-auto rounded-2xl bg-slate-950/60 p-3 font-mono text-[11px] whitespace-pre-wrap text-white/75">
          {job.log.join("\n")}
        </pre>
      ) : null}
    </details>
  );
}

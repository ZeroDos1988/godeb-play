import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PanelFrame } from "@/components/PanelFrame.tsx";
import { api } from "@/lib/api.ts";
import type { CommandEnvelope } from "@/lib/types.ts";
import { useGet } from "@/lib/useAsync.ts";
import { Backups } from "./Backups.tsx";
import { Proton } from "./Proton.tsx";
import { ConfigEditor } from "./ConfigEditor.tsx";
import { forms } from "./games/index.ts";
import { button, card, primary, Stat } from "./parts.tsx";

type Job = {
  game: string;
  action: string;
  step: string;
  running: boolean;
  ok: boolean;
  error?: string;
  started: string;
  finished?: string;
  log: string[];
};

type GameInfo = {
  id: string;
  name: string;
  appId: string;
  platform: "linux" | "windows" | "proton";
  downloadGb: number;
  memoryGb: number;
  hasConfig: boolean;
  installed: boolean;
  ready: boolean;
  service: string;
};

type Status = CommandEnvelope &
  GameInfo & {
    unit: string;
    user: string;
    buildId?: string;
    serverDir: string;
    configPath?: string;
    ports: number[];
    tcpPorts?: number[];
    job: Job | null;
    hub?: string;
    tunnelAddress?: string;
    proton?: string;
  };

export default function Panel() {
  const { t } = useTranslation();
  const list = useGet<{ games: GameInfo[] }>("/api/plugins/steam/games");
  const games = list.data?.games ?? [];
  const [selected, setSelected] = useState("");
  const current = games.find((g) => g.id === selected) ?? games[0];

  return (
    <PanelFrame title={t("steam.title")} description={t("steam.description")} loading={list.loading} error={list.error} onRefresh={list.reload}>
      {list.data ? (
        <div className="space-y-4">
          {games.length === 0 ? <p className="text-sm text-muted">{t("steam.noGames")}</p> : null}
          {games.length > 0 ? (
            <div role="tablist" aria-label={t("steam.games")} className="flex flex-wrap gap-2">
              {games.map((g) => (
                <button
                  key={g.id}
                  type="button"
                  role="tab"
                  aria-selected={current?.id === g.id}
                  onClick={() => setSelected(g.id)}
                  className={`flex items-center gap-2 rounded-2xl border px-3 py-2 text-sm transition-all duration-200 ease-in-out ${current?.id === g.id ? "border-white/30 bg-white/15 text-white" : "border-white/10 bg-slate-900/60 text-white/70 hover:text-white"}`}
                >
                  <span className={`h-2 w-2 rounded-full ${g.service === "active" ? "bg-emerald-400" : g.ready ? "bg-white/40" : "bg-white/15"}`} />
                  {g.name}
                </button>
              ))}
            </div>
          ) : null}
          {current ? <GameView key={current.id} id={current.id} onChanged={list.reload} /> : null}
        </div>
      ) : null}
    </PanelFrame>
  );
}

function GameView({ id, onChanged }: { id: string; onChanged: () => void }) {
  const { t } = useTranslation();
  const base = `/api/plugins/steam/games/${encodeURIComponent(id)}`;
  const status = useGet<Status>(`${base}/status`);
  const [job, setJob] = useState<Job | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (status.data) {
      setJob(status.data.job);
    }
  }, [status.data]);

  const reloadStatus = status.reload;

  // Poll while an install or update runs; refresh the status when it ends.
  useEffect(() => {
    if (!job?.running) {
      return;
    }
    const timer = window.setInterval(() => {
      api<{ job: Job | null }>(`${base}/job`)
        .then((res) => {
          setJob(res.job);
          if (res.job && !res.job.running) {
            reloadStatus();
            onChanged();
          }
        })
        .catch(() => undefined);
    }, 2000);
    return () => window.clearInterval(timer);
  }, [job?.running, reloadStatus, onChanged, base]);

  async function post(action: string, body?: unknown) {
    setBusy(true);
    setError("");
    try {
      const res = await api<{ job?: Job }>(`${base}/${action}`, { method: "POST", body: body ? JSON.stringify(body) : undefined });
      if (res.job) {
        setJob(res.job);
      }
      status.reload();
      onChanged();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("steam.failed"));
    } finally {
      setBusy(false);
    }
  }

  const data = status.data;
  if (status.error) {
    return <p className="text-sm text-debian">{status.error}</p>;
  }
  if (!data) {
    return <p className="text-sm text-muted">{t("common.loading")}</p>;
  }
  const running = job?.running ?? false;
  const active = data.service === "active";

  return (
    <div className="space-y-4">
      <details className="text-xs text-muted">
        <summary className="w-fit cursor-pointer select-none hover:text-debian">{t("panel.technical")}</summary>
        <p className="mt-2 overflow-x-auto rounded-2xl border border-white/10 bg-slate-900/60 px-3 py-2 font-mono text-white/80 backdrop-blur-xl">
          $ {data.command.join(" ")}
        </p>
      </details>
      {data.mocked ? (
        <p className="rounded-2xl border border-amber-300/20 bg-amber-950/30 px-4 py-3 text-sm text-amber-100">
          {t("panel.mocked")}
          {data.detail ? ` ${data.detail}` : ""}
        </p>
      ) : null}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat
          label={t("steam.server")}
          value={t(data.ready ? "steam.installed" : data.installed ? "steam.filesOnly" : "steam.notInstalled")}
          ok={data.ready}
          hint={data.buildId ? `App ${data.appId} · Build ${data.buildId}` : `App ${data.appId}`}
        />
        <Stat label={t("steam.service")} value={data.service} ok={active} />
        <Stat label={t("steam.ports")} value={[...data.ports.map((p) => `${p}/udp`), ...(data.tcpPorts ?? []).map((p) => `${p}/tcp`)].join(", ")} />
        <Stat label={t("steam.account")} value={data.user} hint={data.unit} />
      </div>

      <div className="flex flex-wrap gap-2">
        {!data.ready ? (
          <button type="button" className={primary} disabled={busy || running} onClick={() => void post("install")}>
            {t("steam.install")}
          </button>
        ) : (
          <>
            {active ? (
              <button type="button" className={button} disabled={busy || running} onClick={() => void post("action", { action: "stop" })}>
                {t("steam.stop")}
              </button>
            ) : (
              <button type="button" className={primary} disabled={busy || running} onClick={() => void post("action", { action: "start" })}>
                {t("steam.start")}
              </button>
            )}
            <button
              type="button"
              className={button}
              disabled={busy || running || !active}
              onClick={() => {
                if (!window.confirm(t("steam.confirmRestart"))) return;
                void post("action", { action: "restart" });
              }}
            >
              {t("steam.restart")}
            </button>
            <button
              type="button"
              className={button}
              disabled={busy || running}
              onClick={() => {
                if (!window.confirm(t("steam.confirmUpdate"))) return;
                void post("update");
              }}
            >
              {t("steam.update")}
            </button>
          </>
        )}
      </div>
      {data.hub ? (
        <p className="rounded-2xl border border-emerald-300/20 bg-emerald-400/5 px-3 py-2 text-sm text-white/80">
          {t("steam.behindHub", {
            hub: data.hub,
            ports: [...data.ports.map((p) => `${p}/udp`), ...(data.tcpPorts ?? []).map((p) => `${p}/tcp`)].join(", "),
            address: data.tunnelAddress ?? "",
            game: data.name,
          })}
        </p>
      ) : null}
      {t(`steam.note.${id}`, { defaultValue: "" }) ? (
        <p className="rounded-2xl border border-amber-300/20 bg-amber-400/5 px-3 py-2 text-sm text-white/80">{t(`steam.note.${id}`)}</p>
      ) : null}
      {!data.ready ? (
        <p className="text-xs text-muted">
          {data.installed
            ? t("steam.installHintSeeded")
            : t("steam.installHint", { wine: data.platform === "windows" ? t("steam.wine") : data.platform === "proton" ? t("steam.protonInstall") : "", size: data.downloadGb, memory: data.memoryGb })}
        </p>
      ) : null}
      {error ? <p className="text-sm text-debian">{error}</p> : null}

      {job ? <JobView job={job} /> : null}

      {data.ready ? (
        <Backups base={base} jobRunning={running} refreshKey={job?.finished ? 1 : 0} onStarted={(j) => setJob(j as Job)} />
      ) : null}
      {data.ready && data.platform === "proton" && data.proton ? (
        <Proton game={id} current={data.proton} jobRunning={running} onStarted={(j) => setJob(j as Job)} />
      ) : null}
      {data.hasConfig ? <ConfigEditor base={base} Form={forms[id]} onSaved={status.reload} serverActive={active} /> : null}
      {data.installed ? <Logs base={base} /> : null}
    </div>
  );
}

function JobView({ job }: { job: Job }) {
  const { t } = useTranslation();
  const state = job.running ? t("steam.jobRunning") : job.ok ? t("steam.jobDone") : t("steam.jobFailed");
  return (
    <div className={card}>
      <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
        <span>
          {t(`steam.jobAction.${job.action}`, { defaultValue: job.action })}: <strong>{state}</strong>
        </span>
        <span className="text-xs text-white/60">{job.step}</span>
      </div>
      {job.error ? <p className="mt-2 text-sm text-rose-300">{job.error}</p> : null}
      <pre className="mt-3 max-h-64 overflow-auto rounded-2xl bg-slate-950/50 p-3 font-mono text-[11px] leading-relaxed whitespace-pre-wrap text-white/80">
        {job.log.slice(-120).join("\n")}
      </pre>
    </div>
  );
}

type LogResponse = { lines: string[]; mocked: boolean; detail?: string };

function Logs({ base }: { base: string }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [logs, setLogs] = useState<LogResponse | null>(null);
  const [error, setError] = useState("");

  function load() {
    setError("");
    api<LogResponse>(`${base}/logs`)
      .then(setLogs)
      .catch((err: unknown) => setError(err instanceof Error ? err.message : t("steam.failed")));
  }

  return (
    <div className={card}>
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold">{t("steam.logs")}</h2>
        <div className="flex gap-2">
          {open ? (
            <button type="button" className={button} onClick={load}>
              {t("common.refresh")}
            </button>
          ) : null}
          <button
            type="button"
            className={button}
            onClick={() => {
              if (!open) {
                load();
              }
              setOpen((v) => !v);
            }}
          >
            {open ? t("steam.hide") : t("steam.show")}
          </button>
        </div>
      </div>
      {open && error ? <p className="mt-3 text-sm text-debian">{error}</p> : null}
      {open && logs ? (
        <pre className="mt-3 max-h-80 overflow-auto rounded-2xl bg-slate-950/50 p-3 font-mono text-[11px] leading-relaxed whitespace-pre-wrap text-white/80">
          {logs.mocked ? logs.detail : logs.lines.join("\n")}
        </pre>
      ) : null}
    </div>
  );
}

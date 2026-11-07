import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "@/lib/api.ts";
import { useGet } from "@/lib/useAsync.ts";
import { button, card } from "./parts.tsx";

type Backup = { name: string; reason: "manual" | "update" | "restore"; time: string; size: number };
type BackupList = { supported: boolean; saveDir: string; keep: number; backups: Backup[] };

// Backups lists the savegame backups of a game: one before every update,
// on request, and the state before each restore. Backup and restore run as
// the game's job, so the job view above shows their progress.
export function Backups({ base, jobRunning, refreshKey, onStarted }: { base: string; jobRunning: boolean; refreshKey: number; onStarted: (job: unknown) => void }) {
  const { t, i18n } = useTranslation();
  const list = useGet<BackupList>(`${base}/backups`);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const reload = list.reload;

  useEffect(() => {
    if (!jobRunning) reload();
  }, [jobRunning, refreshKey, reload]);

  async function start(path: string) {
    setBusy(true);
    setError("");
    try {
      const res = await api<{ job?: unknown }>(path, { method: "POST" });
      onStarted(res.job);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("steam.failed"));
    } finally {
      setBusy(false);
    }
  }

  const data = list.data;
  if (!data?.supported) return null;
  const when = (iso: string) => new Date(iso).toLocaleString(i18n.language, { dateStyle: "short", timeStyle: "short" });
  const size = (n: number) => (n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`);

  return (
    <section className={card}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold">{t("steam.backups.title")}</h2>
          <p className="mt-1 text-xs text-white/60">{t("steam.backups.hint", { dir: data.saveDir, keep: data.keep })}</p>
        </div>
        <button type="button" className={button} disabled={busy || jobRunning} onClick={() => void start(`${base}/backups`)}>
          {t("steam.backups.create")}
        </button>
      </div>
      {error ? <p className="mt-2 text-sm text-debian">{error}</p> : null}
      {data.backups.length === 0 ? (
        <p className="mt-3 text-sm text-white/60">{t("steam.backups.none")}</p>
      ) : (
        <ul className="mt-3 divide-y divide-white/10 text-sm">
          {data.backups.map((b) => (
            <li key={b.name} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2">
              <span className="min-w-0 flex-1">
                {when(b.time)}
                <span className="ms-2 text-xs text-white/55">
                  {t(`steam.backups.reason.${b.reason}`)} · {size(b.size)}
                </span>
              </span>
              <button
                type="button"
                className={button}
                disabled={busy || jobRunning}
                onClick={() => {
                  if (!window.confirm(t("steam.backups.confirmRestore", { time: when(b.time) }))) return;
                  void start(`${base}/backups/${encodeURIComponent(b.name)}/restore`);
                }}
              >
                {t("steam.backups.restore")}
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

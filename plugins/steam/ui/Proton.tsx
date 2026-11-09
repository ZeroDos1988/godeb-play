import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "@/lib/api.ts";
import { useGet } from "@/lib/useAsync.ts";
import { button, card, primary } from "./parts.tsx";

type Installed = { version: string; pinned: boolean; usedBy: string[] };
type InstalledList = { pinned: string; dir: string; installed: Installed[] };
type Release = { version: string; published: string; installed: boolean; pinned: boolean };
type Releases = { releases: Release[]; latest: string; checked: string };

// Proton manages the GE-Proton releases of a Proton game: which one the game
// uses, newer ones on GitHub, and removing releases no game uses. Switching
// runs as the game's job (with a savegame backup), so the job view above
// shows its progress.
export function Proton({ game, current, jobRunning, onStarted }: { game: string; current: string; jobRunning: boolean; onStarted: (job: unknown) => void }) {
  const { t, i18n } = useTranslation();
  const installed = useGet<InstalledList>("/api/plugins/steam/proton");
  const [releases, setReleases] = useState<Releases | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const reload = installed.reload;

  useEffect(() => {
    if (!jobRunning) reload();
  }, [jobRunning, reload]);

  async function check(refresh: boolean) {
    setBusy(true);
    setError("");
    try {
      setReleases(await api<Releases>(`/api/plugins/steam/proton/releases${refresh ? "?refresh=1" : ""}`));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("steam.failed"));
    } finally {
      setBusy(false);
    }
  }

  async function use(version: string, download: boolean) {
    const pinned = version === installed.data?.pinned;
    const question = download && !pinned ? t("steam.proton.confirmDownload", { version }) : t("steam.proton.confirmUse", { version });
    if (!window.confirm(question)) return;
    setBusy(true);
    setError("");
    try {
      const res = await api<{ job?: unknown }>(`/api/plugins/steam/games/${encodeURIComponent(game)}/proton`, { method: "POST", body: JSON.stringify({ version }) });
      onStarted(res.job);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("steam.failed"));
    } finally {
      setBusy(false);
    }
  }

  async function remove(version: string) {
    if (!window.confirm(t("steam.proton.confirmDelete", { version }))) return;
    setBusy(true);
    setError("");
    try {
      await api("/api/plugins/steam/proton/delete", { method: "POST", body: JSON.stringify({ version }) });
      reload();
      setReleases((r) => (r ? { ...r, releases: r.releases.map((x) => (x.version === version ? { ...x, installed: false } : x)) } : r));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("steam.failed"));
    } finally {
      setBusy(false);
    }
  }

  const data = installed.data;
  const when = (iso: string) => (iso ? new Date(iso).toLocaleString(i18n.language, { dateStyle: "short", timeStyle: "short" }) : "");
  const newer = releases?.latest && releases.latest !== current ? releases.releases.find((r) => r.version === releases.latest) : undefined;
  const disabled = busy || jobRunning;

  return (
    <section className={card}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold">{t("steam.proton.title")}</h2>
          <p className="mt-1 text-xs text-white/60">{t("steam.proton.current", { version: current })}</p>
        </div>
        <button type="button" className={button} disabled={disabled} onClick={() => void check(releases !== null)}>
          {t("steam.proton.check")}
        </button>
      </div>
      {error ? <p className="mt-2 text-sm text-debian">{error}</p> : null}
      {releases ? (
        newer ? (
          <div className="mt-3 flex flex-wrap items-center gap-2 rounded-2xl border border-emerald-300/20 bg-emerald-400/5 px-3 py-2 text-sm">
            <span className="min-w-0 flex-1">{t("steam.proton.newer", { version: newer.version, date: when(newer.published) })}</span>
            <button type="button" className={primary} disabled={disabled} onClick={() => void use(newer.version, !newer.installed)}>
              {newer.installed ? t("steam.proton.use") : t("steam.proton.install")}
            </button>
          </div>
        ) : (
          <p className="mt-3 text-sm text-white/60">{t("steam.proton.upToDate", { date: when(releases.checked) })}</p>
        )
      ) : null}

      {data && data.installed.length > 0 ? (
        <ul className="mt-3 divide-y divide-white/10 text-sm">
          {data.installed.map((p) => (
            <li key={p.version} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2">
              <span className="min-w-0 flex-1 break-all">
                {p.version}
                <span className="ms-2 text-xs text-white/55">
                  {[p.pinned ? t("steam.proton.pinned") : t("steam.proton.unpinned"), p.usedBy.length > 0 ? t("steam.proton.usedBy", { games: p.usedBy.join(", ") }) : t("steam.proton.unused")].join(" · ")}
                </span>
              </span>
              {p.version !== current ? (
                <button type="button" className={button} disabled={disabled} onClick={() => void use(p.version, false)}>
                  {t("steam.proton.use")}
                </button>
              ) : null}
              {p.usedBy.length === 0 ? (
                <button type="button" className={button} disabled={disabled} onClick={() => void remove(p.version)}>
                  {t("steam.proton.delete")}
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}

      {releases && releases.releases.length > 0 ? (
        <details className="mt-3 text-sm">
          <summary className="w-fit cursor-pointer text-xs text-white/60 select-none hover:text-white">{t("steam.proton.all")}</summary>
          <ul className="mt-2 divide-y divide-white/10">
            {releases.releases.map((r) => (
              <li key={r.version} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2">
                <span className="min-w-0 flex-1 break-all">
                  {r.version}
                  <span className="ms-2 text-xs text-white/55">
                    {when(r.published)}
                    {r.pinned ? ` · ${t("steam.proton.pinned")}` : ""}
                  </span>
                </span>
                {r.version !== current ? (
                  <button type="button" className={button} disabled={disabled} onClick={() => void use(r.version, !r.installed)}>
                    {r.installed ? t("steam.proton.use") : t("steam.proton.install")}
                  </button>
                ) : null}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
      <p className="mt-3 text-xs text-white/50">{t("steam.proton.hint", { pinned: data?.pinned ?? "" })}</p>
    </section>
  );
}

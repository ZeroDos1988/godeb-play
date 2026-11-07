import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "@/lib/api.ts";
import { useGet } from "@/lib/useAsync.ts";

type SessionInfo = {
  id: string;
  current: boolean;
  created_at: string;
  last_seen: string;
  expires_at: string;
  elevated_until?: string;
  ip: string;
  user_agent: string;
};

// SessionsDialog lists the user's logins and ends them server-side.
export function SessionsDialog({ onClose, onSignedOut }: { onClose: () => void; onSignedOut: () => void }) {
  const { t, i18n } = useTranslation();
  const query = useGet<{ sessions: SessionInfo[] }>("/api/auth/sessions");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const sessions = query.data?.sessions ?? [];
  const others = sessions.filter((session) => !session.current).length;
  const format = (value: string) => new Date(value).toLocaleString(i18n.language);

  async function run(key: string, path: string, endsOwn: boolean) {
    setBusy(key);
    setError("");
    try {
      await api(path, { method: "POST" });
      if (endsOwn) {
        onSignedOut();
        return;
      }
      query.reload();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("sessions.failed"));
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="fixed inset-0 z-30 grid place-items-center bg-slate-950/50 p-4 backdrop-blur-sm" role="presentation" onClick={onClose}>
      <div
        role="dialog"
        aria-labelledby="sessions-title"
        className="max-h-[90vh] w-full max-w-xl overflow-y-auto rounded-3xl border border-white/10 bg-slate-900/60 p-5 text-white shadow-xl backdrop-blur-xl transition-all duration-200 ease-in-out"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="mb-4 flex items-start justify-between gap-4">
          <div className="min-w-0">
            <h2 id="sessions-title" className="text-lg font-semibold">
              {t("sessions.title")}
            </h2>
            <p className="mt-1 text-sm text-white/70">{t("sessions.hint")}</p>
          </div>
          <button type="button" onClick={onClose} className="text-sm text-white/70 transition-all duration-200 ease-in-out hover:text-white">
            {t("common.close")}
          </button>
        </div>

        {query.loading ? <p className="text-sm text-white/60">{t("common.loading")}</p> : null}
        {query.error || error ? (
          <p className="mb-3 rounded-2xl bg-rose-500/15 px-3 py-2 text-sm text-rose-200" role="alert">
            {error || query.error}
          </p>
        ) : null}

        <ul className="grid gap-2">
          {sessions.map((session) => (
            <li key={session.id} className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono">{session.ip || "–"}</span>
                <div className="flex flex-wrap items-center gap-2">
                  {session.current ? (
                    <span className="rounded-2xl bg-emerald-500/20 px-2 py-0.5 text-xs text-emerald-200">{t("sessions.current")}</span>
                  ) : null}
                  {session.elevated_until ? (
                    <span className="rounded-2xl bg-amber-500/20 px-2 py-0.5 text-xs text-amber-200">{t("sessions.elevated")}</span>
                  ) : null}
                  <button
                    type="button"
                    disabled={busy !== ""}
                    onClick={() => void run(session.id, `/api/auth/sessions/${session.id}/revoke`, session.current)}
                    className="rounded-2xl px-2 py-1 text-xs text-rose-300 transition-all duration-200 ease-in-out hover:bg-white/10 hover:text-white disabled:opacity-50"
                  >
                    {session.current ? t("sessions.endOwn") : t("sessions.end")}
                  </button>
                </div>
              </div>
              <p className="mt-1 truncate text-xs text-white/60" title={session.user_agent}>
                {session.user_agent || t("sessions.unknownClient")}
              </p>
              <p className="mt-1 text-xs text-white/50">
                {t("sessions.since", { created: format(session.created_at), seen: format(session.last_seen) })}
              </p>
            </li>
          ))}
        </ul>

        {others > 0 ? (
          <div className="mt-4 flex justify-end">
            <button
              type="button"
              disabled={busy !== ""}
              onClick={() => void run("others", "/api/auth/sessions/revoke-others", false)}
              className="rounded-2xl bg-rose-600/80 px-4 py-2 text-sm font-semibold text-on-solid transition-all duration-200 ease-in-out hover:bg-rose-600 disabled:opacity-50"
            >
              {t("sessions.endOthers", { count: others })}
            </button>
          </div>
        ) : null}
      </div>
    </div>
  );
}

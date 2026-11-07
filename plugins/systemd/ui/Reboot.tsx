import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Help } from "@/components/Help.tsx";
import { api } from "@/lib/api.ts";
import { useGet } from "@/lib/useAsync.ts";
import * as ui from "@/components/ui.ts";

type RebootSettings = { auto: boolean; time: string };

type RebootStatus = {
  required: boolean;
  packages?: string[];
  scheduled?: string;
  mode?: string;
  settings: RebootSettings;
  detail?: string;
};

const base = "/api/plugins/systemd/reboot";

export function useReboot() {
  return useGet<RebootStatus>(base);
}

// RebootCard: reboot needed, reboot now (one minute's notice) and cancel a
// pending one. No power-off on purpose: a VPS only comes back through the
// provider's console.
export function RebootCard({ status, onChanged }: { status: RebootStatus; onChanged: () => void }) {
  const { t, i18n } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function post(path: string) {
    setBusy(true);
    setError("");
    try {
      await api(path, { method: "POST" });
      onChanged();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("systemd.failed"));
    } finally {
      setBusy(false);
    }
  }

  function reboot() {
    if (window.confirm(t("systemd.reboot.confirm"))) void post(base);
  }

  const at = status.scheduled
    ? new Date(status.scheduled).toLocaleTimeString(i18n.language, { hour: "2-digit", minute: "2-digit" })
    : "";
  const dot = status.scheduled || status.required ? "bg-amber-400" : "bg-emerald-400";
  const text = status.scheduled
    ? t(status.mode === "reboot" ? "systemd.reboot.scheduled" : "systemd.reboot.scheduledOther", { time: at })
    : status.required
      ? t("systemd.reboot.required")
      : t("systemd.reboot.notRequired");

  return (
    <section className={`${ui.card} mb-4`}>
      <div className="flex flex-wrap items-center gap-3">
        <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${dot}`} aria-hidden />
        <div className="min-w-0 flex-1">
          <h2 className={ui.cardTitle}>{t("systemd.reboot.title")}</h2>
          <p className="text-sm break-words text-white/70">{text}</p>
          {status.required && !status.scheduled && status.packages?.length ? (
            <p className={`${ui.hint} font-mono break-words`}>{status.packages.join(", ")}</p>
          ) : null}
        </div>
        {status.scheduled ? (
          <button type="button" className={ui.button} disabled={busy} onClick={() => void post(`${base}/cancel`)}>
            {t("systemd.reboot.cancel")}
          </button>
        ) : (
          <button type="button" className={status.required ? ui.primary : ui.button} disabled={busy} onClick={reboot}>
            {busy ? t("fix.working") : t("systemd.reboot.now")}
          </button>
        )}
      </div>
      {error ? <p className="mt-2 text-sm break-words text-debian">{error}</p> : null}
    </section>
  );
}

// AutoRebootForm: reboot on its own at night when updates ask for it.
export function AutoRebootForm({ settings, onSaved }: { settings: RebootSettings; onSaved: () => void }) {
  const { t } = useTranslation();
  const [form, setForm] = useState(settings);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const dirty = form.auto !== settings.auto || form.time !== settings.time;

  useEffect(() => setForm(settings), [settings.auto, settings.time]);

  async function save() {
    setBusy(true);
    setError("");
    try {
      await api(`${base}/settings`, { method: "POST", body: JSON.stringify(form) });
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2000);
      onSaved();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("systemd.failed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className={ui.card}>
      <h2 className={ui.cardTitle}>{t("systemd.reboot.autoTitle")}</h2>
      <div className="mt-3 space-y-3 text-sm">
        <label className="flex flex-wrap items-center gap-2">
          <input
            type="checkbox"
            className="h-4 w-4"
            checked={form.auto}
            onChange={(e) => setForm({ ...form, auto: e.target.checked })}
          />
          <span>{t("systemd.reboot.autoBefore")}</span>
          <input
            type="time"
            value={form.time}
            disabled={!form.auto}
            onChange={(e) => setForm({ ...form, time: e.target.value })}
            aria-label={t("systemd.reboot.autoTime")}
            className={`${ui.input} w-28! shrink-0 text-center font-mono`}
          />
          <span className="flex items-center gap-2">
            {t("systemd.reboot.autoAfter")}
            <Help>{t("systemd.reboot.autoHint")}</Help>
          </span>
        </label>
        {dirty || saved || error ? (
          <div className="flex flex-wrap items-center gap-3">
            <button type="button" className={ui.button} disabled={busy || !dirty} onClick={() => void save()}>
              {saved ? t("systemd.reboot.saved") : t("systemd.reboot.save")}
            </button>
            {error ? <span className="text-sm text-debian">{error}</span> : null}
          </div>
        ) : null}
      </div>
    </section>
  );
}

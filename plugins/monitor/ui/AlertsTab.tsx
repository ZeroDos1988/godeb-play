import { useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api } from "@/lib/api.ts";
import { useGet } from "@/lib/useAsync.ts";
import { Card, button, input } from "./shared.tsx";

type Settings = { enabled: boolean; email: string; ntfy: string; level: "warning" | "critical"; resolved: boolean };
type View = Settings & { mailReady: boolean; mailError?: string };

export function AlertsTab() {
  const { t } = useTranslation();
  const query = useGet<View>("/api/plugins/monitor/alerts");
  const [form, setForm] = useState<Settings | null>(null);
  const [busy, setBusy] = useState("");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (query.data) {
      const { enabled, email, ntfy, level, resolved } = query.data;
      setForm({ enabled, email, ntfy, level, resolved });
    }
  }, [query.data]);

  async function run(kind: "save" | "test", fn: () => Promise<unknown>, ok: string) {
    setBusy(kind);
    setError("");
    setNotice("");
    try {
      await fn();
      setNotice(ok);
      query.reload();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy("");
    }
  }

  function save(e: FormEvent) {
    e.preventDefault();
    if (!form) return;
    void run("save", () => api("/api/plugins/monitor/alerts", { method: "POST", body: JSON.stringify(form) }), t("monitor.alerts.saved"));
  }

  if (query.error) return <p className="text-sm text-debian">{query.error}</p>;
  if (!form || !query.data) return null;

  return (
    <form onSubmit={save} className="max-w-2xl space-y-4">
      <Card>
        <p className="text-sm text-white/70">{t("monitor.alerts.intro")}</p>
        <label className="mt-4 flex items-center gap-2 text-sm">
          <input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
          {t("monitor.alerts.enabled")}
        </label>
      </Card>
      <Card className="space-y-4">
        <label className="block text-xs text-white/60">
          <span className="mb-1 block">{t("monitor.alerts.email")}</span>
          <input className={input} type="email" value={form.email} placeholder="admin@example.org" onChange={(e) => setForm({ ...form, email: e.target.value })} />
          {!query.data.mailReady ? <span className="mt-1 block text-amber-200">{t("monitor.alerts.mailMissing", { detail: query.data.mailError ?? "" })}</span> : null}
        </label>
        <label className="block text-xs text-white/60">
          <span className="mb-1 block">{t("monitor.alerts.ntfy")}</span>
          <input className={input} value={form.ntfy} placeholder="https://ntfy.sh/godeb-ein-langes-geheimes-thema" onChange={(e) => setForm({ ...form, ntfy: e.target.value })} />
          <span className="mt-1 block">{t("monitor.alerts.ntfyHint")}</span>
        </label>
        <label className="block text-xs text-white/60">
          <span className="mb-1 block">{t("monitor.alerts.level")}</span>
          <select className={input} value={form.level} onChange={(e) => setForm({ ...form, level: e.target.value as Settings["level"] })}>
            <option value="warning">{t("monitor.alerts.levelWarning")}</option>
            <option value="critical">{t("monitor.alerts.levelCritical")}</option>
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={form.resolved} onChange={(e) => setForm({ ...form, resolved: e.target.checked })} />
          {t("monitor.alerts.resolved")}
        </label>
      </Card>
      {error ? <p className="text-sm text-rose-300">{error}</p> : null}
      {notice ? <p className="text-sm text-emerald-300">{notice}</p> : null}
      <div className="flex flex-wrap gap-3">
        <button type="submit" className={button} disabled={busy !== ""}>
          {busy === "save" ? t("monitor.alerts.saving") : t("monitor.alerts.save")}
        </button>
        <button
          type="button"
          className={button}
          disabled={busy !== ""}
          onClick={() => void run("test", () => api("/api/plugins/monitor/alerts/test", { method: "POST", body: "{}" }), t("monitor.alerts.testSent"))}
        >
          {busy === "test" ? t("monitor.alerts.testing") : t("monitor.alerts.test")}
        </button>
      </div>
      <p className="text-xs text-white/50">{t("monitor.alerts.note")}</p>
    </form>
  );
}

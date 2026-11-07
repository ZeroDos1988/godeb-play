import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { PrintSheet, SheetHeader } from "@/components/Print.tsx";
import { authApi, type Enrollment } from "@/lib/auth.ts";
import { copyText } from "@/lib/clipboard.ts";
import * as ui from "@/components/ui.ts";

type Props = {
  onComplete: (username: string) => void;
  onCancel: () => void;
};

const glassButton =
  "rounded-2xl border border-white/10 bg-white/5 px-3 py-1.5 text-xs text-white transition-all duration-200 ease-in-out hover:bg-white/10";

export function TwoFAEnrollment({ onComplete, onCancel }: Props) {
  const { t } = useTranslation();
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [code, setCode] = useState("");
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function start() {
    setBusy(true);
    setError("");
    try {
      setEnrollment(await authApi.enroll());
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("enroll.failed"));
    } finally {
      setBusy(false);
    }
  }

  async function confirm(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const session = await authApi.verify(code.trim());
      onComplete(session.username);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("enroll.badCode"));
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  async function copySecret() {
    if (!enrollment) {
      return;
    }
    await copyText(enrollment.secret);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-slate-950/50 p-4 backdrop-blur-sm md:items-center">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="enroll-title"
        className="w-full max-w-xl rounded-3xl border border-white/10 bg-slate-900/60 text-white shadow-xl backdrop-blur-xl"
      >
        <div className="flex items-center justify-between border-b border-white/10 px-5 py-3">
          <h2 id="enroll-title" className="text-sm font-semibold">
            {t("enroll.title")}
          </h2>
          <button
            type="button"
            onClick={onCancel}
            className="text-sm text-white/70 transition-all duration-200 ease-in-out hover:text-white"
          >
            {t("common.cancel")}
          </button>
        </div>

        <div className="px-5 py-5">
          {!enrollment ? (
            <>
              <p className="text-sm text-white/70">{t("enroll.intro")}</p>
              <button
                type="button"
                onClick={() => void start()}
                disabled={busy}
                className={`${ui.primary} mt-4`}
              >
                {busy ? t("enroll.starting") : t("enroll.start")}
              </button>
            </>
          ) : (
            <>
              <PrintSheet>
                <BackupSheet enrollment={enrollment} />
              </PrintSheet>
              <ol className="space-y-6 text-sm">
                <li>
                  <p className="font-medium">{t("enroll.scan")}</p>
                  <div className="mt-3 flex flex-col gap-4 sm:flex-row sm:items-start">
                    <img
                      src={enrollment.qr_code}
                      alt={t("enroll.qrAlt")}
                      width={176}
                      height={176}
                      className="h-44 w-44 shrink-0 rounded-2xl border border-white/10 bg-white p-2"
                    />
                    <div className="min-w-0 flex-1">
                      <p className="text-xs text-white/60">{t("enroll.manual")}</p>
                      <div className="mt-2 flex items-stretch">
                        <code className="min-w-0 flex-1 overflow-x-auto rounded-s-2xl bg-black/40 px-3 py-2 font-mono text-xs break-all text-white">
                          {enrollment.secret}
                        </code>
                        <button type="button" onClick={() => void copySecret()} className={`${glassButton} rounded-s-none`}>
                          {copied ? t("common.copied") : t("common.copy")}
                        </button>
                      </div>
                    </div>
                  </div>
                </li>

                <li>
                  <p className="font-medium">{t("enroll.backup")}</p>
                  <p className="mt-2 rounded-2xl border border-amber-300/30 bg-amber-950/40 px-3 py-2 text-amber-100">
                    {t("enroll.warning")}
                  </p>
                  <ul className="mt-3 grid grid-cols-2 gap-2 font-mono text-sm">
                    {enrollment.backup_codes.map((backup) => (
                      <li key={backup} className="rounded-2xl border border-white/10 bg-white/5 px-3 py-1.5 text-center">
                        {backup}
                      </li>
                    ))}
                  </ul>
                  <div className="mt-3 flex flex-wrap items-center gap-4">
                    <button type="button" onClick={() => void copyText(enrollment.backup_codes.join("\n"))} className={glassButton}>
                      {t("enroll.copyCodes")}
                    </button>
                    <button type="button" onClick={() => window.print()} className={glassButton}>
                      {t("common.print")}
                    </button>
                    <label className="flex items-center gap-2 text-xs">
                      <input type="checkbox" checked={saved} onChange={(event) => setSaved(event.target.checked)} />
                      {t("enroll.saved")}
                    </label>
                  </div>
                </li>

                <li>
                  <p className="font-medium">{t("enroll.confirm")}</p>
                  <form onSubmit={(event) => void confirm(event)} className="mt-3 flex flex-wrap items-end gap-2">
                    <input
                      value={code}
                      onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      placeholder="123456"
                      aria-label={t("enroll.codeLabel")}
                      className={`${ui.input} w-36! text-center font-mono text-lg tracking-[0.3em]`}
                    />
                    <button
                      type="submit"
                      disabled={busy || code.length !== 6 || !saved}
                      className={ui.primary}
                    >
                      {t("enroll.activate")}
                    </button>
                  </form>
                </li>
              </ol>
            </>
          )}
          {error ? <p className="mt-4 text-sm text-rose-300">{error}</p> : null}
        </div>
      </div>
    </div>
  );
}

// BackupSheet is the printed page with the backup codes: account, server
// and date, so a sheet in a drawer still says what it is for. The TOTP
// secret is not printed.
function BackupSheet({ enrollment }: { enrollment: Enrollment }) {
  const { t, i18n } = useTranslation();
  const account = accountOf(enrollment.otpauth_url);
  return (
    <>
      <SheetHeader
        title={t("enroll.sheetTitle")}
        subtitle={t("enroll.sheetFor", { account, host: window.location.hostname, date: new Date().toLocaleString(i18n.language) })}
      />
      <p className="mb-4">{t("enroll.sheetText")}</p>
      <ol className="grid grid-cols-2 gap-x-8 gap-y-2 font-mono text-[1.3em]">
        {enrollment.backup_codes.map((backup, i) => (
          <li key={backup} className="flex gap-3 border-b border-neutral-300 py-1.5">
            <span className="w-6 text-right text-neutral-500">{i + 1}.</span>
            <span className="tracking-wider">{backup}</span>
            <span className="ms-auto font-sans text-neutral-400">☐</span>
          </li>
        ))}
      </ol>
      <p className="mt-6 text-neutral-600">{t("enroll.sheetKeep")}</p>
    </>
  );
}

// accountOf reads "user" from otpauth://totp/GoDeb:user?secret=…
function accountOf(otpauth: string): string {
  try {
    const label = decodeURIComponent(new URL(otpauth).pathname.replace(/^\/+(totp\/)?/, ""));
    return label.includes(":") ? label.slice(label.indexOf(":") + 1) : label;
  } catch {
    return "";
  }
}

import { useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { setStepUpPrompt, type StepUpCredentials, type StepUpRequest } from "@/lib/api.ts";
import * as ui from "@/components/ui.ts";

type Pending = StepUpRequest & { resolve: (value: StepUpCredentials | null) => void };

// StepUpDialog asks for a 2FA code whenever the daemon refuses an admin
// action without one. Critical actions also need the account password.
// It is mounted once for the signed-in dashboard.
export function StepUpDialog() {
  const { t } = useTranslation();
  const [pending, setPending] = useState<Pending | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const passwordField = useRef<HTMLInputElement>(null);
  const codeField = useRef<HTMLInputElement>(null);

  useEffect(
    () =>
      setStepUpPrompt(
        (request) =>
          new Promise<StepUpCredentials | null>((resolve) => {
            setCode("");
            setPassword("");
            setPending({ ...request, resolve });
          }),
      ),
    [],
  );

  // Focus the first field once when the dialog opens. Without the
  // dependency this ran after every keystroke and pulled the cursor from
  // the code field back to the password field.
  useEffect(() => {
    if (!pending) {
      return;
    }
    (pending.passwordRequired ? passwordField : codeField).current?.focus();
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        cancel();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // cancel only depends on pending.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pending]);

  if (!pending) {
    return null;
  }

  function finish(value: StepUpCredentials | null) {
    pending?.resolve(value);
    setPending(null);
    setCode("");
    setPassword("");
  }

  function cancel() {
    finish(null);
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    const req = pending;
    if (!req) {
      return;
    }
    const value = code.replace(/\s+/g, "");
    if (!value) {
      return;
    }
    if (req.passwordRequired && !password) {
      return;
    }
    finish({
      code: value,
      password: req.passwordRequired ? password : undefined,
    });
  }

  const canSubmit = Boolean(code.trim()) && (!pending.passwordRequired || Boolean(password));

  return (
    <div className="fixed inset-0 z-[60] grid place-items-center bg-slate-950/60 p-4 backdrop-blur-sm" role="presentation" onClick={cancel}>
      <form
        role="dialog"
        aria-modal="true"
        aria-labelledby="stepup-title"
        onSubmit={submit}
        onClick={(event) => event.stopPropagation()}
        className="w-full max-w-sm rounded-3xl border border-white/10 bg-slate-900/80 p-5 text-white shadow-xl backdrop-blur-xl transition-all duration-200 ease-in-out"
      >
        <h2 id="stepup-title" className="text-lg font-semibold">
          {pending.passwordRequired ? t("stepUp.titleCritical") : t("stepUp.title")}
        </h2>
        <p className="mt-1 text-sm text-white/70">
          {pending.passwordRequired ? t("stepUp.critical") : t("stepUp.window")}
        </p>
        {pending.passwordRequired ? (
          <>
            <label className="mt-4 block text-xs tracking-wide text-white/50 uppercase" htmlFor="stepup-password">
              {t("stepUp.password")}
            </label>
            <input
              id="stepup-password"
              ref={passwordField}
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              className="mt-1 w-full rounded-2xl border border-white/15 bg-slate-950/40 px-3 py-3 text-sm text-white outline-none focus:border-white/40"
            />
          </>
        ) : null}
        <label className="mt-4 block text-xs tracking-wide text-white/50 uppercase" htmlFor="stepup-code">
          {t("stepUp.code")}
        </label>
        <input
          id="stepup-code"
          ref={codeField}
          value={code}
          onChange={(event) => setCode(event.target.value)}
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={16}
          className="mt-1 w-full rounded-2xl border border-white/15 bg-slate-950/40 px-3 py-3 text-center font-mono text-lg tracking-[0.3em] text-white outline-none focus:border-white/40"
        />
        <p className="mt-2 text-xs text-white/50">{t("stepUp.backupHint")}</p>
        {pending.error ? (
          <p className="mt-3 rounded-2xl bg-rose-500/15 px-3 py-2 text-sm text-rose-200" role="alert">
            {pending.error}
            {pending.remaining ? ` ${t("stepUp.remaining", { count: pending.remaining })}` : ""}
          </p>
        ) : null}
        <div className="mt-4 flex flex-wrap justify-end gap-2">
          <button
            type="button"
            onClick={cancel}
            className="rounded-2xl px-4 py-2 text-sm text-white/70 transition-all duration-200 ease-in-out hover:bg-white/10 hover:text-white"
          >
            {t("common.cancel")}
          </button>
          <button
            type="submit"
            disabled={!canSubmit}
            className={ui.primary}
          >
            {t("stepUp.confirm")}
          </button>
        </div>
      </form>
    </div>
  );
}

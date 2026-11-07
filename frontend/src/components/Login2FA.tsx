import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Shield, Wordmark } from "@/components/Brand.tsx";
import { TwoFAEnrollment } from "@/components/2FAEnrollment.tsx";
import { api, ApiError } from "@/lib/api.ts";
import { authApi } from "@/lib/auth.ts";
import * as ui from "@/components/ui.ts";

type OIDCProvider = {
  id: string;
  name: string;
  enabled: boolean;
};

// Three steps like most sign-in pages: name, password, second factor.
// The name step answers the same for every name (see auth.identify), so
// the page never tells whether an account exists.
type Step = "user" | "password" | "code" | "enroll";

const input = ui.input;
const primary = `${ui.primary} w-full`;

export function Login2FA({ onAuthenticated }: { onAuthenticated: (username: string) => void }) {
  const { t } = useTranslation();
  const [step, setStep] = useState<Step>("user");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [providers, setProviders] = useState<OIDCProvider[]>([]);

  useEffect(() => {
    api<{ providers: OIDCProvider[] }>("/api/auth/oidc/providers")
      .then((res) => setProviders(res.providers.filter((provider) => provider.enabled)))
      .catch(() => undefined);
    api<{ username: string; enrollment_required: boolean }>("/api/auth/oidc/resume")
      .then((res) => {
        setUsername(res.username);
        setStep(res.enrollment_required ? "enroll" : "code");
      })
      .catch(() => undefined);
  }, []);

  async function run(action: () => Promise<void>, fallback: string) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : fallback);
    } finally {
      setBusy(false);
    }
  }

  function submitUser(event: FormEvent) {
    event.preventDefault();
    void run(async () => {
      await authApi.identify(username.trim());
      setStep("password");
    }, t("login.failed"));
  }

  function submitPassword(event: FormEvent) {
    event.preventDefault();
    void run(async () => {
      try {
        const res = await authApi.login(username.trim(), password);
        setStep(res.enrollment_required ? "enroll" : "code");
      } finally {
        setPassword("");
      }
    }, t("login.failed"));
  }

  function submitCode(event: FormEvent) {
    event.preventDefault();
    void run(async () => {
      try {
        const session = await authApi.authenticate(code.trim());
        onAuthenticated(session.username);
      } catch (err) {
        setCode("");
        if (err instanceof ApiError && err.status === 429) {
          // The daemon dropped the pending login after too many wrong codes.
          setStep("password");
        }
        throw err;
      }
    }, t("login.badCode"));
  }

  function restart() {
    setStep("user");
    setPassword("");
    setCode("");
    setError("");
  }

  const stepNumber = step === "user" ? 1 : step === "password" ? 2 : 3;
  const title = step === "user" ? t("login.stepUser") : step === "password" ? t("login.stepPassword") : t("login.stepCode");

  return (
    <div className="grid min-h-screen place-items-center bg-paper px-4 py-8 text-ink">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-3">
          <Shield className="h-20 w-auto" />
          <Wordmark className="h-7 w-auto" />
        </div>

        <div className="rounded-3xl border border-white/10 bg-slate-900/60 px-5 py-5 text-white shadow-xl backdrop-blur-xl transition-all duration-200 ease-in-out">
          <p className="text-[11px] tracking-wide text-white/50 uppercase">{t("login.step", { step: stepNumber })}</p>
          <h1 className="mt-1 mb-4 text-lg font-semibold tracking-tight">{title}</h1>

          {step !== "user" ? (
            <div className="mb-4 flex items-center justify-between gap-3 rounded-2xl border border-white/10 bg-white/5 px-3 py-2 text-sm">
              <span className="min-w-0 truncate">{username}</span>
              <button type="button" onClick={restart} className="shrink-0 text-xs text-white/60 transition-all duration-200 ease-in-out hover:text-white">
                {t("login.change")}
              </button>
            </div>
          ) : null}

          {step === "user" ? (
            <form onSubmit={submitUser} className="space-y-4">
              <Field label={t("login.username")}>
                <input
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  autoComplete="username"
                  autoCapitalize="none"
                  spellCheck={false}
                  autoFocus
                  required
                  className={input}
                />
              </Field>
              <button type="submit" disabled={busy || username.trim() === ""} className={primary}>
                {busy ? t("login.checking") : t("login.next")}
              </button>
            </form>
          ) : null}

          {step === "password" || step === "enroll" ? (
            <form onSubmit={submitPassword} className="space-y-4">
              {/* Lets password managers pair the password with the name. */}
              <input type="text" name="username" value={username} autoComplete="username" readOnly hidden />
              <Field label={t("login.password")}>
                <input
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  autoComplete="current-password"
                  autoFocus
                  required
                  className={input}
                />
              </Field>
              <button type="submit" disabled={busy || password === ""} className={primary}>
                {busy ? t("login.checking") : t("login.next")}
              </button>
            </form>
          ) : null}

          {step === "code" ? (
            <form onSubmit={submitCode} className="space-y-4">
              <p className="text-sm text-white/70">{t("login.codeHint")}</p>
              <Field label={t("login.code")}>
                <input
                  value={code}
                  onChange={(event) => setCode(event.target.value.slice(0, 11))}
                  autoComplete="one-time-code"
                  inputMode="text"
                  autoFocus
                  required
                  placeholder={t("login.codePlaceholder")}
                  className={`${input} text-center font-mono text-lg tracking-widest`}
                />
              </Field>
              <button type="submit" disabled={busy || code.trim().length < 6} className={primary}>
                {busy ? t("login.checking") : t("login.signIn")}
              </button>
              <p className="text-center text-xs text-white/50">
                {t("login.lostAccess")} <code className="font-mono">sudo godeb-play 2fa reset</code>
              </p>
            </form>
          ) : null}

          {error ? (
            <p role="alert" className="mt-4 text-sm text-debian">
              {error}
            </p>
          ) : null}

          {providers.length > 0 && step === "user" ? (
            <div className="mt-4 space-y-2 border-t border-white/10 pt-4">
              {providers.map((provider) => (
                <a
                  key={provider.id}
                  href={`/api/auth/oidc/${provider.id}/start`}
                  className="block rounded-2xl border border-white/10 px-4 py-2 text-center text-sm transition-all duration-200 ease-in-out hover:bg-white/10"
                >
                  {t("login.withProvider", { name: provider.name })}
                </a>
              ))}
            </div>
          ) : null}
        </div>
      </div>

      {step === "enroll" ? <TwoFAEnrollment onComplete={onAuthenticated} onCancel={restart} /> : null}
    </div>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block text-xs tracking-wide text-white/50 uppercase">{label}</span>
      {children}
    </label>
  );
}

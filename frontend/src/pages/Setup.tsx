import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { LanguageSelect } from "@/components/LanguageSelect.tsx";
import { Shield, Wordmark } from "@/components/Brand.tsx";
import { ConfigUpload } from "@/components/ConfigUpload.tsx";
import { SetupSummary, type SetupSummaryData } from "@/components/SetupSummary.tsx";
import { api } from "@/lib/api.ts";
import { useGet } from "@/lib/useAsync.ts";
import * as ui from "@/components/ui.ts";

export type SetupStatus = { required: boolean; hasAdmin: boolean };

type LanAddress = { iface: string; address: string; prefix: string };

type SetupInfo = {
  hostname: string;
  publicIp: string;
  lan: LanAddress[];
  sshPorts: number[];
  role: { role: "" | "hub" | "peer"; hub?: string; address?: string };
  ufw: "missing" | "inactive" | "active";
  setupPort: number;
  fingerprint: string;
};

type JoinResult = { address: string; hub: string; notes: string[]; handshake?: boolean; detail?: string };
type FinishResult = { ok: boolean; log: string[]; access: { mode: string; address?: string; port?: number }; summary?: SetupSummaryData };

const input = ui.input;
const primary = `${ui.primary} w-full sm:w-auto`;
const secondary = ui.button;

// tokenFromHash reads ?token= from "#/setup?token=…", the link printed by
// `godeb-play setup-url`.
export function tokenFromHash(): string {
  const query = window.location.hash.split("?")[1] ?? "";
  return new URLSearchParams(query).get("token") ?? "";
}

export function SetupFrame({ step, total, children, wide = false }: { step: number; total: number; children: ReactNode; wide?: boolean }) {
  const { t } = useTranslation();
  return (
    <div className="grid min-h-screen place-items-center bg-paper px-4 py-8 text-ink">
      <div className={`w-full ${wide ? "max-w-2xl" : "max-w-sm"}`}>
        <div className="mb-6 flex items-center gap-3">
          <Shield className="h-12 w-auto" />
          <div className="min-w-0 flex-1">
            <Wordmark className="h-6 w-auto" />
            <div className="mt-1 text-[11px] tracking-wide text-muted uppercase">{t("setup.title")}</div>
          </div>
          <LanguageSelect persist={false} className="text-xs" />
        </div>
        <div className="rounded-3xl border border-white/10 bg-slate-900/60 px-5 py-5 text-white shadow-xl backdrop-blur-xl">
          <p className="mb-4 text-[11px] tracking-wide text-white/50 uppercase">{t("setup.step", { step, total })}</p>
          {children}
        </div>
      </div>
    </div>
  );
}

// SetupAdmin is step 1: the first administrator. It needs the one-time token.
export function SetupAdmin({ onCreated }: { onCreated: (username: string) => void }) {
  const { t } = useTranslation();
  const [token, setToken] = useState(tokenFromHash());
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (password !== repeat) {
      setError(t("setup.passwordMismatch"));
      return;
    }
    setBusy(true);
    setError("");
    try {
      await api("/api/setup/admin", {
        method: "POST",
        headers: { "X-GoDeb-Setup-Token": token.trim() },
        body: JSON.stringify({ username, password }),
      });
      onCreated(username);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("setup.failed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <SetupFrame step={1} total={4}>
      <h1 className="text-base font-semibold">{t("setup.adminTitle")}</h1>
      <p className="mt-1 text-sm text-white/60">{t("setup.adminText")}</p>
      <form onSubmit={(e) => void submit(e)} className="mt-4 space-y-4">
        <Field label={t("setup.token")} hint={t("setup.tokenHint")}>
          <input value={token} onChange={(e) => setToken(e.target.value)} required className={`${input} font-mono`} autoComplete="off" />
        </Field>
        <Field label={t("login.username")}>
          <input value={username} onChange={(e) => setUsername(e.target.value)} required autoComplete="username" className={input} />
        </Field>
        <Field label={t("login.password")} hint={t("setup.passwordHint")}>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={12} maxLength={72} autoComplete="new-password" className={input} />
        </Field>
        <Field label={t("setup.passwordRepeat")}>
          <input type="password" value={repeat} onChange={(e) => setRepeat(e.target.value)} required autoComplete="new-password" className={input} />
        </Field>
        <button type="submit" disabled={busy} className={primary}>
          {busy ? t("setup.working") : t("setup.next")}
        </button>
        {error ? <p className="text-sm text-debian">{error}</p> : null}
      </form>
    </SetupFrame>
  );
}

type Role = "peer" | "none";

// SetupWizard runs after password and 2FA: WireGuard role, then access and
// firewall. Every step goes through the same functions as `godeb-play setup`.
export function SetupWizard({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const info = useGet<SetupInfo>("/api/setup/info");
  const [stage, setStage] = useState<"role" | "access" | "done">("role");
  const [role, setRole] = useState<Role>("peer");
  const [result, setResult] = useState<FinishResult | null>(null);

  useEffect(() => {
    const existing = info.data?.role.role;
    if (existing === "peer") {
      setRole(existing);
    }
  }, [info.data]);

  if (info.error) {
    return (
      <SetupFrame step={3} total={4}>
        <p className="text-sm text-debian">{info.error}</p>
      </SetupFrame>
    );
  }
  if (!info.data) {
    return (
      <SetupFrame step={3} total={4}>
        <p className="text-sm text-white/60">{t("common.loading")}</p>
      </SetupFrame>
    );
  }
  if (stage === "role") {
    return <RoleStep info={info.data} role={role} setRole={setRole} onNext={() => { info.reload(); setStage("access"); }} />;
  }
  if (stage === "access") {
    return <AccessStep info={info.data} role={role} onBack={() => setStage("role")} onFinished={(r) => { setResult(r); setStage("done"); }} />;
  }
  return <DoneStep result={result} info={info.data} onDone={onDone} />;
}

// RoleStep joins the GoDeb hub with the join code of a site (godeb site add
// on the hub) through wireguard.JoinHub, the same code as `godeb-play setup
// --join`. "Without WireGuard" is for trying the panel on the LAN only.
function RoleStep({ info, role, setRole, onNext }: { info: SetupInfo; role: Role; setRole: (r: Role) => void; onNext: () => void }) {
  const { t } = useTranslation();
  const configured = info.role.role === "peer";
  const [config, setConfig] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [joined, setJoined] = useState<JoinResult | null>(null);

  async function apply() {
    setBusy(true);
    setError("");
    try {
      if (role === "peer") {
        setJoined(await api<JoinResult>("/api/setup/join", { method: "POST", body: JSON.stringify({ config }) }));
      } else {
        onNext();
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("setup.failed"));
    } finally {
      setBusy(false);
    }
  }

  const options: { id: Role; title: string; text: string }[] = [
    { id: "peer", title: t("setup.rolePeer"), text: t("setup.rolePeerText") },
    { id: "none", title: t("setup.roleNone"), text: t("setup.roleNoneText") },
  ];

  return (
    <SetupFrame step={3} total={4} wide>
      <h1 className="text-base font-semibold">{t("setup.roleTitle")}</h1>
      <p className="mt-1 text-sm text-white/60">{t("setup.roleText")}</p>
      {configured ? (
        <p className="mt-4 rounded-2xl border border-emerald-300/20 bg-emerald-400/5 px-3 py-2 text-sm">
          {t("setup.roleExisting", { role: t("setup.rolePeer") })}
        </p>
      ) : joined ? null : (
        <div className="mt-4 grid gap-3 md:grid-cols-2">
          {options.map((o) => (
            <button
              key={o.id}
              type="button"
              aria-pressed={role === o.id}
              onClick={() => { setRole(o.id); setError(""); }}
              className={`rounded-2xl border px-3 py-3 text-left text-sm transition-all duration-200 ease-in-out ${role === o.id ? "border-white/40 bg-white/15" : "border-white/10 bg-white/5 hover:bg-white/10"}`}
            >
              <span className="block font-medium">{o.title}</span>
              <span className="mt-1 block text-xs text-white/60">{o.text}</span>
            </button>
          ))}
        </div>
      )}

      {!configured && role === "peer" && !joined ? (
        <div className="mt-4">
          <div className="mb-3">
            <ConfigUpload onLoad={setConfig} />
          </div>
          <Field label={t("setup.joinFile")} hint={t("setup.joinHint")}>
            <textarea value={config} onChange={(e) => setConfig(e.target.value)} rows={8} spellCheck={false} placeholder={t("setup.joinPlaceholder")} className={`${input} font-mono text-xs break-all`} />
          </Field>
        </div>
      ) : null}

      {joined ? (
        <div className="mt-4 space-y-1 text-sm">
          <p className={joined.handshake ? "text-emerald-300" : "text-amber-200"}>
            {joined.handshake ? t("setup.joinDone", { address: joined.address, hub: joined.hub }) : (joined.detail ?? t("setup.joinNoHandshake"))}
          </p>
          {joined.notes.map((n) => (
            <p key={n} className="text-xs text-white/60">{n}</p>
          ))}
        </div>
      ) : null}

      {error ? <p className="mt-3 text-sm text-debian">{error}</p> : null}
      <div className="mt-5 flex flex-wrap gap-2">
        {configured || joined ? (
          <button type="button" className={primary} onClick={onNext}>{t("setup.next")}</button>
        ) : (
          <button type="button" className={primary} disabled={busy || (role === "peer" && config.trim() === "")} onClick={() => void apply()}>
            {busy ? t("setup.working") : role === "none" ? t("setup.next") : t("setup.apply")}
          </button>
        )}
      </div>
    </SetupFrame>
  );
}

function AccessStep({ info, role, onBack, onFinished }: { info: SetupInfo; role: Role; onBack: () => void; onFinished: (r: FinishResult) => void }) {
  const { t } = useTranslation();
  const tunnel = role !== "none";
  const [mode, setMode] = useState<"tunnel" | "lan" | "local">("lan");
  const [lan, setLan] = useState(info.lan[0]?.address ?? "");
  const [trust, setTrust] = useState(role === "peer");
  const [firewall, setFirewall] = useState(info.ufw !== "missing" && info.sshPorts.length > 0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [log, setLog] = useState<string[]>([]);

  async function finish() {
    setBusy(true);
    setError("");
    try {
      const res = await api<FinishResult>("/api/setup/finish", {
        method: "POST",
        body: JSON.stringify({ access: mode, lanAddress: lan, trust: trust && info.lan.length > 0, firewall }),
      });
      onFinished(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("setup.failed"));
      setLog([]);
    } finally {
      setBusy(false);
    }
  }

  const modes: { id: "tunnel" | "lan" | "local"; title: string; text: string; show: boolean }[] = [
    { id: "tunnel", title: t("setup.accessTunnel"), text: t("setup.accessTunnelText"), show: tunnel },
    { id: "lan", title: t("setup.accessLan"), text: t("setup.accessLanText"), show: info.lan.length > 0 },
    { id: "local", title: t("setup.accessLocal"), text: t("setup.accessLocalText"), show: true },
  ];

  return (
    <SetupFrame step={4} total={4} wide>
      <h1 className="text-base font-semibold">{t("setup.accessTitle")}</h1>
      <p className="mt-1 text-sm text-white/60">{t("setup.accessText")}</p>
      <div className="mt-4 grid gap-3 md:grid-cols-3">
        {modes.filter((m) => m.show).map((m) => (
          <button
            key={m.id}
            type="button"
            aria-pressed={mode === m.id}
            onClick={() => setMode(m.id)}
            className={`rounded-2xl border px-3 py-3 text-left text-sm transition-all duration-200 ease-in-out ${mode === m.id ? "border-white/40 bg-white/15" : "border-white/10 bg-white/5 hover:bg-white/10"}`}
          >
            <span className="block font-medium">{m.title}</span>
            <span className="mt-1 block text-xs text-white/60">{m.text}</span>
          </button>
        ))}
      </div>

      {mode === "lan" || trust ? (
        <div className="mt-4">
          <Field label={t("setup.lanAddress")}>
            <select value={lan} onChange={(e) => setLan(e.target.value)} className={input}>
              {info.lan.map((a) => (
                <option key={a.address} value={a.address}>
                  {a.address} ({a.iface}, {a.prefix})
                </option>
              ))}
            </select>
          </Field>
        </div>
      ) : null}

      <div className="mt-4 space-y-3 text-sm">
        {info.lan.length > 0 && tunnel ? (
          <Check checked={trust} onChange={setTrust} label={t("setup.trust")} hint={t("setup.trustHint")} />
        ) : null}
        {info.ufw !== "missing" ? (
          <Check
            checked={firewall}
            onChange={setFirewall}
            disabled={info.sshPorts.length === 0}
            label={info.ufw === "active" ? t("setup.firewallActive") : t("setup.firewall")}
            hint={info.sshPorts.length > 0 ? t("setup.firewallHint", { ports: info.sshPorts.join(", ") }) : t("setup.firewallNoSsh")}
          />
        ) : (
          <p className="text-xs text-amber-200">{t("setup.ufwMissing")}</p>
        )}
      </div>

      {log.length > 0 ? <pre className="mt-3 overflow-auto rounded-2xl bg-slate-950/50 p-3 text-[11px] whitespace-pre-wrap">{log.join("\n")}</pre> : null}
      {error ? <p className="mt-3 text-sm text-debian">{error}</p> : null}
      <div className="mt-5 flex flex-wrap gap-2">
        <button type="button" className={secondary} onClick={onBack} disabled={busy}>{t("setup.back")}</button>
        <button type="button" className={primary} disabled={busy || ((mode === "lan" || trust) && !lan)} onClick={() => void finish()}>
          {busy ? t("setup.working") : t("setup.finish")}
        </button>
      </div>
    </SetupFrame>
  );
}

function DoneStep({ result, info, onDone }: { result: FinishResult | null; info: SetupInfo; onDone: () => void }) {
  const { t } = useTranslation();
  const access = result?.access;
  const onSetupListener = window.location.port === String(info.setupPort) && window.location.protocol === "https:";
  let next = "";
  if (result?.summary?.urls.length) {
    next = result.summary.urls[0].url;
  } else if (access?.mode === "lan" && access.address) {
    next = `https://${access.address}:${access.port ?? 8443}`;
  } else if (access?.mode === "tunnel") {
    next = t("setup.nextTunnel");
  } else {
    next = t("setup.nextLocal");
  }
  return (
    <SetupFrame step={4} total={4} wide>
      <h1 className="text-base font-semibold">{t("setup.doneTitle")}</h1>
      <p className="mt-1 text-sm text-white/70">{t("setup.doneText")}</p>
      <p className="mt-3 rounded-2xl border border-white/10 bg-black/20 px-3 py-2 font-mono text-sm break-all">{next}</p>
      {result?.log.length ? <pre className="mt-3 overflow-auto rounded-2xl bg-slate-950/50 p-3 text-[11px] whitespace-pre-wrap text-white/70">{result.log.join("\n")}</pre> : null}
      {onSetupListener ? <p className="mt-3 text-xs text-amber-200">{t("setup.listenerClosed")}</p> : null}
      {result?.summary ? (
        <div className="mt-6">
          <p className="mb-3 text-sm text-white/70">{t("setup.summaryHint")}</p>
          <SetupSummary data={result.summary} />
        </div>
      ) : null}
      <div className="mt-5">
        <button type="button" className={primary} onClick={onDone}>{t("setup.toDashboard")}</button>
      </div>
    </SetupFrame>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block min-w-0 text-sm">
      <span className="mb-1 block text-[11px] tracking-wide text-white/50 uppercase">{label}</span>
      {children}
      {hint ? <span className="mt-1 block text-xs text-white/50">{hint}</span> : null}
    </label>
  );
}

function Check({ checked, onChange, label, hint, disabled = false }: { checked: boolean; onChange: (v: boolean) => void; label: string; hint?: string; disabled?: boolean }) {
  return (
    <label className={`flex items-start gap-2 ${disabled ? "opacity-50" : ""}`}>
      <input type="checkbox" className="mt-1 h-4 w-4" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span>
        {label}
        {hint ? <span className="block text-xs text-white/50">{hint}</span> : null}
      </span>
    </label>
  );
}

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { ConfigUpload } from "@/components/ConfigUpload.tsx";
import { PanelFrame } from "@/components/PanelFrame.tsx";
import { Help } from "@/components/Help.tsx";
import { More, StatGrid } from "@/components/Section.tsx";
import * as ui from "@/components/ui.ts";
import { api } from "@/lib/api.ts";
import type { CommandEnvelope } from "@/lib/types.ts";
import { useGet } from "@/lib/useAsync.ts";

// GoDeb Play is always a site of a GoDeb hub: this page shows the tunnel to
// the hub and lets the admin join (or join again with a new code). Peers,
// QR codes and the full tunnel live on the hub, in GoDeb.

type WgInterface = { name: string; publicKey?: string; listenPort?: string; addresses: string[]; dns: string[]; up: boolean };
type WgPeer = { name?: string; publicKey: string; allowedIPs: string[]; endpoint?: string; latestHandshake: number; rxBytes: number; txBytes: number };
type WgRole = { role: "" | "hub" | "peer"; hub?: string; address?: string };
type JoinResult = { ok: boolean; address: string; hub: string; notes: string[]; handshake: boolean; detail?: string };
type WgPeers = CommandEnvelope & { path: string; liveDetail?: string; interface: WgInterface; peers: WgPeer[]; configured: boolean; role: WgRole };

const buttonClass = ui.button;
const inputClass = `${ui.input} font-mono`;

// A handshake older than this means the tunnel is down (WireGuard renews
// it every two minutes while traffic or keepalives flow).
const STALE_SECONDS = 180;

export default function Panel() {
  const { t, i18n } = useTranslation();
  const query = useGet<WgPeers>("/api/plugins/wireguard/peers");
  const [rejoin, setRejoin] = useState(false);
  const data = query.data;
  const info = data?.interface;
  const hub = data?.peers[0];
  const fresh = hub ? hub.latestHandshake > 0 && Date.now() / 1000 - hub.latestHandshake < STALE_SECONDS : false;

  return (
    <PanelFrame
      title={t("wg.title")}
      description={t("wg.siteDescription")}
      command={data?.command}
      mocked={data?.mocked}
      detail={data?.detail}
      loading={query.loading}
      error={query.error}
      onRefresh={query.reload}
    >
      {data && info ? (
        <>
          <StatGrid
            items={[
              {
                label: t("wg.status"),
                value: !data.configured ? t("wg.notJoined") : fresh ? t("wg.connected") : t("wg.noHandshake"),
                tone: !data.configured ? "text-white/70" : fresh ? "text-emerald-300" : "text-amber-200",
              },
              { label: t("wg.address"), value: info.addresses.join(", ") || "—", mono: true },
              { label: t("wg.hub"), value: data.role.hub || hub?.endpoint || "—", mono: true },
              { label: t("wg.handshake"), value: hub ? handshake(hub.latestHandshake, i18n.language, t("wg.never")) : "—" },
            ]}
          />
          {data.liveDetail ? <p className="mb-4 text-sm text-muted">wg show: {data.liveDetail}</p> : null}

          {!data.configured ? <JoinCard onJoined={query.reload} /> : null}

          {data.configured && data.role.role === "hub" ? (
            <p className="mb-4 rounded-2xl border border-amber-300/20 bg-amber-400/5 px-4 py-3 text-sm">{t("wg.hubHere")}</p>
          ) : null}

          {data.configured && data.role.role !== "hub" ? (
            <section className="mb-6 rounded-2xl border border-emerald-300/20 bg-emerald-400/5 px-4 py-3 text-sm text-white backdrop-blur-xl">
              <h2 className="font-medium">{t("wg.peerRoleTitle")}</h2>
              <p className="mt-1 text-white/70">{t("wg.siteRoleText", { hub: data.role.hub ?? "—", address: data.role.address ?? "—" })}</p>
              {hub ? (
                <p className="mt-2 font-mono text-xs text-white/60">
                  ↓ {bytes(hub.rxBytes)} · ↑ {bytes(hub.txBytes)}
                </p>
              ) : null}
              {!fresh ? <p className="mt-2 text-xs text-amber-200">{t("wg.noHandshakeHint")}</p> : null}
            </section>
          ) : null}

          <More title={t("common.more")}>
            <dl className="overflow-hidden rounded-2xl border border-white/10 bg-slate-900/60 text-white backdrop-blur-xl">
              <Row label={t("wg.publicKey")} value={info.publicKey || "—"} mono />
              <Row label={t("wg.file")} value={data.path} mono />
              {hub ? <Row label={t("wg.allowedIPs")} value={hub.allowedIPs.join(", ") || "—"} mono /> : null}
            </dl>
            {data.configured ? (
              rejoin ? (
                <JoinCard onJoined={() => { setRejoin(false); query.reload(); }} />
              ) : (
                <button type="button" className={buttonClass} onClick={() => setRejoin(true)}>
                  {t("wg.rejoin")}
                </button>
              )
            ) : null}
          </More>
        </>
      ) : null}
    </PanelFrame>
  );
}

function JoinCard({ onJoined }: { onJoined: () => void }) {
  const { t } = useTranslation();
  const [config, setConfig] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<JoinResult | null>(null);

  async function submit() {
    setBusy(true);
    setError("");
    try {
      const res = await api<JoinResult>("/api/plugins/wireguard/join", { method: "POST", body: JSON.stringify({ config }) });
      setResult(res);
      setConfig("");
      onJoined();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("wg.joinFailed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      className="mb-6 rounded-2xl border border-white/10 bg-slate-900/60 p-4 text-white backdrop-blur-xl"
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <h2 className="flex items-center gap-2 text-base font-semibold">
        {t("wg.joinTitle")}
        <Help>{t("wg.joinText")}</Help>
      </h2>
      <div className="mt-3">
        <ConfigUpload onLoad={setConfig} />
      </div>
      <textarea
        value={config}
        onChange={(event) => setConfig(event.target.value)}
        rows={8}
        spellCheck={false}
        placeholder={t("setup.joinPlaceholder")}
        className={`${inputClass} mt-3 min-h-40`}
      />
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <button type="submit" disabled={busy || config.trim() === ""} className={buttonClass}>
          {busy ? t("wg.joining") : t("wg.joinSubmit")}
        </button>
        {error ? <span className="text-sm text-debian">{error}</span> : null}
      </div>
      {result ? (
        <div className="mt-3 space-y-1 text-sm">
          <p className={result.handshake ? "text-emerald-300" : "text-amber-200"}>
            {result.handshake ? t("wg.joinDone", { address: result.address, hub: result.hub }) : result.detail}
          </p>
          {result.notes.map((note) => (
            <p key={note} className="text-xs text-white/60">
              {note}
            </p>
          ))}
        </div>
      ) : null}
    </form>
  );
}

function Row({ label, value, mono = false, tone = "" }: { label: string; value: string; mono?: boolean; tone?: string }) {
  return (
    <div className="grid gap-1 border-b border-white/10 px-4 py-3 transition-all duration-200 ease-in-out last:border-b-0 hover:bg-white/5 sm:grid-cols-[11rem_1fr] sm:gap-4">
      <dt className="text-xs tracking-wide text-white/50 uppercase">{label}</dt>
      <dd className={`${mono ? "font-mono text-sm break-all" : "text-sm"} ${tone}`}>{value}</dd>
    </div>
  );
}

function bytes(value: number): string {
  if (!value) {
    return "0 B";
  }
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let n = value;
  let unit = 0;
  while (n >= 1024 && unit < units.length - 1) {
    n /= 1024;
    unit += 1;
  }
  return `${n.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function handshake(unix: number, language: string, never: string): string {
  if (!unix) {
    return never;
  }
  const seconds = Math.max(0, Math.floor(Date.now() / 1000 - unix));
  const relative = new Intl.RelativeTimeFormat(language, { numeric: "auto" });
  if (seconds < 60) {
    return relative.format(-seconds, "second");
  }
  if (seconds < 3600) {
    return relative.format(-Math.floor(seconds / 60), "minute");
  }
  if (seconds < 86400) {
    return relative.format(-Math.floor(seconds / 3600), "hour");
  }
  return new Date(unix * 1000).toLocaleString(language);
}

import { ConfigUpload } from "@/components/ConfigUpload.tsx";
import { JoinCodeBox } from "@/components/JoinCodeBox.tsx";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { DataTable, PanelFrame } from "@/components/PanelFrame.tsx";
import { api, apiBlob } from "@/lib/api.ts";
import type { CommandEnvelope } from "@/lib/types.ts";
import { useGet } from "@/lib/useAsync.ts";
import { Modal } from "./Modal.tsx";
import * as ui from "@/components/ui.ts";
import { More, SectionHeader, StatGrid } from "@/components/Section.tsx";
import { Help } from "@/components/Help.tsx";

type WgInterface = {
  name: string;
  publicKey?: string;
  listenPort?: string;
  addresses: string[];
  dns: string[];
  up: boolean;
};

type WgPeer = {
  id?: string;
  name?: string;
  publicKey: string;
  allowedIPs: string[];
  endpoint?: string;
  latestHandshake: number;
  rxBytes: number;
  txBytes: number;
  inConfig: boolean;
  live: boolean;
  hasClient: boolean;
  created?: string;
  site?: boolean;
};

type WgRole = {
  role: "" | "hub" | "peer";
  hub?: string;
  address?: string;
};

type JoinResult = {
  ok: boolean;
  address: string;
  hub: string;
  notes: string[];
  handshake: boolean;
  detail?: string;
};

type WgPeers = CommandEnvelope & {
  path: string;
  clientsDir: string;
  liveDetail?: string;
  defaultEndpoint?: string;
  interface: WgInterface;
  peers: WgPeer[];
  configured: boolean;
  role: WgRole;
  volltunnel?: boolean;
};

type CreateResult = {
  ok: boolean;
  peer: WgPeer;
  live: boolean;
  detail?: string;
};

type AndroidClient = {
  available: boolean;
  filename: string;
  size?: number;
  version?: string;
  modified?: string;
  downloadPath: string;
  tokenRequired?: boolean;
  tokenSet?: boolean;
  detail?: string;
};

type LanAddress = { iface: string; address: string; prefix: string };

type TrustStatus = {
  config: { enabled: boolean; address: string; port: number; iface: string; prefix: string };
  running: boolean;
  error?: string;
  url?: string;
  fingerprint?: string;
  candidates: LanAddress[];
  mocked: boolean;
  detail?: string;
};

const peersPath = "/api/plugins/wireguard/peers";
const androidPath = "/api/plugins/wireguard/android";
const androidApkDiskPath = "/etc/godeb-play/android/godeb-tunnel.apk";

const buttonClass = ui.button;
const linkClass = "text-xs text-white/80 transition-all duration-200 ease-in-out enabled:hover:text-white disabled:opacity-40";
const inputClass = `${ui.input} font-mono`;

export default function Panel() {
  const { t, i18n } = useTranslation();
  const query = useGet<WgPeers>(peersPath);
  const android = useGet<AndroidClient>(androidPath);
  const [qrPeer, setQrPeer] = useState<WgPeer | null>(null);
  const [mailPeer, setMailPeer] = useState<WgPeer | null>(null);
  const [codePeer, setCodePeer] = useState<WgPeer | null>(null);
  const [notice, setNotice] = useState("");
  const [adding, setAdding] = useState(false);
  const [actionError, setActionError] = useState("");
  const [deleteAfterDownload, setDeleteAfterDownload] = useState(false);
  const info = query.data?.interface;
  const peers = query.data?.peers ?? [];
  const isPeer = query.data?.role?.role === "peer";

  async function downloadApk() {
    if (!android.data?.available) {
      return;
    }
    setActionError("");
    try {
      let path = android.data.downloadPath;
      if (android.data.tokenRequired) {
        const tok = await api<{ token?: string }>(`${androidPath}/token`);
        if (tok.token) {
          path = `${android.data.downloadPath}?token=${encodeURIComponent(tok.token)}`;
        }
      }
      const blob = await apiBlob(path);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = android.data.filename || "godeb-tunnel.apk";
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : t("wg.androidDownloadFailed"));
    }
  }

  async function setApkToken(action: "generate" | "clear") {
    setActionError("");
    try {
      await api(`${androidPath}/token`, {
        method: "POST",
        body: JSON.stringify({ action }),
      });
      android.reload();
      setNotice(
        action === "generate" ? t("wg.androidTokenOn") : t("wg.androidTokenOff"),
      );
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : t("wg.androidDownloadFailed"));
    }
  }

  async function download(peer: WgPeer) {
    if (!peer.id) {
      return;
    }
    setActionError("");
    try {
      const blob = await apiBlob(`${peersPath}/${encodeURIComponent(peer.id)}/config`);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${peer.id}.conf`;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      if (deleteAfterDownload) {
        await api(`${peersPath}/${encodeURIComponent(peer.id)}/delete-config`, {
          method: "POST",
          body: "{}",
        });
        query.reload();
        setNotice(t("wg.configDeleted", { name: peer.id }));
      }
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : t("wg.downloadFailed"));
    }
  }

  return (
    <PanelFrame
      title={t("wg.title")}
      description={t("wg.description", { path: `/etc/wireguard/${info?.name ?? "wg0"}.conf` })}
      command={query.data?.command}
      mocked={query.data?.mocked}
      detail={query.data?.detail}
      loading={query.loading}
      error={query.error}
      onRefresh={query.reload}
    >
      {query.data && info ? (
        <>
          <StatGrid
            items={[
              {
                label: t("wg.status"),
                value: info.up ? t("wg.up", { name: info.name }) : t("wg.down", { name: info.name }),
                tone: info.up ? "text-emerald-300" : "text-rose-300",
              },
              { label: t("wg.address"), value: info.addresses.join(", ") || "—", mono: true },
              { label: t("wg.listen"), value: info.listenPort || "—", mono: true },
              { label: t("wg.dns"), value: info.dns.join(", ") || "—", mono: true },
            ]}
          />
          {query.data.liveDetail ? (
            <p className="mb-4 text-sm text-muted">wg show: {query.data.liveDetail}</p>
          ) : null}

          {!query.data.configured ? <JoinCard onJoined={query.reload} /> : null}

          {isPeer ? (
            <section className="mb-6 rounded-2xl border border-emerald-300/20 bg-emerald-400/5 px-4 py-3 text-sm text-white backdrop-blur-xl">
              <h2 className="font-medium">{t("wg.peerRoleTitle")}</h2>
              <p className="mt-1 text-white/70">
                {t("wg.peerRoleText", { hub: query.data.role.hub ?? "—", address: query.data.role.address ?? "—" })}
              </p>
            </section>
          ) : null}

          <SectionHeader title={t("wg.peers")}>
            {!isPeer ? (
              <button type="button" className={adding ? ui.button : ui.primary} onClick={() => setAdding((v) => !v)}>
                {adding ? t("common.cancel") : `+ ${t("wg.new")}`}
              </button>
            ) : null}
          </SectionHeader>

          {!isPeer && adding ? (
            <CreateForm
              disabled={query.data.mocked}
              listenPort={info.listenPort}
              defaultEndpoint={query.data.defaultEndpoint}
              dns={info.dns}
              onCreated={(result) => {
                setAdding(false);
                setActionError("");
                setNotice(
                  result.live
                    ? t("wg.createdLive", { name: result.peer.name })
                    : t("wg.created", { name: result.peer.name, detail: result.detail ?? "" }),
                );
                if (result.peer.site) {
                  // The site needs exactly this code (or file): show it right away.
                  setCodePeer(result.peer);
                }
                query.reload();
              }}
            />
          ) : null}

          {notice ? <p className="mb-4 text-sm text-moss">{notice}</p> : null}
          {actionError ? <p className="mb-4 text-sm text-debian">{actionError}</p> : null}

          {peers.length === 0 ? (
            <p className="text-sm text-muted">{t("wg.none")}</p>
          ) : (
            <>
            <DataTable mobileCards head={[t("wg.name"), t("wg.ip"), t("wg.publicKey"), t("wg.endpoint"), t("wg.handshake"), t("wg.transfer"), ""]}>
              {peers.map((peer, index) => (
                <tr key={`${peer.publicKey || "peer"}-${index}`}>
                  <td className="px-3 py-2">
                    {peer.name || "—"}
                    {peer.site ? <Badge text={t("wg.siteBadge")} /> : null}
                    {!peer.inConfig ? <Badge text={t("wg.liveOnly")} /> : null}
                    {peer.inConfig && !peer.live && info.up ? <Badge text={t("wg.notLive")} /> : null}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{peer.allowedIPs.join(", ") || "—"}</td>
                  <td className="max-w-[12rem] truncate px-3 py-2 font-mono text-xs" title={peer.publicKey}>
                    {peer.publicKey || "—"}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{peer.endpoint || "—"}</td>
                  <td className="px-3 py-2 text-xs whitespace-nowrap">{handshake(peer.latestHandshake, i18n.language, t("wg.never"))}</td>
                  <td className="px-3 py-2 font-mono text-xs whitespace-nowrap">
                    ↓ {bytes(peer.rxBytes)} · ↑ {bytes(peer.txBytes)}
                  </td>
                  <td className="space-x-3 px-3 py-2 text-right whitespace-nowrap">
                    <button
                      type="button"
                      disabled={!peer.hasClient}
                      title={peer.hasClient ? undefined : t("wg.noClient")}
                      onClick={() => void download(peer)}
                      className={linkClass}
                    >
                      .conf
                    </button>
                    {peer.site ? (
                      <button type="button" disabled={!peer.hasClient} onClick={() => setCodePeer(peer)} className={linkClass}>
                        {t("wg.codeAction")}
                      </button>
                    ) : (
                      <button type="button" disabled={!peer.hasClient} onClick={() => setQrPeer(peer)} className={linkClass}>
                        QR
                      </button>
                    )}
                    <button
                      type="button"
                      disabled={!peer.hasClient}
                      onClick={() => setMailPeer(peer)}
                      className={linkClass}
                    >
                      {t("wg.mail")}
                    </button>
                  </td>
                </tr>
              ))}
            </DataTable>
            <label className="mt-3 flex items-start gap-2 text-sm text-muted">
              <input
                type="checkbox"
                checked={deleteAfterDownload}
                onChange={(event) => setDeleteAfterDownload(event.target.checked)}
                className="mt-1"
              />
              <span>
                {t("wg.deleteAfterDownload")}
                <span className="block text-xs">{t("wg.deleteAfterDownloadHint")}</span>
              </span>
            </label>
            </>
          )}

          <More title={t("common.more")}>
            <dl className="overflow-hidden rounded-2xl border border-white/10 bg-slate-900/60 text-white backdrop-blur-xl">
              <Row label={t("wg.publicKey")} value={info.publicKey || "—"} mono />
              <Row label={t("wg.file")} value={query.data.path} mono />
            </dl>
            {query.data.configured ? <TrustCard hub={!isPeer} hasSites={peers.some((p) => p.site)} /> : null}
            {!isPeer && query.data.configured ? (
              <VolltunnelCard
                enabled={Boolean(query.data.volltunnel)}
                disabled={Boolean(query.data.mocked)}
                onChanged={query.reload}
              />
            ) : null}
            {!isPeer ? (
              <AndroidClientCard
                info={android.data ?? undefined}
                loading={android.loading}
                onDownload={() => void downloadApk()}
                onRefresh={android.reload}
                onToken={(action) => void setApkToken(action)}
              />
            ) : null}
          </More>

          {qrPeer?.id ? <QrModal peer={qrPeer} onClose={() => setQrPeer(null)} /> : null}
          {codePeer?.id ? <CodeModal peer={codePeer} onClose={() => setCodePeer(null)} /> : null}
          {mailPeer?.id ? (
            <EmailModal
              peer={mailPeer}
              onClose={() => setMailPeer(null)}
              onSent={(to) => {
                setMailPeer(null);
                setActionError("");
                setNotice(t("wg.sent", { name: mailPeer.id, to }));
              }}
            />
          ) : null}
        </>
      ) : null}
    </PanelFrame>
  );
}

function AndroidClientCard({
  info,
  loading,
  onDownload,
  onRefresh,
  onToken,
}: {
  info?: AndroidClient;
  loading: boolean;
  onDownload: () => void;
  onRefresh: () => void;
  onToken: (action: "generate" | "clear") => void;
}) {
  const { t } = useTranslation();
  return (
    <section className="mb-6 overflow-hidden rounded-2xl border border-white/10 bg-slate-900/60 text-white backdrop-blur-xl">
      <div className="border-b border-white/10 px-4 py-3">
        <h2 className="text-sm font-medium tracking-wide text-white/90">{t("wg.androidTitle")}</h2>
        <p className="mt-1 text-sm text-white/60">{t("wg.androidDescription")}</p>
      </div>
      <div className="space-y-3 px-4 py-4 text-sm">
        {loading && !info ? <p className="text-white/50">{t("common.loading")}</p> : null}
        {info?.available ? (
          <>
            <p className="text-white/80">
              {info.version ? t("wg.androidVersion", { version: info.version }) : info.filename}
              {info.size != null ? ` · ${t("wg.androidSize", { size: bytes(info.size) })}` : null}
            </p>
            <div className="flex flex-wrap gap-2">
              <button type="button" onClick={onDownload} className={buttonClass}>
                {t("wg.androidDownload")}
              </button>
              <button type="button" onClick={onRefresh} className={buttonClass}>
                {t("common.refresh")}
              </button>
            </div>
          </>
        ) : (
          <p className="text-white/60">{t("wg.androidUnavailable", { path: androidApkDiskPath })}</p>
        )}
        <div className="rounded-2xl border border-white/10 bg-white/5 px-3 py-2 text-xs text-white/70">
          <p>{t("wg.androidTokenHint")}</p>
          <div className="mt-2 flex flex-wrap gap-2">
            <button type="button" className={buttonClass} onClick={() => onToken("generate")}>
              {info?.tokenSet ? t("wg.androidTokenRotate") : t("wg.androidTokenEnable")}
            </button>
            {info?.tokenSet ? (
              <button type="button" className={buttonClass} onClick={() => onToken("clear")}>
                {t("wg.androidTokenDisable")}
              </button>
            ) : null}
          </div>
        </div>
        <p className="text-xs text-white/50">{t("wg.androidQrHint")}</p>
      </div>
    </section>
  );
}

// TrustCard: the signed trusted endpoint on this host's LAN address. On a hub
// it also re-writes the trust lines of existing client files.
function TrustCard({ hub, hasSites }: { hub: boolean; hasSites: boolean }) {
  const { t } = useTranslation();
  const status = useGet<TrustStatus>("/api/plugins/wireguard/trust");
  const [address, setAddress] = useState("");
  const [port, setPort] = useState(8787);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const data = status.data;

  useEffect(() => {
    if (!data) {
      return;
    }
    setAddress(data.config.address || data.candidates[0]?.address || "");
    setPort(data.config.port || 8787);
  }, [data]);

  async function save(enabled: boolean) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await api<TrustStatus>("/api/plugins/wireguard/trust", { method: "POST", body: JSON.stringify({ enabled, address, port }) });
      setNotice(enabled ? t("wg.trustEnabled") : t("wg.trustDisabled"));
      status.reload();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("wg.trustFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function sync() {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const res = await api<{ changed: number }>("/api/plugins/wireguard/trust/sync", { method: "POST" });
      setNotice(t("wg.trustSynced", { count: res.changed }));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("wg.trustFailed"));
    } finally {
      setBusy(false);
    }
  }

  const enabled = data?.config.enabled ?? false;
  return (
    <section className="mb-6 overflow-hidden rounded-2xl border border-white/10 bg-slate-900/60 text-white backdrop-blur-xl">
      <div className="border-b border-white/10 px-4 py-3">
        <h2 className="text-sm font-medium tracking-wide text-white/90">{t("wg.trustTitle")}</h2>
        <p className="mt-1 text-sm text-white/60">{t("wg.trustDescription")}</p>
      </div>
      <div className="space-y-3 px-4 py-4 text-sm">
        {status.loading && !data ? <p className="text-white/50">{t("common.loading")}</p> : null}
        {data?.mocked ? <p className="text-amber-200">{data.detail}</p> : null}
        {enabled ? (
          <div className="rounded-2xl border border-white/10 bg-black/20 px-3 py-2">
            <p className={data?.running ? "text-emerald-300" : "text-amber-200"}>
              {data?.running ? t("wg.trustRunning") : t("wg.trustNotRunning", { error: data?.error ?? "" })}
            </p>
            <code className="mt-1 block break-all font-mono text-xs text-emerald-200">{data?.url}</code>
            <p className="mt-1 text-xs text-white/60">
              {t("wg.trustScope", { prefix: data?.config.prefix ?? "", iface: data?.config.iface ?? "" })} · {t("wg.trustFingerprint")}{" "}
              <span className="font-mono">{data?.fingerprint}</span>
            </p>
          </div>
        ) : null}
        <div className="grid gap-3 sm:grid-cols-[1fr_8rem]">
          <label className="text-sm">
            <span className="mb-1 block text-xs tracking-wide text-white/50 uppercase">{t("wg.trustAddress")}</span>
            <select value={address} onChange={(e) => setAddress(e.target.value)} className={inputClass}>
              {(data?.candidates ?? []).length === 0 ? <option value="">{t("wg.trustNoLan")}</option> : null}
              {(data?.candidates ?? []).map((c) => (
                <option key={c.address} value={c.address}>
                  {c.address} ({c.iface}, {c.prefix})
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-xs tracking-wide text-white/50 uppercase">{t("wg.trustPort")}</span>
            <input inputMode="numeric" value={port} onChange={(e) => setPort(Number(e.target.value) || 0)} className={inputClass} />
          </label>
        </div>
        <div className="flex flex-wrap gap-2">
          <button type="button" disabled={busy || !address || data?.mocked} onClick={() => void save(true)} className={buttonClass}>
            {enabled ? t("wg.trustApply") : t("wg.trustEnable")}
          </button>
          {enabled ? (
            <button type="button" disabled={busy} onClick={() => void save(false)} className={buttonClass}>
              {t("wg.trustDisable")}
            </button>
          ) : null}
          {hub && (hasSites || enabled) ? (
            <button type="button" disabled={busy} onClick={() => void sync()} className={buttonClass}>
              {t("wg.trustSync")}
            </button>
          ) : null}
        </div>
        {notice ? <p className="text-moss">{notice}</p> : null}
        {error ? <p className="text-debian">{error}</p> : null}
        <p className="text-xs text-white/50">{hub ? t("wg.trustHubHint") : t("wg.trustPeerHint")}</p>
      </div>
    </section>
  );
}

function VolltunnelCard({
  enabled,
  disabled,
  onChanged,
}: {
  enabled: boolean;
  disabled: boolean;
  onChanged: () => void;
}) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function setEnabled(next: boolean) {
    if (next && !window.confirm(t("wg.volltunnelConfirm"))) {
      return;
    }
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await api("/api/plugins/wireguard/volltunnel", {
        method: "POST",
        body: JSON.stringify({ enabled: next }),
      });
      setNotice(next ? t("wg.volltunnelOn") : t("wg.volltunnelOff"));
      onChanged();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("wg.volltunnelFailed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="mb-6 rounded-2xl border border-white/10 bg-slate-900/60 px-4 py-3 text-sm text-white backdrop-blur-xl">
      <h2 className="font-medium">{t("wg.volltunnelTitle")}</h2>
      <p className="mt-1 text-white/70">{t("wg.volltunnelText")}</p>
      <p className="mt-2 text-xs text-amber-200/90">{t("wg.volltunnelWarn")}</p>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <span className={enabled ? "text-emerald-300" : "text-white/50"}>
          {enabled ? t("wg.volltunnelActive") : t("wg.volltunnelInactive")}
        </span>
        <button
          type="button"
          disabled={busy || disabled}
          onClick={() => void setEnabled(!enabled)}
          className={buttonClass}
        >
          {enabled ? t("wg.volltunnelDisable") : t("wg.volltunnelEnable")}
        </button>
      </div>
      {notice ? <p className="mt-2 text-moss">{notice}</p> : null}
      {error ? <p className="mt-2 text-debian">{error}</p> : null}
    </section>
  );
}

function CreateForm({
  disabled,
  listenPort,
  defaultEndpoint,
  dns,
  onCreated,
}: {
  disabled: boolean;
  listenPort?: string;
  defaultEndpoint?: string;
  dns: string[];
  onCreated: (result: CreateResult) => void;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [endpoint, setEndpoint] = useState(defaultEndpoint || `${window.location.hostname}:${listenPort || "51820"}`);
  const [dnsValue, setDnsValue] = useState(dns.join(", ") || "1.1.1.1");
  const [allowedIPs, setAllowedIPs] = useState("0.0.0.0/0, ::/0");
  const [excludedIPs, setExcludedIPs] = useState("");
  const [address, setAddress] = useState("");
  const [site, setSite] = useState(false);
  const [deviceKey, setDeviceKey] = useState(false);
  const [publicKey, setPublicKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit() {
    setBusy(true);
    setError("");
    try {
      const result = await api<CreateResult>(peersPath, {
        method: "POST",
        body: JSON.stringify({
          name,
          endpoint,
          dns: dnsValue,
          allowedIPs,
          excludedIPs,
          address,
          site,
          publicKey: deviceKey ? publicKey.trim() : undefined,
        }),
      });
      setName("");
      setAddress("");
      setExcludedIPs("");
      setSite(false);
      setDeviceKey(false);
      setPublicKey("");
      onCreated(result);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("wg.createFailed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      className="mb-6 rounded-2xl border border-white/10 bg-slate-900/60 p-4 text-white backdrop-blur-xl transition-all duration-200 ease-in-out"
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <h2 className="mb-3 text-sm font-semibold">{t("wg.new")}</h2>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Field label={t("wg.name")} value={name} onChange={setName} placeholder="phone-anna" required />
        <Field label={t("wg.endpoint")} value={endpoint} onChange={setEndpoint} placeholder="vpn.example.org:51820" required />
        {!site ? (
          <>
            <Field label={t("wg.dns")} value={dnsValue} onChange={setDnsValue} placeholder="1.1.1.1" />
            <Field label={t("wg.allowed")} value={allowedIPs} onChange={setAllowedIPs} />
            <Field
              label={t("wg.excluded")}
              value={excludedIPs}
              onChange={setExcludedIPs}
              placeholder={t("wg.excludedPlaceholder")}
            />
          </>
        ) : null}
        <Field label={t("wg.addressOptional")} value={address} onChange={setAddress} placeholder={site ? "10.8.0.2" : t("wg.auto")} />
      </div>
      <label className="mt-3 flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          checked={site}
          disabled={deviceKey}
          onChange={(event) => {
            setSite(event.target.checked);
            if (event.target.checked && address.trim() === "") {
              setAddress("10.8.0.2");
            }
          }}
          className="mt-1"
        />
        <span>
          {t("wg.siteLabel")}
          <span className="block text-xs text-white/50">{t("wg.siteHint")}</span>
        </span>
      </label>
      {!site ? (
        <label className="mt-3 flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={deviceKey}
            onChange={(event) => {
              setDeviceKey(event.target.checked);
              if (event.target.checked) {
                setSite(false);
              }
            }}
            className="mt-1"
          />
          <span>
            {t("wg.deviceKey")}
            <span className="block text-xs text-white/50">{t("wg.deviceKeyHint")}</span>
          </span>
        </label>
      ) : null}
      {deviceKey && !site ? (
        <div className="mt-3">
          <Field label={t("wg.publicKey")} value={publicKey} onChange={setPublicKey} placeholder="Base64 …=" required />
        </div>
      ) : null}
      {!site ? <p className="mt-2 text-xs text-white/50">{t("wg.excludedHint")}</p> : null}
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <button
          type="submit"
          disabled={busy || disabled || name.trim() === "" || (deviceKey && publicKey.trim() === "")}
          className={buttonClass}
        >
          {busy ? t("wg.creating") : t("wg.create")}
        </button>
        {disabled ? (
          <span className="text-xs text-white/60">{t("wg.needConfig")}</span>
        ) : null}
        {error ? <span className="text-sm text-debian">{error}</span> : null}
      </div>
    </form>
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

function QrModal({ peer, onClose }: { peer: WgPeer; onClose: () => void }) {
  const { t } = useTranslation();
  const [src, setSrc] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    let url = "";
    let cancelled = false;
    apiBlob(`${peersPath}/${encodeURIComponent(peer.id ?? "")}/qr`)
      .then((blob) => {
        if (cancelled) {
          return;
        }
        url = URL.createObjectURL(blob);
        setSrc(url);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : t("wg.qrFailed"));
        }
      });
    return () => {
      cancelled = true;
      if (url) {
        URL.revokeObjectURL(url);
      }
    };
  }, [peer.id]);

  return (
    <Modal title={t("wg.qr", { name: peer.name ?? peer.id })} onClose={onClose}>
      {error ? <p className="text-sm text-rose-300">{error}</p> : null}
      {!error && !src ? <p className="text-sm text-white/60">{t("wg.qrLoading")}</p> : null}
      {src ? (
        <>
          <img src={src} alt={t("wg.qrAlt", { name: peer.name ?? "" })} className="mx-auto w-72 rounded-2xl [image-rendering:pixelated]" />
          <p className="mt-3 text-center text-xs text-white/60">{t("wg.qrHint")}</p>
        </>
      ) : null}
    </Modal>
  );
}

// CodeModal shows the join code of a site, to paste into "Mit Hub
// verbinden" on that GoDeb host.
function CodeModal({ peer, onClose }: { peer: WgPeer; onClose: () => void }) {
  const { t } = useTranslation();
  const [code, setCode] = useState("");
  const [config, setConfig] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    const base = `${peersPath}/${encodeURIComponent(peer.id ?? "")}`;
    Promise.all([api<{ code: string }>(`${base}/code`), apiBlob(`${base}/config`).then((b) => b.text())])
      .then(([res, text]) => {
        if (!cancelled) {
          setCode(res.code);
          setConfig(text);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : t("wg.downloadFailed"));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [peer.id]);

  return (
    <Modal title={t("wg.codeTitle", { name: peer.name ?? peer.id })} onClose={onClose}>
      {error ? <p className="text-sm text-rose-300">{error}</p> : null}
      {!error && !code ? <p className="text-sm text-white/60">{t("common.loading")}</p> : null}
      {code ? <JoinCodeBox code={code} filename={`${peer.id}.conf`} config={config} /> : null}
    </Modal>
  );
}

function EmailModal({
  peer,
  onClose,
  onSent,
}: {
  peer: WgPeer;
  onClose: () => void;
  onSent: (to: string) => void;
}) {
  const { t } = useTranslation();
  const [to, setTo] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function send() {
    setBusy(true);
    setError("");
    try {
      const result = await api<{ ok: boolean; to: string }>(
        `${peersPath}/${encodeURIComponent(peer.id ?? "")}/send-email`,
        { method: "POST", body: JSON.stringify({ to }) },
      );
      onSent(result.to);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("wg.mailFailed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={t("wg.emailTitle", { name: peer.name ?? peer.id })} onClose={onClose}>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void send();
        }}
      >
        <label className="block text-sm">
          <span className="mb-1 block text-xs tracking-wide text-white/50 uppercase">{t("wg.recipient")}</span>
          <input
            type="email"
            required
            autoFocus
            value={to}
            onChange={(event) => setTo(event.target.value)}
            placeholder="anna@example.org"
            className={inputClass}
          />
        </label>
        <p className="mt-3 text-xs text-white/60">{t("wg.emailHint")}</p>
        {error ? <p className="mt-3 text-sm text-debian">{error}</p> : null}
        <div className="mt-4 flex justify-end gap-2">
          <button type="button" onClick={onClose} className={buttonClass}>
            {t("common.cancel")}
          </button>
          <button type="submit" disabled={busy || to.trim() === ""} className={buttonClass}>
            {busy ? t("wg.sending") : t("wg.send")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  required = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  required?: boolean;
}) {
  return (
    <label className="text-sm">
      <span className="mb-1 block text-xs tracking-wide text-white/50 uppercase">{label}</span>
      <input
        value={value}
        required={required}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className={inputClass}
      />
    </label>
  );
}

function Badge({ text }: { text: string }) {
  return <span className="ms-2 rounded-full border border-amber-300/30 px-2 py-0.5 text-[10px] text-amber-200 uppercase">{text}</span>;
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

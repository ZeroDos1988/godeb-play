import { useState } from "react";
import { useTranslation } from "react-i18next";
import { copyText, downloadText } from "@/lib/clipboard.ts";
import * as ui from "@/components/ui.ts";

// JoinCodeBox shows a site's join code with copy and download (WireGuard
// view on a hub). GoDeb Play only joins hubs; the box stays for that view.
const glass = ui.button;
const input = ui.input;
export function JoinCodeBox({ code, filename, config }: { code: string; filename: string; config?: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  async function copy() {
    await copyText(code);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }
  return (
    <div className="space-y-3 text-xs text-white/70">
      <p>{t("clients.siteHint")}</p>
      <label className="block">
        <span className="mb-1 block text-[11px] tracking-wide text-white/50 uppercase">{t("clients.code")}</span>
        <textarea
          readOnly
          value={code}
          rows={4}
          spellCheck={false}
          onFocus={(e) => e.currentTarget.select()}
          className={`${input} resize-none font-mono text-[11px] break-all`}
        />
      </label>
      <div className="flex flex-wrap gap-2">
        <button type="button" className={glass} onClick={() => void copy()} disabled={!code}>
          {copied ? t("common.copied") : t("clients.copyCode")}
        </button>
        {config ? (
          <button type="button" className={glass} onClick={() => downloadText(filename, config)}>
            {t("clients.download")}
          </button>
        ) : null}
      </div>
      <p>
        {t("clients.siteTerminal")} <code className="rounded bg-black/30 px-1.5 py-0.5 font-mono text-white">sudo godeb setup --join -</code>
      </p>
      <p className="text-amber-200/90">{t("clients.secret")}</p>
    </div>
  );
}


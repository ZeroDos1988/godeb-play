import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import * as ui from "@/components/ui.ts";

// ConfigUpload reads a WireGuard client file (e.g. heim-vm.conf from the
// hub) into a text field, so the admin uploads it instead of copying text.
export function ConfigUpload({ onLoad }: { onLoad: (text: string) => void }) {
  const { t } = useTranslation();
  const ref = useRef<HTMLInputElement>(null);
  const [error, setError] = useState("");
  const [name, setName] = useState("");

  async function read(file: File | undefined) {
    setError("");
    if (!file) return;
    if (file.size > 16 * 1024) {
      setError(t("upload.tooLarge"));
      return;
    }
    const text = await file.text();
    if (!text.includes("[Interface]") || !text.includes("[Peer]")) {
      setError(t("upload.notWireGuard"));
      return;
    }
    setName(file.name);
    onLoad(text);
  }

  return (
    <div className="flex flex-wrap items-center gap-2 text-sm">
      <input ref={ref} type="file" accept=".conf,text/plain" className="hidden" onChange={(e) => void read(e.target.files?.[0])} />
      <button
        type="button"
        onClick={() => ref.current?.click()}
        className={ui.button}
      >
        {t("upload.choose")}
      </button>
      {name ? <span className="text-xs text-emerald-300">{t("upload.loaded", { name })}</span> : <span className="text-xs text-white/50">{t("upload.orPaste")}</span>}
      {error ? <span className="text-xs text-rose-300">{error}</span> : null}
    </div>
  );
}

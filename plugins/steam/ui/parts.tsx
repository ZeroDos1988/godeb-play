import type { ReactNode } from "react";
import * as ui from "@/components/ui.ts";

export const button = ui.button;
export const primary = ui.primary;
export const card = ui.card;
export const input = ui.input;

export function Stat({ label, value, ok, hint }: { label: string; value: string; ok?: boolean; hint?: string }) {
  return (
    <div className={card}>
      <div className="text-[11px] tracking-wide text-white/50 uppercase">{label}</div>
      <div className={`mt-1 text-sm font-medium ${ok === undefined ? "" : ok ? "text-emerald-400" : "text-white/80"}`}>{value}</div>
      {hint ? <div className="mt-1 font-mono text-xs break-all text-white/50">{hint}</div> : null}
    </div>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block min-w-0 text-sm">
      <span className="mb-1 block text-xs tracking-wide text-white/60 uppercase">{label}</span>
      {children}
    </label>
  );
}

export function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return (
    <label className="inline-flex cursor-pointer items-center gap-2">
      <input type="checkbox" className="h-4 w-4 accent-[var(--color-primary)]" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span>{label}</span>
    </label>
  );
}

export function randomPassword() {
  const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  // Rejection sampling keeps every symbol equally likely.
  const limit = 256 - (256 % alphabet.length);
  let out = "";
  while (out.length < 16) {
    for (const b of crypto.getRandomValues(new Uint8Array(32))) {
      if (b < limit && out.length < 16) {
        out += alphabet[b % alphabet.length];
      }
    }
  }
  return out;
}

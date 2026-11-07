import type { ReactNode } from "react";
import { Help } from "@/components/Help.tsx";

// Every page follows the same order: state, the main list, forms only on
// demand, rarely needed settings folded away at the bottom. These two
// pieces keep that order the same on every page.

/** Heading of a block on the page, with its actions on the right. */
export function SectionHeader({ title, hint, children }: { title: string; hint?: string; children?: ReactNode }) {
  return (
    <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h2 className="flex items-center gap-2 text-lg font-semibold tracking-tight">
          {title}
          {hint ? <Help>{hint}</Help> : null}
        </h2>
      </div>
      {children ? <div className="flex flex-wrap items-center gap-2">{children}</div> : null}
    </div>
  );
}

/** Settings that are rarely needed, folded away at the bottom of a page. */
export function More({ title, children }: { title: string; children: ReactNode }) {
  return (
    <details className="group mt-10 border-t border-line pt-4">
      <summary className="flex min-h-11 w-fit cursor-pointer list-none items-center gap-2 text-sm font-medium text-muted transition-all duration-200 ease-in-out select-none hover:text-ink [&::-webkit-details-marker]:hidden">
        <span aria-hidden className="inline-block transition-transform duration-200 group-open:rotate-90">
          ›
        </span>
        {title}
      </summary>
      <div className="mt-4 space-y-4">{children}</div>
    </details>
  );
}

export type Stat = { label: string; value: ReactNode; tone?: string; mono?: boolean };

/** Key figures of a page in one compact card instead of a long table. */
export function StatGrid({ items }: { items: Stat[] }) {
  return (
    <dl className="mb-6 grid grid-cols-2 gap-px overflow-hidden rounded-2xl border border-white/10 bg-white/10 text-white lg:grid-cols-4">
      {items.map((item) => (
        <div key={item.label} className="min-w-0 bg-slate-900/95 px-4 py-3">
          <dt className="text-xs text-white/55">{item.label}</dt>
          <dd className={`mt-0.5 truncate text-sm font-medium ${item.mono ? "font-mono" : ""} ${item.tone ?? ""}`}>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

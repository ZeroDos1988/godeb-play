import { useEffect, useState, type ReactNode } from "react";
import { createPortal, flushSync } from "react-dom";
import { Shield, Wordmark } from "@/components/Brand.tsx";

// PrintSheet renders its children only for printing, as a plain sheet
// directly below <body> while the app itself is hidden (index.css). The app
// is dark glass inside scroll containers and backdrop filters, which browsers
// print as blank or clipped pages; a separate sheet avoids all of that.
// It reacts to the print button and to Ctrl+P alike.
export function PrintSheet({ children }: { children: ReactNode }) {
  const printing = usePrinting();
  if (!printing) {
    return null;
  }
  return createPortal(<div className="gd-sheet">{children}</div>, document.body);
}

function usePrinting() {
  const [printing, setPrinting] = useState(false);
  useEffect(() => {
    // The sheet must be in the DOM before the browser lays out the print,
    // so beforeprint renders synchronously.
    const before = () => flushSync(() => setPrinting(true));
    const after = () => setPrinting(false);
    window.addEventListener("beforeprint", before);
    window.addEventListener("afterprint", after);
    return () => {
      window.removeEventListener("beforeprint", before);
      window.removeEventListener("afterprint", after);
    };
  }, []);
  return printing;
}

// SheetHeader is the head of every printed page: what it is, which server,
// when.
export function SheetHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <header className="mb-5 flex items-end justify-between gap-4 border-b-2 border-black pb-2">
      <div>
        <h1 className="text-xl font-semibold">{title}</h1>
        {subtitle ? <p className="text-xs text-neutral-600">{subtitle}</p> : null}
      </div>
      <span className="flex items-center gap-2">
        <Shield className="h-8 w-auto" />
        <Wordmark className="h-4 w-auto" />
      </span>
    </header>
  );
}

export function SheetSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="gd-sheet-block mb-5">
      <h2 className="mb-1.5 border-b border-neutral-400 pb-0.5 text-sm font-semibold tracking-wide uppercase">{title}</h2>
      {children}
    </section>
  );
}

export function SheetRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[11rem_1fr] gap-4 border-b border-neutral-200 py-1 last:border-b-0">
      <div className="text-neutral-600">{label}</div>
      <div className={`min-w-0 break-all ${mono ? "font-mono text-[0.95em]" : ""}`}>{value}</div>
    </div>
  );
}

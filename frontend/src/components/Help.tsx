import { useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

// Help is the small "?" next to a heading or field. The explanation shows
// on hover or keyboard focus, and on tap on touch screens, so the pages
// themselves stay short.
export function Help({ children, className = "" }: { children: ReactNode; className?: string }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [pinned, setPinned] = useState(false);
  const [pos, setPos] = useState<{ left: number; top: number } | null>(null);
  const id = useId();
  const ref = useRef<HTMLSpanElement>(null);
  const bubble = useRef<HTMLSpanElement>(null);

  // Keep the bubble on screen: centred under the "?", but pushed back in
  // at least 12 px from either edge. It is fixed, so scrolling closes it.
  useLayoutEffect(() => {
    if (!open || !ref.current || !bubble.current) {
      setPos(null);
      return;
    }
    const anchor = ref.current.getBoundingClientRect();
    const width = bubble.current.offsetWidth;
    const centre = anchor.left + anchor.width / 2;
    const left = Math.max(12, Math.min(centre - width / 2, window.innerWidth - width - 12));
    setPos({ left, top: anchor.bottom + 8 });
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const close = () => {
      setPinned(false);
      setOpen(false);
    };
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    return () => {
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
    };
  }, [open]);

  useEffect(() => {
    if (!pinned) return;
    const outside = (event: PointerEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) {
        setPinned(false);
        setOpen(false);
      }
    };
    const escape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setPinned(false);
        setOpen(false);
      }
    };
    document.addEventListener("pointerdown", outside);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("pointerdown", outside);
      document.removeEventListener("keydown", escape);
    };
  }, [pinned]);

  return (
    <span
      ref={ref}
      className={`relative inline-flex align-middle ${className}`}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => !pinned && setOpen(false)}
    >
      <button
        type="button"
        aria-label={t("common.help")}
        aria-describedby={open ? id : undefined}
        aria-expanded={open}
        onFocus={() => setOpen(true)}
        onBlur={() => !pinned && setOpen(false)}
        onClick={() => {
          setPinned(!pinned);
          setOpen(!pinned);
        }}
        className="grid h-5 w-5 place-items-center rounded-full border border-current text-[11px] leading-none font-semibold text-muted opacity-70 transition-all duration-200 ease-in-out hover:text-brand-cyan hover:opacity-100 focus-visible:text-brand-cyan focus-visible:opacity-100"
      >
        ?
      </button>
      {open ? (
        <span
          ref={bubble}
          id={id}
          role="tooltip"
          style={pos ? { left: pos.left, top: pos.top } : { left: 0, top: 0, visibility: "hidden" }}
          className={`fixed z-50 w-max max-w-[min(20rem,calc(100vw-1.5rem))] rounded-xl border border-white/10 bg-slate-900 px-3 py-2 text-start text-xs leading-relaxed font-normal tracking-normal text-white normal-case shadow-xl`}
        >
          {children}
        </span>
      ) : null}
    </span>
  );
}


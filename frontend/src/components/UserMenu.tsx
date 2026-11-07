import { useEffect, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { LanguageSelect } from "@/components/LanguageSelect.tsx";

type Props = {
  username: string;
  version?: string;
  onAppearance: () => void;
  onSessions: () => void;
  onLogout: () => void;
};

// UserMenu is the avatar at the top right: everything about the signed-in
// account (language, appearance, sessions, sign out) behind one button, so
// the pages themselves stay free of it.
export function UserMenu({ username, version, onAppearance, onSessions, onLogout }: Props) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) {
      return;
    }
    const outside = (event: PointerEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const escape = (event: KeyboardEvent) => event.key === "Escape" && setOpen(false);
    document.addEventListener("pointerdown", outside);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("pointerdown", outside);
      document.removeEventListener("keydown", escape);
    };
  }, [open]);

  const pick = (action: () => void) => () => {
    setOpen(false);
    action();
  };

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        aria-haspopup="true"
        aria-expanded={open}
        aria-label={t("user.menu", { name: username })}
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 rounded-full p-0.5 pe-1.5 text-sidebar-fg/70 transition-all duration-200 ease-in-out hover:bg-sidebar-fg/10 hover:text-sidebar-fg"
      >
        <Avatar name={username} />
        <span aria-hidden className={`text-xs transition-transform duration-200 ${open ? "rotate-180" : ""}`}>
          ▾
        </span>
      </button>
      {open ? (
        <div className="absolute end-0 top-full z-40 mt-2 w-72 max-w-[calc(100vw-1.5rem)] overflow-hidden rounded-2xl border border-white/10 bg-slate-900 text-sm text-white shadow-2xl">
          <div className="flex items-center gap-3 border-b border-white/10 px-4 py-3">
            <Avatar name={username} />
            <div className="min-w-0">
              <div className="text-xs text-white/50">{t("user.signedInAs")}</div>
              <div className="truncate font-medium">{username}</div>
            </div>
          </div>
          <div className="border-b border-white/10 px-4 py-3">
            <div className="mb-1.5 text-[11px] tracking-wide text-white/50 uppercase">{t("common.language")}</div>
            <LanguageSelect persist className="w-full" />
          </div>
          <div className="py-1">
            <Item onClick={pick(onAppearance)}>{t("nav.appearance")}</Item>
            <Item onClick={pick(onSessions)}>{t("nav.sessions")}</Item>
          </div>
          <div className="border-t border-white/10 py-1">
            <Item onClick={pick(onLogout)} danger>
              {t("nav.logout")}
            </Item>
          </div>
          {version ? <div className="border-t border-white/10 px-4 py-2 font-mono text-[11px] text-white/40">GoDeb {version}</div> : null}
        </div>
      ) : null}
    </div>
  );
}

function Item({ children, onClick, danger = false }: { children: ReactNode; onClick: () => void; danger?: boolean }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`block w-full px-4 py-2 text-start transition-all duration-200 ease-in-out hover:bg-white/10 ${danger ? "text-rose-300" : "text-white/85"}`}
    >
      {children}
    </button>
  );
}

// Avatar shows up to two initials of the account name.
function Avatar({ name }: { name: string }) {
  const initials =
    name
      .split(/[^\p{L}\p{N}]+/u)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0]?.toUpperCase())
      .join("") || "?";
  return (
    <span aria-hidden className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-debian text-xs font-semibold text-on-solid ring-2 ring-white/15">
      {initials}
    </span>
  );
}

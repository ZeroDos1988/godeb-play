import {
  Children,
  cloneElement,
  isValidElement,
  type ReactElement,
  type ReactNode,
} from "react";
import { useTranslation } from "react-i18next";
import { Help } from "@/components/Help.tsx";
import * as ui from "@/components/ui.ts";

type PanelFrameProps = {
  title: string;
  description?: string;
  command?: string[];
  mocked?: boolean;
  detail?: string;
  loading: boolean;
  error: string;
  onRefresh: () => void;
  /** Sub tabs of the page, shown right under the heading. */
  tabs?: ReactNode;
  children?: ReactNode;
};

export function PanelFrame({
  title,
  description,
  command,
  mocked,
  detail,
  loading,
  error,
  onRefresh,
  tabs,
  children,
}: PanelFrameProps) {
  const { t } = useTranslation();
  return (
    <section>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            {title}
            {description ? <Help>{description}</Help> : null}
          </h1>
        </div>
        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          title={t("common.refresh")}
          aria-label={t("common.refresh")}
          className={`${ui.button} w-11 px-0 text-lg md:w-10`}
        >
          <span aria-hidden className={loading ? "animate-spin" : ""}>
            ↻
          </span>
        </button>
      </div>

      {tabs ? <div className="mt-4 overflow-x-auto">{tabs}</div> : null}

      {mocked ? (
        <p className="mt-4 rounded-2xl border border-amber-300/20 bg-amber-950/30 px-4 py-3 text-sm text-amber-100">{t("panel.mocked")}</p>
      ) : null}

      {/* What GoDeb ran and why sample data is shown: for diagnosis only,
          folded away so the page shows what the admin needs. */}
      {(command && command.length > 0) || (mocked && detail) ? (
        <details className="group mt-3 text-xs text-muted">
          <summary className="w-fit cursor-pointer select-none transition-all duration-200 ease-in-out hover:text-debian">
            {t("panel.technical")}
          </summary>
          <div className="mt-2 space-y-2">
            {command && command.length > 0 ? (
              <p className="overflow-x-auto rounded-2xl border border-white/10 bg-slate-900/60 px-3 py-2 font-mono text-white/80 backdrop-blur-xl">
                $ {command.join(" ")}
              </p>
            ) : null}
            {mocked && detail ? <p className="font-mono break-words">{detail}</p> : null}
          </div>
        </details>
      ) : null}

      {loading && !children ? <p className="mt-6 text-sm text-muted">{t("common.loading")}</p> : null}
      {error ? <p className="mt-6 text-sm text-debian">{error}</p> : null}
      {children ? <div className={loading ? "mt-6 opacity-60 transition-all duration-200" : "mt-6"}>{children}</div> : null}
    </section>
  );
}

export function DataTable({
  head,
  children,
  mobileCards = false,
}: {
  head: string[];
  children: ReactNode;
  /** Under `sm`, render each row as a labelled card (WireGuard, UFW, …). */
  mobileCards?: boolean;
}) {
  const body = mobileCards ? labelCells(head, children) : children;
  return (
    <div
      className={`gd-table overflow-x-auto rounded-2xl border border-white/10 bg-slate-900/60 text-white backdrop-blur-xl transition-all duration-200 ease-in-out ${
        mobileCards ? "gd-table-cards" : ""
      }`}
    >
      <table className="w-full border-collapse text-left text-sm">
        <thead className="text-[11px] tracking-wide text-white/50 uppercase">
          <tr>
            {head.map((label) => (
              <th key={label || "action"} className="px-3 py-3 font-medium">
                {label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-white/10 [&>tr]:transition-all [&>tr]:duration-200 [&>tr]:ease-in-out [&>tr:hover]:bg-white/5">
          {body}
        </tbody>
      </table>
    </div>
  );
}

function labelCells(head: string[], children: ReactNode): ReactNode {
  return Children.map(children, (row) => {
    if (!isValidElement(row)) return row;
    const el = row as ReactElement<{ children?: ReactNode }>;
    const cells = Children.map(el.props.children, (cell, i) => {
      if (!isValidElement(cell)) return cell;
      const cellEl = cell as ReactElement<{ "data-label"?: string; className?: string }>;
      return cloneElement(cellEl, {
        "data-label": head[i] || "",
        className: `${cellEl.props.className ?? ""} gd-card-cell`.trim(),
      });
    });
    return cloneElement(el, {}, cells);
  });
}

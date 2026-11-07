// Shared classes for cards, fields and buttons. Every panel uses these, so
// inputs and buttons have the same height, radius and border everywhere
// (44 px on touch screens, 40 px from md on).

const control = "min-h-11 rounded-xl text-sm transition-all duration-200 ease-in-out md:min-h-10";

/** Card: one block of content on a page. */
export const card = "rounded-2xl border border-white/10 bg-slate-900/60 p-4 text-white backdrop-blur-xl md:p-5";

/** Text field, select or textarea. Add font-mono where values are technical. */
export const input = `${control} block w-full border border-white/15 bg-slate-950/40 px-3 py-2 text-white outline-none placeholder:text-white/40 focus:border-debian disabled:opacity-50`;

/** Secondary button. */
export const button = `${control} inline-flex shrink-0 items-center justify-center gap-2 border border-white/15 bg-white/5 px-4 text-white enabled:hover:bg-white/10 disabled:opacity-50`;

/** The one main action of a form. */
export const primary = `${control} inline-flex shrink-0 items-center justify-center gap-2 border border-transparent bg-debian px-4 font-medium text-on-solid enabled:hover:brightness-110 disabled:opacity-50`;

/** Destructive action (remove, stop). */
export const danger = `${control} inline-flex shrink-0 items-center justify-center gap-2 border border-rose-400/30 bg-rose-500/10 px-4 text-rose-200 enabled:hover:bg-rose-500/20 disabled:opacity-50`;

/** Small text button inside tables and lists. */
export const link = "text-sm text-white/70 underline-offset-2 transition-all duration-200 ease-in-out enabled:hover:text-white hover:underline disabled:opacity-40";

/** Label above a field. */
export const label = "mb-1 block text-xs font-medium text-white/60";

/** Heading inside a card. */
export const cardTitle = "text-base font-semibold";

/** Hint under a field or a card title. */
export const hint = "mt-1 text-xs text-white/55";

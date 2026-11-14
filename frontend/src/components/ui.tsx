import { AnimatePresence, motion } from "framer-motion";
import { Check, ClipboardCopy, Info, Loader2, X } from "lucide-react";
import { ReactNode, useEffect, useState } from "react";
import { clamp, copy, cx } from "../lib/util";

export type Tone = "cy" | "gn" | "am" | "rd" | "vi" | "mute" | "bl";
export const TONE: Record<Tone, { text: string; bg: string; border: string; hex: string }> = {
  cy: { text: "text-cy", bg: "bg-cy/10", border: "border-cy/40", hex: "#4f46e5" },
  gn: { text: "text-gn", bg: "bg-gn/10", border: "border-gn/40", hex: "#059669" },
  am: { text: "text-am", bg: "bg-amber-50", border: "border-amber-200", hex: "#d97706" },
  rd: { text: "text-rd", bg: "bg-rd/10", border: "border-rd/40", hex: "#dc2626" },
  vi: { text: "text-vi", bg: "bg-vi/10", border: "border-vi/40", hex: "#7c3aed" },
  bl: { text: "text-bl", bg: "bg-bl/10", border: "border-bl/40", hex: "#2563eb" },
  mute: { text: "text-mute", bg: "bg-slate-100", border: "border-line", hex: "#64748b" },
};

export function Card({ children, className, glow, ...rest }: { children: ReactNode; className?: string; glow?: "cy" | "rd" | "gn" | "am" } & React.HTMLAttributes<HTMLDivElement>) {
  return <div {...rest} className={cx("card", glow && `glow-${glow}`, className)}>{children}</div>;
}

export function CardHead({ icon, title, sub, right }: { icon?: ReactNode; title: ReactNode; sub?: ReactNode; right?: ReactNode }) {
  return (
    <div className="flex items-center gap-3 px-4 pt-3.5 pb-2.5">
      {icon && <div className="text-cy">{icon}</div>}
      <div className="min-w-0 flex-1">
        <div className="text-[14px] font-semibold text-ink">{title}</div>
        {sub && <div className="text-[11.5px] text-mute leading-snug">{sub}</div>}
      </div>
      {right}
    </div>
  );
}

export function Badge({ tone = "mute", children, className, dot }: { tone?: Tone; children: ReactNode; className?: string; dot?: boolean }) {
  const t = TONE[tone];
  return (
    <span className={cx("inline-flex items-center gap-1.5 rounded-full border px-2.5 py-[2px] text-[11px] font-semibold whitespace-nowrap", t.bg, t.border, t.text, className)}>
      {dot && <span className="h-1.5 w-1.5 rounded-full" style={{ background: t.hex }} />}
      {children}
    </span>
  );
}

export function Btn({ children, onClick, variant = "primary", loading, disabled, icon, className, title, type = "button", size = "md", testId }: {
  children?: ReactNode; onClick?: () => void; variant?: "primary" | "danger" | "ghost" | "ok" | "warn"; loading?: boolean; disabled?: boolean; icon?: ReactNode; className?: string; title?: string; type?: "button" | "submit"; size?: "sm" | "md" | "lg"; testId?: string;
}) {
  const v = {
    primary: "bg-cy border-cy text-white shadow-sm hover:bg-cy/90",
    danger: "bg-rd border-rd text-white shadow-sm hover:bg-rd/90",
    ok: "bg-gn border-gn text-white shadow-sm hover:bg-gn/90",
    warn: "bg-amber-50 border-amber-200 text-am hover:bg-amber-100",
    ghost: "bg-white border-slate-300 text-ink shadow-sm hover:bg-slate-50",
  }[variant];
  const s = { sm: "px-2.5 py-1 text-xs", md: "px-3.5 py-2 text-[13px]", lg: "px-5 py-2.5 text-sm" }[size];
  return (
    <button type={type} title={title} data-testid={testId} disabled={disabled || loading} onClick={onClick}
      className={cx("inline-flex items-center justify-center gap-2 rounded-lg border font-semibold transition-all disabled:cursor-not-allowed disabled:opacity-45 active:scale-[0.97]", v, s, className)}>
      {loading ? <Loader2 size={14} className="spin" /> : icon}
      {children}
    </button>
  );
}

export function Switch({ on, onChange, disabled, label }: { on: boolean; onChange: (v: boolean) => void; disabled?: boolean; label?: string }) {
  return (
    <button role="switch" aria-checked={on} aria-label={label} disabled={disabled} onClick={() => onChange(!on)}
      className={cx("relative h-[22px] w-10 shrink-0 rounded-full border transition-all disabled:opacity-40", on ? "border-gn bg-gn" : "border-slate-300 bg-slate-200")}>
      <motion.span layout transition={{ type: "spring", stiffness: 500, damping: 32 }} className="absolute top-[2px] h-4 w-4 rounded-full" style={{ left: on ? 20 : 2, background: "#fff", boxShadow: "0 1px 2px rgba(0,0,0,.3)" }} />
    </button>
  );
}

export function Spinner({ label }: { label?: string }) {
  return <div className="flex items-center gap-2 p-6 text-sm text-mute"><Loader2 size={16} className="spin text-cy" />{label ?? "Loading…"}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="p-8 text-center text-sm text-mute">{children}</div>;
}

export function ErrorBox({ error, retry }: { error: string; retry?: () => void }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-rd/40 bg-rd/10 p-3 text-sm text-rd">
      <X size={16} /> <span className="flex-1">{error}</span>
      {retry && <Btn variant="ghost" size="sm" onClick={retry}>Retry</Btn>}
    </div>
  );
}

export function Modal({ open, onClose, title, children, width = 560 }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; width?: number }) {
  useEffect(() => {
    if (!open) return;
    const h = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [open, onClose]);
  return (
    <AnimatePresence>
      {open && (
        <motion.div className="fixed inset-0 z-[80] flex items-center justify-center p-4" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
          <div className="absolute inset-0 bg-slate-900/40 backdrop-blur-sm" onClick={onClose} />
          <motion.div role="dialog" aria-modal="true" initial={{ scale: 0.94, y: 12 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.96, opacity: 0 }}
            className="card relative max-h-[88vh] w-full overflow-auto" style={{ maxWidth: width }}>
            <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
              <div className="text-sm font-semibold">{title}</div>
              <button onClick={onClose} aria-label="Close" className="text-mute hover:text-ink"><X size={18} /></button>
            </div>
            <div className="p-5">{children}</div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

export function Confirm({ open, title, body, confirmLabel = "Confirm", danger, onConfirm, onCancel }: { open: boolean; title: string; body: ReactNode; confirmLabel?: string; danger?: boolean; onConfirm: () => void; onCancel: () => void }) {
  return (
    <Modal open={open} onClose={onCancel} title={title} width={460}>
      <div className="text-sm leading-relaxed text-ink/90">{body}</div>
      <div className="mt-5 flex justify-end gap-2">
        <Btn variant="ghost" onClick={onCancel}>Cancel</Btn>
        <Btn variant={danger ? "danger" : "primary"} onClick={onConfirm}>{confirmLabel}</Btn>
      </div>
    </Modal>
  );
}

export function Tip({ text, children }: { text: string; children?: ReactNode }) {
  return (
    <span className="group relative inline-flex items-center">
      {children ?? <Info size={13} className="text-mute" />}
      <span className="pointer-events-none absolute bottom-full left-1/2 z-50 mb-2 hidden w-60 -translate-x-1/2 rounded-lg bg-slate-900 p-2.5 text-[11.5px] font-normal normal-case leading-snug tracking-normal text-white shadow-xl group-hover:block">{text}</span>
    </span>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: ReactNode }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="inline-flex gap-1 rounded-xl border border-line bg-slate-100 p-1" role="tablist">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={value === t.id} onClick={() => onChange(t.id)}
          className={cx("relative rounded-lg px-3.5 py-1.5 text-[13px] font-medium transition-colors", value === t.id ? "text-cy" : "text-mute hover:text-ink")}>
          {value === t.id && <motion.span layoutId={`tab-${tabs.map((x) => x.id).join("")}`} className="absolute inset-0 rounded-lg border border-line bg-white shadow-sm" />}
          <span className="relative">{t.label}</span>
        </button>
      ))}
    </div>
  );
}

export function Bar({ value, tone = "cy", height = 6, className }: { value: number; tone?: Tone; height?: number; className?: string }) {
  return (
    <div className={cx("overflow-hidden rounded-full bg-slate-200", className)} style={{ height }}>
      <motion.div className="h-full rounded-full" initial={false} animate={{ width: `${clamp(value)}%` }} transition={{ type: "spring", stiffness: 120, damping: 20 }}
        style={{ background: TONE[tone].hex }} />
    </div>
  );
}

export function Gauge({ value, label, size = 120, color, sub }: { value: number; label: string; size?: number; color?: string; sub?: string }) {
  const v = clamp(value);
  const col = color ?? (v >= 85 ? "#059669" : v >= 60 ? "#d97706" : "#dc2626");
  const r = size / 2 - 9, c = 2 * Math.PI * r;
  return (
    <div className="relative flex flex-col items-center" style={{ width: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} stroke="#e2e8f0" strokeWidth={8} fill="none" />
        <motion.circle cx={size / 2} cy={size / 2} r={r} stroke={col} strokeWidth={8} fill="none" strokeLinecap="round" strokeDasharray={c}
          initial={false} animate={{ strokeDashoffset: c * (1 - v / 100) }} transition={{ type: "spring", stiffness: 70, damping: 18 }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center" style={{ height: size }}>
        <div className="mono text-[26px] font-bold leading-none" style={{ color: col }}>{Math.round(v)}</div>
        <div className="mt-1 text-[10px] font-semibold uppercase tracking-widest text-mute">{label}</div>
      </div>
      {sub && <div className="mt-1 text-[11px] text-mute">{sub}</div>}
    </div>
  );
}

export function Stat({ icon, label, value, tone = "cy", sub, pulse }: { icon: ReactNode; label: string; value: ReactNode; tone?: Tone; sub?: ReactNode; pulse?: boolean }) {
  return (
    <Card className="relative overflow-hidden p-4">
      <div className="flex items-center gap-2 text-[11.5px] font-semibold text-mute">
        <span className={cx("flex h-7 w-7 items-center justify-center rounded-lg", TONE[tone].bg, TONE[tone].text)}>{icon}</span>{label}
      </div>
      <div className={cx("mt-3 text-[28px] font-bold leading-none tracking-tight", TONE[tone].text, pulse && "flicker")}>{value}</div>
      {sub && <div className="mt-1.5 text-[11.5px] text-mute">{sub}</div>}
    </Card>
  );
}

export function CopyBtn({ text }: { text: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button aria-label="Copy" className="text-mute hover:text-cy" onClick={() => { copy(text); setOk(true); setTimeout(() => setOk(false), 1200); }}>
      {ok ? <Check size={14} className="text-gn" /> : <ClipboardCopy size={14} />}
    </button>
  );
}

export function Code({ children, tone, className, wrap = true }: { children: ReactNode; tone?: "danger" | "ok" | "warn" | ""; className?: string; wrap?: boolean }) {
  const c = tone === "danger" ? "border-rd/30 bg-rd/5 text-rd" : tone === "ok" ? "border-gn/30 bg-gn/5 text-gn" : tone === "warn" ? "border-amber-200 bg-amber-50 text-am" : "border-line bg-slate-50 text-slate-700";
  return <pre className={cx("mono overflow-auto rounded-lg border p-3 text-[12px] leading-relaxed", wrap ? "whitespace-pre-wrap break-all" : "whitespace-pre", c, className)}>{children}</pre>;
}

export function Hex({ label, value, tone = "cy" }: { label: string; value: string; tone?: Tone }) {
  return (
    <div className="rounded-lg border border-line bg-panel2 p-2.5">
      <div className="mb-1 flex items-center justify-between text-[10px] font-semibold uppercase tracking-wider text-mute">{label}<CopyBtn text={value} /></div>
      <div className={cx("mono break-all text-[11.5px] leading-snug", TONE[tone].text)}>{value}</div>
    </div>
  );
}

export function PageHead({ title, sub, right, icon }: { title: string; sub?: ReactNode; right?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div className="flex items-center gap-3">
        {icon && <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cy/10 text-cy">{icon}</div>}
        <div>
          <h1 className="text-[22px] font-bold tracking-tight">{title}</h1>
          {sub && <p className="mt-1 max-w-3xl text-[13.5px] leading-relaxed text-mute">{sub}</p>}
        </div>
      </div>
      {right}
    </div>
  );
}

export function useFetch<T>(loader: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    setLoading(true);
    loader().then((d) => { if (live) { setData(d); setError(null); } }).catch((e) => live && setError(e.message)).finally(() => live && setLoading(false));
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { data, error, loading, reload: () => setTick((t) => t + 1), setData };
}

export function Toasts({ toasts, dismiss }: { toasts: { id: number; kind: string; title: string; msg?: string }[]; dismiss: (id: number) => void }) {
  const tone: Record<string, Tone> = { ok: "gn", err: "rd", warn: "am", info: "cy" };
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-[360px] max-w-[92vw] flex-col gap-2">
      <AnimatePresence>
        {toasts.map((t) => (
          <motion.div key={t.id} layout initial={{ opacity: 0, x: 60 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 60 }}
            className={cx("pointer-events-auto card flex gap-3 border p-3", TONE[tone[t.kind]].border)} role="status">
            <div className={cx("mt-0.5 h-2 w-2 shrink-0 rounded-full", t.kind === "err" && "pulse-rd")} style={{ background: TONE[tone[t.kind]].hex }} />
            <div className="min-w-0 flex-1">
              <div className="text-[13px] font-semibold">{t.title}</div>
              {t.msg && <div className="mt-0.5 break-words text-[12px] text-mute">{t.msg}</div>}
            </div>
            <button onClick={() => dismiss(t.id)} aria-label="Dismiss" className="text-mute hover:text-ink"><X size={14} /></button>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}

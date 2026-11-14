import { AlertOctagon, ExternalLink, ShieldCheck, ShieldHalf } from "lucide-react";
import { Security } from "./lib";
import { href } from "../lib/route";
import { cx } from "../lib/util";

const TITLES: Record<string, string> = { sql_injection: "SQL injection attempt", xss: "Script injection (XSS) attempt", idor: "Access to another customer's order", price_tampering: "Price tampering" };

/** Shown on the shop whenever one of its own security checks fires, so the audience can SEE the attack and the defence. */
export function SecurityPanel({ s, onClose }: { s: Security; onClose?: () => void }) {
  const breach = s.result === "breach";
  const tone = breach ? { box: "border-red-200 bg-red-50", ico: "text-rd", pill: "bg-rd text-white", icon: <AlertOctagon size={20} />, head: "Attack succeeded — the shop was vulnerable" }
    : s.result === "neutralised" ? { box: "border-blue-200 bg-blue-50", ico: "text-bl", pill: "bg-bl text-white", icon: <ShieldHalf size={20} />, head: "Attack neutralised — nothing was harmed" }
    : { box: "border-emerald-200 bg-emerald-50", ico: "text-gn", pill: "bg-gn text-white", icon: <ShieldCheck size={20} />, head: "Attack blocked by a defence" };
  return (
    <div role="status" data-testid="security-panel" data-result={s.result} className={cx("rounded-xl border p-4 text-[13px]", tone.box)}>
      <div className="flex items-start gap-3">
        <div className={tone.ico}>{tone.icon}</div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-bold">{tone.head}</span>
            <span className={cx("rounded-full px-2 py-0.5 text-[11px] font-semibold", tone.pill)}>{TITLES[s.attack] ?? s.attack}</span>
          </div>
          {s.message && <p className="mt-1 leading-relaxed text-slate-700">{s.message}</p>}
          {s.by && <p className="mt-1.5"><span className="font-semibold">Stopped by:</span> {s.by}</p>}
          {!s.by && breach && <p className="mt-1.5 text-rd"><span className="font-semibold">Stopped by:</span> nothing — the matching defence is switched OFF in the Security Centre.</p>}
          {s.payload && <div className="mt-2"><div className="text-[11px] font-semibold uppercase tracking-wide text-mute">What the attacker typed</div><code className="mono mt-1 block break-all rounded-md border border-line bg-white px-2.5 py-1.5 text-[12px]">{s.payload}</code></div>}
          {s.query && <div className="mt-2"><div className="text-[11px] font-semibold uppercase tracking-wide text-mute">What the database actually ran</div><code className="mono mt-1 block break-all rounded-md border border-rd/30 bg-white px-2.5 py-1.5 text-[12px] text-rd">{s.query}</code></div>}
          {!!s.leaked?.length && (
            <div className="mt-2">
              <div className="text-[11px] font-semibold uppercase tracking-wide text-mute">Data that leaked ({s.leaked.length} rows)</div>
              <div className="mt-1 max-h-44 overflow-auto rounded-md border border-rd/30 bg-white">
                <table><tbody>{s.leaked.slice(0, 12).map((r: any, i: number) => <tr key={i}>{(Array.isArray(r) ? r : Object.values(r)).map((c: any, j: number) => <td key={j} className="mono !py-1 text-[12px]">{String(c)}</td>)}</tr>)}</tbody></table>
              </div>
              <p className="mt-1 text-[11.5px] text-mute">Demo data only — this is an isolated copy, never your real database.</p>
            </div>
          )}
          {s.error && <p className="mt-1.5 text-[12px] text-mute">Database said: {s.error}</p>}
          <div className="mt-3 flex flex-wrap items-center gap-3 text-[12px]">
            <a href={href("soc/attacks")} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-semibold text-cy hover:underline"><ExternalLink size={13} /> See it in the Security Centre</a>
            {onClose && <button onClick={onClose} className="text-mute hover:text-ink">Dismiss</button>}
          </div>
        </div>
      </div>
    </div>
  );
}

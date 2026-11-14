import { CheckCircle2, CreditCard, Info, Lock, MapPin } from "lucide-react";
import { useEffect, useState } from "react";
import { AuthCard } from "../components/AuthCard";
import { ApiError, get, post } from "../lib/api";
import { go, href } from "../lib/route";
import { inr } from "../lib/util";
import { useStore } from "../store";
import { Btn, Spinner } from "../components/ui";
import { ShopLayout } from "./Layout";
import { PAYMENTS, Security, cartTotal, useCart } from "./lib";
import { SecurityPanel } from "./SecurityPanel";
import { create } from "zustand";

export const useLastOrder = create<{ last: any | null; set: (o: any | null) => void }>((set) => ({ last: null, set: (last) => set({ last }) }));

export function SignInPage({ initialMode = "signin" }: { initialMode?: "signin" | "register" }) {
  const user = useStore((s) => s.user);
  useEffect(() => { if (user?.role === "customer") { const next = sessionStorage.getItem("nm_after") || ""; sessionStorage.removeItem("nm_after"); go(next); } }, [user]);
  return (
    <ShopLayout>
      <div className="mx-auto max-w-[520px] py-4"><AuthCard audience="customer" initialMode={initialMode} onSwitchMode={(m) => go(m === "register" ? "register" : "signin")} /></div>
    </ShopLayout>
  );
}

export function CheckoutPage() {
  const { lines, clear } = useCart();
  const { user, toast } = useStore();
  const setLast = useLastOrder((s) => s.set);
  const [method, setMethod] = useState("UPI");
  const [profile, setProfile] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [sec, setSec] = useState<Security | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const customer = user?.role === "customer";
  const total = cartTotal(lines);

  useEffect(() => { if (customer) get("/shop/me").then(setProfile).catch(() => {}); }, [customer]);
  useEffect(() => { if (!customer) sessionStorage.setItem("nm_after", "checkout"); }, [customer]);

  async function place() {
    setBusy(true); setErr(null); setSec(null);
    try {
      const r = await post("/shop/checkout", { items: lines.map((l) => ({ product_id: l.id, qty: l.qty })), payment_method: method });
      setLast(r); clear();
      if (r.security) toast("warn", "Order accepted with a security problem", "See the order page for details.");
      go(`orders/${r.order_no}`);
    } catch (e) {
      const er = e as ApiError;
      if (er.body?.security) setSec(er.body.security);
      setErr(er.message);
    } finally { setBusy(false); }
  }

  if (!customer) {
    return (
      <ShopLayout>
        <div className="mx-auto max-w-[520px] py-2">
          <div className="mb-4 flex items-start gap-2 rounded-lg border border-cy/30 bg-cy/5 p-3 text-[13px] text-slate-700"><Info size={16} className="mt-0.5 shrink-0 text-cy" />Sign in or create an account to finish your order. Your cart is saved.</div>
          <AuthCard audience="customer" initialMode="signin" onSwitchMode={(m) => go(m === "register" ? "register" : "signin")} />
        </div>
      </ShopLayout>
    );
  }
  if (lines.length === 0) return <ShopLayout><div className="card p-12 text-center"><div className="text-[16px] font-semibold">Your cart is empty</div><a href={href("")} className="mt-3 inline-block text-cy hover:underline">Back to the shop</a></div></ShopLayout>;

  return (
    <ShopLayout>
      <h1 className="mb-5 text-[26px] font-extrabold tracking-tight">Checkout</h1>
      <div className="grid gap-6 lg:grid-cols-[1fr_360px]">
        <div className="space-y-5">
          <section className="card p-5">
            <h2 className="flex items-center gap-2 text-[16px] font-bold"><MapPin size={17} className="text-cy" />Delivery details</h2>
            {!profile ? <Spinner /> : (
              <div className="mt-3 text-[14px] leading-relaxed"><div className="font-semibold">{profile.name}</div><div className="text-slate-600">{profile.address || "No address saved yet"}</div><div className="text-slate-600">{profile.phone}</div>
                <a href={href("account")} className="mt-1 inline-block text-[13px] font-semibold text-cy hover:underline">Edit details</a></div>
            )}
          </section>
          <section className="card p-5">
            <h2 className="flex items-center gap-2 text-[16px] font-bold"><CreditCard size={17} className="text-cy" />Payment method</h2>
            <div className="mt-3 space-y-2" role="radiogroup" aria-label="Payment method">
              {PAYMENTS.map((m) => (
                <label key={m.id} className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 ${method === m.id ? "border-cy bg-cy/5" : "border-line hover:bg-slate-50"}`}>
                  <input type="radio" name="pay" checked={method === m.id} onChange={() => setMethod(m.id)} className="mt-1" />
                  <span><span className="block text-[14px] font-semibold">{m.label}</span><span className="block text-[12.5px] text-mute">{m.hint}</span></span>
                </label>
              ))}
            </div>
            <p className="mt-3 flex items-center gap-1.5 text-[12px] text-mute"><Lock size={13} />No card details are collected. This demo records an encrypted, signed payment entry instead.</p>
          </section>
          {sec && <SecurityPanel s={sec} onClose={() => setSec(null)} />}
          {err && !sec && <div role="alert" className="rounded-lg border border-rd/30 bg-rd/5 p-3 text-[13.5px] text-rd">{err}</div>}
        </div>
        <aside className="card h-fit p-5">
          <h2 className="text-[16px] font-bold">Order summary</h2>
          <div className="mt-3 divide-y divide-line text-[13.5px]">{lines.map((l) => <div key={l.id} className="flex justify-between gap-3 py-2"><span>{l.name} <span className="text-mute">× {l.qty}</span></span><span className="font-medium">{inr(l.price * l.qty)}</span></div>)}</div>
          <div className="mt-2 flex justify-between border-t border-line pt-3 text-[18px] font-extrabold"><span>Total</span><span>{inr(total)}</span></div>
          <Btn size="lg" className="mt-4 w-full" loading={busy} onClick={place} icon={<CheckCircle2 size={17} />} testId="place-order">Place order</Btn>
          <p className="mt-3 text-[12px] leading-snug text-mute">The final amount is calculated by our server from the signed product prices.</p>
        </aside>
      </div>
    </ShopLayout>
  );
}

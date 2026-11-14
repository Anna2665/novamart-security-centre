import { ArrowLeft, CheckCircle2, Clock, Mail, Package } from "lucide-react";
import { useEffect, useState } from "react";
import { ApiError, get } from "../lib/api";
import { go, href } from "../lib/route";
import { fmtDateTime, inr } from "../lib/util";
import { useStore } from "../store";
import { Badge, Spinner } from "../components/ui";
import { ShopLayout } from "./Layout";
import { Security, STATUS_LABEL } from "./lib";
import { SecurityPanel } from "./SecurityPanel";
import { useLastOrder } from "./Checkout";

function Gate({ children }: { children: React.ReactNode }) {
  const user = useStore((s) => s.user);
  useEffect(() => { if (user?.role !== "customer") { sessionStorage.setItem("nm_after", location.hash.replace("#/", "")); go("signin"); } }, [user]);
  return user?.role === "customer" ? <>{children}</> : null;
}

export function OrdersPage() {
  const [rows, setRows] = useState<any[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { get("/shop/orders").then(setRows).catch((e) => setErr(e.message)); }, []);
  return (
    <ShopLayout>
      <Gate>
        <h1 className="mb-5 text-[26px] font-extrabold tracking-tight">Your orders</h1>
        {err && <div className="rounded-lg border border-rd/30 bg-rd/5 p-3 text-sm text-rd">{err}</div>}
        {!rows ? <Spinner /> : rows.length === 0 ? (
          <div className="card flex flex-col items-center gap-3 p-14 text-center"><Package size={32} className="text-slate-300" /><div className="text-[16px] font-semibold">No orders yet</div><a href={href("")} className="rounded-lg bg-cy px-5 py-2.5 text-[14px] font-semibold text-white hover:bg-cy/90">Start shopping</a></div>
        ) : (
          <div className="space-y-3">
            {rows.map((o) => { const st = STATUS_LABEL[o.status] ?? { label: o.status, tone: "mute" as const }; return (
              <a key={o.order_no} href={href(`orders/${o.order_no}`)} className="card flex flex-wrap items-center gap-4 p-4 transition-shadow hover:shadow-md" data-testid="order-row">
                <div className="min-w-0 flex-1"><div className="flex items-center gap-2"><span className="text-[15px] font-bold">{o.order_no}</span><Badge tone={st.tone}>{st.label}</Badge></div>
                  <div className="mt-1 truncate text-[13px] text-mute">{o.items.map((i: any) => `${i.name} × ${i.qty}`).join(", ")}</div><div className="text-[12px] text-slate-400">{fmtDateTime(o.date)}</div></div>
                <div className="text-[17px] font-bold">{inr(o.total)}</div>
              </a>); })}
          </div>
        )}
      </Gate>
    </ShopLayout>
  );
}

export function OrderPage({ no }: { no: string }) {
  const [o, setO] = useState<any>(null);
  const [sec, setSec] = useState<Security | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const last = useLastOrder((s) => s.last);
  const banner = last && last.order_no === no ? last : null;
  useEffect(() => () => useLastOrder.getState().set(null), []); // the thank-you banner is shown once, right after checkout
  useEffect(() => {
    setO(null); setSec(null); setErr(null);
    get(`/shop/orders/${no}`).then((r) => { setO(r); if (r.security) setSec(r.security); })
      .catch((e: ApiError) => { if (e.body?.security) setSec(e.body.security); else setErr(e.message); });
  }, [no]);
  const st = o ? (STATUS_LABEL[o.status] ?? { label: o.status, tone: "mute" as const }) : null;
  return (
    <ShopLayout>
      <Gate>
        <a href={href("orders")} className="mb-4 inline-flex items-center gap-1.5 text-[13px] font-medium text-slate-600 hover:text-cy"><ArrowLeft size={15} />All orders</a>
        {banner && (
          <div className={`mb-5 rounded-xl border p-5 ${banner.status === "review" ? "border-amber-200 bg-amber-50" : "border-gn/30 bg-gn/5"}`} data-testid="order-banner">
            <div className="flex items-start gap-3">
              {banner.status === "review" ? <Clock size={24} className="text-am" /> : <CheckCircle2 size={24} className="text-gn" />}
              <div>
                <div className="text-[18px] font-bold">{banner.status === "review" ? "Thanks — we're doing a quick safety check on your order" : "Thank you — your order is confirmed!"}</div>
                <div className="mt-1 text-[13.5px] text-slate-600">Order <b>{banner.order_no}</b> · {inr(banner.total)}</div>
                {banner.status === "review" && <ul className="mt-2 list-disc pl-5 text-[13px] text-slate-600">{banner.risk_reasons?.map((r: string) => <li key={r}>{r}</li>)}<li>A member of our team will approve it shortly (risk score {banner.risk_score}/100).</li></ul>}
                {banner.receipt_email && <div className="mt-2 flex items-center gap-1.5 text-[12.5px] text-slate-500"><Mail size={14} />{banner.receipt_email.status === "sent" ? "A receipt has been emailed to you." : banner.receipt_email.status === "skipped" ? banner.receipt_email.detail : "Receipt email is not set up on this demo server."}</div>}
              </div>
            </div>
          </div>
        )}
        {sec && <div className="mb-5"><SecurityPanel s={sec} onClose={() => setSec(null)} /></div>}
        {err && <div className="rounded-lg border border-rd/30 bg-rd/5 p-3 text-sm text-rd">{err}</div>}
        {!o && !err && !sec && <Spinner />}
        {o && st && (
          <div className="card p-5">
            <div className="flex flex-wrap items-center justify-between gap-3"><div><div className="text-[12px] font-semibold uppercase tracking-wide text-mute">Order</div><div className="text-[22px] font-extrabold">{o.order_no}</div></div><Badge tone={st.tone}>{st.label}</Badge></div>
            <div className="mt-1 text-[13px] text-mute">Placed {fmtDateTime(o.date)}{o.customer ? ` · by ${o.customer}` : ""}</div>
            <div className="mt-4 divide-y divide-line">{o.items.map((i: any, k: number) => <div key={k} className="flex justify-between py-2.5 text-[14px]"><span>{i.name} <span className="text-mute">× {i.qty}</span></span><span className="font-medium">{inr(i.amount)}</span></div>)}</div>
            <div className="flex justify-between border-t border-line pt-3 text-[17px] font-extrabold"><span>Total</span><span>{inr(o.total)}</span></div>
            <div className="mt-4 rounded-lg bg-slate-50 p-3 text-[13px] text-slate-600">Paid with <b>{o.payment.method}</b> · payment {o.payment.status} · reference <span className="mono">{o.payment.ref}</span></div>
          </div>
        )}
      </Gate>
    </ShopLayout>
  );
}

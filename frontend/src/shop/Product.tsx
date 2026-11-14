import { ArrowLeft, Minus, Plus, ShieldAlert, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { ApiError, get, post } from "../lib/api";
import { go, href } from "../lib/route";
import { fmtDateTime, inr } from "../lib/util";
import { useStore } from "../store";
import { Btn, Spinner } from "../components/ui";
import { Art } from "./Art";
import { Stars } from "./Home";
import { ShopLayout } from "./Layout";
import { Product, Security, useCart } from "./lib";
import { SecurityPanel } from "./SecurityPanel";

export function ProductPage({ id }: { id: number }) {
  const [p, setP] = useState<Product | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [qty, setQty] = useState(1);
  const [added, setAdded] = useState(false);
  const [rating, setRating] = useState(5);
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [sec, setSec] = useState<Security | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const add = useCart((s) => s.add);
  const { user, toast } = useStore();
  const customer = user?.role === "customer";
  const load = () => get<Product>(`/shop/products/${id}`).then(setP).catch((e) => setErr(e.message));
  useEffect(() => { setP(null); setErr(null); void load(); /* eslint-disable-next-line */ }, [id]);

  async function submitReview(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setSec(null); setMsg(null);
    try {
      const r = await post(`/shop/products/${id}/reviews`, { rating, body });
      if (r.security) setSec(r.security);
      setMsg("Thanks — your review is live."); setBody(""); await load();
    } catch (e2) {
      const er = e2 as ApiError;
      if (er.body?.security) setSec(er.body.security); else toast("err", "Could not post review", er.message);
      setMsg(null);
    } finally { setBusy(false); }
  }

  return (
    <ShopLayout category={p?.category}>
      <a href={href("")} className="mb-4 inline-flex items-center gap-1.5 text-[13px] font-medium text-slate-600 hover:text-cy"><ArrowLeft size={15} />Back to shop</a>
      {err ? <div className="rounded-lg border border-rd/30 bg-rd/5 p-3 text-sm text-rd">{err}</div> : !p ? <Spinner /> : (
        <>
          <div className="grid gap-8 md:grid-cols-2">
            <Art sku={p.sku} size={120} className="h-[360px] w-full rounded-2xl" />
            <div>
              <div className="text-[12px] font-semibold uppercase tracking-wide text-cy">{p.category}</div>
              <h1 className="mt-1 text-[30px] font-extrabold leading-tight tracking-tight">{p.name}</h1>
              <div className="mt-2"><Stars v={p.rating} n={p.reviews} /></div>
              <div className="mt-4 text-[34px] font-extrabold tracking-tight" data-testid="product-price">{p.price !== null ? inr(p.price) : "—"}</div>
              {p.price_verified ? <div className="mt-1 inline-flex items-center gap-1.5 text-[12.5px] text-gn"><ShieldCheck size={14} />Price verified by digital signature</div>
                : <div className="mt-1 inline-flex items-center gap-1.5 text-[12.5px] font-medium text-am"><ShieldAlert size={14} />We are checking this price — it cannot be bought right now.</div>}
              <p className="mt-4 text-[15px] leading-relaxed text-slate-600">{p.description}</p>
              <div className="mt-2 text-[13px] text-mute">{p.stock > 0 ? `${p.stock} in stock · SKU ${p.sku}` : "Sold out"}</div>
              <div className="mt-6 flex items-center gap-3">
                <div className="flex items-center rounded-lg border border-slate-300 bg-white">
                  <button aria-label="Fewer" onClick={() => setQty(Math.max(1, qty - 1))} className="px-3 py-2.5 text-slate-600 hover:text-cy"><Minus size={15} /></button>
                  <span className="w-8 text-center text-[14px] font-semibold" data-testid="qty">{qty}</span>
                  <button aria-label="More" onClick={() => setQty(Math.min(10, qty + 1))} className="px-3 py-2.5 text-slate-600 hover:text-cy"><Plus size={15} /></button>
                </div>
                <Btn size="lg" disabled={!p.available} onClick={() => { if (p.price !== null) { add({ id: p.id, sku: p.sku, name: p.name, price: p.price, category: p.category }, qty); setAdded(true); setTimeout(() => setAdded(false), 1600); } }}>{added ? "Added ✓" : "Add to cart"}</Btn>
                <Btn size="lg" variant="ghost" disabled={!p.available} onClick={() => { if (p.price !== null) { add({ id: p.id, sku: p.sku, name: p.name, price: p.price, category: p.category }, qty); go("cart"); } }}>Buy now</Btn>
              </div>
            </div>
          </div>

          <section className="mt-12 grid gap-8 md:grid-cols-[1fr_380px]">
            <div>
              <h2 className="text-[20px] font-bold tracking-tight">Customer reviews</h2>
              {!p.reviews_list?.length ? <p className="mt-3 text-sm text-mute">No reviews yet — be the first.</p> : (
                <div className="mt-4 space-y-3">
                  {p.reviews_list.map((r) => (
                    <div key={r.id} className="card p-4" data-testid="review">
                      <div className="flex items-center justify-between"><div className="text-[14px] font-semibold">{r.author}</div><Stars v={r.rating} /></div>
                      <p className="mt-1.5 break-words text-[14px] leading-relaxed text-slate-600">{r.body}</p>
                      <div className="mt-1.5 text-[11.5px] text-slate-400">{fmtDateTime(r.created_at)}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div>
              <div className="card p-5">
                <h3 className="text-[16px] font-bold">Write a review</h3>
                {customer ? (
                  <form onSubmit={submitReview} className="mt-3 space-y-3">
                    <label className="block text-[13px] font-medium text-slate-700">Rating
                      <select value={rating} onChange={(e) => setRating(Number(e.target.value))} className="mt-1.5" aria-label="Rating">{[5, 4, 3, 2, 1].map((n) => <option key={n} value={n}>{n} star{n > 1 ? "s" : ""}</option>)}</select>
                    </label>
                    <label className="block text-[13px] font-medium text-slate-700">Your review
                      <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={4} maxLength={500} placeholder="What did you like?" className="mt-1.5" aria-label="Review text" />
                    </label>
                    <Btn type="submit" loading={busy} disabled={body.trim().length < 3}>Post review</Btn>
                    {msg && <div className="text-[13px] text-gn">{msg}</div>}
                  </form>
                ) : <p className="mt-2 text-[13.5px] text-mute">Please <a className="font-semibold text-cy hover:underline" href={href("signin")}>sign in</a> to write a review.</p>}
              </div>
              {sec && <div className="mt-4"><SecurityPanel s={sec} onClose={() => setSec(null)} /></div>}
            </div>
          </section>
        </>
      )}
    </ShopLayout>
  );
}

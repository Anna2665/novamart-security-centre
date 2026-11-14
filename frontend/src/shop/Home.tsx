import { ArrowRight, Lock, Search, ShieldCheck, Star, Truck } from "lucide-react";
import { useEffect, useState } from "react";
import { ApiError, get } from "../lib/api";
import { href } from "../lib/route";
import { inr } from "../lib/util";
import { Spinner } from "../components/ui";
import { Art } from "./Art";
import { ShopLayout } from "./Layout";
import { Product, Security, useCart } from "./lib";
import { SecurityPanel } from "./SecurityPanel";

export function Stars({ v, n }: { v: number; n?: number }) {
  return (
    <span className="inline-flex items-center gap-1 text-[12px] text-slate-500">
      <span className="flex">{[1, 2, 3, 4, 5].map((i) => <Star key={i} size={13} className={i <= Math.round(v) ? "fill-amber-400 text-amber-400" : "text-slate-300"} />)}</span>
      {n !== undefined && <span>({n})</span>}
    </span>
  );
}

export function ProductCard({ p }: { p: Product }) {
  const add = useCart((s) => s.add);
  return (
    <div className="card group flex flex-col overflow-hidden transition-shadow hover:shadow-md" data-testid="product-card">
      <a href={href(`product/${p.id}`)} className="block"><Art sku={p.sku} size={64} className="h-40 w-full" /></a>
      <div className="flex flex-1 flex-col p-4">
        <div className="text-[11.5px] font-semibold uppercase tracking-wide text-cy">{p.category}</div>
        <a href={href(`product/${p.id}`)} className="mt-1 text-[15px] font-semibold leading-snug text-slate-900 hover:text-cy">{p.name}</a>
        <div className="mt-1.5"><Stars v={p.rating} n={p.reviews} /></div>
        <div className="mt-auto flex items-end justify-between pt-3">
          {p.price !== null ? <div className="text-[20px] font-bold tracking-tight">{inr(p.price)}</div> : <div className="text-[12.5px] font-semibold text-am">Price being verified</div>}
          <button disabled={!p.available} onClick={() => p.price !== null && add({ id: p.id, sku: p.sku, name: p.name, price: p.price, category: p.category })}
            className="rounded-lg bg-cy px-3.5 py-2 text-[13px] font-semibold text-white shadow-sm hover:bg-cy/90 disabled:cursor-not-allowed disabled:bg-slate-300">{p.stock <= 0 ? "Sold out" : "Add to cart"}</button>
        </div>
      </div>
    </div>
  );
}

export function Home({ q = "", category = "" }: { q?: string; category?: string }) {
  const [items, setItems] = useState<Product[] | null>(null);
  const [sec, setSec] = useState<Security | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [sort, setSort] = useState("featured");

  useEffect(() => {
    let live = true;
    setItems(null); setSec(null); setErr(null);
    const qs = new URLSearchParams({ q, sort, ...(category ? { category } : {}) }).toString();
    get<{ products: Product[]; security?: Security }>(`/shop/products?${qs}`)
      .then((r) => { if (!live) return; setItems(r.products); setSec(r.security ?? null); })
      .catch((e: ApiError) => { if (!live) return; setItems([]); if (e.body?.security) setSec(e.body.security); else setErr(e.message); });
    return () => { live = false; };
  }, [q, category, sort]);

  const browsing = !q && !category;
  return (
    <ShopLayout q={q} category={category}>
      {browsing && (
        <section className="mb-7 overflow-hidden rounded-2xl bg-gradient-to-br from-indigo-600 via-indigo-600 to-violet-600 p-8 text-white shadow-sm">
          <div className="max-w-xl">
            <div className="text-[12.5px] font-semibold uppercase tracking-widest text-indigo-200">New season picks</div>
            <h1 className="mt-2 text-[34px] font-extrabold leading-tight tracking-tight">Everyday tech and home essentials, delivered fast.</h1>
            <p className="mt-3 text-[15px] leading-relaxed text-indigo-100">Shop 12 hand-picked products. Every order is protected by encrypted storage, signed price records and a fraud check.</p>
            <a href="#products" onClick={(e) => { e.preventDefault(); document.getElementById("products")?.scrollIntoView({ behavior: "smooth" }); }} className="mt-5 inline-flex items-center gap-2 rounded-lg bg-white px-5 py-2.5 text-[14px] font-semibold text-indigo-700 shadow-sm hover:bg-indigo-50">Start shopping <ArrowRight size={16} /></a>
          </div>
        </section>
      )}
      {browsing && (
        <div className="mb-7 grid gap-3 sm:grid-cols-3">
          {[[<Truck size={18} />, "Fast delivery", "Free over ₹999 across India"], [<Lock size={18} />, "Encrypted & private", "Your details are encrypted at rest"], [<ShieldCheck size={18} />, "Protected checkout", "Prices are signed; risky orders are checked"]].map(([i, t, d], k) => (
            <div key={k} className="flex items-center gap-3 rounded-xl border border-line bg-white p-4"><span className="flex h-10 w-10 items-center justify-center rounded-lg bg-cy/10 text-cy">{i}</span><div><div className="text-[14px] font-semibold">{t as string}</div><div className="text-[12.5px] text-mute">{d as string}</div></div></div>
          ))}
        </div>
      )}
      {sec && <div className="mb-5"><SecurityPanel s={sec} onClose={() => setSec(null)} /></div>}
      <div id="products" className="mb-4 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-[22px] font-bold tracking-tight">{q ? <>Results for “{q}”</> : category || "All products"}</h2>
          {items && <div className="text-[13px] text-mute" data-testid="result-count">{items.length} product{items.length === 1 ? "" : "s"}</div>}
        </div>
        <label className="flex items-center gap-2 text-[13px] text-slate-600">Sort by
          <select value={sort} onChange={(e) => setSort(e.target.value)} className="!w-auto !py-1.5" aria-label="Sort products">
            <option value="featured">Featured</option><option value="price_asc">Price: low to high</option><option value="price_desc">Price: high to low</option><option value="name">Name</option>
          </select>
        </label>
      </div>
      {err && <div className="rounded-lg border border-rd/30 bg-rd/5 p-3 text-sm text-rd">{err}</div>}
      {items === null ? <Spinner label="Loading products…" /> : items.length === 0 && !err ? (
        <div className="card flex flex-col items-center gap-2 p-12 text-center text-mute"><Search size={28} className="text-slate-300" /><div className="text-[15px] font-semibold text-slate-700">No products found</div><div className="text-[13px]">Try a different word, or browse all products.</div><a href={href("")} className="mt-2 text-[13px] font-semibold text-cy hover:underline">Back to all products</a></div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">{items.map((p) => <ProductCard key={p.id} p={p} />)}</div>
      )}
    </ShopLayout>
  );
}

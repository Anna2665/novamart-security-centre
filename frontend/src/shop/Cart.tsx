import { Lock, Minus, Plus, ShoppingCart, Trash2 } from "lucide-react";
import { go, href } from "../lib/route";
import { inr } from "../lib/util";
import { Art } from "./Art";
import { ShopLayout } from "./Layout";
import { cartTotal, useCart } from "./lib";

export function CartPage() {
  const { lines, setQty, remove } = useCart();
  const total = cartTotal(lines);
  return (
    <ShopLayout>
      <h1 className="mb-5 text-[26px] font-extrabold tracking-tight">Your cart</h1>
      {lines.length === 0 ? (
        <div className="card flex flex-col items-center gap-3 p-14 text-center"><ShoppingCart size={34} className="text-slate-300" /><div className="text-[16px] font-semibold">Your cart is empty</div><a href={href("")} className="rounded-lg bg-cy px-5 py-2.5 text-[14px] font-semibold text-white hover:bg-cy/90">Browse products</a></div>
      ) : (
        <div className="grid gap-6 lg:grid-cols-[1fr_340px]">
          <div className="space-y-3">
            {lines.map((l) => (
              <div key={l.id} className="card flex items-center gap-4 p-4" data-testid="cart-line">
                <a href={href(`product/${l.id}`)} className="hidden sm:block"><Art sku={l.sku} size={30} className="h-16 w-16 rounded-lg" /></a>
                <div className="min-w-0 flex-1"><a href={href(`product/${l.id}`)} className="text-[15px] font-semibold hover:text-cy">{l.name}</a><div className="text-[12.5px] text-mute">{l.category} · {inr(l.price)} each</div></div>
                <div className="flex items-center rounded-lg border border-slate-300 bg-white">
                  <button aria-label={`Fewer ${l.name}`} onClick={() => setQty(l.id, l.qty - 1)} className="px-2.5 py-2 text-slate-600 hover:text-cy"><Minus size={14} /></button>
                  <span className="w-7 text-center text-[14px] font-semibold">{l.qty}</span>
                  <button aria-label={`More ${l.name}`} onClick={() => setQty(l.id, l.qty + 1)} className="px-2.5 py-2 text-slate-600 hover:text-cy"><Plus size={14} /></button>
                </div>
                <div className="w-24 text-right text-[16px] font-bold">{inr(l.price * l.qty)}</div>
                <button aria-label={`Remove ${l.name}`} onClick={() => remove(l.id)} className="text-slate-400 hover:text-rd"><Trash2 size={17} /></button>
              </div>
            ))}
          </div>
          <aside className="card h-fit p-5">
            <h2 className="text-[16px] font-bold">Order summary</h2>
            <div className="mt-4 space-y-2 text-[14px]"><div className="flex justify-between"><span className="text-mute">Subtotal</span><span>{inr(total)}</span></div><div className="flex justify-between"><span className="text-mute">Delivery</span><span className="text-gn">{total >= 999 ? "Free" : "Free (demo)"}</span></div></div>
            <div className="mt-3 flex justify-between border-t border-line pt-3 text-[18px] font-extrabold"><span>Total</span><span data-testid="cart-total">{inr(total)}</span></div>
            <button onClick={() => go("checkout")} className="mt-4 w-full rounded-lg bg-cy py-3 text-[15px] font-semibold text-white shadow-sm hover:bg-cy/90">Proceed to checkout</button>
            <p className="mt-3 flex items-start gap-1.5 text-[12px] leading-snug text-mute"><Lock size={13} className="mt-0.5 shrink-0" />Prices shown here are for convenience. At checkout our server re-reads every price from the signed product records — the browser can never change what you pay.</p>
          </aside>
        </div>
      )}
    </ShopLayout>
  );
}

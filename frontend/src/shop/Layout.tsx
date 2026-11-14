import { LogOut, Package, Search, ShieldCheck, ShoppingBag, ShoppingCart, User } from "lucide-react";
import { ReactNode, useState } from "react";
import { go, href } from "../lib/route";
import { cx } from "../lib/util";
import { useStore } from "../store";
import { Toolbox } from "./Toolbox";
import { cartCount, useCart } from "./lib";

export const CATEGORIES = ["Electronics", "Wearables", "Home", "Kitchen", "Fitness", "Travel", "Fashion"];

export function ShopLayout({ children, q = "", category = "" }: { children: ReactNode; q?: string; category?: string }) {
  const { user, logout } = useStore();
  const lines = useCart((s) => s.lines);
  const [term, setTerm] = useState(q);
  const customer = user?.role === "customer";
  const n = cartCount(lines);
  return (
    <div id="shop-scroll" className="h-full overflow-auto bg-bg">
      <div className="bg-slate-900 px-4 py-1.5 text-center text-[12px] text-slate-200">Free delivery on orders over ₹999 · This is a demonstration store — no real payments are taken</div>
      <header className="sticky top-0 z-30 border-b border-line bg-white/95 backdrop-blur">
        <div className="mx-auto flex max-w-[1180px] items-center gap-4 px-4 py-3">
          <a href={href("")} className="flex items-center gap-2.5" aria-label="NovaMart home">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-cy text-white"><ShoppingBag size={19} /></span>
            <span className="text-[19px] font-extrabold tracking-tight">Nova<span className="text-cy">Mart</span></span>
          </a>
          <form className="relative mx-auto hidden max-w-xl flex-1 sm:block" role="search" onSubmit={(e) => { e.preventDefault(); go(term.trim() ? `search/${encodeURIComponent(term.trim())}` : ""); }}>
            <Search size={16} className="absolute left-3.5 top-[11px] text-slate-400" />
            <input value={term} onChange={(e) => setTerm(e.target.value)} placeholder="Search products, e.g. earbuds, lamp, kettle" aria-label="Search products" className="!rounded-full !bg-slate-50 !pl-10 !pr-24" />
            <button type="submit" className="absolute right-1 top-1 rounded-full bg-cy px-4 py-1.5 text-[13px] font-semibold text-white hover:bg-cy/90">Search</button>
          </form>
          <nav className="ml-auto flex items-center gap-1 text-[13.5px] font-medium sm:ml-0">
            {customer && <a href={href("orders")} className="hidden items-center gap-1.5 rounded-lg px-3 py-2 text-slate-700 hover:bg-slate-100 md:flex"><Package size={16} />Orders</a>}
            <a href={href("cart")} className="relative flex items-center gap-1.5 rounded-lg px-3 py-2 text-slate-700 hover:bg-slate-100" aria-label={`Cart, ${n} items`}>
              <ShoppingCart size={17} /><span className="hidden sm:inline">Cart</span>
              {n > 0 && <span data-testid="cart-count" className="absolute -right-0.5 -top-0.5 flex h-[18px] min-w-[18px] items-center justify-center rounded-full bg-cy px-1 text-[10.5px] font-bold text-white">{n}</span>}
            </a>
            {customer ? (
              <>
                <a href={href("account")} className="flex items-center gap-2 rounded-lg px-3 py-2 text-slate-700 hover:bg-slate-100"><span className="flex h-7 w-7 items-center justify-center rounded-full bg-cy/10 text-[12px] font-bold uppercase text-cy">{(user.full_name || user.username)[0]}</span><span className="hidden lg:inline">{(user.full_name || user.username).split(" ")[0]}</span></a>
                <button onClick={() => { void logout(); go(""); }} className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-slate-500 hover:bg-slate-100 hover:text-rd" aria-label="Sign out"><LogOut size={16} /></button>
              </>
            ) : (
              <a href={href("signin")} className="flex items-center gap-1.5 rounded-lg bg-cy px-4 py-2 text-white shadow-sm hover:bg-cy/90"><User size={15} />Sign in</a>
            )}
          </nav>
        </div>
        <div className="border-t border-line bg-white">
          <div className="mx-auto flex max-w-[1180px] gap-1 overflow-x-auto px-4 py-1.5 text-[13px]">
            <a href={href("")} className={cx("whitespace-nowrap rounded-full px-3 py-1.5 font-medium", !category && !q ? "bg-cy/10 text-cy" : "text-slate-600 hover:bg-slate-100")}>All products</a>
            {CATEGORIES.map((c) => <a key={c} href={href(`category/${c}`)} className={cx("whitespace-nowrap rounded-full px-3 py-1.5 font-medium", category === c ? "bg-cy/10 text-cy" : "text-slate-600 hover:bg-slate-100")}>{c}</a>)}
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-[1180px] px-4 py-6">{children}</main>
      <footer className="mt-10 border-t border-line bg-white">
        <div className="mx-auto flex max-w-[1180px] flex-wrap items-center justify-between gap-3 px-4 py-5 text-[12.5px] text-mute">
          <div>© NovaMart — a demonstration e-commerce store for a cybersecurity project. Your data is encrypted and the checkout is simulated.</div>
          <a href={href("soc")} className="inline-flex items-center gap-1.5 font-semibold text-slate-600 hover:text-cy"><ShieldCheck size={14} />Security Centre (staff)</a>
        </div>
      </footer>
      <Toolbox />
    </div>
  );
}

import { motion } from "framer-motion";
import { ArrowLeft, Lock, ShieldCheck, ShoppingBag, Swords } from "lucide-react";
import { AuthCard } from "../components/AuthCard";
import { href } from "../lib/route";

export function StaffLogin() {
  return (
    <div className="relative flex min-h-full items-center justify-center overflow-auto bg-bg p-4">
      <div className="grid w-full max-w-[1040px] items-center gap-10 lg:grid-cols-[1.1fr_1fr]">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="hidden lg:block">
          <div className="flex items-center gap-3"><span className="flex h-11 w-11 items-center justify-center rounded-xl bg-slate-900 text-white"><ShieldCheck size={22} /></span><div><div className="text-[20px] font-extrabold tracking-tight">NovaMart Security Centre</div><div className="text-[12.5px] text-mute">Protecting the online store</div></div></div>
          <h1 className="mt-9 text-[38px] font-extrabold leading-[1.1] tracking-tight">Watch the store being attacked — and defended.</h1>
          <p className="mt-4 max-w-md text-[15.5px] leading-relaxed text-slate-600">This is the control room for the NovaMart shop. Launch attacks, switch defences on and off, and see exactly what is blocked, what leaks and how the team recovers.</p>
          <div className="mt-8 grid max-w-md gap-3 text-[13.5px]">
            {[[<ShoppingBag size={17} />, "The shop", "A real store customers can browse, order from and review."], [<Swords size={17} />, "The attacks", "12 attack types, run live against the shop."], [<Lock size={17} />, "The defences", "21 protections you can switch on and off."]].map(([i, t, d], k) => (
              <div key={k} className="flex items-start gap-3 rounded-xl border border-line bg-white p-3.5"><span className="mt-0.5 text-cy">{i}</span><div><div className="font-semibold">{t as string}</div><div className="text-mute">{d as string}</div></div></div>
            ))}
          </div>
        </motion.div>
        <div>
          <AuthCard audience="staff" />
          <a href={href("")} className="mt-4 flex items-center justify-center gap-1.5 text-[13px] font-medium text-slate-600 hover:text-cy"><ArrowLeft size={14} />Back to the NovaMart shop</a>
        </div>
      </div>
    </div>
  );
}

import { AnimatePresence, motion } from "framer-motion";
import { Activity, Archive, BookOpen, Crosshair, Database, ExternalLink, FileSignature, FlaskConical, Info, LayoutDashboard, LogOut, Menu, Network, Radar, ScrollText, Settings as Cog, ShieldCheck, ShoppingBag, Siren, UserCog, Wifi, WifiOff, X } from "lucide-react";
import { ReactNode, useEffect, useState } from "react";
import { Switch, Toasts, Tip } from "./components/ui";
import { go, href, useRoute } from "./lib/route";
import { post } from "./lib/api";
import { cx } from "./lib/util";
import { Attacks } from "./pages/Attacks";
import { Backup } from "./pages/Backup";
import { Cia } from "./pages/Cia";
import { Crypto } from "./pages/Crypto";
import { Database as Db } from "./pages/Database";
import { Guide } from "./pages/Guide";
import { Iam } from "./pages/Iam";
import { Incidents } from "./pages/Incidents";
import { Intel } from "./pages/Intel";
import { Logs } from "./pages/Logs";
import { Overview } from "./pages/Overview";
import { Settings } from "./pages/Settings";
import { ShopOps } from "./pages/ShopOps";
import { Signatures } from "./pages/Signatures";
import { StaffLogin } from "./pages/StaffLogin";
import { TopologyPage } from "./pages/TopologyPage";
import { Storefront } from "./shop/index";
import { useStore } from "./store";

type Item = { id: string; label: string; icon: ReactNode; el: () => ReactNode; help: string };
const NAV: { group: string; items: Item[] }[] = [
  { group: "Start here", items: [
    { id: "guide", label: "Guided Demo", icon: <BookOpen size={17} />, el: () => <Guide />, help: "A step-by-step script for presenting the project: what to click, what you will see and what to say." },
  ] },
  { group: "Monitor", items: [
    { id: "overview", label: "Security Overview", icon: <LayoutDashboard size={17} />, el: () => <Overview />, help: "The big picture: how many attacks were seen, how many were stopped, and how healthy the shop's protection is right now." },
    { id: "orders", label: "Store Orders & Fraud", icon: <ShoppingBag size={17} />, el: () => <ShopOps />, help: "Every order from the NovaMart shop. Suspicious ones are held here until a team member approves or rejects them." },
    { id: "cia", label: "CIA Scores", icon: <Activity size={17} />, el: () => <Cia />, help: "Scores for Confidentiality, Integrity and Availability. They drop when an attack gets through and recover as problems are fixed." },
    { id: "intel", label: "Threat Intelligence", icon: <Radar size={17} />, el: () => <Intel />, help: "Which attack types are most likely and most damaging for an online store, and which known attacker techniques they map to." },
    { id: "topology", label: "Network Map", icon: <Network size={17} />, el: () => <TopologyPage />, help: "A map of the shop's systems (website, database, payments…). Each box changes colour as it is attacked, protected or isolated." },
  ] },
  { group: "Attack & defend", items: [
    { id: "attacks", label: "Attack Lab", icon: <Crosshair size={17} />, el: () => <Attacks />, help: "Launch any of 12 attacks and watch each step. Switch individual defences on or off to see which one stops it." },
    { id: "incidents", label: "Incident Response", icon: <Siren size={17} />, el: () => <Incidents />, help: "When an attack gets through, this is the checklist the security team follows to contain, fix and recover." },
    { id: "backup", label: "Backup & Recovery", icon: <Archive size={17} />, el: () => <Backup />, help: "Encrypted, verified copies of the shop's data, and the button that restores them after a ransomware attack." },
  ] },
  { group: "Protection labs", items: [
    { id: "crypto", label: "Encryption Lab", icon: <FlaskConical size={17} />, el: () => <Crypto />, help: "Try encryption and hashing yourself: change one character and see how completely the result changes." },
    { id: "signatures", label: "Digital Signatures", icon: <FileSignature size={17} />, el: () => <Signatures />, help: "How product prices and orders are signed so that any tampering is detected." },
    { id: "iam", label: "Accounts & Access", icon: <UserCog size={17} />, el: () => <Iam />, help: "Who can do what (roles), how sign-in is protected (password + email code) and how accounts get locked after repeated failures." },
    { id: "database", label: "Database Security", icon: <Database size={17} />, el: () => <Db />, help: "See how customer details are encrypted in the database, simulate someone tampering with a price, and restore the trusted version." },
  ] },
  { group: "Admin", items: [
    { id: "logs", label: "Audit Log", icon: <ScrollText size={17} />, el: () => <Logs />, help: "A tamper-evident diary of everything that happened: sign-ins, changes and decisions. Each entry is chained to the one before it." },
    { id: "settings", label: "Settings", icon: <Cog size={17} />, el: () => <Settings />, help: "Email delivery status, one-time-code settings and platform details." },
  ] },
];
const ALL = NAV.flatMap((g) => g.items);

function Shell({ page }: { page: string }) {
  const [menu, setMenu] = useState(false);
  const { user, live, wsOpen, logout, health, toast, can } = useStore();
  const runView = useStore((s) => s.run);
  const cur = ALL.find((n) => n.id === page) ?? ALL[1];
  const running = live?.running;
  const mode: string = live?.mode ?? "enabled";
  const canCfg = can("sim:configure");
  const nav = (id: string) => { go(`soc/${id}`); setMenu(false); };
  /** "Watch it": open the Attack Lab if needed, then scroll to the live attack pipeline (the hash does not change when you are already there). */
  const watchLive = () => {
    const onLab = cur.id === "attacks";
    if (!onLab) nav("attacks");
    window.setTimeout(() => document.getElementById("live-run")?.scrollIntoView({ behavior: "smooth", block: "start" }), onLab ? 0 : 450);
  };

  async function toggleAll(v: boolean) {
    try { await post("/sim/mode", { enabled: v }); toast(v ? "ok" : "warn", v ? "All 21 defences are ON" : "All defences are OFF", v ? "Attacks will now be checked against real rules." : "The shop is deliberately unprotected — attacks will succeed."); void useStore.getState().refreshLive(); }
    catch (e: any) { toast("err", "Could not change defences", e.message); }
  }

  const side = (
    <nav className="flex h-full flex-col">
      <a href={href("soc/overview")} className="flex items-center gap-2.5 px-4 py-4">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-slate-900 text-white"><ShieldCheck size={19} /></div>
        <div className="leading-tight"><div className="text-[15px] font-extrabold tracking-tight">NovaMart</div><div className="text-[11px] font-semibold text-mute">Security Centre</div></div>
      </a>
      <div className="flex-1 overflow-auto px-3 pb-3">
        {NAV.map((g) => (
          <div key={g.group} className="mb-3">
            <div className="px-3 pb-1 pt-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">{g.group}</div>
            {g.items.map((n) => (
              <button key={n.id} onClick={() => nav(n.id)} data-testid={`nav-${n.id}`}
                className={cx("flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-[13.5px] font-medium transition-colors", cur.id === n.id ? "bg-cy/10 text-cy" : "text-slate-600 hover:bg-slate-100 hover:text-ink")}>
                {n.icon}<span className="flex-1">{n.label}</span>
              </button>
            ))}
          </div>
        ))}
      </div>
      <div className="space-y-2 border-t border-line p-3 text-[12px] text-mute">
        <a href={href("")} target="_blank" rel="noreferrer" className="flex items-center gap-2 rounded-lg px-2 py-1.5 font-medium text-slate-600 hover:bg-slate-100"><ExternalLink size={14} />Open the shop</a>
        <div className="flex items-center gap-2 px-2">{wsOpen ? <Wifi size={13} className="text-gn" /> : <WifiOff size={13} className="text-am" />}{wsOpen ? "Live updates connected" : "Reconnecting…"}</div>
        {health && !health.smtp_configured && <div className="rounded-md border border-amber-200 bg-amber-50 p-1.5 text-am">Email is not set up — codes show on screen</div>}
      </div>
    </nav>
  );

  return (
    <div className="flex h-full">
      <aside className="hidden w-[244px] shrink-0 border-r border-line bg-white lg:block">{side}</aside>
      <AnimatePresence>
        {menu && (
          <motion.div className="fixed inset-0 z-50 flex lg:hidden" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <div className="w-[260px] border-r border-line bg-white">{side}</div><div className="flex-1 bg-slate-900/40" onClick={() => setMenu(false)} />
          </motion.div>
        )}
      </AnimatePresence>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center gap-3 border-b border-line bg-white px-4 py-2.5">
          <button className="lg:hidden" onClick={() => setMenu(!menu)} aria-label="Menu">{menu ? <X size={20} /> : <Menu size={20} />}</button>
          <div className="hidden text-[15px] font-bold sm:block">{cur.label}</div>
          <div className="flex-1" />
          <div className="flex items-center gap-2.5 rounded-xl border border-line bg-slate-50 px-3 py-1.5">
            <Tip text="Master switch for all 21 defences. OFF = the shop is deliberately unprotected, so every attack succeeds. ON = every attack is checked against real rules (firewall, signatures, access control…). Individual defences can be toggled on the Attack Lab page.">
              <span className="text-[12.5px] font-semibold text-slate-600">Defences</span>
            </Tip>
            <span className={cx("text-[12px] font-bold", mode === "enabled" ? "text-gn" : mode === "disabled" ? "text-rd" : "text-am")} data-testid="defence-mode">{mode === "enabled" ? "All on" : mode === "disabled" ? "All off" : "Partial"}</span>
            <Switch on={mode === "enabled"} onChange={toggleAll} disabled={!canCfg || !!running} label="Enable all defences" />
          </div>
          <div className="hidden items-center gap-2.5 rounded-xl border border-line bg-white px-3 py-1.5 sm:flex">
            <div className="flex h-7 w-7 items-center justify-center rounded-full bg-cy/10 text-[12px] font-bold uppercase text-cy">{user.username[0]}</div>
            <div className="leading-tight"><div className="text-[12.5px] font-semibold">{user.username}</div><div className="text-[11px] font-medium capitalize text-mute">{user.role}</div></div>
          </div>
          <button onClick={() => { void logout(); }} className="flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-semibold text-slate-600 shadow-sm hover:border-rd/50 hover:text-rd" aria-label="Sign out"><LogOut size={14} /><span className="hidden sm:inline">Sign out</span></button>
        </header>
        <AnimatePresence>
          {running && (
            <motion.div initial={{ height: 0 }} animate={{ height: "auto" }} exit={{ height: 0 }} className="overflow-hidden">
              <div className="flex items-center gap-3 border-b border-rd/30 bg-rd/5 px-4 py-1.5 text-[12.5px] font-semibold text-rd">
                <span className="h-2 w-2 rounded-full bg-rd pulse-rd" /> Attack running — {runView?.run.name ?? running.scenario_id}{running.total ? ` · step ${Math.min(running.total, (runView?.active ?? 0) + 1)} of ${running.total}` : ""}
                <button onClick={watchLive} className="ml-auto underline underline-offset-2" data-testid="watch-live">Watch it</button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
        <main className="min-h-0 flex-1 overflow-auto">
          <AnimatePresence mode="wait">
            <motion.div key={cur.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.16 }} className="mx-auto max-w-[1500px] p-6">
              {cur.id !== "guide" && <div className="mb-4 flex items-start gap-2.5 rounded-lg border border-cy/15 bg-cy/5 px-3.5 py-2.5 text-[13px] leading-relaxed text-slate-700" data-testid="page-help"><Info size={16} className="mt-0.5 shrink-0 text-cy" /><span><b>What is this page?</b> {cur.help}</span></div>}
              {cur.el()}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  const { user, booting, init, toasts, dismiss } = useStore();
  const parts = useRoute();
  useEffect(() => { void init(); }, [init]);
  const boot = <div className="flex h-full items-center justify-center text-mute"><ShieldCheck className="mr-3 text-cy" />Loading NovaMart…</div>;
  let body: ReactNode;
  if (booting) body = boot;
  else if (parts[0] === "soc") {
    const staff = user && user.role !== "customer";
    body = !staff ? <StaffLogin /> : <Shell page={parts[1] ?? "overview"} />;
  } else body = <Storefront parts={parts} />;
  return (<>{body}<Toasts toasts={toasts} dismiss={dismiss} /></>);
}

import { motion } from "framer-motion";
import { Link2, Link2Off, ScrollText, Search, ShieldCheck, Zap } from "lucide-react";
import { useState } from "react";
import { Badge, Btn, Card, CardHead, Empty, ErrorBox, PageHead, Spinner, Tabs, Tip, useFetch } from "../components/ui";
import { get } from "../lib/api";
import { cx, fmtDateTime } from "../lib/util";
import { useStore } from "../store";
import { EventRow } from "./Overview";

function Audit() {
  const { bump, can, toast } = useStore();
  const [q, setQ] = useState("");
  const [prefix, setPrefix] = useState("");
  const rows = useFetch<any[]>(() => get(`/audit?limit=300${prefix ? `&action=${encodeURIComponent(prefix)}` : ""}${q ? `&q=${encodeURIComponent(q)}` : ""}`), [bump.audit, prefix, q]);
  const [chain, setChain] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  if (!can("audit:read")) return <Card className="p-8 text-center text-mute">Your role does not have the audit:read permission.</Card>;
  async function verify() { setBusy(true); try { const r = await get("/audit/verify"); setChain(r); toast(r.valid ? "ok" : "err", r.valid ? "Audit chain intact" : "AUDIT LOG TAMPERED", r.message); } catch (e: any) { toast("err", "Verification failed", e.message); } finally { setBusy(false); } }
  return (
    <div className="space-y-4">
      <Card className={cx("p-4", chain && (chain.valid ? "glow-gn" : "glow-rd"))}>
        <div className="flex flex-wrap items-center gap-4">
          <div className={cx("flex h-12 w-12 items-center justify-center rounded-xl border", chain ? (chain.valid ? "border-gn/50 bg-gn/10" : "border-rd/50 bg-rd/10 pulse-rd") : "border-cy/40 bg-cy/10")}>{chain && !chain.valid ? <Link2Off className="text-rd" /> : <Link2 className={chain ? "text-gn" : "text-cy"} />}</div>
          <div className="min-w-[260px] flex-1"><div className="font-semibold">Tamper-evident hash chain <Tip text="Each entry stores the SHA-256 of its own content plus the previous entry's hash. Editing or deleting any past entry breaks every hash after it, so tampering is detectable." /></div>
            <div className="text-[12.5px] text-mute">{chain ? chain.message : "Verify that no entry has been altered or removed since it was written."}</div>
            {chain?.head && <div className="mono mt-1 text-[10.5px] text-mute">head {chain.head.slice(0, 32)}…</div>}</div>
          <Btn icon={<ShieldCheck size={15} />} loading={busy} onClick={verify}>Verify chain</Btn>
        </div>
      </Card>
      <Card>
        <CardHead icon={<ScrollText size={16} />} title="Audit trail" sub="Append-only record of every security-relevant action"
          right={<div className="flex gap-2"><select className="!w-36" value={prefix} onChange={(e) => setPrefix(e.target.value)} aria-label="Category"><option value="">All actions</option><option value="auth">Authentication</option><option value="defence">Defences</option><option value="sim">Simulations</option><option value="db">Database</option><option value="backup">Backup</option><option value="incident">Incidents</option><option value="sig">Signatures</option></select>
            <div className="relative"><Search size={14} className="absolute left-2.5 top-3 text-mute" /><input className="!w-52 !pl-8" placeholder="Search…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search audit log" /></div></div>} />
        {rows.loading && !rows.data ? <Spinner /> : rows.error ? <div className="p-4"><ErrorBox error={rows.error} retry={rows.reload} /></div> : !rows.data?.length ? <Empty>No entries match.</Empty> : (
          <div className="max-h-[560px] overflow-auto"><table><thead><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th><th>Entry hash</th></tr></thead>
            <tbody>{rows.data.map((r) => (
              <motion.tr key={r.id} initial={{ backgroundColor: "rgba(79,70,229,.1)" }} animate={{ backgroundColor: "rgba(0,0,0,0)" }} transition={{ duration: 1.2 }}>
                <td className="mono text-mute">{r.id}</td><td className="mono whitespace-nowrap text-mute">{fmtDateTime(r.ts)}</td><td className="font-semibold">{r.actor}</td><td><Badge tone={r.action.startsWith("auth.login_failed") || r.action.includes("fail") || r.action.includes("lockout") ? "rd" : r.action.startsWith("db.tamper") ? "am" : "cy"}>{r.action}</Badge></td>
                <td className="mono max-w-[140px] truncate text-[11.5px]">{r.target}</td><td className="mono max-w-[300px] truncate text-[11px] text-mute" title={JSON.stringify(r.detail)}>{JSON.stringify(r.detail)}</td>
                <td className="mono text-[10.5px] text-mute" title={`prev ${r.prev_hash}`}>{r.entry_hash.slice(0, 12)}…</td></motion.tr>))}</tbody></table></div>)}
      </Card>
    </div>
  );
}

function Events() {
  const { bump } = useStore();
  const [sev, setSev] = useState("");
  const [res, setRes] = useState("");
  const [origin, setOrigin] = useState("");
  const [type, setType] = useState("");
  const ev = useFetch<any[]>(() => get(`/events?limit=200${sev ? `&severity=${sev}` : ""}${res ? `&result=${res}` : ""}${origin ? `&origin=${origin}` : ""}${type ? `&attack_type=${type}` : ""}`), [sev, res, origin, type, bump.event]);
  const m = useFetch<any>(() => get("/metrics"), []);
  return (
    <Card>
      <CardHead icon={<Zap size={16} />} title="Security event log" sub="SIM = simulated telemetry · LIVE = something that really happened in this system (sign-ins, signature failures…)"
        right={<div className="flex flex-wrap gap-2">{[["Severity", sev, setSev, ["low", "medium", "high", "critical"]], ["Result", res, setRes, ["blocked", "contained", "breach", "detected"]], ["Source", origin, setOrigin, ["user_run", "seed", "background", "system"]]].map(([l, v, f, o]: any) => (
          <select key={l} className="!w-32" value={v} onChange={(e) => f(e.target.value)} aria-label={l}><option value="">{l}: any</option>{o.map((x: string) => <option key={x}>{x}</option>)}</select>))}
          <select className="!w-44" value={type} onChange={(e) => setType(e.target.value)} aria-label="Attack type"><option value="">Type: any</option>{m.data?.distribution.map((x: any) => <option key={x.type} value={x.type}>{x.label}</option>)}</select></div>} />
      {ev.loading && !ev.data ? <Spinner /> : !ev.data?.length ? <Empty>No events match.</Empty> : <div className="max-h-[620px] overflow-auto">{ev.data.map((e) => <EventRow key={e.id} e={e} />)}</div>}
    </Card>
  );
}

export function Logs() {
  const [tab, setTab] = useState<"audit" | "events">("audit");
  return (
    <div className="space-y-4">
      <PageHead icon={<ScrollText size={20} />} title="Security Audit Logs" sub="Two records: the tamper-evident audit trail of who did what, and the stream of security events (attacks, blocks, alerts)." right={<Tabs tabs={[{ id: "audit", label: "Audit trail" }, { id: "events", label: "Security events" }]} value={tab} onChange={setTab} />} />
      {tab === "audit" ? <Audit /> : <Events />}
    </div>
  );
}

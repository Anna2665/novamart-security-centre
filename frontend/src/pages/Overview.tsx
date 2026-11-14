import { motion } from "framer-motion";
import { Archive, Biohazard, Fingerprint, Flame, LayoutDashboard, Lock, Network, ShieldAlert, ShieldCheck, Swords, Siren, Zap } from "lucide-react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Topology } from "../components/Topology";
import { Badge, Btn, Card, CardHead, Empty, ErrorBox, Gauge, PageHead, Spinner, Stat, useFetch } from "../components/ui";
import { get } from "../lib/api";
import { RESULT, SEV_TONE, ago, cx, fmtTime } from "../lib/util";
import { useStore } from "../store";

const TIP = { contentStyle: { background: "#ffffff", border: "1px solid #e2e8f0", borderRadius: 8, fontSize: 12 }, cursor: { fill: "rgba(79,70,229,.06)" } };
const COLORS = ["#dc2626", "#ea580c", "#d97706", "#4f46e5", "#2563eb", "#7c3aed", "#059669", "#db2777", "#94a3b8", "#0d9488", "#c026d3", "#ca8a04"];

export function EventRow({ e, compact }: { e: any; compact?: boolean }) {
  const r = RESULT[e.result];
  return (
    <motion.div initial={{ opacity: 0, x: -14, backgroundColor: "rgba(79,70,229,.12)" }} animate={{ opacity: 1, x: 0, backgroundColor: "rgba(0,0,0,0)" }} transition={{ duration: 0.9 }}
      className="flex items-center gap-3 border-b border-line/50 px-3 py-2 text-[12.5px]">
      <span className="mono w-[58px] shrink-0 text-[11px] text-mute">{fmtTime(e.ts)}</span>
      <Badge tone={SEV_TONE[e.severity] ?? "mute"} className="w-[62px] justify-center">{e.severity}</Badge>
      <div className="min-w-0 flex-1"><div className="truncate font-semibold">{e.label}{e.details?.kind === "guard" && <span className="ml-2 text-[10px] font-normal text-mute">defence trigger</span>}</div>
        {!compact && <div className="truncate text-[11px] text-mute">{e.source_node} → {e.target_node} · {e.detection}</div>}</div>
      {r ? <Badge tone={r.tone}>{r.label}</Badge> : <Badge tone="mute">{e.result}</Badge>}
      <Badge tone={e.simulated ? "vi" : "gn"} className="hidden w-[48px] justify-center sm:inline-flex">{e.simulated ? "SIM" : "LIVE"}</Badge>
    </motion.div>
  );
}

export function Overview() {
  const { live, topology, events, bump } = useStore();
  const m = useFetch<any>(() => get("/metrics"), [bump.event, live?.mode, live?.running ? 1 : 0, JSON.stringify(live?.node_counts)]);
  if (m.loading && !m.data) return <Spinner />;
  if (!m.data) return <ErrorBox error={m.error ?? "No data"} retry={m.reload} />;
  const d = m.data, c = d.counters, cia = live?.cia ?? d.cia;
  const trend = d.trend.map((t: any) => ({ ...t, label: new Date(t.ts).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" }) }));
  const dist = d.distribution.slice(0, 10);
  const posture = d.defences_on / d.defences_total * 100;
  const feed = events.filter((e) => e.details?.kind !== "guard").slice(0, 14);

  return (
    <div className="space-y-4">
      <PageHead icon={<LayoutDashboard size={20} />} title="Security Overview" sub="NovaMart online store · live posture of the platform. Historical telemetry is simulated and labelled SIM; actions you take in this console are LIVE."
        right={<Btn icon={<Swords size={15} />} variant="danger" onClick={() => { location.hash = "#/soc/attacks"; }}>Launch an attack</Btn>} />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-5">
        <Stat icon={<Swords size={14} />} label="Attacks seen" value={c.total_attacks} tone="cy" sub="12 attack families" />
        <Stat icon={<ShieldCheck size={14} />} label="Blocked" value={c.blocked} tone="gn" sub={`${Math.round(c.blocked / Math.max(1, c.total_attacks) * 100)}% stopped at the edge`} />
        <Stat icon={<Flame size={14} />} label="Contained" value={c.contained} tone="am" sub="Damage limited / recovered" />
        <Stat icon={<Biohazard size={14} />} label="Breaches" value={c.breaches} tone="rd" pulse={c.breaches > 0 && live?.mode !== "enabled"} sub="Attacker objective reached" />
        <Stat icon={<Siren size={14} />} label="Critical alerts" value={c.critical_alerts} tone="rd" />
        <Stat icon={<Network size={14} />} label="Protected nodes" value={`${d.protected_nodes}/${d.total_nodes}`} tone={d.protected_nodes === d.total_nodes ? "gn" : "am"} sub={`${d.node_counts.compromised ?? 0} compromised · ${d.node_counts.isolated ?? 0} isolated`} />
        <Stat icon={<Lock size={14} />} label="Encryption coverage" value={`${d.encryption_coverage.percent}%`} tone={d.encryption_coverage.percent === 100 ? "gn" : "am"} sub="AES-256-GCM at rest" />
        <Stat icon={<Fingerprint size={14} />} label="Record integrity" value={`${d.integrity.intact}/${d.integrity.total}`} tone={d.integrity.tampered ? "rd" : "gn"} sub={d.integrity.tampered ? `${d.integrity.tampered} tampered!` : "Hash + RSA signature verified"} />
        <Stat icon={<ShieldAlert size={14} />} label="MFA enforcement" value={d.mfa.email_otp_enforced ? "ON" : "OFF"} tone={d.mfa.email_otp_enforced ? "gn" : "rd"} sub={`Email OTP · ${d.mfa.totp_enrolled}/${d.mfa.users} TOTP enrolled`} />
        <Stat icon={<Archive size={14} />} label="Backup health" value={d.backup.health.toUpperCase()} tone={d.backup.health === "healthy" ? "gn" : "am"} sub={`${d.backup.verified} verified snapshot(s)`} />
      </div>

      <div className="grid gap-4 xl:grid-cols-[360px_1fr]">
        <Card className="p-4">
          <div className="mb-3 flex items-center justify-between"><div className="text-[13px] font-semibold">CIA security posture</div><Badge tone={cia.overall >= 85 ? "gn" : cia.overall >= 60 ? "am" : "rd"}>{cia.overall >= 85 ? "Protected" : cia.overall >= 60 ? "At risk" : "Compromised"}</Badge></div>
          <div className="flex justify-between"><Gauge value={cia.C} label="Confid." size={100} /><Gauge value={cia.I} label="Integrity" size={100} /><Gauge value={cia.A} label="Availab." size={100} /></div>
          <div className="mt-4"><div className="mb-1 flex justify-between text-[11.5px] text-mute"><span>Defences enabled</span><span className="mono">{d.defences_on}/{d.defences_total}</span></div>
            <div className="h-2 overflow-hidden rounded-full bg-slate-100"><motion.div className={cx("h-full rounded-full", posture === 100 ? "bg-gn" : posture > 50 ? "bg-am" : "bg-rd")} animate={{ width: `${posture}%` }} /></div></div>
        </Card>
        <Card>
          <CardHead title="Attack activity · last 48 h" sub="Outcome of every attack attempt, grouped in 3-hour buckets" />
          <div className="h-[230px] px-2 pb-3">
            <ResponsiveContainer>
              <AreaChart data={trend}>
                <defs>{[["b", "#059669"], ["c", "#d97706"], ["r", "#dc2626"]].map(([k, col]) => <linearGradient key={k} id={`g${k}`} x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor={col} stopOpacity={0.5} /><stop offset="95%" stopColor={col} stopOpacity={0} /></linearGradient>)}</defs>
                <CartesianGrid stroke="#e2e8f0" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="label" stroke="#64748b" fontSize={10} interval={1} /><YAxis stroke="#64748b" fontSize={10} allowDecimals={false} />
                <Tooltip {...TIP} />
                <Area type="monotone" dataKey="blocked" stackId="1" stroke="#059669" fill="url(#gb)" name="Blocked" />
                <Area type="monotone" dataKey="contained" stackId="1" stroke="#d97706" fill="url(#gc)" name="Contained" />
                <Area type="monotone" dataKey="breach" stackId="1" stroke="#dc2626" fill="url(#gr)" name="Breach" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1fr_1.15fr]">
        <Card>
          <CardHead title="Attack types" sub="Share of observed attacks" />
          <div className="h-[300px] px-2 pb-3">
            <ResponsiveContainer>
              <BarChart data={dist} layout="vertical" margin={{ left: 40 }}>
                <CartesianGrid stroke="#e2e8f0" strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" stroke="#64748b" fontSize={10} /><YAxis type="category" dataKey="label" stroke="#475569" fontSize={11} width={130} />
                <Tooltip {...TIP} />
                <Bar dataKey="count" radius={[0, 6, 6, 0]}>{dist.map((_: any, i: number) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}</Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card>
          <CardHead icon={<Zap size={16} />} title="Live security events" sub="Streaming over WebSocket" right={<span className="flex items-center gap-1.5 text-[11px] text-gn"><span className="h-1.5 w-1.5 rounded-full bg-gn pulse-gn" />LIVE</span>} />
          <div className="max-h-[300px] overflow-auto">{feed.length === 0 ? <Empty>No events yet.</Empty> : feed.map((e) => <EventRow key={e.id} e={e} />)}</div>
        </Card>
      </div>

      <Card className="overflow-hidden">
        <CardHead icon={<Network size={16} />} title="Infrastructure" sub="Click through to Network Topology for the interactive map" right={<Btn variant="ghost" size="sm" onClick={() => { location.hash = "#/soc/topology"; }}>Open map</Btn>} />
        <Topology topology={topology} live={live} height={300} compact />
      </Card>
      <p className="text-center text-[11px] text-mute">Last refreshed {ago(new Date().toISOString())} · {c.simulated_events} simulated + {c.real_events} live events recorded</p>
    </div>
  );
}

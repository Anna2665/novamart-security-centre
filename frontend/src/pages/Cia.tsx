import { motion } from "framer-motion";
import { Activity, CheckCircle2, Eye, FileSignature, Info, Lock, Server, ShieldAlert, XCircle } from "lucide-react";
import { CartesianGrid, Legend, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, Card, CardHead, Empty, ErrorBox, Gauge, PageHead, Spinner, useFetch } from "../components/ui";
import { get } from "../lib/api";
import { PILLAR_COLOR, PILLAR_NAME, cx, fmtTime } from "../lib/util";
import { useStore } from "../store";
import { EventRow } from "./Overview";

const PILLARS = [
  { k: "C", icon: Lock, blurb: "Only authorised people can read the data: encryption at rest, MFA, access control, DLP." },
  { k: "I", icon: FileSignature, blurb: "Data cannot be changed unnoticed: hashes, digital signatures, integrity monitoring, tamper-evident logs." },
  { k: "A", icon: Server, blurb: "The store stays up and recoverable: DDoS protection, verified backups, segmentation." },
] as const;

export function Cia() {
  const { live, bump } = useStore();
  const d = useFetch<any>(() => get("/cia"), [bump.event, bump.incident, JSON.stringify(live?.cia), JSON.stringify(live?.defences)]);
  if (d.loading && !d.data) return <Spinner />;
  if (!d.data) return <ErrorBox error={d.error ?? "No data"} retry={d.reload} />;
  const { scores, signals, history, impacts, events, status } = d.data;
  const hist = history.map((h: any) => ({ ...h, t: new Date(h.ts).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" }) }));
  const icon = (s: string) => s === "ok" ? <CheckCircle2 size={15} className="text-gn" /> : s === "warn" ? <ShieldAlert size={15} className="text-am" /> : <XCircle size={15} className="text-rd" />;

  return (
    <div className="space-y-4">
      <PageHead icon={<Activity size={20} />} title="CIA Security Monitoring" sub="Confidentiality, Integrity and Availability, scored from the defences that are actually enabled minus unresolved attack damage. Every signal below is read from live platform data." />
      <div className="grid gap-4 xl:grid-cols-3">
        {PILLARS.map(({ k, icon: I, blurb }) => {
          const base = scores.baseline[k], now = scores[k], imp = scores.impact[k];
          const st = status[k] as string;
          return (
            <Card key={k} className="p-4" glow={st === "compromised" ? "rd" : undefined}>
              <div className="flex items-start gap-4">
                <Gauge value={now} label={k === "C" ? "Confid." : k === "I" ? "Integrity" : "Availab."} size={118} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2"><I size={16} style={{ color: PILLAR_COLOR[k] }} /><div className="font-bold">{PILLAR_NAME[k]}</div></div>
                  <Badge tone={st === "protected" ? "gn" : st === "at risk" ? "am" : "rd"} dot className="mt-1.5">{st}</Badge>
                  <div className="mt-2 grid grid-cols-3 gap-1 text-center text-[11px]">
                    <div className="rounded-md bg-panel2 p-1"><div className="text-mute">Defences</div><div className="mono font-bold text-cy">{Math.round(base)}</div></div>
                    <div className="rounded-md bg-panel2 p-1"><div className="text-mute">Damage</div><div className={cx("mono font-bold", imp > 0 ? "text-rd" : "text-gn")}>{imp > 0 ? `−${Math.round(imp)}` : "0"}</div></div>
                    <div className="rounded-md bg-panel2 p-1"><div className="text-mute">Score</div><div className="mono font-bold">{Math.round(now)}</div></div>
                  </div>
                </div>
              </div>
              <p className="mt-3 text-[12px] leading-snug text-mute">{blurb}</p>
              <div className="mt-3 space-y-1.5">
                {signals[k].map((s: any) => (
                  <motion.div key={s.name} layout className={cx("flex items-start gap-2 rounded-lg border px-2.5 py-1.5 text-[12px]", s.status === "ok" ? "border-gn/20 bg-gn/5" : s.status === "warn" ? "border-amber-200 bg-amber-50" : "border-rd/40 bg-rd/10")}>
                    {icon(s.status)}<div className="min-w-0 flex-1"><div className="font-semibold leading-tight">{s.name}</div><div className="mono mt-0.5 text-[10.5px] text-mute">{s.value}</div></div>
                  </motion.div>))}
              </div>
            </Card>
          );
        })}
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.5fr_1fr]">
        <Card>
          <CardHead title="Score history" sub="Last 60 hours · earlier points are simulated, recent ones reflect your actions" />
          <div className="h-[260px] px-2 pb-3"><ResponsiveContainer><LineChart data={hist}>
            <CartesianGrid stroke="#e2e8f0" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="t" stroke="#64748b" fontSize={10} interval={Math.floor(hist.length / 8)} /><YAxis domain={[0, 100]} stroke="#64748b" fontSize={10} />
            <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #e2e8f0", borderRadius: 8, fontSize: 12 }} /><Legend wrapperStyle={{ fontSize: 11 }} />
            <ReferenceLine y={85} stroke="#05966955" strokeDasharray="4 4" label={{ value: "protected", fill: "#059669", fontSize: 10, position: "insideTopRight" }} />
            <Line dataKey="C" name="Confidentiality" stroke={PILLAR_COLOR.C} dot={false} strokeWidth={2} /><Line dataKey="I" name="Integrity" stroke={PILLAR_COLOR.I} dot={false} strokeWidth={2} /><Line dataKey="A" name="Availability" stroke={PILLAR_COLOR.A} dot={false} strokeWidth={2} />
          </LineChart></ResponsiveContainer></div>
        </Card>
        <Card>
          <CardHead icon={<ShieldAlert size={16} />} title="Unresolved damage" sub="Cleared by completing the incident-response checklist" />
          {impacts.length === 0 ? <Empty>No open damage — all pillars at their defence baseline.</Empty> : (
            <div className="space-y-2 px-4 pb-4">{impacts.map((i: any) => (
              <div key={i.run_id} className="rounded-lg border border-rd/30 bg-rd/5 p-2.5 text-[12.5px]"><div className="flex justify-between"><span className="font-semibold">{i.scenario}</span><span className="mono text-mute">{i.run_id}</span></div>
                <div className="mt-1 flex gap-3">{(["C", "I", "A"] as const).map((p) => i[p] > 0 && <span key={p} className="mono" style={{ color: PILLAR_COLOR[p] }}>{p} −{Math.round(i[p])}</span>)}</div></div>))}
              <button className="text-[12px] font-semibold text-cy" onClick={() => { location.hash = "#/soc/incidents"; }}>Open incident response →</button></div>)}
        </Card>
      </div>

      <Card>
        <CardHead icon={<Eye size={16} />} title="Recent security-relevant events" sub="Live actions and high-severity events" />
        {events.length === 0 ? <Empty>Nothing notable.</Empty> : <div className="max-h-[300px] overflow-auto">{events.slice(0, 14).map((e: any) => <EventRow key={e.id} e={e} />)}</div>}
      </Card>
      <div className="flex items-start gap-2 rounded-lg border border-line bg-panel2 p-3 text-[12px] text-mute"><Info size={14} className="mt-0.5 shrink-0 text-cy" />Score = defence baseline (each enabled defence adds weight to the pillars it protects, from 35 up to 98) minus open damage (blocked attacks cost ~3% of an attack's potential, contained ~45%, successful breaches 100%). Last updated {fmtTime(new Date().toISOString())}.</div>
    </div>
  );
}

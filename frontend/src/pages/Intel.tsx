import { motion } from "framer-motion";
import { Globe2, Link2, Network, Radar, Skull, Target, UserX, Hash, Mail } from "lucide-react";
import { Badge, Bar, Card, CardHead, CopyBtn, ErrorBox, PageHead, Spinner, Tone, useFetch } from "../components/ui";
import { get } from "../lib/api";
import { SEV_TONE } from "../lib/util";

const TYPE_ICON: Record<string, any> = { ip: Network, domain: Globe2, url: Link2, hash: Hash };
const cell = (l: number, i: number) => { const s = l * i; return s >= 15 ? "rgba(220,38,38,.35)" : s >= 8 ? "rgba(234,88,12,.28)" : s >= 4 ? "rgba(217,119,6,.2)" : "rgba(5,150,105,.14)"; };

export function Intel() {
  const d = useFetch<any>(() => get("/intel/overview"), []);
  if (d.loading) return <Spinner />;
  if (!d.data) return <ErrorBox error={d.error ?? "No data"} retry={d.reload} />;
  const { mitre, risk_matrix, iocs, actors, geo, top_types, disclaimer } = d.data;
  return (
    <div className="space-y-4">
      <PageHead icon={<Radar size={20} />} title="Threat Intelligence" sub="Which attacks matter most for an online store, how they map to MITRE ATT&CK, and example indicators of compromise." />
      <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-[12.5px] text-am">{disclaimer}</div>

      <div className="grid gap-4 xl:grid-cols-[1.1fr_1fr]">
        <Card>
          <CardHead icon={<Target size={16} />} title="Risk matrix" sub="Likelihood (from observed attack frequency) × impact (potential damage to CIA)" />
          <div className="px-4 pb-4">
            <div className="flex gap-3">
              <div className="flex w-5 items-center justify-center"><span className="-rotate-90 whitespace-nowrap text-[10px] font-semibold uppercase tracking-widest text-mute">Likelihood →</span></div>
              <div className="flex-1">
                <div className="grid grid-rows-5 gap-1">
                  {[5, 4, 3, 2, 1].map((l) => (
                    <div key={l} className="grid grid-cols-5 gap-1">
                      {[1, 2, 3, 4, 5].map((i) => {
                        const here = risk_matrix.filter((r: any) => r.likelihood === l && r.impact === i);
                        return (<div key={i} className="flex min-h-[56px] flex-wrap content-center items-center justify-center gap-1 rounded-lg border border-line p-1" style={{ background: cell(l, i) }}>
                          {here.map((r: any) => <motion.span key={r.id} initial={{ scale: 0 }} animate={{ scale: 1 }} title={`${r.name} (score ${r.score})`} className="mono cursor-default rounded-md bg-black/55 px-1.5 py-0.5 text-[9.5px] font-bold text-white">{r.id.slice(0, 5)}</motion.span>)}
                        </div>);
                      })}
                    </div>))}
                </div>
                <div className="mt-1 text-center text-[10px] font-semibold uppercase tracking-widest text-mute">Impact →</div>
              </div>
            </div>
          </div>
        </Card>
        <Card>
          <CardHead title="Ranked risks" sub="likelihood × impact" />
          <div className="max-h-[360px] space-y-2 overflow-auto px-4 pb-4">{risk_matrix.map((r: any, i: number) => (
            <div key={r.id} className="flex items-center gap-3 text-[12.5px]"><span className="mono w-5 text-mute">{i + 1}</span><span className="w-44 shrink-0 truncate font-semibold">{r.name}</span><Bar value={r.score * 4} tone={r.score >= 15 ? "rd" : r.score >= 8 ? "am" : "cy"} className="flex-1" /><span className="mono w-6 text-right text-mute">{r.score}</span></div>))}</div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card><CardHead icon={<Skull size={16} />} title="MITRE ATT&CK mapping" sub="Techniques used by the 12 simulated attacks" />
          <div className="max-h-[360px] overflow-auto"><table><thead><tr><th>Technique</th><th>Name</th><th>Scenario</th></tr></thead>
            <tbody>{mitre.map((m: any, i: number) => (<tr key={i}><td><Badge tone="vi">{m.technique}</Badge></td><td>{m.name}</td><td><button className="text-cy hover:underline" onClick={() => { location.hash = "#/soc/attacks"; }}>{m.scenario}</button></td></tr>))}</tbody></table></div></Card>
        <Card><CardHead icon={<UserX size={16} />} title="Threat actors (fictional)" sub="Profiles of the kinds of adversaries that target online stores" />
          <div className="space-y-2 px-4 pb-4">{actors.map((a: any) => (
            <div key={a.name} className="rounded-xl border border-line bg-panel2 p-3"><div className="flex items-center justify-between"><span className="font-bold text-rd">{a.name}</span><span className="text-[11.5px] text-mute">{a.motive}</span></div>
              <div className="mt-1 text-[12px] text-mute">Targets: {a.targets}</div><div className="mt-2 flex flex-wrap gap-1.5">{a.ttp.map((t: string) => <Badge key={t} tone="am">{t}</Badge>)}</div></div>))}</div></Card>
      </div>

      <Card><CardHead icon={<Mail size={16} />} title="Indicators of compromise (simulated)" sub="Documentation IP ranges and .example domains — safe, non-routable examples" />
        <div className="overflow-auto"><table><thead><tr><th>Type</th><th>Indicator</th><th>Associated with</th><th>Severity</th><th>Confidence</th></tr></thead>
          <tbody>{iocs.map((i: any, k: number) => { const I = TYPE_ICON[i.type] ?? Network; return (
            <tr key={k}><td><span className="flex items-center gap-1.5 text-mute"><I size={14} />{i.type}</span></td><td className="mono text-[12px]"><span className="inline-flex items-center gap-2">{i.value}<CopyBtn text={i.value} /></span></td><td>{i.description}</td><td><Badge tone={SEV_TONE[i.severity] as Tone}>{i.severity}</Badge></td><td className="min-w-[120px]"><div className="flex items-center gap-2"><Bar value={i.confidence} tone={i.confidence > 85 ? "rd" : "am"} className="flex-1" height={4} /><span className="mono text-[11px] text-mute">{i.confidence}%</span></div></td></tr>); })}</tbody></table></div></Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card><CardHead icon={<Globe2 size={16} />} title="Attack origins (illustrative)" sub="Anonymised regions — no real geolocation" />
          <div className="space-y-2.5 px-4 pb-4">{geo.map((g: any) => <div key={g.region} className="flex items-center gap-3 text-[12.5px]"><span className="w-40 shrink-0">{g.region}</span><Bar value={g.percent * 3} className="flex-1" /><span className="mono w-9 text-right text-mute">{g.percent}%</span></div>)}</div></Card>
        <Card><CardHead title="Most frequent attack types" sub="From the event log" />
          <div className="space-y-2.5 px-4 pb-4">{top_types.map((t: any, i: number) => <div key={t.type} className="flex items-center gap-3 text-[12.5px]"><span className="w-40 shrink-0">{t.label}</span><Bar value={(t.count / top_types[0].count) * 100} tone={i === 0 ? "rd" : "cy"} className="flex-1" /><span className="mono w-9 text-right text-mute">{t.count}</span></div>)}</div></Card>
      </div>
    </div>
  );
}

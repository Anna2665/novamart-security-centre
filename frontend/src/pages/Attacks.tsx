import { AnimatePresence, motion } from "framer-motion";
import { AlertOctagon, ArrowRight, ArrowUpCircle, Bug, Check, CheckCircle2, Circle, Code, Crosshair, Database, Eye, Fish, GitCompare, KeyRound, Link as LinkIcon, Loader2, Pencil, Play, Rocket, ShieldCheck, ShieldX, Siren, SkipForward, Users, Zap, CloudDownload } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Evidence } from "../components/Evidence";
import { NodeDrawer } from "../components/NodeDrawer";
import { StatusLegend, Topology } from "../components/Topology";
import { Badge, Bar, Btn, Card, CardHead, Modal, PageHead, Spinner, Switch, TONE, Tone, useFetch } from "../components/ui";
import { ApiError, get, post, put } from "../lib/api";
import { PILLAR_COLOR, RESULT, cx } from "../lib/util";
import { useStore } from "../store";

const ICON: Record<string, any> = { sqli: Database, db_tamper: Pencil, xss: Code, csrf: LinkIcon, brute_force: KeyRound, cred_stuffing: Users, phishing: Fish, ddos: Zap, ransomware: Bug, priv_esc: ArrowUpCircle, exfiltration: CloudDownload, mitm: Eye };
const OUT: Record<string, { icon: any; tone: Tone; label: string }> = {
  blocked: { icon: ShieldCheck, tone: "gn", label: "Blocked" }, alerted: { icon: Siren, tone: "am", label: "Alert raised" }, throttled: { icon: ShieldCheck, tone: "am", label: "Throttled" },
  recovered: { icon: ShieldCheck, tone: "gn", label: "Recovered" }, passed: { icon: ShieldX, tone: "rd", label: "Rule bypassed" }, inactive: { icon: ShieldX, tone: "mute", label: "Defence OFF" },
};
const stageTone = (s: string): Tone => (s === "blocked" ? "gn" : s === "detected" ? "am" : s === "succeeded" ? "rd" : s === "active" ? "cy" : "mute");

function Pipeline({ stages, active, done, ended, selected, onSelect }: { stages: any[]; active: number; done: number; ended: boolean; selected: number; onSelect: (i: number) => void }) {
  return (
    <div className="flex flex-wrap items-stretch gap-y-3">
      {stages.map((s, i) => {
        const visible = i < done || ended;
        const status = i === active ? "active" : visible ? s.status : "pending";
        const t = stageTone(status);
        const Icon = status === "active" ? Loader2 : status === "blocked" ? ShieldCheck : status === "detected" ? Siren : status === "succeeded" ? AlertOctagon : status === "skipped" ? SkipForward : Circle;
        return (
          <div key={s.id} className="flex items-center">
            <motion.button onClick={() => onSelect(i)} layout
              className={cx("relative w-[158px] rounded-xl border p-3 text-left transition-all", TONE[t].border, TONE[t].bg, selected === i && "ring-2 ring-white/20", status === "active" && "pulse-cy", status === "pending" && "opacity-60", status === "skipped" && "opacity-40")}
              animate={status === "active" ? { scale: 1.04 } : { scale: 1 }}>
              <div className="flex items-center gap-2">
                <span className={cx("mono flex h-5 w-5 items-center justify-center rounded-md text-[10px] font-bold", TONE[t].text)} style={{ background: TONE[t].hex + "22" }}>{i + 1}</span>
                <Icon size={15} className={cx(TONE[t].text, status === "active" && "spin")} />
                <span className={cx("ml-auto text-[9.5px] font-bold uppercase tracking-wider", TONE[t].text)}>{status === "succeeded" ? "attack passes" : status}</span>
              </div>
              <div className="mt-2 text-[12.5px] font-semibold leading-tight">{s.title}</div>
              <div className="mt-0.5 line-clamp-2 text-[10.5px] leading-snug text-mute">{s.description}</div>
            </motion.button>
            {i < stages.length - 1 && (
              <svg width="38" height="20" className="shrink-0">
                <line x1="2" y1="10" x2="30" y2="10" stroke={i < done - (status === "blocked" ? 1 : 0) || (ended && stages[i].status !== "blocked") ? (stages[i].status === "blocked" ? "#059669" : "#dc2626") : "#cbd5e1"} strokeWidth="2.5" className={i === active ? "marching" : ""} />
                <polygon points="30,5 38,10 30,15" fill={i < done ? "#dc2626" : "#cbd5e1"} />
              </svg>
            )}
          </div>
        );
      })}
    </div>
  );
}

function Terminal({ lines }: { lines: { level: string; msg: string; stage: number; key: string }[] }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" }); }, [lines.length]);
  const col: Record<string, string> = { info: "text-mute", warn: "text-am", error: "text-rd", success: "text-gn", danger: "text-rd" };
  return (
    <div ref={ref} className="mono h-[250px] overflow-auto rounded-lg border border-line bg-[#f8fafc] p-3 text-[11.5px] leading-relaxed">
      {lines.length === 0 && <div className="text-mute">$ awaiting simulation<span className="blink">▮</span></div>}
      {lines.map((l) => (
        <motion.div key={l.key} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} className={cx("flex gap-2", col[l.level] ?? "text-ink")}>
          <span className="shrink-0 text-cy/50">[{String(l.stage + 1).padStart(2, "0")}]</span><span className="break-words">{l.msg}</span>
        </motion.div>
      ))}
    </div>
  );
}

function ResultBanner({ run, go }: { run: any; go: () => void }) {
  const r = RESULT[run.result];
  const blockedAt = run.stages.find((s: any) => s.status === "blocked");
  const imp = run.impact;
  return (
    <motion.div initial={{ opacity: 0, y: 14, scale: 0.97 }} animate={{ opacity: 1, y: 0, scale: 1 }} className={cx("card relative overflow-hidden p-5", r.tone === "gn" ? "glow-gn" : r.tone === "am" ? "glow-am" : "glow-rd")}>
      <div className="flex flex-wrap items-start gap-5">
        <div className={cx("flex h-16 w-16 shrink-0 items-center justify-center rounded-2xl border-2", TONE[r.tone].border, TONE[r.tone].bg, r.tone === "rd" ? "pulse-rd" : "pulse-gn")}>
          {r.tone === "gn" ? <ShieldCheck size={34} className="text-gn" /> : r.tone === "am" ? <ShieldCheck size={34} className="text-am" /> : <AlertOctagon size={34} className="glitch text-rd" />}
        </div>
        <div className="min-w-[260px] flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className={cx("text-2xl font-black tracking-wide", TONE[r.tone].text)}>{run.result === "blocked" ? "ATTACK BLOCKED" : run.result === "contained" ? "ATTACK CONTAINED" : "SYSTEM BREACHED"}</span>
            <Badge tone={run.detected ? "cy" : "rd"} dot>{run.detected ? "Detected" : "Undetected"}</Badge>
            {run.dry && <Badge tone="mute">dry run</Badge>}
          </div>
          <p className="mt-1 text-[13.5px] text-ink/90">{run.summary}</p>
          {blockedAt && <p className="mt-1 text-[12.5px] text-gn">Stopped at stage {blockedAt.index + 1}: {blockedAt.title}</p>}
          <div className="mt-3 flex flex-wrap gap-1.5">
            {run.defence_used.length ? run.defence_used.map((d: string) => <Badge key={d} tone="gn"><Check size={11} /> {d}</Badge>) : <Badge tone="rd">No defence engaged</Badge>}
          </div>
        </div>
        <div className="w-[230px] space-y-2">
          <div className="text-[10.5px] font-semibold uppercase tracking-wider text-mute">Impact on CIA</div>
          {(["C", "I", "A"] as const).map((k) => (
            <div key={k} className="flex items-center gap-2 text-[12px]"><span className="mono w-4 font-bold" style={{ color: PILLAR_COLOR[k] }}>{k}</span><Bar value={imp[k]} tone={imp[k] > 40 ? "rd" : imp[k] > 5 ? "am" : "gn"} className="flex-1" /><span className="mono w-9 text-right text-mute">{imp[k] > 0 ? `−${Math.round(imp[k])}` : "0"}</span></div>
          ))}
          {run.result !== "blocked" && !run.dry && <Btn variant="danger" size="sm" className="mt-1 w-full" icon={<Siren size={14} />} onClick={go}>Open incident response</Btn>}
        </div>
      </div>
    </motion.div>
  );
}

function CompareModal({ open, onClose, data, loading }: { open: boolean; onClose: () => void; data: any; loading: boolean }) {
  return (
    <Modal open={open} onClose={onClose} title="Same attack · defences OFF vs ON" width={980}>
      {loading || !data ? <Spinner label="Evaluating both configurations…" /> : (
        <div className="grid gap-4 md:grid-cols-2">
          {([["off", "Defences OFF", "rd"], ["on", "All 21 defences ON", "gn"]] as const).map(([k, label, tone]) => {
            const r = data[k];
            return (
              <div key={k} className={cx("rounded-xl border p-4", TONE[tone].border, TONE[tone].bg)}>
                <div className="flex items-center justify-between"><span className={cx("text-sm font-bold", TONE[tone].text)}>{label}</span><Badge tone={RESULT[r.result].tone}>{RESULT[r.result].label}</Badge></div>
                <p className="mt-2 text-[13px]">{r.summary}</p>
                <div className="mt-3 space-y-1.5">
                  {r.stages.map((s: any) => (
                    <div key={s.id} className="flex items-center gap-2 text-[12px]">
                      <span className="mono w-4 text-mute">{s.index + 1}</span>
                      <span className="flex-1">{s.title}</span>
                      <Badge tone={stageTone(s.status)}>{s.status === "succeeded" ? "attack passes" : s.status}</Badge>
                    </div>
                  ))}
                </div>
                <div className="mt-3 flex gap-3 text-[12px]">{(["C", "I", "A"] as const).map((p) => <span key={p} className="mono" style={{ color: PILLAR_COLOR[p] }}>{p} {r.impact[p] > 0 ? `−${Math.round(r.impact[p])}` : "0"}</span>)}</div>
                <div className="mt-2 flex flex-wrap gap-1">{r.defence_used.map((d: string) => <Badge key={d} tone="gn">{d}</Badge>)}</div>
              </div>
            );
          })}
        </div>
      )}
      <p className="mt-4 text-[12px] text-mute">This is a dry run: nothing in the live platform state, database or event log was changed.</p>
    </Modal>
  );
}

export function Attacks() {
  const { live, topology, run, toast, can, startRun, refreshLive } = useStore();
  const scen = useFetch<any[]>(() => get("/sim/scenarios"), []);
  const defs = useFetch<{ defences: any[] }>(() => get("/sim/defences"), [live?.mode, JSON.stringify(live?.defences)]);
  const [sel, setSel] = useState("sqli");
  const [stageSel, setStageSel] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [payload, setPayload] = useState("");
  const [cmp, setCmp] = useState<{ open: boolean; data: any; loading: boolean }>({ open: false, data: null, loading: false });
  const [node, setNode] = useState<string | null>(null);
  const [campaign, setCampaign] = useState<string[]>([]);
  const [showAll, setShowAll] = useState(false);
  const canRun = can("sim:run"), canCfg = can("sim:configure");

  const sc = scen.data?.find((s) => s.id === sel);
  const view = run && run.run.scenario_id === sel ? run : null;
  const running = !!live?.running;

  // Follow the running scenario (also when started from elsewhere or by the campaign).
  useEffect(() => { if (run && !run.ended) setSel(run.run.scenario_id); }, [run?.run.run_id]);
  useEffect(() => { setStageSel(null); setPayload(""); }, [sel]);

  // Campaign: run every scenario in turn.
  useEffect(() => {
    if (campaign.length && run?.ended && !running) {
      const t = setTimeout(() => { const [next, ...rest] = campaign; setCampaign(rest); void launch(next); }, 1800);
      return () => clearTimeout(t);
    }
  }, [run?.ended, run?.run.run_id, campaign.length, running]);

  async function launch(id = sel) {
    setBusy(true);
    try {
      setSel(id);
      const params = payload.trim() && (id === "sqli" || id === "xss") ? { payload: payload.trim() } : undefined;
      const r = await post("/sim/run", { scenario_id: id, params });
      startRun(r); setStageSel(null);
    } catch (e) {
      const err = e as ApiError;
      toast("err", err.status === 409 ? "Another simulation is running" : "Could not start the attack", err.message); setCampaign([]);
    } finally { setBusy(false); }
  }
  async function compare() {
    setCmp({ open: true, data: null, loading: true });
    try { setCmp({ open: true, data: await post("/sim/compare", { scenario_id: sel }), loading: false }); }
    catch (e: any) { setCmp({ open: false, data: null, loading: false }); toast("err", "Comparison failed", e.message); }
  }
  async function toggle(id: string, on: boolean) {
    try { await put(`/sim/defences/${id}`, { enabled: on }); await refreshLive(); defs.reload(); }
    catch (e: any) { toast("err", "Could not change the defence", e.message); }
  }

  const stages = view?.run.stages ?? sc?.stages.map((s: any, i: number) => ({ ...s, index: i, status: "pending", logs: [], checks: [], evidence: [] })) ?? [];
  const idx = view ? (view.active >= 0 ? view.active : view.done > 0 ? Math.min(view.done, stages.length) - 1 : -1) : -1;
  const curStage = stages[idx];
  const pathTone: "rd" | "gn" | "am" = !view ? "rd" : view.active >= 0 ? "rd" : view.ended ? (view.run.result === "blocked" ? "gn" : view.run.result === "contained" ? "am" : "rd") : curStage?.status === "blocked" ? "gn" : curStage?.status === "detected" ? "am" : "rd";
  const lines = useMemo(() => {
    if (!view) return [];
    const out: { level: string; msg: string; stage: number; key: string }[] = [];
    view.run.stages.forEach((s: any, i: number) => {
      if (i < view.done || i === view.active || view.ended) {
        s.logs.forEach((l: any, j: number) => out.push({ ...l, stage: i, key: `${view.run.run_id}-${i}-${j}` }));
        if (i < view.done || view.ended) s.checks.filter((c: any) => c.outcome !== "inactive").forEach((c: any, j: number) => out.push({ level: c.outcome === "passed" ? "error" : "success", msg: `${c.name}: ${c.detail}`, stage: i, key: `${view.run.run_id}-${i}-c${j}` }));
      }
    });
    return out;
  }, [view?.run.run_id, view?.active, view?.done, view?.ended]);

  const shown = stageSel ?? (idx >= 0 ? idx : null);
  const shownStage = shown !== null ? stages[shown] : null;
  const relevant = (defs.data?.defences ?? []).filter((d) => sc?.defences.includes(d.id));
  const allDefs = defs.data?.defences ?? [];
  const enabledCount = allDefs.filter((d) => d.enabled).length;

  if (scen.loading && !scen.data) return <Spinner />;
  return (
    <div className="space-y-4">
      <PageHead icon={<Crosshair size={20} />} title="Attack Simulation" sub="Pick an attack, switch defences on or off, and watch the pipeline run through the real rules. Everything executes in an isolated sandbox — no real systems are touched."
        right={<div className="flex gap-2"><Btn variant="warn" icon={<Rocket size={15} />} disabled={!canRun || running || !!campaign.length} onClick={() => { const ids = scen.data!.map((s) => s.id); setCampaign(ids.slice(1)); void launch(ids[0]); }}>Run full campaign (12)</Btn></div>} />
      {campaign.length > 0 && <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-[12.5px] text-am">Campaign in progress — {campaign.length} attack(s) queued. <button className="ml-2 underline" onClick={() => setCampaign([])}>Cancel queue</button></div>}

      <div className="grid grid-cols-2 gap-2.5 md:grid-cols-3 xl:grid-cols-6">
        {scen.data?.map((s) => {
          const Icon = ICON[s.id] ?? Crosshair;
          const on = sel === s.id;
          const last = run?.run.scenario_id === s.id ? run : null;
          return (
            <motion.button key={s.id} whileHover={{ y: -2 }} onClick={() => setSel(s.id)} aria-pressed={on}
              className={cx("card relative p-3 text-left transition-all", on ? "glow-cy" : "hover:border-cy/30")} style={on ? { borderColor: "#4f46e599" } : {}}>
              <div className="flex items-center gap-2"><Icon size={16} className={on ? "text-cy" : "text-mute"} />
                {last?.ended && <span className="ml-auto h-2 w-2 rounded-full" style={{ background: TONE[RESULT[last.run.result].tone].hex }} />}</div>
              <div className="mt-2 text-[12.5px] font-semibold leading-tight">{s.name}</div>
              <div className="mono mt-0.5 text-[9.5px] text-mute">{s.tag}</div>
              <div className="mt-2 flex gap-1">{(["C", "I", "A"] as const).map((p) => <div key={p} className="h-1 flex-1 rounded-full bg-slate-100" title={`${p} impact ${s.impact[p]}`}><div className="h-full rounded-full" style={{ width: `${s.impact[p]}%`, background: PILLAR_COLOR[p] }} /></div>)}</div>
            </motion.button>
          );
        })}
      </div>

      {sc && (
        <div className="grid gap-4 xl:grid-cols-[1fr_390px]">
          <div className="min-w-0 space-y-4">
            <Card className="p-4">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="min-w-[280px] flex-1">
                  <div className="flex flex-wrap items-center gap-2"><h2 className="text-lg font-bold">{sc.name}</h2><Badge tone="rd">{sc.tag}</Badge>{sc.mitre.map((m: any) => <Badge key={m.id} tone="vi">{m.id}</Badge>)}</div>
                  <p className="mt-1.5 text-[13px] leading-relaxed text-mute">{sc.description}</p>
                  <div className="mt-2 flex flex-wrap items-center gap-2 text-[12px] text-mute"><span className="rounded-md bg-rd/10 px-2 py-0.5 text-rd">{sc.source}</span><ArrowRight size={13} /><span className="rounded-md bg-amber-50 px-2 py-0.5 text-am">{sc.target}</span></div>
                </div>
                <div className="flex flex-col gap-2">
                  <Btn size="lg" variant="danger" icon={<Play size={16} />} loading={busy} disabled={!canRun || running} onClick={() => launch()}>{running ? "Simulation running…" : "Launch attack"}</Btn>
                  <Btn variant="ghost" icon={<GitCompare size={15} />} onClick={compare} disabled={!canRun}>Compare OFF vs ON</Btn>
                </div>
              </div>
              {(sel === "sqli" || sel === "xss") && (
                <div className="mt-3"><label className="text-[11px] font-semibold uppercase tracking-wider text-mute">Custom payload (optional — the real filters evaluate whatever you type)</label>
                  <input className="mono mt-1" value={payload} onChange={(e) => setPayload(e.target.value)} placeholder={sel === "sqli" ? "' OR '1'='1' --" : "<script>alert(document.cookie)</script>"} maxLength={300} /></div>
              )}
              {!canRun && <div className="mt-3 text-[12px] text-am">Your role (viewer) is read-only — sign in as analyst or admin to run attacks.</div>}
            </Card>

            <div id="live-run" className="scroll-mt-3"><Card className="p-4">
              <div className="mb-3 flex items-center justify-between"><div className="text-[13px] font-semibold">Attack pipeline</div>
                <div className="text-[11px] text-mute">{view ? (view.ended ? "Completed" : "Executing…") : "Idle — launch an attack to animate"} · click a stage for details</div></div>
              <div className="overflow-x-auto pb-1"><Pipeline stages={stages} active={view?.active ?? -1} done={view?.done ?? 0} ended={!!view?.ended} selected={shown ?? -1} onSelect={(i) => setStageSel(i)} /></div>
            </Card></div>

            <AnimatePresence>{view?.ended && <ResultBanner run={view.run} go={() => { location.hash = "#/soc/incidents"; }} />}</AnimatePresence>

            <Card className="relative overflow-hidden">
              <CardHead title="Live network view" sub="Red = attack traffic · green = blocked · click any node for details" right={<StatusLegend />} />
              <Topology topology={topology} live={live} path={curStage?.path} tone={pathTone} onNodeClick={setNode} height={380} interactive />
              <NodeDrawer nodeId={node} defences={allDefs} onClose={() => setNode(null)} />
            </Card>
          </div>

          <div className="min-w-0 space-y-4">
            <Card>
              <CardHead title="Attack console" sub={view ? `${view.run.run_id} · ${view.run.mode === "enabled" ? "defences ON" : view.run.mode === "disabled" ? "defences OFF" : "partial defences"}` : "No run yet"} />
              <div className="px-4 pb-4"><Terminal lines={lines} /></div>
            </Card>

            <Card>
              <CardHead title={`Defences for this attack (${relevant.filter((d) => d.enabled).length}/${relevant.length} on)`} sub="Toggle one and re-run to see exactly where it matters" />
              <div className="space-y-1 px-4 pb-3">
                {relevant.map((d) => (
                  <div key={d.id} className="flex items-center gap-3 rounded-lg border border-line bg-panel2 px-3 py-2">
                    <div className="min-w-0 flex-1"><div className="flex items-center gap-2 text-[12.5px] font-semibold">{d.name}<Badge tone={d.kind === "preventive" ? "cy" : d.kind === "detective" ? "am" : "gn"}>{d.kind}</Badge></div>
                      <div className="text-[11px] leading-snug text-mute">{d.description}</div></div>
                    <Switch on={d.enabled} onChange={(v) => toggle(d.id, v)} disabled={!canCfg || running} label={d.name} />
                  </div>
                ))}
                <button onClick={() => setShowAll(!showAll)} className="w-full pt-1 text-center text-[12px] font-semibold text-cy">{showAll ? "Hide" : "Show"} all 21 defences ({enabledCount} on)</button>
                {showAll && allDefs.filter((d) => !sc.defences.includes(d.id)).map((d) => (
                  <div key={d.id} className="flex items-center gap-3 px-2 py-1 text-[12px]"><span className="flex-1 text-mute">{d.name}</span><Switch on={d.enabled} onChange={(v) => toggle(d.id, v)} disabled={!canCfg || running} label={d.name} /></div>
                ))}
              </div>
            </Card>

            {shownStage && (view ? (shown! < view.done || shown === view.active || view.ended) : false) && (
              <Card>
                <CardHead title={`Stage ${shown! + 1}: ${shownStage.title}`} sub={shownStage.description} />
                <div className="space-y-3 px-4 pb-4">
                  {shownStage.checks.length > 0 && (
                    <div className="space-y-1.5">
                      <div className="text-[10.5px] font-semibold uppercase tracking-wider text-mute">Defence checks</div>
                      {shownStage.checks.map((c: any, i: number) => {
                        const o = OUT[c.outcome] ?? OUT.inactive; const I = o.icon;
                        return (
                          <div key={i} className={cx("rounded-lg border p-2.5", TONE[o.tone].border, TONE[o.tone].bg)}>
                            <div className="flex items-center gap-2 text-[12.5px] font-semibold"><I size={14} className={TONE[o.tone].text} />{c.name}<span className={cx("ml-auto text-[10px] font-bold uppercase", TONE[o.tone].text)}>{o.label}</span></div>
                            <div className="mt-1 text-[11.5px] leading-snug text-ink/80">{c.detail}</div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                  {shownStage.evidence.map((ev: any, i: number) => <Evidence key={i} ev={ev} />)}
                  {shownStage.checks.length === 0 && shownStage.evidence.length === 0 && <div className="text-[12px] text-mute">No defence was evaluated at this stage.</div>}
                </div>
              </Card>
            )}
          </div>
        </div>
      )}
      <CompareModal open={cmp.open} onClose={() => setCmp({ ...cmp, open: false })} data={cmp.data} loading={cmp.loading} />
    </div>
  );
}

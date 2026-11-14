import { AnimatePresence, motion } from "framer-motion";
import { ArrowRight, Check, CheckCircle2, Circle, ClipboardList, Play, ShieldAlert, Siren, Timer } from "lucide-react";
import { useEffect, useState } from "react";
import { Badge, Btn, Card, CardHead, Empty, ErrorBox, PageHead, Spinner, Tabs, Tone, useFetch } from "../components/ui";
import { get, post, put } from "../lib/api";
import { SEV_TONE, ago, cx, fmtDateTime, fmtTime } from "../lib/util";
import { useStore } from "../store";

const ACTION_LABEL: Record<string, string> = { block_ip: "Block IP", revoke_sessions: "Revoke sessions", rotate_keys: "Rotate secrets", integrity_scan: "Run integrity scan", restore_db: "Restore database", verify_backup: "Verify backup", restore_backup: "Restore backup", isolate_node: "Isolate host", reset_credentials: "Reset credentials" };
const actionLabel = (a: string) => a.startsWith("enable_defence:") ? `Enable ${a.split(":")[1].replace(/_/g, " ")}` : ACTION_LABEL[a] ?? a.replace(/_/g, " ");

function Detail({ id, onChange }: { id: number; onChange: () => void }) {
  const { toast, can, bump } = useStore();
  const d = useFetch<any>(() => get(`/incidents/${id}`), [id, bump.incident]);
  const [busy, setBusy] = useState("");
  const [notes, setNotes] = useState("");
  const [tab, setTab] = useState<"list" | "time" | "audit">("list");
  useEffect(() => { if (d.data) setNotes(d.data.notes ?? ""); }, [d.data?.id, d.data?.updated_at]);
  if (d.loading && !d.data) return <Spinner />;
  if (!d.data) return <ErrorBox error={d.error ?? "Not found"} />;
  const inc = d.data;
  const canOp = can("incident:manage");
  const resolved = inc.status === "resolved";

  async function toggle(tid: string) {
    setBusy(tid);
    try { await post(`/incidents/${id}/tasks/${tid}/toggle`); d.reload(); onChange(); } catch (e: any) { toast("err", "Step not allowed", e.message); } finally { setBusy(""); }
  }
  async function advance() {
    setBusy("adv");
    try { await post(`/incidents/${id}/advance`); toast("ok", inc.phase >= 5 ? "Incident resolved" : `Moved to ${inc.phases[inc.phase + 1]}`); d.reload(); onChange(); void useStore.getState().refreshLive(); } catch (e: any) { toast("err", "Cannot advance yet", e.message); } finally { setBusy(""); }
  }
  async function saveNotes() { setBusy("n"); try { await put(`/incidents/${id}/notes`, { text: notes }); toast("ok", "Notes saved"); d.reload(); } catch (e: any) { toast("err", "Could not save", e.message); } finally { setBusy(""); } }
  const openInPhase = inc.checklist.filter((t: any) => t.phase === inc.phase && !t.done).length;

  return (
    <div className="space-y-4">
      <Card className="p-4" glow={resolved ? "gn" : inc.severity === "critical" ? "rd" : undefined}>
        <div className="flex flex-wrap items-start gap-3">
          <div className={cx("flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border", resolved ? "border-gn/50 bg-gn/10" : "border-rd/50 bg-rd/10")}>{resolved ? <CheckCircle2 className="text-gn" /> : <Siren className="text-rd" />}</div>
          <div className="min-w-[240px] flex-1"><div className="flex flex-wrap items-center gap-2"><span className="mono text-sm font-bold text-cy">{inc.code}</span><Badge tone={SEV_TONE[inc.severity]}>{inc.severity}</Badge><Badge tone={resolved ? "gn" : "am"} dot>{inc.status}</Badge></div>
            <div className="mt-1 font-semibold">{inc.title}</div>
            <div className="mt-1 text-[12px] text-mute">Opened {fmtDateTime(inc.ts)} · detected by: {inc.detection_source}</div>
            <div className="mt-2 flex flex-wrap gap-1.5">{inc.affected_assets.map((a: any) => <Badge key={a.id} tone="am">{a.label}</Badge>)}</div></div>
          <div className="w-[170px]"><div className="mb-1 flex justify-between text-[11px] text-mute"><span>Progress</span><span className="mono">{inc.progress.done}/{inc.progress.total}</span></div>
            <div className="h-2 overflow-hidden rounded-full bg-slate-100"><motion.div className="h-full rounded-full bg-cy" animate={{ width: `${inc.progress.done / inc.progress.total * 100}%` }} /></div></div>
        </div>
        <div className="mt-5 flex items-center">
          {inc.phases.map((p: string, i: number) => {
            const state = resolved || i < inc.phase ? "done" : i === inc.phase ? "now" : "todo";
            return (<div key={p} className="flex flex-1 items-center last:flex-none">
              <div className="flex flex-col items-center gap-1.5"><motion.div animate={state === "now" ? { scale: 1.15 } : { scale: 1 }} className={cx("flex h-8 w-8 items-center justify-center rounded-full border-2 text-xs font-bold", state === "done" ? "border-gn bg-gn/15 text-gn" : state === "now" ? "border-cy bg-cy/15 text-cy pulse-cy" : "border-line text-mute")}>{state === "done" ? <Check size={15} /> : i + 1}</motion.div>
                <div className={cx("w-[84px] text-center text-[10.5px] font-semibold leading-tight", state === "todo" ? "text-mute" : "text-ink")}>{p}</div></div>
              {i < 5 && <div className={cx("mx-1 mb-5 h-[2px] flex-1", i < inc.phase || resolved ? "bg-gn" : "bg-line")} />}</div>);
          })}
        </div>
      </Card>

      <div className="flex items-center justify-between"><Tabs tabs={[{ id: "list", label: "Response checklist" }, { id: "time", label: `Attack timeline (${inc.timeline.length})` }, { id: "audit", label: `Actions taken (${inc.audit.length})` }]} value={tab} onChange={setTab} />
        {!resolved && <Btn testId="advance" icon={<ArrowRight size={15} />} disabled={!canOp || openInPhase > 0} loading={busy === "adv"} onClick={advance}>{inc.phase >= 5 ? "Close incident" : `Advance to ${inc.phases[inc.phase + 1]}`}</Btn>}</div>
      {!resolved && openInPhase > 0 && tab === "list" && <div className="text-[12px] text-am">{openInPhase} step{openInPhase > 1 ? "s" : ""} left in “{inc.phases[inc.phase]}” — phases cannot be skipped.</div>}

      {tab === "list" && inc.phases.map((p: string, pi: number) => {
        const tasks = inc.checklist.filter((t: any) => t.phase === pi);
        if (!tasks.length) return null;
        const active = pi === inc.phase && !resolved;
        return (
          <Card key={p} className={cx("p-4", active && "glow-cy", pi > inc.phase && !resolved && "opacity-55")}>
            <div className="mb-2 flex items-center gap-2 text-[13px] font-semibold"><span className="mono flex h-5 w-5 items-center justify-center rounded-full bg-cy/15 text-[10px] text-cy">{pi + 1}</span>{p}{active && <Badge tone="cy">current phase</Badge>}</div>
            <div className="space-y-1.5">{tasks.map((t: any) => (
              <div key={t.id} className={cx("flex items-center gap-3 rounded-lg border px-3 py-2", t.done ? "border-gn/25 bg-gn/5" : "border-line bg-panel2")}>
                {t.done ? <CheckCircle2 size={18} className="shrink-0 text-gn" /> : <Circle size={18} className="shrink-0 text-mute" />}
                <div className="min-w-0 flex-1"><div className={cx("text-[13px]", t.done && "text-ink/80")}>{t.title}</div>
                  {t.done && <div className="text-[11px] text-mute">{t.result}{t.by && t.by !== "system" ? ` · ${t.by}` : t.by === "system" ? " · system" : ""}{t.at ? ` · ${fmtTime(t.at)}` : ""}</div>}</div>
                {!t.done && active && <Btn testId="task-btn" size="sm" variant={t.action ? "primary" : "ghost"} icon={t.action ? <Play size={13} /> : <Check size={13} />} disabled={!canOp} loading={busy === t.id} onClick={() => toggle(t.id)}>{t.action ? actionLabel(t.action) : "Mark done"}</Btn>}
              </div>))}</div>
            {pi === 5 && !resolved && active && <div className="mt-3"><textarea className="min-h-[80px]" placeholder="Root cause and lessons learned…" value={notes} onChange={(e) => setNotes(e.target.value)} maxLength={4000} /><Btn className="mt-2" size="sm" variant="ghost" loading={busy === "n"} onClick={saveNotes}>Save notes</Btn></div>}
          </Card>);
      })}
      {resolved && inc.notes && <Card className="p-4"><div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-mute">Lessons learned</div><div className="text-[13px]">{inc.notes}</div></Card>}

      {tab === "time" && <Card className="p-4"><div className="space-y-3">{inc.timeline.map((t: any, i: number) => (
        <div key={i} className="flex gap-3"><div className="flex flex-col items-center"><span className={cx("h-2.5 w-2.5 rounded-full", t.kind === "blocked" ? "bg-gn" : t.kind === "incident" ? "bg-cy" : t.kind === "detected" ? "bg-am" : "bg-rd")} />{i < inc.timeline.length - 1 && <span className="w-px flex-1 bg-line" />}</div>
          <div className="pb-2"><div className="mono text-[11px] text-mute">{fmtTime(t.ts)}</div><div className="text-[12.5px]">{t.text}</div></div></div>))}</div></Card>}
      {tab === "audit" && (inc.audit.length === 0 ? <Empty>No response actions yet.</Empty> : <Card className="p-4"><div className="space-y-2">{inc.audit.map((a: any, i: number) => (
        <div key={i} className="flex gap-3 rounded-lg border border-line bg-panel2 p-2.5 text-[12.5px]"><Timer size={15} className="mt-0.5 shrink-0 text-cy" /><div><div className="font-semibold">{a.action}<span className="ml-2 font-normal text-mute">by {a.actor} · {fmtTime(a.ts)}</span></div><div className="text-mute">{a.result}</div></div></div>))}</div></Card>)}
    </div>
  );
}

export function Incidents() {
  const { bump } = useStore();
  const list = useFetch<any[]>(() => get("/incidents"), [bump.incident]);
  const [sel, setSel] = useState<number | null>(null);
  useEffect(() => { if (list.data?.length && (sel === null || !list.data.find((i) => i.id === sel))) setSel(list.data[0].id); }, [list.data]);
  if (list.loading && !list.data) return <Spinner />;
  return (
    <div className="space-y-4">
      <PageHead icon={<Siren size={20} />} title="Incident Response" sub="Every attack that gets through (or is only contained) opens an incident. Work it through the six phases — the response actions are real operations on the platform, and CIA scores recover as you complete them." />
      {!list.data?.length ? (
        <Card className="p-10 text-center"><ShieldAlert size={36} className="mx-auto text-mute" /><div className="mt-3 font-semibold">No incidents yet</div><p className="mx-auto mt-1 max-w-md text-[13px] text-mute">Incidents are created when an attack is contained or succeeds. Turn some defences off in <b>Attack Simulation</b>, launch an attack, then come back here to respond.</p>
          <Btn className="mt-4" icon={<ClipboardList size={15} />} onClick={() => { location.hash = "#/soc/attacks"; }}>Go to Attack Simulation</Btn></Card>
      ) : (
        <div className="grid gap-4 xl:grid-cols-[320px_1fr]">
          <div className="space-y-2">{list.data.map((i) => (
            <button key={i.id} onClick={() => setSel(i.id)} className={cx("card w-full p-3 text-left transition-all", sel === i.id ? "glow-cy" : "hover:border-cy/30")}>
              <div className="flex items-center gap-2"><span className="mono text-[12px] font-bold text-cy">{i.code}</span><Badge tone={SEV_TONE[i.severity] as Tone}>{i.severity}</Badge><Badge tone={i.status === "resolved" ? "gn" : "am"}>{i.status}</Badge></div>
              <div className="mt-1.5 line-clamp-2 text-[12.5px] font-semibold">{i.title}</div>
              <div className="mt-1 flex justify-between text-[11px] text-mute"><span>{i.status === "resolved" ? "Resolved" : i.phase_name}</span><span>{ago(i.ts)} · {i.progress.done}/{i.progress.total}</span></div>
            </button>))}</div>
          <div className="min-w-0">{sel !== null && <Detail key={sel} id={sel} onChange={list.reload} />}</div>
        </div>
      )}
    </div>
  );
}

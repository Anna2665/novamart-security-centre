import { AnimatePresence, motion } from "framer-motion";
import { ShieldCheck, ShieldOff, X } from "lucide-react";
import { STATUS, ago, cx } from "../lib/util";
import { useStore } from "../store";
import { Badge } from "./ui";

export function NodeDrawer({ nodeId, defences, onClose }: { nodeId: string | null; defences: any[]; onClose: () => void }) {
  const { topology, live, events } = useStore();
  const node = topology?.nodes.find((n) => n.id === nodeId);
  const st = node ? STATUS[live?.nodes?.[node.id]?.status ?? "healthy"] : null;
  const prot = node ? defences.filter((d) => d.nodes?.includes(node.id)) : [];
  const evs = node ? events.filter((e) => e.target_node === node.id && e.details?.kind !== "guard").slice(0, 6) : [];
  return (
    <AnimatePresence>
      {node && st && (
        <motion.aside initial={{ x: 380, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: 380, opacity: 0 }} transition={{ type: "spring", stiffness: 260, damping: 28 }}
          className="card absolute right-3 top-3 z-20 max-h-[calc(100%-24px)] w-[340px] overflow-auto p-4" style={{ borderColor: st.color + "88" }}>
          <div className="flex items-start justify-between gap-2">
            <div>
              <div className="text-base font-bold">{node.label}</div>
              <div className="mono text-[11px] text-mute">{node.zone} zone · {node.ip}</div>
            </div>
            <button onClick={onClose} aria-label="Close details" className="text-mute hover:text-ink"><X size={17} /></button>
          </div>
          <div className="mt-3 flex items-center gap-2">
            <Badge tone={live?.nodes?.[node.id]?.status === "compromised" ? "rd" : live?.nodes?.[node.id]?.status === "protected" ? "gn" : "cy"} dot>{st.label}</Badge>
            <span className="text-[11px] text-mute">Criticality {node.crit}/5</span>
          </div>
          {live?.nodes?.[node.id]?.note && <div className="mt-2 rounded-md border border-line bg-panel2 p-2 text-[12px] text-ink/90">{live.nodes[node.id].note}</div>}
          <p className="mt-3 text-[12.5px] leading-relaxed text-mute">{node.desc}</p>
          {node.data?.length > 0 && (
            <div className="mt-3"><div className="mb-1 text-[10.5px] font-semibold uppercase tracking-wider text-mute">Data held</div>
              <div className="flex flex-wrap gap-1.5">{node.data.map((d: string) => <Badge key={d} tone="vi">{d}</Badge>)}</div></div>
          )}
          <div className="mt-3"><div className="mb-1 text-[10.5px] font-semibold uppercase tracking-wider text-mute">Defences protecting this node</div>
            {prot.length === 0 ? <div className="text-[12px] text-mute">None mapped.</div> : (
              <div className="space-y-1">{prot.map((d) => (
                <div key={d.id} className="flex items-center gap-2 text-[12.5px]">
                  {d.enabled ? <ShieldCheck size={14} className="text-gn" /> : <ShieldOff size={14} className="text-rd" />}
                  <span className={cx(!d.enabled && "text-mute line-through")}>{d.name}</span>
                </div>))}</div>
            )}
          </div>
          {evs.length > 0 && (
            <div className="mt-3"><div className="mb-1 text-[10.5px] font-semibold uppercase tracking-wider text-mute">Recent events here</div>
              <div className="space-y-1">{evs.map((e) => (
                <div key={e.id} className="flex items-center justify-between gap-2 text-[12px]"><span className="truncate">{e.label}</span><span className="shrink-0 text-mute">{ago(e.ts)}</span></div>))}</div>
            </div>
          )}
        </motion.aside>
      )}
    </AnimatePresence>
  );
}

import { Background, BackgroundVariant, BaseEdge, Controls, EdgeProps, Handle, MiniMap, NodeProps, Position, ReactFlow, ReactFlowProvider, getStraightPath, useReactFlow } from "@xyflow/react";
import { Archive, Cloud, CreditCard, Database, Flame, Globe, KeyRound, Lock, Package, Radar, Server, ShieldAlert, ShieldCheck, ShieldHalf, ShoppingCart, Skull, Unplug, UserCog } from "lucide-react";
import { memo, useEffect, useMemo } from "react";
import { STATUS, cx } from "../lib/util";

const ICONS: Record<string, any> = { internet: Globe, firewall: Flame, waf: ShieldHalf, portal: ShoppingCart, auth: KeyRound, admin: UserCog, app: Server, payment: CreditCard, product: Package, db: Database, enc: Lock, cloud: Cloud, backup: Archive, soc: Radar };

const SecNode = memo(({ id, data }: NodeProps) => {
  const d = data as any;
  const st = STATUS[d.status] ?? STATUS.healthy;
  const Icon = ICONS[id] ?? Server;
  const hot = d.status === "compromised";
  const ext = d.kind === "external";
  return (
    <div className="relative" style={{ width: d.compact ? 118 : 150 }}>
      <Handle type="target" position={Position.Left} style={{ left: "50%", top: "50%" }} />
      <Handle type="source" position={Position.Right} style={{ left: "50%", top: "50%" }} />
      {d.active && <span className="absolute -inset-2 rounded-2xl border-2 animate-ping" style={{ borderColor: d.activeColor, opacity: 0.55 }} />}
      <div
        className={cx("relative rounded-xl border px-2.5 py-2 text-center backdrop-blur transition-all duration-500", hot && "pulse-rd", d.status === "protected" && "pulse-gn", d.onClick && "cursor-pointer hover:scale-[1.04]")}
        style={{
          borderColor: st.color, borderStyle: d.status === "isolated" ? "dashed" : "solid",
          background: `linear-gradient(180deg, ${st.color}1f, #ffffffee)`,
          boxShadow: d.status === "healthy" ? "none" : `0 0 20px ${st.ring}`,
        }}
      >
        <div className="mx-auto mb-1 flex h-8 w-8 items-center justify-center rounded-lg" style={{ background: `${st.color}22`, color: st.color }}>
          {hot ? <Skull size={17} className="glitch" /> : <Icon size={17} />}
        </div>
        <div className="text-[11px] font-semibold leading-tight text-ink">{d.label}</div>
        {!d.compact && <div className="mono mt-0.5 text-[9px] text-mute">{d.zone}{d.ip ? ` · ${d.ip}` : ""}</div>}
        {!ext && !d.compact && (
          <div className="mt-1 text-[9px] font-bold uppercase tracking-wider" style={{ color: st.color }}>{st.label}</div>
        )}
        {d.status === "protected" && <ShieldCheck size={15} className="absolute -right-2 -top-2 rounded-full bg-[#ffffff] text-gn" />}
        {hot && <ShieldAlert size={15} className="absolute -right-2 -top-2 rounded-full bg-[#ffffff] text-rd" />}
        {d.status === "isolated" && <Unplug size={15} className="absolute -right-2 -top-2 rounded-full bg-[#ffffff] text-vi" />}
      </div>
    </div>
  );
});

const FlowEdge = memo(({ id, sourceX, sourceY, targetX, targetY, data }: EdgeProps) => {
  const d = (data ?? {}) as any;
  const wrap = id === "e-cloud-internet";
  const [path] = wrap ? [`M ${sourceX} ${sourceY} C ${sourceX} ${sourceY + 330}, ${targetX} ${targetY + 330}, ${targetX} ${targetY}`] : getStraightPath({ sourceX, sourceY, targetX, targetY });
  const col = d.color ?? "#94a3b8";
  const active = !!d.color;
  return (
    <>
      <BaseEdge id={id} path={path} style={{ stroke: active ? col : "#94a3b8", strokeWidth: active ? 3 : 1.5, opacity: active ? 1 : 0.9, filter: active ? `drop-shadow(0 0 5px ${col})` : "none" }} className={active ? "marching" : ""} />
      {active && [0, 0.33, 0.66].map((o) => (
        <circle key={o} r="4.5" fill={col} style={{ filter: `drop-shadow(0 0 6px ${col})` }}>
          <animateMotion dur="1.5s" repeatCount="indefinite" begin={`${o * 1.5}s`} path={path} />
        </circle>
      ))}
    </>
  );
});

const nodeTypes = { sec: SecNode };
const edgeTypes = { flow: FlowEdge };

export interface TopoProps {
  topology: { nodes: any[]; edges: any[] } | null;
  live: any;
  path?: string[];
  tone?: "rd" | "gn" | "am";
  onNodeClick?: (id: string) => void;
  height?: number | string;
  compact?: boolean;
  interactive?: boolean;
  minimap?: boolean;
  selected?: string | null;
}

function Inner({ topology, live, path, tone = "rd", onNodeClick, compact, interactive, minimap }: TopoProps) {
  const rf = useReactFlow();
  const color = tone === "gn" ? "#059669" : tone === "am" ? "#d97706" : "#dc2626";
  const nodes = useMemo(() => (topology?.nodes ?? []).map((n) => ({
    id: n.id, type: "sec", position: { x: n.x, y: n.y }, draggable: !!interactive, selectable: false,
    data: { ...n, compact, status: live?.nodes?.[n.id]?.status ?? "healthy", active: !!path?.includes(n.id), activeColor: color, onClick: !!onNodeClick },
  })), [topology, live, path, compact, interactive, onNodeClick, color]);
  const edges = useMemo(() => (topology?.edges ?? []).map((e) => {
    const on = !!path && path.some((p, i) => i < path.length - 1 && ((p === e.source && path[i + 1] === e.target) || (p === e.target && path[i + 1] === e.source)));
    return { id: `e-${e.source}-${e.target}`, source: e.source, target: e.target, type: "flow", data: { color: on ? color : undefined } };
  }), [topology, path, color]);
  useEffect(() => { const t = setTimeout(() => rf.fitView({ padding: 0.05, duration: 400 }), 60); return () => clearTimeout(t); }, [topology, rf]);
  return (
    <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} edgeTypes={edgeTypes} fitView fitViewOptions={{ padding: 0.05 }} minZoom={0.25} maxZoom={1.8}
      nodesDraggable={!!interactive} nodesConnectable={false} elementsSelectable={false} zoomOnScroll={!!interactive} panOnDrag={!!interactive} zoomOnDoubleClick={false} preventScrolling={!!interactive}
      onNodeClick={(_, n) => onNodeClick?.(n.id)} proOptions={{ hideAttribution: true }}>
      <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#cbd5e1" />
      {interactive && <Controls showInteractive={false} />}
      {minimap && <MiniMap pannable zoomable nodeColor={(n) => STATUS[(n.data as any).status]?.color ?? "#4f46e5"} maskColor="rgba(241,245,249,.7)" />}
    </ReactFlow>
  );
}

export function Topology(props: TopoProps) {
  return (
    <div style={{ height: props.height ?? 420, width: "100%" }} className="relative">
      <ReactFlowProvider><Inner {...props} /></ReactFlowProvider>
    </div>
  );
}

export function StatusLegend() {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-mute">
      {Object.entries(STATUS).map(([k, v]) => (
        <span key={k} className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: v.color, boxShadow: `0 0 8px ${v.color}` }} />{v.label}</span>
      ))}
    </div>
  );
}

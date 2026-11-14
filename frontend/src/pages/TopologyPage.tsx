import { Network } from "lucide-react";
import { useState } from "react";
import { NodeDrawer } from "../components/NodeDrawer";
import { StatusLegend, Topology } from "../components/Topology";
import { Badge, Card, PageHead, useFetch } from "../components/ui";
import { get } from "../lib/api";
import { STATUS } from "../lib/util";
import { useStore } from "../store";

export function TopologyPage() {
  const { topology, live, run } = useStore();
  const defs = useFetch<{ defences: any[] }>(() => get("/sim/defences"), [JSON.stringify(live?.defences)]);
  const [sel, setSel] = useState<string | null>(null);
  const stg = run && !run.ended && run.active >= 0 ? run.run.stages[run.active] : null;
  const counts = live?.node_counts ?? {};
  return (
    <div className="space-y-4">
      <PageHead icon={<Network size={20} />} title="Network Topology" sub="The NovaMart infrastructure as an interactive map. Drag nodes, scroll to zoom, click a node for its data, defences and recent events. During an attack the traffic path animates in red; blocked paths turn green." />
      <div className="flex flex-wrap items-center gap-2">
        {Object.entries(STATUS).map(([k, v]) => <Badge key={k} tone={k === "compromised" ? "rd" : k === "protected" ? "gn" : k === "under_attack" ? "am" : k === "isolated" ? "vi" : "cy"} dot>{v.label}: {counts[k] ?? 0}</Badge>)}
        {stg && <Badge tone="rd" className="flicker">ATTACK ACTIVE — {run!.run.name}: {stg.title}</Badge>}
      </div>
      <Card className="relative overflow-hidden">
        <Topology topology={topology} live={live} path={stg?.path} onNodeClick={setSel} height="calc(100vh - 290px)" interactive />
        <NodeDrawer nodeId={sel} defences={defs.data?.defences ?? []} onClose={() => setSel(null)} />
        <div className="absolute bottom-3 left-3 rounded-lg border border-line bg-[#ffffff]/90 p-2"><StatusLegend /></div>
      </Card>
    </div>
  );
}

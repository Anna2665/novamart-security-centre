import { BadgeCheck, Ban, Package, ShoppingBag, Users, Wallet } from "lucide-react";
import { useState } from "react";
import { Badge, Btn, Card, CardHead, Empty, ErrorBox, PageHead, Spinner, Stat, Tabs, useFetch } from "../components/ui";
import { get, post } from "../lib/api";
import { fmtDateTime, inr } from "../lib/util";
import { useStore } from "../store";
import { STATUS_LABEL } from "../shop/lib";

export function ShopOps() {
  const { can, toast, bump } = useStore();
  const [tab, setTab] = useState<"all" | "review" | "paid" | "cancelled">("all");
  const sum = useFetch<any>(() => get("/shop/admin/summary"), [bump.event]);
  const rows = useFetch<any[]>(() => get("/shop/admin/orders"), [bump.event]);
  const [busy, setBusy] = useState("");
  const canDecide = can("incident:manage");

  async function decide(no: string, decision: "approve" | "reject") {
    setBusy(no + decision);
    try { await post(`/shop/admin/orders/${no}/review`, { decision }); toast(decision === "approve" ? "ok" : "warn", decision === "approve" ? `Order ${no} approved` : `Order ${no} rejected`, decision === "approve" ? "The customer was emailed a receipt." : "Stock was returned and the payment refunded."); rows.reload(); sum.reload(); }
    catch (e: any) { toast("err", "Could not update the order", e.message); } finally { setBusy(""); }
  }

  const list = (rows.data ?? []).filter((o) => tab === "all" || o.status === tab);
  const held = (rows.data ?? []).filter((o) => o.status === "review").length;
  return (
    <div className="space-y-4">
      <PageHead icon={<ShoppingBag size={20} />} title="Store Orders & Fraud Review" sub="Every order placed in the NovaMart shop appears here. The fraud check gives each order a risk score; high-risk orders are held until a team member approves or rejects them." />
      {sum.data && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          <Stat icon={<Package size={14} />} label="Orders" value={sum.data.orders} tone="cy" />
          <Stat icon={<Wallet size={14} />} label="Revenue" value={inr(sum.data.revenue)} tone="gn" sub="Confirmed orders" />
          <Stat icon={<BadgeCheck size={14} />} label="Waiting for review" value={sum.data.held} tone={sum.data.held ? "am" : "gn"} />
          <Stat icon={<Users size={14} />} label="Customers" value={sum.data.customers} tone="bl" />
          <Stat icon={<ShoppingBag size={14} />} label="Products" value={sum.data.products} tone="vi" />
        </div>
      )}
      <Card>
        <CardHead title="Orders" sub="Newest first" right={<Tabs value={tab} onChange={setTab} tabs={[{ id: "all", label: "All" }, { id: "review", label: <>Needs review{held > 0 && <span className="ml-1.5 rounded-full bg-am px-1.5 text-[10.5px] font-bold text-white">{held}</span>}</> }, { id: "paid", label: "Confirmed" }, { id: "cancelled", label: "Cancelled" }]} />} />
        {rows.loading && !rows.data ? <Spinner /> : rows.error ? <div className="p-4"><ErrorBox error={rows.error} retry={rows.reload} /></div> : list.length === 0 ? <Empty>No orders here yet.</Empty> : (
          <div className="overflow-auto"><table data-testid="orders-table"><thead><tr><th>Order</th><th>Customer</th><th>Items</th><th>Total</th><th>Fraud risk</th><th>Status</th><th>When</th><th /></tr></thead>
            <tbody>{list.map((o) => { const st = STATUS_LABEL[o.status] ?? { label: o.status, tone: "mute" as const }; return (
              <tr key={o.order_no}>
                <td className="mono font-semibold">{o.order_no}</td><td>{o.customer}</td>
                <td className="max-w-[260px] truncate text-mute">{o.items.map((i: any) => `${i.name} × ${i.qty}`).join(", ")}</td>
                <td className="font-semibold">{inr(o.total)}</td>
                <td><Badge tone={o.risk_score >= 60 ? "rd" : o.risk_score >= 30 ? "am" : "gn"}>{o.risk_score}/100</Badge></td>
                <td><Badge tone={st.tone} dot>{st.label}</Badge></td><td className="whitespace-nowrap text-mute">{fmtDateTime(o.date)}</td>
                <td className="whitespace-nowrap text-right">{o.status === "review" && (canDecide ? <span className="inline-flex gap-1.5"><Btn size="sm" variant="ok" icon={<BadgeCheck size={13} />} loading={busy === o.order_no + "approve"} onClick={() => decide(o.order_no, "approve")}>Approve</Btn><Btn size="sm" variant="ghost" icon={<Ban size={13} />} loading={busy === o.order_no + "reject"} onClick={() => decide(o.order_no, "reject")}>Reject</Btn></span> : <span className="text-[12px] text-mute">Needs analyst or admin</span>)}</td>
              </tr>); })}</tbody></table></div>
        )}
      </Card>
      <p className="text-[12.5px] text-mute">How the risk score works: very large order value, an unusual quantity of one item, several orders within 10 minutes, or a brand-new account placing a large order each add points. At 60 or more the order is held for review.</p>
    </div>
  );
}

import { AnimatePresence, motion } from "framer-motion";
import { AlertTriangle, Database as DbIcon, Eye, EyeOff, FileCheck2, History, Lock, Pencil, RotateCcw, ScanSearch, ShieldCheck, ShieldX, Syringe, Table2 } from "lucide-react";
import { useState } from "react";
import { Badge, Btn, Card, CardHead, Code, Empty, ErrorBox, PageHead, Spinner, Switch, Tabs, Tip, useFetch } from "../components/ui";
import { get, post } from "../lib/api";
import { cx, fmtTime, inr } from "../lib/util";
import { useStore } from "../store";

const StatusBadge = ({ ok, label }: { ok: boolean; label: string }) => <Badge tone={ok ? "gn" : "rd"} dot>{label}</Badge>;

function Records() {
  const { toast, can, bump } = useStore();
  const [ent, setEnt] = useState<"products" | "orders" | "payments">("products");
  const rows = useFetch<any[]>(() => get(`/db/${ent}`), [ent, bump.db, bump.event]);
  const prods = useFetch<any[]>(() => get("/db/products"), [bump.db]);
  const scan = useFetch<any>(() => get("/db/integrity"), [bump.db, bump.event]);
  const [pid, setPid] = useState(1);
  const [price, setPrice] = useState(1);
  const [smart, setSmart] = useState(false);
  const [busy, setBusy] = useState("");
  const [last, setLast] = useState<any>(null);
  const [newPrice, setNewPrice] = useState(1399);
  const [confirm, setConfirm] = useState(false);

  const refresh = () => { rows.reload(); prods.reload(); scan.reload(); };
  async function tamper() {
    setBusy("tamper"); setConfirm(false);
    try { const r = await post("/db/tamper", { product_id: pid, new_price: price, recompute_hash: smart }); setLast(r); toast("warn", "Record modified directly in the database", `Price changed ${inr(r.before.price)} → ${inr(r.after.current.price)}. Now run the integrity scan.`); refresh(); }
    catch (e: any) { toast("err", "Tamper simulation refused", e.message); } finally { setBusy(""); }
  }
  async function restore(e: string, id: number) {
    setBusy(`r${e}${id}`);
    try { const r = await post("/db/restore", { entity: e, id }); toast("ok", "Restored from the signed ledger", r.verified ? "Hash and signature verified after restore." : "Restored."); setLast(null); refresh(); }
    catch (er: any) { toast("err", "Restore failed", er.message); } finally { setBusy(""); }
  }
  async function authorised() {
    setBusy("auth");
    try { await post(`/db/products/${pid}/price`, { price: newPrice }); toast("ok", "Price updated through the application", "Record re-signed — integrity stays green."); refresh(); }
    catch (e: any) { toast("err", "Update refused", e.message); } finally { setBusy(""); }
  }

  const tampered: any[] = scan.data?.tampered ?? [];
  const selected = prods.data?.find((p) => p.id === pid);
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_400px]">
      <div className="min-w-0 space-y-4">
        <Card className={cx("p-4", tampered.length > 0 && "glow-rd")}>
          <div className="flex flex-wrap items-center gap-4">
            <div className={cx("flex h-14 w-14 items-center justify-center rounded-2xl border-2", tampered.length ? "border-rd bg-rd/10 pulse-rd" : "border-gn bg-gn/10")}>{tampered.length ? <ShieldX size={30} className="glitch text-rd" /> : <ShieldCheck size={30} className="text-gn" />}</div>
            <div className="flex-1"><div className={cx("text-lg font-bold", tampered.length ? "text-rd" : "text-gn")}>{tampered.length ? `${tampered.length} record${tampered.length > 1 ? "s" : ""} TAMPERED` : "All records verified"}</div>
              <div className="text-[12.5px] text-mute">{scan.data ? `${scan.data.intact}/${scan.data.total} records pass hash + RSA-PSS signature checks` : "Scanning…"}</div></div>
            <Btn icon={<ScanSearch size={15} />} loading={scan.loading} onClick={() => { scan.reload(); toast("info", "Integrity scan complete"); }}>Run integrity scan</Btn>
          </div>
          <AnimatePresence>{tampered.map((t) => (
            <motion.div key={t.entity + t.id} initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }} className="mt-3 overflow-hidden">
              <div className="rounded-xl border border-rd/50 bg-rd/10 p-3">
                <div className="flex flex-wrap items-center gap-3"><AlertTriangle className="text-rd" size={18} /><div className="flex-1 text-[13px]"><b>{t.label}</b> — stored value differs from the last signed version.</div>
                  {can("backup:restore") && <Btn variant="ok" size="sm" icon={<RotateCcw size={14} />} loading={busy === `r${t.entity}${t.id}`} onClick={() => restore(t.entity, t.id)}>Restore trusted version</Btn>}</div>
                <div className="mt-2 grid gap-2 md:grid-cols-2"><div><div className="text-[10.5px] font-semibold uppercase text-rd">Found in database</div><Code tone="danger">{JSON.stringify(t.current)}</Code></div>
                  <div><div className="text-[10.5px] font-semibold uppercase text-gn">Trusted (signed ledger)</div><Code tone="ok">{JSON.stringify(t.trusted)}</Code></div></div>
                <div className="mt-2 flex gap-2"><StatusBadge ok={t.hash_ok} label={t.hash_ok ? "hash matches" : "hash mismatch"} /><StatusBadge ok={t.sig_ok} label={t.sig_ok ? "signature valid" : "signature invalid"} /></div>
              </div>
            </motion.div>))}</AnimatePresence>
        </Card>

        <Card>
          <CardHead icon={<Table2 size={16} />} title="Live database records" sub="Every row carries a hash and a digital signature" right={<Tabs tabs={[{ id: "products", label: "Products" }, { id: "orders", label: "Orders" }, { id: "payments", label: "Payments" }]} value={ent} onChange={setEnt} />} />
          {rows.loading && !rows.data ? <Spinner /> : rows.error ? <div className="p-4"><ErrorBox error={rows.error} retry={rows.reload} /></div> : (
            <div className="max-h-[420px] overflow-auto"><table>
              <thead><tr>{Object.keys(rows.data?.[0]?.current ?? {}).filter((k) => k !== "id").map((k) => <th key={k}>{k.replace("_", " ")}</th>)}<th>Hash</th><th>Signature</th><th>Status</th></tr></thead>
              <tbody>{rows.data?.map((r) => {
                const bad = !r.intact;
                return (
                  <motion.tr key={r.id} animate={{ backgroundColor: bad ? "rgba(220,38,38,.08)" : "rgba(0,0,0,0)" }}>
                    {Object.entries(r.current).filter(([k]) => k !== "id").map(([k, v]) => <td key={k} className={cx("mono text-[12px]", k === "sku" && "whitespace-nowrap", bad && (k === "price" || k === "amount") && "font-bold text-rd")}>{k === "price" || k === "amount" ? inr(v as number) : String(v)}</td>)}
                    <td><StatusBadge ok={r.hash_ok} label={r.hash_ok ? "ok" : "bad"} /></td><td><StatusBadge ok={r.sig_ok} label={r.sig_ok ? "valid" : "invalid"} /></td>
                    <td>{bad ? <Badge tone="rd" className="flicker">TAMPERED</Badge> : <Badge tone="gn">intact</Badge>}</td>
                  </motion.tr>);
              })}</tbody>
            </table></div>
          )}
        </Card>
      </div>

      <div className="space-y-4">
        <Card className="p-4">
          <div className="flex items-center gap-2 text-[13px] font-semibold"><Pencil size={15} className="text-rd" />Tamper simulation <Tip text="Simulates an attacker (or rogue insider) who bypasses the application and edits the database file directly. The change is made to the real demo database so you can watch detection and recovery work." /></div>
          <div className="mt-3 space-y-3">
            <label className="block text-[11px] font-semibold uppercase tracking-wider text-mute">Product<select className="mt-1" value={pid} onChange={(e) => setPid(Number(e.target.value))}>{prods.data?.map((p) => <option key={p.id} value={p.id}>{p.current.name} — {inr(p.current.price)}</option>)}</select></label>
            {selected && <div className="flex items-center justify-center gap-4 rounded-xl border border-line bg-panel2 py-3">
              <div className="text-center"><div className="text-[10px] uppercase text-mute">Before</div><div className="mono text-2xl font-bold text-gn">{inr(selected.current.price)}</div></div>
              <span className="text-xl text-mute">→</span>
              <div className="text-center"><div className="text-[10px] uppercase text-mute">Attacker sets</div><div className="mono text-2xl font-bold text-rd">{inr(price)}</div></div></div>}
            <label className="block text-[11px] font-semibold uppercase tracking-wider text-mute">New price (₹)<input type="number" min={0} max={1000000} className="mono mt-1" value={price} onChange={(e) => setPrice(Math.max(0, Number(e.target.value) || 0))} /></label>
            <label className="flex items-center justify-between gap-3 rounded-lg border border-line bg-panel2 p-2.5 text-[12.5px]"><span><b>Smart attacker</b><br /><span className="text-mute">also rewrites the stored hash to match</span></span><Switch on={smart} onChange={setSmart} label="Smart attacker" /></label>
            <Btn variant="danger" className="w-full" icon={<DbIcon size={15} />} disabled={!can("db:tamper")} loading={busy === "tamper"} onClick={() => setConfirm(true)}>Modify the record directly</Btn>
            {!can("db:tamper") && <div className="text-[12px] text-am">Only the admin role may run the tamper simulation.</div>}
            {confirm && <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-[12.5px]"><div className="mb-2 text-am">This changes the demo database. You can restore it afterwards from the signed ledger.</div><div className="flex gap-2"><Btn size="sm" variant="danger" onClick={tamper}>Yes, tamper</Btn><Btn size="sm" variant="ghost" onClick={() => setConfirm(false)}>Cancel</Btn></div></div>}
            {last && <div className="rounded-lg border border-line bg-panel2 p-3 text-[12px]"><div className="mb-1 font-semibold">Result of the write</div><div className="flex flex-wrap gap-2"><StatusBadge ok={last.after.hash_ok} label={last.after.hash_ok ? "hash still matches (rewritten)" : "hash mismatch"} /><StatusBadge ok={last.after.sig_ok} label={last.after.sig_ok ? "signature valid" : "signature INVALID"} /></div>
              {last.after.hash_ok && !last.after.sig_ok && <div className="mt-2 text-am">The smart attacker fixed the hash, but cannot forge the RSA signature — detection still works.</div>}</div>}
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2 text-[13px] font-semibold"><FileCheck2 size={15} className="text-gn" />Authorised price change</div>
          <p className="mt-1 text-[12px] text-mute">Going through the application re-signs the record, so integrity stays green. Compare with a direct edit.</p>
          <div className="mt-3 flex gap-2"><input type="number" className="mono" min={1} value={newPrice} onChange={(e) => setNewPrice(Number(e.target.value) || 0)} /><Btn variant="ok" disabled={!can("db:write")} loading={busy === "auth"} onClick={authorised}>Update</Btn></div>
        </Card>
      </div>
    </div>
  );
}

function Customers() {
  const { user } = useStore();
  const c = useFetch<any>(() => get("/db/customers"), []);
  const [raw, setRaw] = useState(false);
  return (
    <Card>
      <CardHead icon={<Lock size={16} />} title="Customer records — PII encrypted at rest" sub={c.data?.pii_revealed ? "Your role may decrypt PII (shown in the clear)." : "Your role cannot decrypt PII — values are masked."}
        right={<label className="flex items-center gap-2 text-[12px] text-mute">{raw ? <EyeOff size={14} /> : <Eye size={14} />}Show stored ciphertext<Switch on={raw} onChange={setRaw} label="Show ciphertext" /></label>} />
      {c.loading ? <Spinner /> : c.error ? <div className="p-4"><ErrorBox error={c.error} retry={c.reload} /></div> : (
        <>
          <div className={cx("mx-4 mb-3 rounded-lg border p-2.5 text-[12.5px]", raw ? "border-rd/40 bg-rd/10 text-rd" : "border-gn/40 bg-gn/10 text-gn")}>
            {raw ? "This is exactly what an attacker holding a stolen copy of the database would see: AES-256-GCM ciphertext — no names-to-email mapping, no readable phone numbers." : `Signed in as ${user.role}. The database stores ciphertext; the application decrypts only for roles with the pii:read permission.`}
          </div>
          <div className="overflow-auto"><table>
            <thead><tr><th>#</th><th>Name</th><th>Tier</th><th>Email</th><th>Phone</th><th>Address</th></tr></thead>
            <tbody>{c.data.rows.map((r: any) => (
              <tr key={r.id}><td className="mono text-mute">{r.id}</td><td className="font-semibold">{r.name}</td><td><Badge tone={r.tier === "platinum" ? "vi" : r.tier === "gold" ? "am" : "mute"}>{r.tier}</Badge></td>
                {(["email", "phone", "address"] as const).map((k) => <td key={k} className={cx("mono max-w-[260px] break-all text-[11.5px]", raw ? "text-rd/80" : r[k]?.includes("•") ? "text-mute" : "text-ink")}>{raw ? r[`${k}_cipher`] : r[k]}</td>)}</tr>))}</tbody>
          </table></div>
        </>
      )}
    </Card>
  );
}

const PRESETS = [["Normal login", "arjun.m"], ["Tautology", "' OR '1'='1' --"], ["Comment bypass", "admin'--"], ["UNION extract", "x' UNION SELECT id, username, role, email FROM users --"], ["Stacked DROP", "admin'; DROP TABLE users; --"]];

function Sqli() {
  const { toast } = useStore();
  const [u, setU] = useState("' OR '1'='1' --");
  const [pw, setPw] = useState("anything");
  const [res, setRes] = useState<Record<string, any>>({});
  const [busy, setBusy] = useState(false);
  async function run() {
    setBusy(true);
    try {
      const modes = ["unsafe", "waf", "parameterised"];
      const out = await Promise.all(modes.map((m) => post("/db/sqli", { username: u, password: pw, mode: m })));
      setRes(Object.fromEntries(modes.map((m, i) => [m, out[i]])));
    } catch (e: any) { toast("err", "Lab request failed", e.message); } finally { setBusy(false); }
  }
  const cols = [["unsafe", "Vulnerable code", "String concatenation — the input becomes part of the SQL", "rd"], ["waf", "Behind the WAF", "Signature filter in front of the same vulnerable code", "am"], ["parameterised", "Parameterised query", "Input is bound as data, never parsed as SQL", "gn"]] as const;
  return (
    <div className="space-y-4">
      <Card className="p-4">
        <div className="flex items-center gap-2 text-[13px] font-semibold"><Syringe size={15} className="text-rd" />SQL injection lab <Badge tone="vi">isolated sandbox</Badge></div>
        <p className="mt-1 text-[12.5px] text-mute">Runs against a throw-away in-memory database with fictional users and a read-only connection — it can never touch the real store data. The same input is sent through three implementations.</p>
        <div className="mt-3 flex flex-wrap gap-1.5">{PRESETS.map(([l, v]) => <button key={l} onClick={() => setU(v)} className="rounded-md border border-line bg-panel2 px-2.5 py-1 text-[11.5px] text-mute hover:border-cy/40 hover:text-cy">{l}</button>)}</div>
        <div className="mt-3 grid gap-3 md:grid-cols-[2fr_1fr_auto]">
          <input className="mono" value={u} onChange={(e) => setU(e.target.value)} placeholder="Username field" maxLength={300} aria-label="Username" /><input className="mono" value={pw} onChange={(e) => setPw(e.target.value)} placeholder="Password" maxLength={100} aria-label="Password" />
          <Btn variant="danger" loading={busy} onClick={run} icon={<Syringe size={15} />}>Run on all three</Btn></div>
      </Card>
      {Object.keys(res).length > 0 && (
        <div className="grid gap-4 xl:grid-cols-3">
          {cols.map(([m, t, d, tone]) => {
            const r = res[m]; const hacked = r.authenticated || r.row_count > 0;
            return (
              <motion.div key={m} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
                <Card className={cx("h-full p-4", hacked ? "glow-rd" : "glow-gn")}>
                  <div className="flex items-center justify-between"><div className={cx("font-bold", tone === "rd" ? "text-rd" : tone === "am" ? "text-am" : "text-gn")}>{t}</div><Badge tone={hacked ? "rd" : "gn"}>{hacked ? "EXPLOITED" : "SAFE"}</Badge></div>
                  <div className="mb-3 text-[11.5px] text-mute">{d}</div>
                  {r.waf?.blocked ? <div className="rounded-lg border border-gn/40 bg-gn/10 p-3 text-[12.5px] text-gn"><b>WAF blocked the request</b><div className="mono mt-1 text-[11px]">rule {r.waf.rule} — {r.waf.name}</div><div className="mt-1 text-gn/80">The query was never executed.</div></div> : (
                    <>
                      <div className="text-[10.5px] font-semibold uppercase tracking-wider text-mute">SQL sent to the database</div><Code>{r.query}</Code>
                      {r.params && <div className="mono mt-1 text-[11px] text-gn">bound params: {JSON.stringify(r.params)}</div>}
                      {r.error ? <div className="mt-2 rounded-lg border border-amber-200 bg-amber-50 p-2 text-[12px] text-am">DB error: {r.error}</div> : (
                        <div className="mt-2"><div className="text-[10.5px] font-semibold uppercase tracking-wider text-mute">{r.row_count} row(s) returned · {r.authenticated ? "login SUCCEEDED" : "login failed"}</div>
                          {r.rows.length > 0 && <div className="mt-1 overflow-auto rounded-lg border border-rd/30 bg-rd/5"><table><tbody>{r.rows.map((row: any[], i: number) => <tr key={i}>{row.map((c, j) => <td key={j} className="mono text-[11px] text-rd">{String(c)}</td>)}</tr>)}</tbody></table></div>}</div>
                      )}
                    </>
                  )}
                </Card>
              </motion.div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function Access() {
  const log = useFetch<any[]>(() => get("/db/access-log?limit=40"), []);
  const schema = useFetch<any>(() => get("/db/schema"), []);
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card><CardHead icon={<History size={16} />} title="Database access log" sub="Every query path records who touched which table" right={<Btn variant="ghost" size="sm" onClick={log.reload}>Refresh</Btn>} />
        {log.loading ? <Spinner /> : !log.data?.length ? <Empty>No access recorded.</Empty> : <div className="max-h-[420px] overflow-auto"><table><thead><tr><th>Time</th><th>Actor</th><th>Table</th><th>Op</th><th>Rows</th><th>Result</th></tr></thead><tbody>{log.data.map((l) => <tr key={l.id}><td className="mono text-mute">{fmtTime(l.ts)}</td><td>{l.actor} <span className="text-mute">({l.role})</span></td><td className="mono">{l.table}</td><td className="mono">{l.operation}</td><td className="mono">{l.rows}</td><td><Badge tone={l.allowed ? "gn" : "rd"}>{l.allowed ? "allowed" : "denied"}</Badge></td></tr>)}</tbody></table></div>}
      </Card>
      <Card><CardHead icon={<DbIcon size={16} />} title="Schema" sub={schema.data ? `${schema.data.dialect} · ${schema.data.tables.length} tables` : ""} />
        {schema.loading ? <Spinner /> : <div className="max-h-[420px] space-y-2 overflow-auto px-4 pb-4">{schema.data?.tables.map((t: any) => <div key={t.name} className="rounded-lg border border-line bg-panel2 p-2.5"><div className="mono text-[12.5px] font-semibold text-cy">{t.name}</div><div className="mt-1 flex flex-wrap gap-1">{t.columns.map((c: any) => <span key={c.name} className="mono rounded bg-slate-100 px-1.5 py-0.5 text-[10.5px] text-mute">{c.name}<span className="text-mute/50"> {c.type.toLowerCase()}</span></span>)}</div></div>)}</div>}
      </Card>
    </div>
  );
}

export function Database() {
  const [tab, setTab] = useState<"rec" | "cust" | "sqli" | "acc">("rec");
  return (
    <div className="space-y-4">
      <PageHead icon={<DbIcon size={20} />} title="Database Security" sub="Integrity protection (hash + digital signature), encryption of customer PII, a live SQL-injection lab and access logging for the NovaMart database."
        right={<Tabs tabs={[{ id: "rec", label: "Integrity & tampering" }, { id: "cust", label: "Encrypted PII" }, { id: "sqli", label: "SQL injection lab" }, { id: "acc", label: "Access & schema" }]} value={tab} onChange={setTab} />} />
      {tab === "rec" && <Records />}{tab === "cust" && <Customers />}{tab === "sqli" && <Sqli />}{tab === "acc" && <Access />}
    </div>
  );
}

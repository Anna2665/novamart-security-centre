import { AnimatePresence, motion } from "framer-motion";
import { Archive, BadgeCheck, Bug, DatabaseBackup, FileLock2, FileText, HardDriveDownload, Lock, RotateCcw, ShieldCheck, Skull, Trash2 } from "lucide-react";
import { useState } from "react";
import { Badge, Bar, Btn, Card, CardHead, Confirm, Empty, ErrorBox, PageHead, Spinner, Stat, useFetch } from "../components/ui";
import { get, post } from "../lib/api";
import { cx, fmtDateTime } from "../lib/util";
import { useStore } from "../store";

const STEP_LABEL: Record<string, string> = { decrypt: "AES-256-GCM decrypts", hash: "SHA-256 matches", signature: "RSA-PSS signature valid" };

export function Backup() {
  const { toast, can, bump } = useStore();
  const d = useFetch<any>(() => get("/backup"), [bump.backup, bump.incident, bump.event]);
  const [busy, setBusy] = useState("");
  const [last, setLast] = useState<any>(null);
  const [confirm, setConfirm] = useState<null | "ransom" | { restore: string | null }>(null);
  if (d.loading && !d.data) return <Spinner />;
  if (!d.data) return <ErrorBox error={d.error ?? "No data"} retry={d.reload} />;
  const b = d.data, vol = b.volume;
  const run = async (key: string, fn: () => Promise<any>, ok: (r: any) => [string, string, string?]) => {
    setBusy(key);
    try { const r = await fn(); const [t, m, kind] = ok(r); toast((kind as any) ?? "ok", t, m); d.reload(); return r; }
    catch (e: any) { toast("err", "Action refused", e.message); } finally { setBusy(""); }
  };
  const create = () => run("create", () => post("/backup/create", { label: "Manual snapshot" }), (r) => ["Backup created and verified", `${r.id} · ${r.file_count} files · encrypted and signed`]);
  const verify = (id: string) => run(`v${id}`, () => post(`/backup/${id}/verify`), (r) => r.status === "verified" ? ["Backup verified", "Decrypts, hash and signature all check out."] : ["Backup FAILED verification", "Do not restore from this snapshot.", "err"]);
  const corrupt = (id: string) => run(`c${id}`, () => post(`/backup/${id}/corrupt`), () => ["Backup poisoned (simulation)", "One byte of the encrypted blob was flipped. Re-verify it to see detection.", "warn"]);
  const ransom = () => { setConfirm(null); void run("ransom", () => post("/backup/ransomware"), (r) => ["Sandbox volume encrypted", `${r.files_encrypted} fictional files locked by simulated ransomware.`, "warn"]); };
  const restore = (id: string | null) => { setConfirm(null); void run("restore", async () => { const r = await post("/backup/restore", { backup_id: id }); setLast(r); await useStore.getState().refreshLive(); return r; }, (r) => ["Recovery complete", `${r.files_restored} files restored from ${r.backup} after verification.`]); };

  return (
    <div className="space-y-4">
      <PageHead icon={<Archive size={20} />} title="Backup & Recovery" sub="Encrypted, signed snapshots. A restore only happens after the backup passes three checks — a poisoned or tampered backup is refused. The ransomware demo encrypts only an in-memory sandbox of fictional files."
        right={<div className="flex gap-2"><Btn icon={<DatabaseBackup size={15} />} loading={busy === "create"} disabled={!can("backup:manage") || vol.state !== "healthy"} onClick={create}>Create backup</Btn></div>} />

      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        <Stat icon={<ShieldCheck size={14} />} label="Backup health" value={b.health.replace("_", " ").toUpperCase()} tone={b.health === "healthy" ? "gn" : "am"} sub={b.age_hours != null ? `Newest verified: ${b.age_hours} h ago` : "No verified snapshot"} />
        <Stat icon={<Archive size={14} />} label="Snapshots" value={b.backups.length} tone="cy" sub={`${b.verified_count} verified`} />
        <Stat icon={<FileText size={14} />} label="Production volume" value={vol.state.replace("_", " ").toUpperCase()} tone={vol.state === "healthy" ? "gn" : "rd"} pulse={vol.state !== "healthy"} sub={`${vol.encrypted}/${vol.total} files encrypted`} />
        <Stat icon={<Lock size={14} />} label="Backup protection" value="AES-GCM" tone="vi" sub="Encrypted + hash + RSA signature" />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1fr_1.1fr]">
        <Card className={cx(vol.state !== "healthy" && "glow-rd")}>
          <CardHead icon={<HardDriveDownload size={16} />} title="Production volume (sandbox)" sub="Fictional NovaMart business files, held in memory"
            right={<div className="flex gap-2"><Btn variant="danger" size="sm" icon={<Bug size={14} />} disabled={!can("backup:manage") || vol.state === "encrypted"} loading={busy === "ransom"} onClick={() => setConfirm("ransom")}>Simulate ransomware</Btn>
              {vol.state !== "healthy" && <Btn variant="ok" size="sm" icon={<RotateCcw size={14} />} disabled={!can("backup:restore")} loading={busy === "restore"} onClick={() => restore(null)}>Recover now</Btn>}</div>} />
          {vol.state !== "healthy" && <div className="mx-4 mb-3 flex items-center gap-2 rounded-lg border border-rd/50 bg-rd/10 p-3 text-[13px] text-rd"><Skull size={18} className="glitch shrink-0" /><div><b>Files are encrypted by the attacker.</b> Entropy jumped to ~8 bits/byte (random-looking). Recover from the newest verified backup — no ransom needed.</div></div>}
          <div className="max-h-[420px] overflow-auto"><table><thead><tr><th>File</th><th>Size</th><th>Entropy (bits/byte)</th><th>State</th></tr></thead>
            <tbody>{vol.files.map((f: any) => (
              <motion.tr key={f.path} animate={{ backgroundColor: f.status === "encrypted" ? "rgba(220,38,38,.07)" : "rgba(0,0,0,0)" }}>
                <td className="mono text-[12px]">{f.status === "encrypted" ? <FileLock2 size={13} className="mr-1.5 inline text-rd" /> : <FileText size={13} className="mr-1.5 inline text-mute" />}{f.path}</td><td className="mono text-mute">{(f.size / 1024).toFixed(1)} KB</td>
                <td className="min-w-[130px]"><div className="mono mb-0.5 text-[11px]">{f.entropy.toFixed(2)}</div><Bar value={f.entropy / 8 * 100} tone={f.entropy > 7 ? "rd" : "cy"} height={4} /></td>
                <td><Badge tone={f.status === "encrypted" ? "rd" : "gn"}>{f.status}</Badge></td></motion.tr>))}</tbody></table></div>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHead icon={<Archive size={16} />} title="Snapshots" sub="Newest first" />
            {b.backups.length === 0 ? <Empty>No snapshots.</Empty> : (
              <div className="max-h-[340px] space-y-2 overflow-auto px-4 pb-4">{b.backups.map((k: any) => (
                <div key={k.id} className={cx("rounded-xl border p-3", k.status === "verified" ? "border-gn/25 bg-gn/5" : "border-rd/40 bg-rd/10")}>
                  <div className="flex flex-wrap items-center gap-2"><span className="mono text-[12px] font-bold text-cy">{k.id}</span><Badge tone={k.status === "verified" ? "gn" : "rd"} dot>{k.status}</Badge><Badge tone="mute">{k.kind}</Badge><span className="ml-auto text-[11px] text-mute">{fmtDateTime(k.ts)}</span></div>
                  <div className="mt-1 text-[12px] text-mute">{k.label} · {k.file_count} files · {(k.size_bytes / 1024).toFixed(0)} KB · sha256 <span className="mono">{k.sha256.slice(0, 14)}…</span></div>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    <Btn size="sm" variant="ghost" icon={<BadgeCheck size={13} />} disabled={!can("backup:manage")} loading={busy === `v${k.id}`} onClick={() => verify(k.id)}>Verify</Btn>
                    <Btn size="sm" variant="warn" icon={<Trash2 size={13} />} disabled={!can("backup:manage")} loading={busy === `c${k.id}`} onClick={() => corrupt(k.id)}>Poison (sim)</Btn>
                    <Btn size="sm" variant="ok" icon={<RotateCcw size={13} />} disabled={!can("backup:restore")} onClick={() => setConfirm({ restore: k.id })}>Restore this</Btn>
                  </div></div>))}</div>)}
          </Card>
          <AnimatePresence>{last && (
            <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
              <Card className="p-4" glow="gn"><div className="flex items-center gap-2 text-[13px] font-bold text-gn"><ShieldCheck size={17} />Last recovery — {last.backup}</div>
                <div className="mt-2 text-[12.5px] text-mute">Volume: <b className="text-rd">{last.before}</b> → <b className="text-gn">{last.after}</b> · {last.files_restored} files</div>
                <div className="mt-2 space-y-1">{Object.entries(last.checks).map(([k, v]) => <div key={k} className="flex items-center gap-2 text-[12.5px]"><span className={v ? "text-gn" : "text-rd"}>{v ? "✓" : "✗"}</span>{STEP_LABEL[k] ?? k}</div>)}</div></Card>
            </motion.div>)}</AnimatePresence>
        </div>
      </div>

      <Confirm open={confirm === "ransom"} title="Run the ransomware simulation?" body={<>This encrypts only the in-memory sandbox files shown here (all fictional), using a throw-away key. Nothing on disk or in the database is touched. You can recover afterwards.</>} confirmLabel="Encrypt sandbox" danger onConfirm={ransom} onCancel={() => setConfirm(null)} />
      <Confirm open={!!confirm && typeof confirm === "object"} title="Restore from this snapshot?" body={<>The snapshot is decrypted and its hash and digital signature are checked first. If any check fails, the restore is refused.</>} confirmLabel="Verify & restore" onConfirm={() => restore((confirm as any).restore)} onCancel={() => setConfirm(null)} />
    </div>
  );
}

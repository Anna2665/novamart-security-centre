import { motion } from "framer-motion";
import { ArrowRight, Binary, CheckCircle2, FlaskConical, KeyRound, Lock, LockOpen, RefreshCw, ShieldAlert, Wand2, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Badge, Bar, Btn, Card, CardHead, Code, Hex, PageHead, Spinner, Tabs, Tip, useFetch } from "../components/ui";
import { get, post } from "../lib/api";
import { cx } from "../lib/util";
import { useStore } from "../store";

function Scramble({ text, run }: { text: string; run: number }) {
  const [out, setOut] = useState(text);
  useEffect(() => {
    let n = 0;
    const id = setInterval(() => {
      n++;
      const settled = Math.floor((n / 14) * text.length);
      setOut(text.split("").map((ch, i) => (i < settled ? ch : "0123456789abcdef"[Math.floor(Math.random() * 16)])).join(""));
      if (n >= 14) { clearInterval(id); setOut(text); }
    }, 45);
    return () => clearInterval(id);
  }, [text, run]);
  return <>{out}</>;
}

const bitsOf = (hex: string) => hex.split("").flatMap((c) => parseInt(c, 16).toString(2).padStart(4, "0").split(""));

function Avalanche() {
  const [a, setA] = useState("Order #1 | INR 1,499 | NovaBeat Pro");
  const [b, setB] = useState("Order #1 | INR 1,498 | NovaBeat Pro");
  const [r, setR] = useState<any>(null);
  useEffect(() => { const t = setTimeout(() => post("/crypto/hash", { a, b }).then(setR).catch(() => {}), 250); return () => clearTimeout(t); }, [a, b]);
  const ba = r ? bitsOf(r.a) : [], bb = r ? bitsOf(r.b) : [];
  return (
    <Card>
      <CardHead icon={<Binary size={16} />} title="Hash avalanche — why a one-character change is always detected" sub="SHA-256 turns any record into a 256-bit fingerprint. Change one character and about half of the bits flip." />
      <div className="grid gap-3 px-4 pb-4 md:grid-cols-2">
        <div><label className="text-[11px] font-semibold uppercase tracking-wider text-mute">Record A</label><input className="mono mt-1" value={a} onChange={(e) => setA(e.target.value)} maxLength={200} /></div>
        <div><label className="text-[11px] font-semibold uppercase tracking-wider text-mute">Record B (edit me)</label><input className="mono mt-1" value={b} onChange={(e) => setB(e.target.value)} maxLength={200} /></div>
        {r && (
          <>
            <Hex label="SHA-256(A)" value={r.a} /><Hex label="SHA-256(B)" value={r.b} tone={r.a === r.b ? "gn" : "rd"} />
            <div className="md:col-span-2">
              <div className="mb-2 flex items-center justify-between text-[12.5px]"><span className="text-mute">Bits that differ</span><span className="mono text-lg font-bold text-am">{r.bits_changed} / 256 <span className="text-sm text-mute">({Math.round(r.bits_changed / 2.56)}%)</span></span></div>
              <div className="grid gap-[3px]" style={{ gridTemplateColumns: "repeat(32, minmax(0, 1fr))" }}>
                {ba.map((x, i) => <motion.div key={i} initial={false} animate={{ backgroundColor: x !== bb[i] ? "#dc2626" : "#cbd5e1", scale: x !== bb[i] ? 1 : 0.85 }} className="aspect-square rounded-[3px]" />)}
              </div>
              <div className="mt-1.5 text-[11px] text-mute">Red cell = that bit of the fingerprint changed. This is why a tampered price (₹1,499 → ₹1) cannot hide from integrity checks.</div>
            </div>
          </>
        )}
      </div>
    </Card>
  );
}

export function Crypto() {
  const { toast } = useStore();
  const samples = useFetch<any>(() => get("/crypto/samples"), []);
  const algs = useFetch<{ algorithms: any[] }>(() => get("/crypto/algorithms"), []);
  const [ds, setDs] = useState<"customer" | "order" | "transaction">("customer");
  const [plain, setPlain] = useState("");
  const [enc, setEnc] = useState<any>(null);
  const [dec, setDec] = useState<any>(null);
  const [busy, setBusy] = useState("");
  const [runN, setRunN] = useState(0);
  const [history, setHistory] = useState<string[]>([]);
  const [tab, setTab] = useState<"lab" | "hash" | "algs">("lab");

  useEffect(() => { if (samples.data) { setPlain(samples.data[ds]); setEnc(null); setDec(null); setHistory([]); } }, [samples.data, ds]);

  async function encrypt() {
    setBusy("enc"); setDec(null);
    try { const r = await post("/crypto/aes/encrypt", { plaintext: plain, dataset: ds }); setEnc(r); setRunN((n) => n + 1); setHistory((h) => [r.ciphertext_hex.slice(0, 40) + "…  nonce " + r.nonce_hex, ...h].slice(0, 4)); }
    catch (e: any) { toast("err", "Encryption failed", e.message); } finally { setBusy(""); }
  }
  async function decrypt(mode: "correct" | "wrong_key" | "tampered") {
    if (!enc) return;
    setBusy(mode);
    try { setDec(await post("/crypto/aes/decrypt", { blob: enc.blob, dataset: ds, mode })); }
    catch (e: any) { toast("err", "Decryption request failed", e.message); } finally { setBusy(""); }
  }
  const ctHex = useMemo(() => {
    if (!enc) return null;
    const h: string = enc.ciphertext_hex;
    const fb = dec?.flipped_byte;
    return fb == null ? h : <>{h.slice(0, fb * 2)}<span className="rounded bg-rd/40 px-0.5 text-rd">{h.slice(fb * 2, fb * 2 + 2)}</span>{h.slice(fb * 2 + 2)}</>;
  }, [enc, dec]);

  return (
    <div className="space-y-4">
      <PageHead icon={<FlaskConical size={20} />} title="Cryptography Laboratory" sub="Real AES-256-GCM encryption running on the server. The 256-bit key never leaves the backend — you only ever see the nonce, ciphertext and authentication tag." right={<Tabs tabs={[{ id: "lab", label: "AES-256-GCM" }, { id: "hash", label: "Hashing" }, { id: "algs", label: "Algorithms" }]} value={tab} onChange={setTab} />} />

      {tab === "lab" && (
        <>
          <Card className="p-4">
            <div className="flex flex-wrap items-center gap-3">
              <div className="text-[13px] font-semibold">1 · Choose data</div>
              <Tabs tabs={[{ id: "customer", label: "Customer PII" }, { id: "order", label: "Order" }, { id: "transaction", label: "Payment transaction" }]} value={ds} onChange={setDs} />
            </div>
            {samples.loading ? <Spinner /> : <textarea className="mono mt-3 min-h-[84px]" value={plain} onChange={(e) => { setPlain(e.target.value); setEnc(null); setDec(null); }} maxLength={600} aria-label="Plaintext" />}
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Btn icon={<Lock size={15} />} loading={busy === "enc"} disabled={!plain.trim()} onClick={encrypt}>Encrypt with AES-256-GCM</Btn>
              {enc && <Btn variant="ghost" icon={<RefreshCw size={14} />} loading={busy === "enc"} onClick={encrypt}>Encrypt the same text again</Btn>}
              <span className="text-[12px] text-mute">{plain.length} characters · fresh random 96-bit nonce every time</span>
            </div>
          </Card>

          {enc && (
            <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
              <Card className="p-4">
                <div className="mb-3 text-[13px] font-semibold">2 · What happened</div>
                <div className="flex flex-wrap items-stretch gap-3">
                  <div className="min-w-[200px] flex-1 rounded-xl border border-gn/40 bg-gn/5 p-3"><div className="mb-1 text-[10.5px] font-bold uppercase tracking-wider text-gn">Plaintext · readable</div><div className="mono break-all text-[12px] text-gn">{plain}</div></div>
                  <div className="flex flex-col items-center justify-center gap-1 px-1 text-center"><ArrowRight className="text-cy" /><div className="mono rounded-lg border border-cy/40 bg-cy/10 px-2 py-1 text-[10.5px] font-bold text-cy">AES-256-GCM</div><div className="text-[10px] text-mute">key + nonce + AAD</div></div>
                  <div className="min-w-[200px] flex-1 rounded-xl border border-rd/40 bg-rd/5 p-3"><div className="mb-1 text-[10.5px] font-bold uppercase tracking-wider text-rd">Ciphertext · unreadable</div><div className="mono break-all text-[12px] text-rd"><Scramble text={enc.ciphertext_hex} run={runN} /></div></div>
                </div>
              </Card>
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                <Hex label="Key (256-bit) — fingerprint only" value={`${enc.key_id}  · stays on the server`} tone="am" />
                <Hex label="Nonce (96-bit, random)" value={enc.nonce_hex} />
                <Hex label="Authentication tag (128-bit)" value={enc.tag_hex} tone="vi" />
                <Hex label="Associated data (authenticated, not secret)" value={enc.aad} tone="mute" />
              </div>
              <Card className="p-4"><div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-mute">Stored value (base64 of nonce ‖ ciphertext ‖ tag)</div><Code>{enc.blob}</Code>
                {history.length > 1 && <div className="mt-3"><div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-mute">Same plaintext, different output each time <Tip text="GCM requires a unique nonce per message. Reusing a nonce with the same key would leak the XOR of plaintexts and break authentication — so the server always draws a fresh random one." /></div>
                  <div className="space-y-1">{history.map((h, i) => <div key={i} className="mono truncate rounded border border-line bg-panel2 px-2 py-1 text-[11px] text-mute">{h}</div>)}</div></div>}
              </Card>

              <Card className="p-4">
                <div className="mb-1 text-[13px] font-semibold">3 · Decrypt — and try to break it</div>
                <p className="mb-3 text-[12.5px] text-mute">GCM is <i>authenticated</i> encryption: it doesn't just hide the data, it proves the data and key are exactly right. Any other key, or a single flipped bit, makes decryption fail.</p>
                <div className="flex flex-wrap gap-2">
                  <Btn variant="ok" icon={<LockOpen size={15} />} loading={busy === "correct"} onClick={() => decrypt("correct")}>Decrypt with the correct key</Btn>
                  <Btn variant="warn" icon={<KeyRound size={15} />} loading={busy === "wrong_key"} onClick={() => decrypt("wrong_key")}>Try a wrong key</Btn>
                  <Btn variant="danger" icon={<Wand2 size={15} />} loading={busy === "tampered"} onClick={() => decrypt("tampered")}>Tamper: flip 1 bit of ciphertext</Btn>
                </div>
                {dec && (
                  <motion.div key={dec.mode + String(dec.verified)} initial={{ opacity: 0, scale: 0.97 }} animate={{ opacity: 1, scale: 1 }} className={cx("mt-4 rounded-xl border p-4", dec.verified ? "border-gn/50 bg-gn/10 glow-gn" : "border-rd/50 bg-rd/10 glow-rd")}>
                    <div className="flex items-center gap-2 text-sm font-bold">{dec.verified ? <CheckCircle2 className="text-gn" /> : <XCircle className="text-rd" />}<span className={dec.verified ? "text-gn" : "text-rd"}>{dec.status}</span></div>
                    <div className="mt-1 text-[12.5px] text-mute">{dec.note}</div>
                    {dec.verified ? <div className="mono mt-3 break-all rounded-lg bg-panel2 p-3 text-[12.5px] text-gn">{dec.plaintext}</div>
                      : <div className="mt-3 flex items-center gap-2 text-[12.5px] text-rd"><ShieldAlert size={15} /> No plaintext released. The authentication tag did not match, so the server refuses to output anything.</div>}
                    {dec.flipped_byte != null && <div className="mt-3"><div className="mb-1 text-[10.5px] font-semibold uppercase tracking-wider text-mute">Ciphertext (flipped byte {dec.flipped_byte} highlighted)</div><div className="mono break-all rounded-lg bg-panel2 p-2 text-[11.5px] text-mute">{ctHex}</div></div>}
                  </motion.div>
                )}
              </Card>
            </motion.div>
          )}
        </>
      )}

      {tab === "hash" && <Avalanche />}

      {tab === "algs" && (
        <Card>
          <CardHead title="Algorithm reference" sub="What NovaMart uses, and what it deliberately does not." />
          {algs.loading ? <Spinner /> : (
            <div className="overflow-auto"><table>
              <thead><tr><th>Algorithm</th><th>Type</th><th>Strength</th><th>Brute-force estimate</th><th>Status</th><th>Used for / limits</th></tr></thead>
              <tbody>{algs.data?.algorithms.map((a) => (
                <tr key={a.id}>
                  <td className="whitespace-nowrap font-semibold">{a.name}</td><td className="text-mute">{a.type}</td>
                  <td className="min-w-[140px]"><div className="mono mb-1 text-[11px]">{a.security_bits} bits</div><Bar value={Math.min(100, a.security_bits / 2.56)} tone={a.status === "broken" ? "rd" : a.status === "deprecated" ? "am" : "gn"} /></td>
                  <td className="mono text-[11.5px] text-mute">{a.brute_force?.human ?? "—"}</td>
                  <td><Badge tone={a.status === "recommended" ? "gn" : a.status === "deprecated" ? "am" : a.status === "broken" ? "rd" : "cy"}>{a.status}</Badge></td>
                  <td className="max-w-[420px] text-[12px] text-mute"><div className="text-ink/90">{a.purpose}</div><div className="mt-0.5">{a.limits}</div></td>
                </tr>))}</tbody>
            </table></div>
          )}
        </Card>
      )}
    </div>
  );
}

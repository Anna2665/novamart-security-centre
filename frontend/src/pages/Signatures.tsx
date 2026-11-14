import { motion } from "framer-motion";
import { BadgeCheck, CheckCircle2, FileSignature, FileWarning, KeyRound, Lock, PenTool, ScrollText, ShieldCheck, ShieldX, Stamp, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { Badge, Btn, Card, CardHead, Code, Hex, PageHead, Spinner, Tabs, useFetch } from "../components/ui";
import { get, post } from "../lib/api";
import { cx, fmtDateTime } from "../lib/util";
import { useStore } from "../store";

function SignVerify() {
  const { toast } = useStore();
  const samples = useFetch<any>(() => get("/sig/samples"), []);
  const [alg, setAlg] = useState("RSA-PSS");
  const [key, setKey] = useState<any>(null);
  const [which, setWhich] = useState("order");
  const [recText, setRecText] = useState("");
  const [signed, setSigned] = useState<any>(null);
  const [recvText, setRecvText] = useState("");
  const [res, setRes] = useState<any>(null);
  const [busy, setBusy] = useState("");

  useEffect(() => { if (samples.data) { const t = JSON.stringify(samples.data[which], null, 2); setRecText(t); setRecvText(t); setSigned(null); setRes(null); } }, [samples.data, which]);

  const parse = (t: string) => { try { return JSON.parse(t); } catch { toast("err", "Invalid JSON", "Fix the record before continuing."); return null; } };
  async function gen() { setBusy("gen"); setSigned(null); setRes(null); try { setKey(await post("/sig/keys", { algorithm: alg })); } catch (e: any) { toast("err", "Key generation failed", e.message); } finally { setBusy(""); } }
  async function sign() {
    const rec = parse(recText); if (!rec || !key) return;
    setBusy("sign"); setRes(null);
    try { const s = await post("/sig/sign", { key_id: key.key_id, record: rec }); setSigned(s); setRecvText(JSON.stringify(rec, null, 2)); } catch (e: any) { toast("err", "Signing failed", e.message); } finally { setBusy(""); }
  }
  async function verify() {
    const rec = parse(recvText); if (!rec || !signed) return;
    setBusy("ver");
    try { setRes(await post("/sig/verify", { key_id: key.key_id, record: rec, signature: signed.signature, kind: which })); } catch (e: any) { toast("err", "Verification failed", e.message); } finally { setBusy(""); }
  }
  function tamper() {
    const rec = parse(recvText); if (!rec) return;
    const k = ["amount", "price", "quantity", "stock"].find((x) => x in rec) ?? Object.keys(rec).find((x) => typeof rec[x] === "number");
    if (k) rec[k] = 1; else rec.tampered = true;
    setRecvText(JSON.stringify(rec, null, 2)); setRes(null);
  }

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <div className="space-y-4">
        <Card className="p-4">
          <div className="mb-3 text-[13px] font-semibold">1 · Signer — generate a key pair</div>
          <div className="flex flex-wrap items-center gap-2">
            <select className="!w-auto" value={alg} onChange={(e) => { setAlg(e.target.value); setKey(null); setSigned(null); }} aria-label="Algorithm"><option value="RSA-PSS">RSA-PSS · 2048-bit · SHA-256</option><option value="ECDSA-P256">ECDSA · P-256 · SHA-256</option></select>
            <Btn icon={<KeyRound size={15} />} loading={busy === "gen"} onClick={gen}>Generate key pair</Btn>
          </div>
          {key && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mt-3 space-y-2">
              <div className="flex flex-wrap items-center gap-2"><Badge tone="gn" dot>{key.algorithm_detail}</Badge><Badge tone="vi">{key.key_size}-bit</Badge><Badge tone="am">private key: not exposed</Badge></div>
              <Hex label="Public key fingerprint (SHA-256)" value={key.fingerprint} />
              <Code>{key.public_key_pem}</Code>
            </motion.div>
          )}
        </Card>
        <Card className="p-4">
          <div className="mb-3 flex flex-wrap items-center gap-3"><div className="text-[13px] font-semibold">2 · Record to sign</div>
            <Tabs tabs={[{ id: "order", label: "Order" }, { id: "price", label: "Price" }, { id: "payment", label: "Payment" }, { id: "db_record", label: "DB record" }]} value={which} onChange={setWhich} /></div>
          {samples.loading ? <Spinner /> : <textarea className="mono min-h-[170px]" value={recText} onChange={(e) => { setRecText(e.target.value); setSigned(null); setRes(null); }} aria-label="Record JSON" />}
          <div className="mt-3"><Btn icon={<PenTool size={15} />} disabled={!key} loading={busy === "sign"} onClick={sign}>Sign record with private key</Btn>{!key && <span className="ml-3 text-[12px] text-mute">Generate a key pair first</span>}</div>
          {signed && (
            <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mt-3 space-y-2">
              <Hex label="Canonical form (sorted keys, no whitespace) — what actually gets hashed" value={signed.canonical} tone="mute" />
              <Hex label="SHA-256 digest" value={signed.hash} />
              <Hex label={`Signature (${signed.algorithm}, base64)`} value={signed.signature} tone="gn" />
            </motion.div>
          )}
        </Card>
      </div>

      <Card className={cx("p-4", res && (res.valid ? "glow-gn" : "glow-rd"))}>
        <div className="mb-1 text-[13px] font-semibold">3 · Receiver — verify with the public key</div>
        <p className="mb-3 text-[12.5px] text-mute">The receiver gets the record and the signature. Edit the record to play the attacker, then verify.</p>
        <textarea className="mono min-h-[170px]" value={recvText} onChange={(e) => { setRecvText(e.target.value); setRes(null); }} disabled={!signed} aria-label="Record as received" />
        <div className="mt-3 flex flex-wrap gap-2">
          <Btn variant="danger" icon={<FileWarning size={15} />} disabled={!signed} onClick={tamper}>Simulate attacker: set value to 1</Btn>
          <Btn variant="ok" icon={<BadgeCheck size={15} />} disabled={!signed} loading={busy === "ver"} onClick={verify}>Verify signature</Btn>
        </div>
        {res && (
          <motion.div key={String(res.valid) + res.hash} initial={{ opacity: 0, scale: 0.94 }} animate={{ opacity: 1, scale: 1 }} className="mt-4 space-y-3">
            <div className={cx("flex items-center gap-3 rounded-xl border p-4", res.valid ? "border-gn/50 bg-gn/10" : "border-rd/50 bg-rd/10")}>
              {res.valid ? <CheckCircle2 size={34} className="text-gn" /> : <XCircle size={34} className="glitch text-rd" />}
              <div><div className={cx("text-base font-bold", res.valid ? "text-gn" : "text-rd")}>{res.valid ? "SIGNATURE VALID" : "SIGNATURE INVALID"}</div><div className="text-[12.5px] text-ink/85">{res.status}</div></div>
            </div>
            <Hex label="Digest of the record as received" value={res.hash} tone={res.valid ? "gn" : "rd"} />
            {signed && res.hash !== signed.hash && <div className="rounded-lg border border-amber-200 bg-amber-50 p-2.5 text-[12px] text-am">The digest differs from the one that was signed ({signed.hash.slice(0, 16)}…), so the signature cannot verify.</div>}
            {res.alert && <div className="flex items-start gap-2 rounded-lg border border-rd/40 bg-rd/10 p-2.5 text-[12px] text-rd"><ShieldX size={15} className="mt-0.5 shrink-0" /><div><b>Security alert raised:</b> {res.alert.detection} — recorded as a LIVE integrity-violation event ({res.alert.event_id}). It appears in the Audit Logs and Overview feed.</div></div>}
          </motion.div>
        )}
      </Card>
    </div>
  );
}

function Pki() {
  const ca = useFetch<any>(() => get("/sig/pki/ca"), []);
  const [host, setHost] = useState("shop.novamart.demo");
  const [validateAs, setValidateAs] = useState("shop.novamart.demo");
  const [issuer, setIssuer] = useState("trusted");
  const [r, setR] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const { toast } = useStore();
  async function issue() { setBusy(true); try { setR(await post("/sig/pki/issue", { hostname: host, issuer, validate_as: validateAs })); } catch (e: any) { toast("err", "Issuance failed", e.message); } finally { setBusy(false); } }
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card>
        <CardHead icon={<Stamp size={16} />} title="Trusted root CA (the trust store)" sub="A certificate is only trusted if a CA in this store signed it." />
        <div className="space-y-2 px-4 pb-4">
          {ca.loading || !ca.data ? <Spinner /> : (
            <>
              <div className="grid grid-cols-2 gap-2 text-[12.5px]">
                {[["Subject", ca.data.subject], ["Serial", ca.data.serial], ["Valid from", fmtDateTime(ca.data.not_before)], ["Valid until", fmtDateTime(ca.data.not_after)], ["Signature", ca.data.signature_algorithm], ["Public key", ca.data.public_key]].map(([k, v]) => (
                  <div key={k} className="rounded-lg border border-line bg-panel2 p-2"><div className="text-[10px] font-semibold uppercase tracking-wider text-mute">{k}</div><div className="mono mt-0.5 break-all">{v}</div></div>))}
              </div>
              <Hex label="SHA-256 fingerprint" value={ca.data.sha256} />
              <Code>{ca.data.pem}</Code>
            </>
          )}
        </div>
      </Card>
      <Card className="p-4">
        <div className="mb-3 text-[13px] font-semibold">Issue &amp; validate a certificate</div>
        <div className="grid gap-3 md:grid-cols-2">
          <label className="text-[11px] font-semibold uppercase tracking-wider text-mute">Certificate hostname<input className="mono mt-1" value={host} onChange={(e) => setHost(e.target.value.toLowerCase())} /></label>
          <label className="text-[11px] font-semibold uppercase tracking-wider text-mute">Browser connects to<input className="mono mt-1" value={validateAs} onChange={(e) => setValidateAs(e.target.value.toLowerCase())} /></label>
          <label className="text-[11px] font-semibold uppercase tracking-wider text-mute md:col-span-2">Who issues it?
            <select className="mt-1" value={issuer} onChange={(e) => setIssuer(e.target.value)}><option value="trusted">Trusted CyberGuard Root CA (legitimate)</option><option value="rogue">“Totally Legit Certificate Authority” (attacker's CA → man-in-the-middle)</option></select></label>
        </div>
        <div className="mt-3"><Btn icon={<ScrollText size={15} />} loading={busy} onClick={issue}>Issue &amp; validate</Btn></div>
        {r && (
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mt-4 space-y-3">
            <div className="flex items-center justify-center gap-3 py-2">
              <div className="flex flex-col items-center gap-1"><div className="flex h-12 w-12 items-center justify-center rounded-xl border border-gn/50 bg-gn/10"><ShieldCheck className="text-gn" /></div><div className="text-[10px] text-mute">Trusted root</div></div>
              <svg width="70" height="12"><line x1="0" y1="6" x2="70" y2="6" stroke={r.validation.checks[1].ok ? "#059669" : "#dc2626"} strokeWidth="2.5" strokeDasharray={r.validation.checks[1].ok ? "0" : "6 5"} /></svg>
              <div className="flex flex-col items-center gap-1"><div className={cx("flex h-12 w-12 items-center justify-center rounded-xl border", r.validation.valid ? "border-gn/50 bg-gn/10" : "border-rd/50 bg-rd/10 pulse-rd")}>{r.validation.valid ? <Lock className="text-gn" /> : <ShieldX className="text-rd" />}</div><div className="text-[10px] text-mute">{r.certificate.subject}</div></div>
            </div>
            <div className={cx("rounded-xl border p-3 text-center text-sm font-bold", r.validation.valid ? "border-gn/50 bg-gn/10 text-gn" : "border-rd/50 bg-rd/10 text-rd")}>{r.validation.valid ? "CERTIFICATE ACCEPTED — padlock shown" : "CERTIFICATE REJECTED — browser blocks the connection"}</div>
            <div className="space-y-1.5">{r.validation.checks.map((c: any) => (
              <div key={c.check} className={cx("flex items-start gap-2 rounded-lg border p-2 text-[12.5px]", c.ok ? "border-gn/30 bg-gn/5" : "border-rd/40 bg-rd/10")}>
                {c.ok ? <CheckCircle2 size={15} className="mt-0.5 shrink-0 text-gn" /> : <XCircle size={15} className="mt-0.5 shrink-0 text-rd" />}<div><div className="font-semibold">{c.check}</div><div className="mono text-[11px] text-mute">{c.detail}</div></div></div>))}</div>
            <div className="text-[12px] text-mute">Issuer: <span className="mono text-ink">{r.certificate.issuer}</span> · {r.certificate.signature_algorithm} · serial <span className="mono">{r.certificate.serial}</span></div>
          </motion.div>
        )}
      </Card>
    </div>
  );
}

function ServerKey() {
  const k = useFetch<any>(() => get("/sig/server-key"), []);
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card>
        <CardHead icon={<KeyRound size={16} />} title="Record-signing key (the platform's own)" sub="Every order, price and payment record in the database is hashed (SHA-256) and signed with this key." />
        <div className="space-y-2 px-4 pb-4">{k.loading || !k.data ? <Spinner /> : (<>
          <div className="flex flex-wrap gap-2"><Badge tone="gn" dot>{k.data.algorithm}</Badge></div>
          <Hex label="Public key fingerprint" value={k.data.fingerprint} />
          <Code>{k.data.public_key_pem}</Code>
          <div className="rounded-lg border border-amber-200 bg-amber-50 p-2.5 text-[12px] text-am"><b>Private key:</b> {k.data.private_key}</div></>)}</div>
      </Card>
      <Card className="p-4">
        <div className="text-[13px] font-semibold">How it protects the store</div>
        <ol className="mt-3 space-y-3 text-[13px] text-ink/90">
          {[["Sign on write", "When a price or order is saved by an authorised path, the server stores the record, its SHA-256 hash, an RSA-PSS signature, and a copy in a signed version ledger."], ["Verify on read", "The integrity monitor recomputes the hash and checks the signature. Edits that bypass the application (SQL injection, a rogue admin, a stolen DB login) fail both checks."], ["A smart attacker still loses", "Rewriting the stored hash to match the new data doesn't help — without the private key they cannot forge a valid signature."], ["Restore", "The last signed version in the ledger is verified and restored — see Database Security."]].map(([t, d], i) => (
            <li key={t} className="flex gap-3"><span className="mono flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-cy/40 bg-cy/10 text-xs font-bold text-cy">{i + 1}</span><div><div className="font-semibold">{t}</div><div className="text-mute">{d}</div></div></li>))}
        </ol>
        <Btn className="mt-4" variant="ghost" onClick={() => { location.hash = "#/soc/database"; }}>Open Database Security</Btn>
      </Card>
    </div>
  );
}

export function Signatures() {
  const [tab, setTab] = useState<"sv" | "pki" | "srv">("sv");
  return (
    <div className="space-y-4">
      <PageHead icon={<FileSignature size={20} />} title="Digital Signature Verification" sub="Sign a record with a private key, verify it with the public key, and see why even a one-value change (₹1,499 → ₹1) is rejected. Real RSA-PSS and ECDSA, real X.509 certificates."
        right={<Tabs tabs={[{ id: "sv", label: "Sign & verify" }, { id: "pki", label: "Certificates (PKI)" }, { id: "srv", label: "Platform signing key" }]} value={tab} onChange={setTab} />} />
      {tab === "sv" && <SignVerify />}{tab === "pki" && <Pki />}{tab === "srv" && <ServerKey />}
    </div>
  );
}

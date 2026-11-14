import { motion } from "framer-motion";
import { Check, Fingerprint, KeyRound, Lock, LockOpen, ShieldCheck, Smartphone, UserCog, Users, X } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { useState } from "react";
import { Badge, Btn, Card, CardHead, CopyBtn, Empty, ErrorBox, PageHead, Spinner, Tabs, useFetch } from "../components/ui";
import { ApiError, api, get, post, put } from "../lib/api";
import { cx, fmtDateTime } from "../lib/util";
import { useStore } from "../store";

function Totp({ me, reload }: { me: any; reload: () => void }) {
  const { toast } = useStore();
  const [en, setEn] = useState<any>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState("");
  async function enroll() { setBusy("e"); try { setEn(await post("/auth/totp/enroll")); setCode(""); } catch (e: any) { toast("err", "Could not start enrolment", e.message); } finally { setBusy(""); } }
  async function confirm() { setBusy("c"); try { await post("/auth/totp/confirm", { code }); toast("ok", "Authenticator app enrolled", "Next sign-in offers the Authenticator option."); setEn(null); setCode(""); reload(); } catch (e: any) { toast("err", "Wrong code", e.message); } finally { setBusy(""); } }
  async function disable() { setBusy("d"); try { await post("/auth/totp/disable", { code }); toast("warn", "Authenticator app removed"); setCode(""); reload(); } catch (e: any) { toast("err", "Could not disable", e.message); } finally { setBusy(""); } }
  return (
    <Card className="p-4">
      <div className="flex items-center gap-2 text-[13px] font-semibold"><Smartphone size={16} className="text-cy" />Authenticator app (TOTP) — optional second factor<Badge tone={me.totp_enabled ? "gn" : "mute"} dot>{me.totp_enabled ? "enrolled" : "not enrolled"}</Badge></div>
      <p className="mt-1 text-[12.5px] text-mute">Email OTP is always required. Enrol Google Authenticator, Authy or similar to also sign in with rotating 6-digit codes that work offline (RFC 6238).</p>
      {!me.totp_enabled && !en && <Btn className="mt-3" icon={<Smartphone size={15} />} loading={busy === "e"} onClick={enroll}>Set up authenticator</Btn>}
      {en && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mt-3 grid gap-4 md:grid-cols-[auto_1fr]">
          <div className="rounded-xl bg-white p-3"><QRCodeSVG value={en.uri} size={160} /></div>
          <div className="space-y-3"><div className="text-[12.5px] text-mute">Scan with your authenticator app, or type this secret manually:</div>
            <div className="mono flex items-center gap-2 rounded-lg border border-line bg-panel2 p-2.5 text-[13px] tracking-wider text-cy">{en.secret}<CopyBtn text={en.secret} /></div>
            <div className="flex gap-2"><input className="mono !w-40 text-center tracking-[0.3em]" inputMode="numeric" maxLength={6} placeholder="000000" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} aria-label="Authenticator code" /><Btn loading={busy === "c"} disabled={code.length !== 6} onClick={confirm}>Confirm</Btn></div></div>
        </motion.div>
      )}
      {me.totp_enabled && <div className="mt-3 flex gap-2"><input className="mono !w-40 text-center tracking-[0.3em]" inputMode="numeric" maxLength={6} placeholder="code" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} aria-label="Authenticator code to disable" /><Btn variant="danger" loading={busy === "d"} disabled={code.length !== 6} onClick={disable}>Disable (needs a current code)</Btn></div>}
    </Card>
  );
}

const PROBES = [
  { label: "List all user accounts", perm: "users:manage", call: () => api("/auth/users") },
  { label: "Read the security audit log", perm: "audit:read", call: () => api("/audit?limit=1") },
  { label: "Change a defence setting", perm: "sim:configure", call: () => put("/sim/defences/rbac-probe", { enabled: true }) },
  { label: "Decrypt customer PII", perm: "pii:read", call: async () => { const r = await get("/db/customers"); if (!r.pii_revealed) throw new ApiError(403, { detail: "PII returned masked — pii:read not granted" }); return r; } },
];

export function Iam() {
  const { user, can, toast, bump } = useStore();
  const me = useFetch<any>(() => get("/auth/me"), []);
  const users = useFetch<any[]>(() => (can("users:manage") ? get("/auth/users") : Promise.resolve([])), []);
  const rbac = useFetch<any>(() => get("/auth/rbac"), []);
  const policy = useFetch<any>(() => get("/auth/policy"), []);
  const hist = useFetch<any[]>(() => get("/auth/audit?limit=40"), [bump.audit]);
  const [tab, setTab] = useState<"users" | "rbac" | "policy" | "history">("users");
  const [role, setRole] = useState("viewer");
  const [perm, setPerm] = useState("db:tamper");
  const [chk, setChk] = useState<any>(null);
  const [probe, setProbe] = useState<Record<string, { status: number; msg: string }>>({});

  async function unlock(u: string) { try { await post(`/auth/users/${u}/unlock`); toast("ok", `${u} unlocked`); users.reload(); } catch (e: any) { toast("err", "Unlock failed", e.message); } }
  async function check() { try { setChk(await post("/auth/check-permission", { role, permission: perm })); } catch (e: any) { toast("err", "Check failed", e.message); } }
  async function runProbe(p: (typeof PROBES)[number]) {
    try { await p.call(); setProbe((x) => ({ ...x, [p.perm]: { status: 200, msg: "Allowed — the server executed the request." } })); }
    catch (e) { const er = e as ApiError; setProbe((x) => ({ ...x, [p.perm]: er.status === 404 ? { status: 200, msg: "Allowed — passed the permission check (404 is only my probe id; nothing was changed)." } : { status: er.status, msg: er.message } })); }
  }

  return (
    <div className="space-y-4">
      <PageHead icon={<UserCog size={20} />} title="Identity & Access Management" sub="Argon2id passwords, email OTP + optional TOTP, role-based access control enforced on the server for every request, lockout and rate limiting."
        right={<Tabs tabs={[{ id: "users", label: "Accounts & MFA" }, { id: "rbac", label: "Roles & permissions" }, { id: "policy", label: "Security policy" }, { id: "history", label: "Sign-in history" }]} value={tab} onChange={setTab} />} />

      {tab === "users" && (
        <div className="grid gap-4 xl:grid-cols-[1fr_1fr]">
          <Card className="xl:col-span-2">
            <CardHead icon={<Users size={16} />} title="User accounts" sub={can("users:manage") ? "Admin view" : "Only admins can list all accounts — showing yours"} />
            {users.loading || me.loading ? <Spinner /> : (
              <div className="overflow-auto"><table><thead><tr><th>User</th><th>Role</th><th>OTP email</th><th>TOTP</th><th>Password hash</th><th>Failed</th><th>Status</th><th>Last sign-in</th><th /></tr></thead>
                <tbody>{(can("users:manage") ? users.data ?? [] : [{ ...me.data, hash_algorithm: "argon2id", failed_attempts: 0, locked: false }]).map((u: any) => (
                  <tr key={u.username}><td className="font-semibold">{u.username}{u.username === user.username && <Badge tone="cy" className="ml-2">you</Badge>}</td><td><Badge tone={u.role === "admin" ? "rd" : u.role === "analyst" ? "am" : "cy"}>{u.role}</Badge></td>
                    <td className="mono text-mute">{u.email_masked}</td><td>{u.totp_enabled ? <Check size={16} className="text-gn" /> : <X size={16} className="text-mute" />}</td><td><Badge tone="vi">{u.hash_algorithm}</Badge></td><td className="mono">{u.failed_attempts}</td>
                    <td>{u.locked ? <Badge tone="rd" dot>locked</Badge> : <Badge tone="gn" dot>active</Badge>}</td><td className="text-mute">{fmtDateTime(u.last_login)}</td>
                    <td>{u.locked && can("users:manage") && <Btn size="sm" variant="warn" icon={<LockOpen size={13} />} onClick={() => unlock(u.username)}>Unlock</Btn>}</td></tr>))}</tbody></table></div>
            )}
          </Card>
          {me.data && <Totp me={me.data} reload={me.reload} />}
          <Card className="p-4">
            <div className="flex items-center gap-2 text-[13px] font-semibold"><ShieldCheck size={16} className="text-gn" />Live RBAC test — signed in as <Badge tone="cy">{user.role}</Badge></div>
            <p className="mt-1 text-[12.5px] text-mute">These call the real API with your token. The server decides — the UI can't override it.</p>
            <div className="mt-3 space-y-2">{PROBES.map((p) => {
              const r = probe[p.perm];
              return (<div key={p.perm} className="flex items-center gap-3 rounded-lg border border-line bg-panel2 p-2.5"><div className="min-w-0 flex-1"><div className="text-[12.5px] font-semibold">{p.label}</div><div className="mono text-[10.5px] text-mute">needs {p.perm}</div>
                {r && <div className={cx("mt-1 text-[11.5px]", r.status === 200 ? "text-gn" : "text-rd")}>{r.status === 200 ? "✓ " : `✗ HTTP ${r.status} — `}{r.msg}</div>}</div><Btn size="sm" variant="ghost" onClick={() => runProbe(p)}>Try</Btn></div>);
            })}</div>
          </Card>
        </div>
      )}

      {tab === "rbac" && (
        <div className="space-y-4">
          <Card><CardHead icon={<Fingerprint size={16} />} title="Role × permission matrix" sub="Least privilege: each role gets only what its job needs" />
            {rbac.loading || !rbac.data ? <Spinner /> : (
              <div className="overflow-auto"><table><thead><tr><th>Permission</th><th>What it allows</th>{rbac.data.roles.map((r: string) => <th key={r} className="text-center">{r}</th>)}</tr></thead>
                <tbody>{rbac.data.permissions.map((p: string) => (<tr key={p}><td className="mono text-[11.5px] text-cy">{p}</td><td className="text-mute">{rbac.data.descriptions[p]}</td>
                  {rbac.data.roles.map((r: string) => <td key={r} className="text-center">{rbac.data.matrix[r].includes(p) ? <Check size={16} className="mx-auto text-gn" /> : <X size={15} className="mx-auto text-rd/50" />}</td>)}</tr>))}</tbody></table></div>)}
          </Card>
          <Card className="p-4">
            <div className="text-[13px] font-semibold">Permission checker</div>
            <div className="mt-3 flex flex-wrap items-end gap-3">
              <label className="text-[11px] font-semibold uppercase tracking-wider text-mute">Role<select className="mt-1 !w-40" value={role} onChange={(e) => setRole(e.target.value)}>{rbac.data?.roles.map((r: string) => <option key={r}>{r}</option>)}</select></label>
              <label className="text-[11px] font-semibold uppercase tracking-wider text-mute">Permission<select className="mono mt-1 !w-52" value={perm} onChange={(e) => setPerm(e.target.value)}>{rbac.data?.permissions.map((p: string) => <option key={p}>{p}</option>)}</select></label>
              <Btn onClick={check} icon={<KeyRound size={15} />}>Check</Btn></div>
            {chk && <motion.div key={String(chk.allowed) + chk.role + chk.permission} initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className={cx("mt-3 flex items-center gap-3 rounded-xl border p-3", chk.allowed ? "border-gn/50 bg-gn/10" : "border-rd/50 bg-rd/10")}>
              {chk.allowed ? <Check className="text-gn" /> : <Lock className="text-rd" />}<div><div className={cx("font-bold", chk.allowed ? "text-gn" : "text-rd")}>{chk.allowed ? "ALLOWED" : "DENIED (HTTP 403)"}</div><div className="text-[12.5px] text-mute">{chk.role} → {chk.permission}: {chk.reason}</div></div></motion.div>}
          </Card>
        </div>
      )}

      {tab === "policy" && (policy.loading || !policy.data ? <Spinner /> : (
        <div className="grid gap-4 md:grid-cols-2">
          <Card className="p-4"><div className="text-[13px] font-semibold">Password storage</div>
            <div className="mt-3 grid grid-cols-2 gap-2 text-[12.5px]">{[["Algorithm", policy.data.password_hash.algorithm], ["Time cost", policy.data.password_hash.time_cost], ["Memory", `${policy.data.password_hash.memory_kib / 1024} MiB`], ["Parallelism", policy.data.password_hash.parallelism]].map(([k, v]) => <div key={k} className="rounded-lg border border-line bg-panel2 p-2"><div className="text-[10px] uppercase tracking-wider text-mute">{k}</div><div className="mono mt-0.5 text-cy">{v}</div></div>)}</div>
            <ul className="mt-3 list-inside list-disc space-y-1 text-[12.5px] text-mute">{policy.data.password_rules.map((r: string) => <li key={r}>{r}</li>)}</ul></Card>
          <Card className="p-4"><div className="text-[13px] font-semibold">Email OTP</div>
            <div className="mt-3 space-y-2 text-[12.5px]">{[["Digits", policy.data.otp.digits], ["Lifetime", `${policy.data.otp.ttl_seconds} s`], ["Max attempts", policy.data.otp.max_attempts], ["Resend cool-down", `${policy.data.otp.resend_cooldown} s`]].map(([k, v]) => <div key={k} className="flex justify-between rounded-lg border border-line bg-panel2 px-3 py-1.5"><span className="text-mute">{k}</span><span className="mono text-cy">{v}</span></div>)}<div className="rounded-lg border border-gn/30 bg-gn/5 p-2 text-gn">{policy.data.otp.storage}</div></div></Card>
          <Card className="p-4"><div className="text-[13px] font-semibold">Lockout &amp; sessions</div>
            <div className="mt-3 space-y-2 text-[12.5px]"><div className="rounded-lg border border-line bg-panel2 p-2.5">Account locks after <b className="text-am">{policy.data.lockout.max_failed}</b> wrong passwords for <b className="text-am">{policy.data.lockout.minutes} min</b>. A per-IP rate limiter also caps sign-in attempts.</div><div className="rounded-lg border border-line bg-panel2 p-2.5">Session: <b className="text-cy">{policy.data.session.minutes} min</b> · {policy.data.session.alg}</div></div></Card>
          <Card className="p-4"><div className="text-[13px] font-semibold">Sign-in flow</div>
            <ol className="mt-3 space-y-2 text-[12.5px]">{["Username + password → verified against the Argon2id hash", "Server generates a 6-digit code with a cryptographically secure RNG", "Only an HMAC of the code is stored; the code itself is emailed over SMTP/TLS", "Code must be entered within 60 s, max 3 tries; resend invalidates the previous code", "Optional: TOTP code from an authenticator app as an alternative second factor", "A short-lived signed session token is issued; the role is re-read from the database on every request"].map((s, i) => <li key={i} className="flex gap-2.5"><span className="mono flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-cy/15 text-[10px] font-bold text-cy">{i + 1}</span><span className="text-mute">{s}</span></li>)}</ol></Card>
        </div>))}

      {tab === "history" && (
        <Card><CardHead title="Sign-in history" sub={can("users:manage") ? "All accounts" : "Your account"} />
          {hist.loading && !hist.data ? <Spinner /> : hist.error ? <div className="p-4"><ErrorBox error={hist.error} /></div> : !hist.data?.length ? <Empty>No sign-ins recorded.</Empty> : (
            <div className="max-h-[520px] overflow-auto"><table><thead><tr><th>Time</th><th>User</th><th>IP</th><th>Method</th><th>Result</th><th>Detail</th></tr></thead>
              <tbody>{hist.data.map((h) => <tr key={h.id}><td className="mono text-mute">{fmtDateTime(h.ts)}</td><td>{h.username}</td><td className="mono">{h.ip}</td><td>{h.method}</td><td><Badge tone={h.result === "success" ? "gn" : h.result === "otp_sent" ? "cy" : "rd"}>{h.result}</Badge></td><td className="text-mute">{h.detail}</td></tr>)}</tbody></table></div>)}
        </Card>
      )}
    </div>
  );
}

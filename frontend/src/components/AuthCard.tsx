import { AnimatePresence, motion } from "framer-motion";
import { AlertTriangle, ArrowLeft, Check, CheckCircle2, KeyRound, Loader2, Lock, Mail, MailWarning, Phone, MapPin, RefreshCw, ShieldCheck, Smartphone, User, UserPlus } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, post } from "../lib/api";
import { cx } from "../lib/util";
import { useStore } from "../store";
import { Btn, CopyBtn } from "./ui";

type Delivery = { status: string; detail: string; dev_otp?: string; dev_mode?: boolean };
type Challenge = { challenge_id: string; email_masked: string; ttl: number; max_attempts: number; resend_cooldown: number; methods: string[]; delivery: Delivery };

export function OtpBoxes({ value, onChange, disabled, shake, onComplete }: { value: string; onChange: (v: string) => void; disabled?: boolean; shake?: boolean; onComplete: (v: string) => void }) {
  const refs = useRef<(HTMLInputElement | null)[]>([]);
  const set = (i: number, ch: string) => {
    const digits = value.padEnd(6, " ").split("");
    digits[i] = ch;
    const v = digits.join("").replace(/ /g, "");
    onChange(v);
    if (ch && i < 5) refs.current[i + 1]?.focus();
    if (v.length === 6 && !v.includes(" ")) onComplete(v);
  };
  useEffect(() => { refs.current[Math.min(value.length, 5)]?.focus(); }, [shake]);
  return (
    <div className={cx("flex justify-center gap-2.5", shake && "shake")}>
      {Array.from({ length: 6 }).map((_, i) => (
        <input key={i} ref={(el) => { refs.current[i] = el; }} inputMode="numeric" autoComplete="one-time-code" maxLength={1} disabled={disabled} aria-label={`Digit ${i + 1}`}
          value={value[i] ?? ""}
          onChange={(e) => { const c = e.target.value.replace(/\D/g, "").slice(-1); if (c) set(i, c); }}
          onKeyDown={(e) => {
            if (e.key === "Backspace") { e.preventDefault(); onChange(value.slice(0, value[i] ? i : Math.max(0, i - 1))); refs.current[Math.max(0, value[i] ? i : i - 1)]?.focus(); }
            if (e.key === "ArrowLeft") refs.current[Math.max(0, i - 1)]?.focus();
            if (e.key === "ArrowRight") refs.current[Math.min(5, i + 1)]?.focus();
          }}
          onPaste={(e) => { const t = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, 6); if (t) { e.preventDefault(); onChange(t); if (t.length === 6) onComplete(t); } }}
          className="mono !h-14 !w-12 !rounded-xl !p-0 text-center !text-2xl font-bold text-ink" style={{ borderColor: value[i] ? "#4f46e5" : undefined }} />
      ))}
    </div>
  );
}

const RULES: [string, (p: string) => boolean][] = [
  ["At least 12 characters", (p) => p.length >= 12], ["Upper and lower case letters", (p) => /[a-z]/.test(p) && /[A-Z]/.test(p)],
  ["A number", (p) => /\d/.test(p)], ["A symbol (for example ! or #)", (p) => /[^\w\s]/.test(p)],
];

function Field({ label, icon, children }: { label: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <label className="block text-[13px] font-medium text-slate-700">{label}
      <div className="relative mt-1.5"><span className="pointer-events-none absolute left-3 top-[11px] text-slate-400">{icon}</span>{children}</div>
    </label>
  );
}

/** Sign in / create account with a one-time code. Used by the shop (customers) and the Security Centre (staff). */
export function AuthCard({ audience, initialMode = "signin", onSwitchMode }: { audience: "customer" | "staff"; initialMode?: "signin" | "register"; onSwitchMode?: (m: "signin" | "register") => void }) {
  const signedIn = useStore((s) => s.signedIn);
  const health = useStore((s) => s.health);
  const staff = audience === "staff";
  const mode = initialMode;
  const [username, setUsername] = useState(staff ? "admin" : "");
  const [password, setPassword] = useState("");
  const [full, setFull] = useState(""); const [phone, setPhone] = useState(""); const [address, setAddress] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ch, setCh] = useState<Challenge | null>(null);
  const [purpose, setPurpose] = useState<"signin" | "register">("signin");
  const [code, setCode] = useState("");
  const [method, setMethod] = useState<"email" | "totp">("email");
  const [shake, setShake] = useState(0);
  const [left, setLeft] = useState<number | null>(null);
  const [expiresAt, setExpiresAt] = useState(0);
  const [resendAt, setResendAt] = useState(0);
  const [now, setNow] = useState(Date.now());
  const [success, setSuccess] = useState(false);

  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 250); return () => clearInterval(t); }, []);
  const remaining = Math.max(0, Math.ceil((expiresAt - now) / 1000));
  const resendIn = Math.max(0, Math.ceil((resendAt - now) / 1000));
  const startTimers = (c: { ttl: number; resend_cooldown?: number }, cooldown: number) => { setExpiresAt(Date.now() + c.ttl * 1000); setResendAt(Date.now() + (c.resend_cooldown ?? cooldown) * 1000); };
  const begin = (c: Challenge, why: "signin" | "register") => { setCh(c); setPurpose(why); setCode(""); setLeft(null); setMethod("email"); startTimers(c, c.resend_cooldown); };

  async function submit(e?: React.FormEvent) {
    e?.preventDefault();
    if (busy) return;
    setBusy(true); setError(null);
    try {
      if (mode === "register") begin(await post<Challenge>("/auth/register", { full_name: full.trim(), email: username.trim(), password, phone: phone.trim() || null, address: address.trim() || null }), "register");
      else begin(await post<Challenge>("/auth/login", { username: username.trim().toLowerCase(), password }), "signin");
    } catch (err) { setError((err as ApiError).message); setShake((s) => s + 1); }
    finally { setBusy(false); }
  }

  const verify = useCallback(async (c: string) => {
    if (!ch || busy || success) return;
    setBusy(true); setError(null);
    try {
      const r = await post(method === "email" ? "/auth/otp/verify" : "/auth/totp/verify", { challenge_id: ch.challenge_id, code: c });
      const isCustomer = r.user?.role === "customer";
      if (staff && isCustomer) { await post("/auth/logout", {}).catch(() => {}); setError("That is a customer account. Customers shop at NovaMart — only staff use the Security Centre."); setCode(""); setShake((s) => s + 1); setBusy(false); return; }
      if (!staff && !isCustomer) { setError("That is a staff account. Staff sign in to the Security Centre (link at the bottom of the page)."); setCode(""); setShake((s) => s + 1); setBusy(false); return; }
      setSuccess(true);
      setTimeout(() => signedIn(r.token, r.user), 900);
    } catch (err) {
      const e2 = err as ApiError;
      setError(e2.message); setCode(""); setShake((s) => s + 1);
      if (typeof e2.body?.attempts_left === "number") setLeft(e2.body.attempts_left);
      if (e2.body?.restart) setTimeout(() => { setCh(null); setPassword(""); }, 1800);
      if (e2.body?.expired) setExpiresAt(0);
    } finally { setBusy(false); }
  }, [ch, busy, method, signedIn, success, staff]);

  async function resend() {
    if (!ch || resendIn > 0 || busy) return;
    setBusy(true); setError(null);
    try {
      const r = await post("/auth/otp/resend", { challenge_id: ch.challenge_id });
      setCh({ ...ch, delivery: r.delivery, ttl: r.ttl }); setCode(""); setLeft(null); startTimers({ ttl: r.ttl }, ch.resend_cooldown);
    } catch (err) {
      const e2 = err as ApiError;
      setError(e2.message);
      if (e2.body?.retry_after) setResendAt(Date.now() + e2.body.retry_after * 1000);
      if (e2.body?.restart) setTimeout(() => setCh(null), 1800);
    } finally { setBusy(false); }
  }

  const d = ch?.delivery;
  const failed = d && (d.status === "failed" || d.status === "not_configured");
  const strong = RULES.every(([, f]) => f(password));
  const canSubmit = mode === "register" ? full.trim().length >= 2 && /\S+@\S+\.\S+/.test(username) && strong : username.trim() !== "" && password !== "";

  return (
    <div className="card relative overflow-hidden p-7 shadow-lg shadow-slate-200/60">
      <AnimatePresence mode="wait">
        {success ? (
          <motion.div key="ok" initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} className="flex min-h-[340px] flex-col items-center justify-center text-center">
            <div className="mb-5 flex h-20 w-20 items-center justify-center rounded-full bg-gn/10"><CheckCircle2 size={44} className="text-gn" /></div>
            <div className="text-xl font-bold">{purpose === "register" ? "Email confirmed — welcome!" : "You're signed in"}</div>
            <div className="mt-1 text-sm text-mute">{staff ? "Opening the Security Centre…" : "Taking you back to the shop…"}</div>
          </motion.div>
        ) : !ch ? (
          <motion.form key="creds" onSubmit={submit} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className={cx("space-y-4", shake > 0 && "shake")}>
            <div>
              <div className="text-[22px] font-bold tracking-tight">{staff ? "Security Centre sign-in" : mode === "register" ? "Create your NovaMart account" : "Welcome back"}</div>
              <div className="mt-1 text-[13.5px] text-mute">{staff ? "For NovaMart security staff only." : mode === "register" ? "It takes a minute. We email a code to confirm your address." : "Sign in to check out and see your orders."}</div>
            </div>
            {health === null && <div className="rounded-lg border border-amber-200 bg-amber-50 p-2.5 text-xs text-am">Cannot reach the server yet…</div>}
            {mode === "register" && <Field label="Full name" icon={<User size={15} />}><input value={full} onChange={(e) => setFull(e.target.value)} className="!pl-9" placeholder="Anna Mariya Jose" autoComplete="name" autoFocus /></Field>}
            {staff ? (
              <Field label="Account" icon={<User size={15} />}>
                <select value={username} onChange={(e) => setUsername(e.target.value)} className="!pl-9" aria-label="Account">
                  <option value="admin">admin — full control</option><option value="analyst">analyst — security operations</option><option value="viewer">viewer — read-only</option>
                </select>
              </Field>
            ) : (
              <Field label={mode === "register" ? "Email address" : "Email (or username)"} icon={<Mail size={15} />}>
                <input value={username} onChange={(e) => setUsername(e.target.value)} className="!pl-9" placeholder="you@example.com" autoComplete="username" autoFocus={mode === "signin"} aria-label="Email" />
              </Field>
            )}
            <Field label="Password" icon={<Lock size={15} />}>
              <input type="password" autoFocus={staff} autoComplete={mode === "register" ? "new-password" : "current-password"} value={password} onChange={(e) => setPassword(e.target.value)} className="!pl-9" placeholder={staff ? "Demo password" : "Your password"} />
            </Field>
            {mode === "register" && (
              <>
                <ul className="grid grid-cols-2 gap-x-3 gap-y-1 text-[12px]">
                  {RULES.map(([t, f]) => <li key={t} className={cx("flex items-center gap-1.5", f(password) ? "text-gn" : "text-mute")}><Check size={13} className={f(password) ? "" : "opacity-30"} />{t}</li>)}
                </ul>
                <div className="grid gap-3 sm:grid-cols-2">
                  <Field label="Phone (optional)" icon={<Phone size={15} />}><input value={phone} onChange={(e) => setPhone(e.target.value)} className="!pl-9" placeholder="+91 …" autoComplete="tel" /></Field>
                  <Field label="Delivery address (optional)" icon={<MapPin size={15} />}><input value={address} onChange={(e) => setAddress(e.target.value)} className="!pl-9" placeholder="House, street, city" autoComplete="street-address" /></Field>
                </div>
              </>
            )}
            {error && <div role="alert" className="flex gap-2 rounded-lg border border-rd/30 bg-rd/5 p-2.5 text-[13px] text-rd"><AlertTriangle size={16} className="mt-0.5 shrink-0" />{error}</div>}
            <Btn type="submit" size="lg" loading={busy} disabled={!canSubmit} icon={mode === "register" ? <UserPlus size={16} /> : <KeyRound size={16} />} className="w-full">{mode === "register" ? "Create account" : "Continue"}</Btn>
            {!staff && onSwitchMode && (
              <p className="text-center text-[13px] text-mute">
                {mode === "signin" ? <>New to NovaMart? <button type="button" onClick={() => onSwitchMode("register")} className="font-semibold text-cy hover:underline">Create an account</button></>
                  : <>Already have an account? <button type="button" onClick={() => onSwitchMode("signin")} className="font-semibold text-cy hover:underline">Sign in</button></>}
              </p>
            )}
            <p className="text-center text-[12px] text-mute">After this step we email you a 6-digit code to confirm it is really you.</p>
          </motion.form>
        ) : (
          <motion.div key="otp" initial={{ opacity: 0, x: 24 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} className="space-y-4">
            <button onClick={() => { setCh(null); setError(null); }} className="flex items-center gap-1 text-xs text-mute hover:text-ink"><ArrowLeft size={13} /> Back</button>
            <div>
              <div className="text-[22px] font-bold tracking-tight">{purpose === "register" ? "Confirm your email" : "Enter your code"}</div>
              <div className="mt-1 text-[13.5px] text-mute">{method === "email" ? "Type the 6-digit code we just emailed you." : "Type the 6-digit code from your authenticator app."}</div>
            </div>
            {ch.methods.includes("totp") && (
              <div className="grid grid-cols-2 gap-1 rounded-lg bg-slate-100 p-1 text-xs">
                {([["email", "Email code", Mail], ["totp", "Authenticator app", Smartphone]] as const).map(([m, l, I]) => (
                  <button key={m} onClick={() => { setMethod(m); setCode(""); setError(null); }} className={cx("flex items-center justify-center gap-1.5 rounded-md py-1.5 font-semibold", method === m ? "bg-white text-cy shadow-sm" : "text-mute")}><I size={13} />{l}</button>
                ))}
              </div>
            )}
            {method === "email" && d && (
              failed ? (
                <div role="alert" className="rounded-lg border border-rd/30 bg-rd/5 p-3 text-[12.5px] text-rd"><div className="mb-1 flex items-center gap-2 font-bold"><MailWarning size={16} /> The email was not delivered</div>{d.detail}</div>
              ) : d.dev_mode ? (
                <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-[12.5px] text-am">
                  <div className="mb-1 flex items-center gap-2 font-bold"><AlertTriangle size={15} /> Practice mode — email is switched off</div>
                  <div>{d.detail}</div>
                  <div className="mt-2 flex items-center gap-2 rounded-md bg-white px-3 py-2"><span className="text-mute">Your code:</span><span className="mono text-xl font-bold tracking-[0.3em] text-ink">{d.dev_otp}</span><CopyBtn text={d.dev_otp ?? ""} /></div>
                </div>
              ) : (
                <div className="flex items-start gap-2 rounded-lg border border-gn/30 bg-gn/5 p-3 text-[12.5px] text-gn"><Mail size={16} className="mt-0.5 shrink-0" /><div>We sent a code to <b>{ch.email_masked}</b>. Check your inbox (and spam folder).</div></div>
              )
            )}
            <OtpBoxes value={code} onChange={setCode} disabled={busy || (method === "email" && remaining === 0)} shake={shake > 0 && !!error} onComplete={verify} />
            <div className="flex items-center justify-between text-xs">
              {method === "email" ? <span className={cx("mono font-semibold", remaining === 0 ? "text-rd" : remaining <= 15 ? "text-am" : "text-cy")}>{remaining === 0 ? "Code expired" : `Expires in 0:${String(remaining).padStart(2, "0")}`}</span> : <span className="text-mute">Codes refresh every 30 seconds</span>}
              {left !== null && <span className="font-semibold text-am">{left} attempt{left === 1 ? "" : "s"} left</span>}
            </div>
            {method === "email" && <div className="h-1 overflow-hidden rounded-full bg-slate-200"><div className="h-full rounded-full transition-all" style={{ width: `${(remaining / ch.ttl) * 100}%`, background: remaining <= 15 ? "#d97706" : "#4f46e5" }} /></div>}
            {error && <div role="alert" className="flex gap-2 rounded-lg border border-rd/30 bg-rd/5 p-2.5 text-[13px] text-rd"><AlertTriangle size={16} className="mt-0.5 shrink-0" />{error}</div>}
            <Btn size="lg" className="w-full" loading={busy} disabled={code.length !== 6 || (method === "email" && remaining === 0)} onClick={() => verify(code)} icon={busy ? undefined : <ShieldCheck size={16} />}>{purpose === "register" ? "Confirm and continue" : "Verify and sign in"}</Btn>
            {method === "email" && (
              <button onClick={resend} disabled={resendIn > 0 || busy} className="flex w-full items-center justify-center gap-2 text-[13px] font-semibold text-cy disabled:text-mute">
                {busy ? <Loader2 size={14} className="spin" /> : <RefreshCw size={14} />}{resendIn > 0 ? `Send a new code in ${resendIn}s` : "Send a new code"}
              </button>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

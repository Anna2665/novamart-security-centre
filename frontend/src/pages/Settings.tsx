import { motion } from "framer-motion";
import { AlertTriangle, CheckCircle2, Mail, MailWarning, RotateCcw, Send, Settings as Cog, Trash2 } from "lucide-react";
import { useState } from "react";
import { Badge, Btn, Card, CardHead, Confirm, ErrorBox, PageHead, Spinner, Switch, useFetch } from "../components/ui";
import { get, post, put } from "../lib/api";
import { cx } from "../lib/util";
import { useStore } from "../store";

export function Settings() {
  const { toast, can, user } = useStore();
  const s = useFetch<any>(() => get("/settings"), []);
  const [test, setTest] = useState<any>(null);
  const [busy, setBusy] = useState("");
  const [confirm, setConfirm] = useState(false);
  if (s.loading && !s.data) return <Spinner />;
  if (!s.data) return <ErrorBox error={s.error ?? "No data"} retry={s.reload} />;
  const d = s.data, admin = can("settings:manage");

  async function sendTest() { setBusy("t"); try { setTest(await post("/settings/test-email")); } catch (e: any) { toast("err", "Test failed", e.message); } finally { setBusy(""); } }
  async function telemetry(v: boolean) { try { await put("/settings", { telemetry_enabled: v }); toast("ok", v ? "Background telemetry on" : "Background telemetry off"); s.reload(); } catch (e: any) { toast("err", "Could not change", e.message); } }
  async function reset() { setConfirm(false); setBusy("r"); try { await post("/settings/reset-all", { confirm: true }); toast("ok", "Simulation reset", "Defences, node states, incidents' impact and the sandbox were restored."); await useStore.getState().refreshLive(); } catch (e: any) { toast("err", "Reset refused", e.message); } finally { setBusy(""); } }

  return (
    <div className="space-y-4">
      <PageHead icon={<Cog size={20} />} title="System Settings" sub="Email delivery for one-time codes, telemetry and platform information." />
      <div className="grid gap-4 xl:grid-cols-2">
        <Card className="p-4">
          <div className="flex items-center gap-2 text-[13px] font-semibold"><Mail size={16} className="text-cy" />Email delivery (SMTP)<Badge tone={d.smtp.configured ? "gn" : "rd"} dot>{d.smtp.configured ? "configured" : "not configured"}</Badge></div>
          <div className="mt-3 grid grid-cols-2 gap-2 text-[12.5px]">{[["Host", d.smtp.host ?? "—"], ["Port", d.smtp.port], ["Security", d.smtp.security], ["Sender", d.smtp.user], ["Password", d.smtp.password], ["OTP recipient", d.recipient]].map(([k, v]) => <div key={k} className="rounded-lg border border-line bg-panel2 p-2"><div className="text-[10px] font-semibold uppercase tracking-wider text-mute">{k}</div><div className="mono mt-0.5 break-all">{String(v)}</div></div>)}</div>
          {!d.smtp.configured && <div className="mt-3 rounded-lg border border-amber-200 bg-amber-50 p-3 text-[12.5px] text-am"><b>Real email OTP needs SMTP.</b> Put the sender's SMTP settings in <span className="mono">.env</span> (see <span className="mono">.env.example</span>) and restart. For Gmail, enable 2-Step Verification, create an <b>App password</b>, and use it as <span className="mono">SMTP_PASSWORD</span>.</div>}
          <div className="mt-3"><Btn icon={<Send size={15} />} loading={busy === "t"} disabled={!admin} onClick={sendTest}>Send test email to the OTP recipient</Btn></div>
          {test && <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className={cx("mt-3 flex items-start gap-2 rounded-lg border p-3 text-[12.5px]", test.status === "sent" ? "border-gn/50 bg-gn/10 text-gn" : "border-rd/50 bg-rd/10 text-rd")}>
            {test.status === "sent" ? <CheckCircle2 size={16} className="mt-0.5 shrink-0" /> : <MailWarning size={16} className="mt-0.5 shrink-0" />}<div><b>{test.status === "sent" ? "Email accepted by the SMTP server" : "Email NOT sent"}</b><div className="mt-0.5 opacity-90">{test.detail}</div></div></motion.div>}
          {!admin && <div className="mt-2 text-[12px] text-mute">Only admins can send test emails.</div>}
        </Card>

        <div className="space-y-4">
          <Card className="p-4"><div className="text-[13px] font-semibold">One-time password policy</div>
            <div className="mt-3 grid grid-cols-3 gap-2 text-center text-[12px]">{[["Lifetime", `${d.otp.ttl}s`], ["Max attempts", d.otp.max_attempts], ["Code length", "6 digits"]].map(([k, v]) => <div key={k} className="rounded-lg border border-line bg-panel2 p-2"><div className="text-[10px] uppercase tracking-wider text-mute">{k}</div><div className="mono mt-0.5 text-lg font-bold text-cy">{v}</div></div>)}</div>
            {d.otp.dev_echo && <div className="mt-3 flex gap-2 rounded-lg border border-amber-200 bg-amber-50 p-2.5 text-[12.5px] text-am"><AlertTriangle size={16} className="shrink-0" /><div><b>OTP_DEV_ECHO is ON.</b> Codes are shown on the login screen. Turn it off for a real demo so codes only arrive by email.</div></div>}</Card>
          <Card className="p-4"><div className="flex items-center justify-between"><div><div className="text-[13px] font-semibold">Background telemetry</div><div className="text-[12px] text-mute">Occasional simulated scans and probes so the dashboards stay alive. Always labelled SIM.</div></div><Switch on={d.telemetry_enabled} onChange={telemetry} disabled={!admin} label="Telemetry" /></div></Card>
          <Card className="p-4"><div className="text-[13px] font-semibold">Platform</div>
            <div className="mt-2 grid grid-cols-2 gap-2 text-[12.5px]">{[["Version", d.version], ["Database", d.database], ["Session length", `${d.session_minutes} min`], ["Signed in as", `${user.username} (${user.role})`]].map(([k, v]) => <div key={k} className="flex justify-between rounded-lg border border-line bg-panel2 px-3 py-1.5"><span className="text-mute">{k}</span><span className="mono">{v}</span></div>)}</div></Card>
          <Card className="border-rd/30 p-4"><div className="flex items-center gap-2 text-[13px] font-semibold text-rd"><Trash2 size={15} />Reset simulation</div>
            <p className="mt-1 text-[12.5px] text-mute">Restores all defences to ON, clears node states and unresolved attack damage, restores the sandbox volume and re-signs any tampered records. Audit history is kept.</p>
            <Btn className="mt-3" variant="danger" icon={<RotateCcw size={15} />} disabled={!can("system:reset")} loading={busy === "r"} onClick={() => setConfirm(true)}>Reset to a clean state</Btn></Card>
        </div>
      </div>
      <Confirm open={confirm} danger title="Reset the simulation?" body="Defences return to ON, damage is cleared and any tampered demo records are restored. The audit log is preserved." confirmLabel="Reset" onConfirm={reset} onCancel={() => setConfirm(false)} />
    </div>
  );
}

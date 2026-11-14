import { BookOpen, CheckCircle2, ExternalLink, MonitorPlay, Power, ShieldCheck, ShieldOff } from "lucide-react";
import { ReactNode, useState } from "react";
import { Badge, Btn, Card, PageHead, Switch } from "../components/ui";
import { post } from "../lib/api";
import { cx } from "../lib/util";
import { useStore } from "../store";

function Scene({ n, title, goal, cia, children }: { n: number; title: string; goal: string; cia?: string; children: ReactNode }) {
  return (
    <Card className="p-5">
      <div className="flex items-start gap-3.5">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-cy text-[15px] font-bold text-white">{n}</div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2"><h2 className="text-[17px] font-bold tracking-tight">{title}</h2>{cia && <Badge tone="vi">{cia}</Badge>}</div>
          <p className="mt-1 text-[13.5px] text-mute">{goal}</p>
          <div className="mt-3 space-y-3 text-[14px] leading-relaxed">{children}</div>
        </div>
      </div>
    </Card>
  );
}
const Do = ({ children }: { children: ReactNode }) => <div className="flex gap-2.5"><span className="mt-0.5 shrink-0 self-start rounded bg-slate-900 px-1.5 py-0.5 text-[10.5px] font-bold uppercase tracking-wide text-white">Do</span><div>{children}</div></div>;
const See = ({ children }: { children: ReactNode }) => <div className="flex gap-2.5"><span className="mt-0.5 shrink-0 self-start rounded bg-gn px-1.5 py-0.5 text-[10.5px] font-bold uppercase tracking-wide text-white">See</span><div>{children}</div></div>;
const Say = ({ children }: { children: ReactNode }) => <div className="rounded-lg border border-cy/20 bg-cy/5 p-3 text-[13.5px] italic text-slate-700"><span className="mr-1.5 not-italic font-bold text-cy">Say:</span>{children}</div>;
const K = ({ children }: { children: ReactNode }) => <code className="mono rounded bg-slate-100 px-1.5 py-0.5 text-[12.5px] text-slate-800">{children}</code>;

export function Guide() {
  const { live, can, toast, health } = useStore();
  const [busy, setBusy] = useState(false);
  const mode: string = live?.mode ?? "enabled";
  const on = mode === "enabled";
  async function setAll(v: boolean) {
    setBusy(true);
    try { await post("/sim/mode", { enabled: v }); void useStore.getState().refreshLive(); toast(v ? "ok" : "warn", v ? "All defences are ON" : "All defences are OFF", v ? "Attacks will now be stopped." : "The shop is now deliberately unprotected."); }
    catch (e: any) { toast("err", "Could not change defences", e.message); } finally { setBusy(false); }
  }
  const shopUrl = `${location.origin}/#/`;
  return (
    <div className="space-y-4">
      <PageHead icon={<BookOpen size={20} />} title="Guided Demo" sub="A step-by-step script for presenting this project. Follow the scenes in order; each one tells you what to click, what you will see, and what to say." />

      <Card className="p-5">
        <div className="grid gap-5 md:grid-cols-[1fr_auto]">
          <div>
            <h2 className="text-[16px] font-bold">The idea in four sentences</h2>
            <ol className="mt-2 list-decimal space-y-1 pl-5 text-[14px] leading-relaxed text-slate-700">
              <li><b>NovaMart</b> is a working online shop (System A): customers register, search, review, buy and see their orders.</li>
              <li>This <b>Security Centre</b> (System B) is the control room that protects it: it watches, blocks, alerts and recovers.</li>
              <li>We attack the shop on purpose. With the defences <b>off</b> the attack works; with them <b>on</b> it is stopped.</li>
              <li>Everything is judged by the <b>CIA triad</b>: <b>C</b>onfidentiality (secrets stay secret), <b>I</b>ntegrity (data cannot be changed unnoticed), <b>A</b>vailability (the shop stays up).</li>
            </ol>
          </div>
          <div className="min-w-[250px] space-y-3 rounded-xl border border-line bg-slate-50 p-4">
            <div className="text-[12px] font-semibold uppercase tracking-wide text-mute">Quick controls</div>
            <a href={shopUrl} target="_blank" rel="noreferrer"><Btn variant="ghost" className="w-full" icon={<ExternalLink size={15} />}>Open the shop in a new tab</Btn></a>
            <div className="flex items-center justify-between gap-3 rounded-lg border border-line bg-white p-3">
              <div><div className="text-[13px] font-semibold">All defences</div><div className={cx("text-[12.5px] font-semibold", on ? "text-gn" : mode === "disabled" ? "text-rd" : "text-am")}>{on ? "ON — shop is protected" : mode === "disabled" ? "OFF — shop is vulnerable" : "PARTIAL"}</div></div>
              <Switch on={on} onChange={setAll} disabled={!can("sim:configure") || busy || !!live?.running} label="All defences" />
            </div>
            <div className="flex items-center gap-2 text-[12.5px] text-mute">{health?.smtp_configured ? <><CheckCircle2 size={15} className="text-gn" />Real email is set up</> : <><Power size={15} className="text-am" />Email is not set up — codes appear on screen</>}</div>
          </div>
        </div>
      </Card>

      <Scene n={1} title="Set up the stage" goal="Two windows side by side, so the audience sees cause and effect.">
        <Do>Keep this window (the Security Centre). Click <b>Open the shop in a new tab</b> above and place the two windows side by side.</Do>
        <Do>In the shop, click <b>Sign in → Create an account</b>, register with your own email, and type the 6-digit code that arrives in your inbox. Afterwards press the sign-out icon and sign in again to show the sign-in flow (password, then a fresh code).</Do>
        <See>A real, professional email arrives from “NovaMart Security”, then you are signed in as a customer.</See>
        <Say>“A customer signs up and proves the email address is theirs with a one-time code. That is multi-factor authentication — Confidentiality of the account.”</Say>
      </Scene>

      <Scene n={2} title="Attack 1 — SQL injection on the search box" cia="Confidentiality" goal="An attacker types database commands instead of a product name, to make the shop leak data it should hide.">
        <Do>Turn <b>All defences OFF</b> (switch above). In the shop, click <b>Attacker's toolbox</b> (bottom-left) and press <K>' OR 1=1 --</K>.</Do>
        <See>A <b>red “Attack succeeded”</b> panel on the shop shows the exact database query that ran and the rows that leaked. Here in the Security Centre a new alert appears and the Confidentiality score drops.</See>
        <Do>Turn <b>All defences ON</b> and press the same payload again.</Do>
        <See>A <b>green “Attack blocked”</b> panel: the Web Application Firewall recognised the pattern. Turn individual defences off one at a time (Attack Simulation page) and the next layer — input validation, then parameterised queries — still catches it.</See>
        <Say>“Defence in depth: three independent layers each stop SQL injection. Parameterised queries mean the text is only ever treated as data, never as a command.”</Say>
      </Scene>

      <Scene n={3} title="Attack 2 — a malicious script in a product review (XSS)" cia="Integrity" goal="An attacker posts JavaScript as a review so it runs in every visitor's browser and steals their session.">
        <Do>With defences OFF, in the toolbox press <b>Post a script as a review</b> (you must be signed in as a customer).</Do>
        <See>Red panel: the script was saved exactly as typed. With defences ON the panel turns green: blocked by the firewall, or the dangerous tags were removed before saving.</See>
        <Say>“The fix is never to trust user input: filter it on the way in and escape it on the way out. Our page also sends a strict Content-Security-Policy header.”</Say>
      </Scene>

      <Scene n={4} title="Attack 3 — reading someone else's order (IDOR)" cia="Confidentiality" goal="A logged-in customer changes the order number in the address to peek at a stranger's purchase.">
        <Do>Toolbox → <b>Open order NM-1001</b>. First with the defences OFF, then ON.</Do>
        <See>OFF: the panel shows another customer's name and items. ON: <b>access denied</b> — the server checks that the order belongs to you (role-based access control).</See>
        <Say>“Authentication says who you are; authorisation says what you may touch. Every request is re-checked on the server.”</Say>
      </Scene>

      <Scene n={5} title="Attack 4 — tampering with a price in the database" cia="Integrity" goal="An insider or intruder edits a price directly in the database, bypassing the website.">
        <Do>Go to <b>Database Security</b> in the left menu. Pick a product, set a very low price (for example ₹1) and press <b>Modify the record directly</b>.</Do>
        <Do>Back in the shop, refresh and try to buy that product.</Do>
        <See>With defences ON the shop refuses: <b>“price being verified”</b>, because the stored price no longer matches its digital signature. With defences OFF the order goes through at the fake price. Afterwards press <b>Restore trusted version</b> on the Database page.</See>
        <Say>“Every product is digitally signed (RSA). Change one rupee and the signature breaks — Integrity you can prove.”</Say>
      </Scene>

      <Scene n={6} title="Attack 5 — flooding the checkout" cia="Availability" goal="Too many orders in a few seconds can overload a shop; a rate limiter keeps it available for real customers.">
        <Do>Toolbox → <b>Fire 10 orders at once</b> with defences ON, then OFF.</Do>
        <See>ON: only 8 per minute are accepted and the rest are refused (HTTP 429). OFF: all 10 go through. Note: this creates a few cheap test orders.</See>
      </Scene>

      <Scene n={7} title="The fraud check" cia="Integrity" goal="Suspicious orders are held for a human before any money moves.">
        <Do>In the shop add 5 × <b>PixelPad 10″ Tablet</b> to the cart and place the order.</Do>
        <See>The customer sees “we're doing a quick safety check”, with the reasons. Open <b>Store Orders & Fraud Review</b> here: the order is waiting. Press <b>Approve</b> — the customer is emailed a receipt — or <b>Reject</b>, which returns the stock and refunds the payment.</See>
      </Scene>

      <Scene n={8} title="Ransomware, backup and recovery" cia="Availability" goal="If everything else fails, the team recovers from encrypted, verified backups.">
        <Do>Attack Simulation → choose <b>Ransomware</b> with defences OFF → Launch. Watch the files turn red.</Do>
        <Do>Open <b>Incident Response</b>, follow the checklist and press the recovery actions; then show <b>Backup &amp; Recovery</b> (every backup is encrypted, hashed and signed).</Do>
        <Say>“Prevention is never perfect, so we also plan for recovery: detect, contain, eradicate, restore, learn.”</Say>
      </Scene>

      <Card className="p-5">
        <div className="flex items-center gap-2 text-[16px] font-bold"><ShieldCheck size={18} className="text-cy" />If sir asks: what is real and what is simulated?</div>
        <div className="mt-3 grid gap-4 md:grid-cols-2 text-[13.5px]">
          <div><div className="mb-1.5 flex items-center gap-2 font-semibold text-gn"><ShieldCheck size={15} />Real</div>
            <ul className="list-disc space-y-1 pl-5 text-slate-700"><li>The shop: accounts, search, reviews, cart, checkout, orders</li><li>Email one-time codes and receipts (real SMTP when configured)</li><li>Password hashing (Argon2id), AES-256-GCM encryption, RSA digital signatures</li><li>Role-based access, account lockout, rate limiting, firewall rules, audit log chain</li><li>The fraud risk score and review queue</li></ul></div>
          <div><div className="mb-1.5 flex items-center gap-2 font-semibold text-am"><ShieldOff size={15} />Simulated (safely)</div>
            <ul className="list-disc space-y-1 pl-5 text-slate-700"><li>The attacker — you play them with the toolbox and the attack lab</li><li>SQL injection runs against an isolated, read-only copy of fake data — never the real database</li><li>Ransomware, DDoS volume and the network map are animations of what would happen</li><li>Historical attack statistics (labelled SIM)</li></ul></div>
        </div>
      </Card>
      <div className="flex items-center justify-center gap-2 pb-4 text-[12.5px] text-mute"><MonitorPlay size={14} />Tip: practise the scenes once before the demo, and leave defences ON when you finish.</div>
    </div>
  );
}

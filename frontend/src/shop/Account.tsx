import { Smartphone } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { useEffect, useState } from "react";
import { ApiError, get, post, put } from "../lib/api";
import { go } from "../lib/route";
import { fmtDateTime } from "../lib/util";
import { useStore } from "../store";
import { Badge, Btn, CopyBtn, Spinner } from "../components/ui";
import { ShopLayout } from "./Layout";

export function AccountPage() {
  const { user, toast } = useStore();
  const [me, setMe] = useState<any>(null);
  const [form, setForm] = useState({ name: "", phone: "", address: "" });
  const [busy, setBusy] = useState("");
  const [en, setEn] = useState<any>(null);
  const [code, setCode] = useState("");
  const load = () => get("/shop/me").then((m) => { setMe(m); setForm({ name: m.name, phone: m.phone, address: m.address }); }).catch((e) => toast("err", "Could not load your account", e.message));
  useEffect(() => { if (user?.role !== "customer") go("signin"); else void load(); /* eslint-disable-next-line */ }, [user]);

  async function save(e: React.FormEvent) {
    e.preventDefault(); setBusy("save");
    try { setMe(await put("/shop/me", form)); toast("ok", "Details saved", "Your phone and address are stored encrypted."); } catch (er) { toast("err", "Could not save", (er as ApiError).message); } finally { setBusy(""); }
  }
  const run = async (key: string, fn: () => Promise<void>) => { setBusy(key); try { await fn(); } catch (er) { toast("err", "That did not work", (er as ApiError).message); } finally { setBusy(""); } };

  return (
    <ShopLayout>
      <h1 className="mb-5 text-[26px] font-extrabold tracking-tight">My account</h1>
      {!me ? <Spinner /> : (
        <div className="grid gap-6 md:grid-cols-2">
          <form onSubmit={save} className="card space-y-3 p-5">
            <h2 className="text-[16px] font-bold">Your details</h2>
            <div className="text-[13px] text-mute">Signed in as <b className="text-ink">{me.email}</b> · member since {fmtDateTime(me.member_since)}</div>
            <label className="block text-[13px] font-medium text-slate-700">Full name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="mt-1.5" /></label>
            <label className="block text-[13px] font-medium text-slate-700">Phone<input value={form.phone} onChange={(e) => setForm({ ...form, phone: e.target.value })} className="mt-1.5" maxLength={20} /></label>
            <label className="block text-[13px] font-medium text-slate-700">Delivery address<textarea value={form.address} onChange={(e) => setForm({ ...form, address: e.target.value })} rows={3} className="mt-1.5" maxLength={200} /></label>
            <Btn type="submit" loading={busy === "save"} disabled={form.name.trim().length < 2}>Save changes</Btn>
            <p className="text-[12px] text-mute">Your phone number and address are encrypted (AES-256-GCM) before they are stored.</p>
          </form>
          <section className="card p-5">
            <h2 className="flex items-center gap-2 text-[16px] font-bold"><Smartphone size={17} className="text-cy" />Two-step sign-in <Badge tone={me.totp_enabled ? "gn" : "mute"} dot>{me.totp_enabled ? "On" : "Off"}</Badge></h2>
            <p className="mt-2 text-[13.5px] leading-relaxed text-slate-600">We always email you a code when you sign in. You can also use an authenticator app (Google Authenticator, Authy) for extra protection.</p>
            {!me.totp_enabled && !en && <Btn className="mt-3" loading={busy === "e"} onClick={() => run("e", async () => { setEn(await post("/auth/totp/enroll")); setCode(""); })}>Set up authenticator app</Btn>}
            {en && (
              <div className="mt-4 space-y-3">
                <div className="inline-block rounded-xl border border-line bg-white p-3"><QRCodeSVG value={en.uri} size={150} /></div>
                <div className="text-[12.5px] text-mute">Scan this with your authenticator app, or type the secret:</div>
                <div className="mono flex items-center gap-2 rounded-lg border border-line bg-slate-50 p-2.5 text-[13px] tracking-wider">{en.secret}<CopyBtn text={en.secret} /></div>
                <div className="flex gap-2"><input className="mono !w-40 text-center tracking-[0.3em]" inputMode="numeric" maxLength={6} placeholder="000000" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} aria-label="Authenticator code" />
                  <Btn loading={busy === "c"} disabled={code.length !== 6} onClick={() => run("c", async () => { await post("/auth/totp/confirm", { code }); toast("ok", "Authenticator enrolled", "You can choose it at your next sign-in."); setEn(null); setCode(""); await load(); })}>Confirm</Btn></div>
              </div>
            )}
            {me.totp_enabled && (
              <div className="mt-4 flex gap-2"><input className="mono !w-40 text-center tracking-[0.3em]" inputMode="numeric" maxLength={6} placeholder="code" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} aria-label="Code to turn off" />
                <Btn variant="danger" loading={busy === "d"} disabled={code.length !== 6} onClick={() => run("d", async () => { await post("/auth/totp/disable", { code }); toast("warn", "Authenticator removed"); setCode(""); await load(); })}>Turn off</Btn></div>
            )}
          </section>
        </div>
      )}
    </ShopLayout>
  );
}

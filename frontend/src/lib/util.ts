export const cx = (...a: (string | false | null | undefined)[]) => a.filter(Boolean).join(" ");
export const inr = (n: number) => "₹" + Math.round(n).toLocaleString("en-IN");
export const fmtTime = (iso?: string) => (iso ? new Date(iso).toLocaleTimeString("en-GB", { hour12: false }) : "—");
export const fmtDateTime = (iso?: string) =>
  iso ? new Date(iso).toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }) : "—";
export function ago(iso?: string) {
  if (!iso) return "—";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
export const clamp = (n: number, a = 0, b = 100) => Math.min(b, Math.max(a, n));

export const STATUS: Record<string, { label: string; color: string; ring: string }> = {
  healthy: { label: "Healthy", color: "#2563eb", ring: "rgba(79,70,229,.35)" },
  under_attack: { label: "Under attack", color: "#d97706", ring: "rgba(217,119,6,.45)" },
  compromised: { label: "Compromised", color: "#dc2626", ring: "rgba(220,38,38,.5)" },
  protected: { label: "Protected", color: "#059669", ring: "rgba(5,150,105,.45)" },
  isolated: { label: "Isolated", color: "#7c3aed", ring: "rgba(124,58,237,.45)" },
  degraded: { label: "Degraded", color: "#ea580c", ring: "rgba(234,88,12,.45)" },
};

export const RESULT: Record<string, { label: string; tone: "gn" | "am" | "rd" | "cy" }> = {
  blocked: { label: "Blocked", tone: "gn" },
  contained: { label: "Contained", tone: "am" },
  breach: { label: "Breach", tone: "rd" },
  detected: { label: "Detected", tone: "cy" },
};
export const SEV_TONE: Record<string, "gn" | "am" | "rd" | "cy" | "mute"> = { low: "cy", medium: "am", high: "rd", critical: "rd", info: "mute" };

export const PILLAR_NAME: Record<string, string> = { C: "Confidentiality", I: "Integrity", A: "Availability" };
export const PILLAR_COLOR: Record<string, string> = { C: "#4f46e5", I: "#7c3aed", A: "#059669" };

export function copy(text: string) {
  try { void navigator.clipboard.writeText(text); } catch { /* ignore */ }
}

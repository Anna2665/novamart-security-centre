import { BedDouble, Dumbbell, Footprints, Headphones, Lamp, Package, Backpack, Speaker, Tablet, Watch, Zap, CookingPot, Coffee } from "lucide-react";
import { ReactNode } from "react";

const ART: Record<string, { icon: ReactNode; from: string; to: string }> = {
  "NVB-001": { icon: <Headphones />, from: "#6366f1", to: "#a5b4fc" },
  "AFB-002": { icon: <Watch />, from: "#0ea5e9", to: "#7dd3fc" },
  "TMB-003": { icon: <Backpack />, from: "#f59e0b", to: "#fde68a" },
  "PBK-004": { icon: <Coffee />, from: "#10b981", to: "#6ee7b7" },
  "LMD-005": { icon: <Lamp />, from: "#f97316", to: "#fdba74" },
  "CMA-006": { icon: <CookingPot />, from: "#ef4444", to: "#fca5a5" },
  "FMY-007": { icon: <Dumbbell />, from: "#8b5cf6", to: "#c4b5fd" },
  "SSB-008": { icon: <Speaker />, from: "#14b8a6", to: "#99f6e4" },
  "CCB-009": { icon: <BedDouble />, from: "#ec4899", to: "#f9a8d4" },
  "PXT-010": { icon: <Tablet />, from: "#3b82f6", to: "#93c5fd" },
  "VCG-011": { icon: <Zap />, from: "#eab308", to: "#fde047" },
  "SRS-012": { icon: <Footprints />, from: "#06b6d4", to: "#67e8f9" },
};

/** Illustrated product tile (no external images needed, so the shop works offline in the demo room). */
export function Art({ sku, size = 56, className = "" }: { sku: string; size?: number; className?: string }) {
  const a = ART[sku] ?? { icon: <Package />, from: "#64748b", to: "#cbd5e1" };
  return (
    <div className={`relative flex items-center justify-center overflow-hidden ${className}`} style={{ background: `linear-gradient(135deg, ${a.from}, ${a.to})` }} aria-hidden>
      <div className="absolute -right-6 -top-6 h-28 w-28 rounded-full bg-white/20" />
      <div className="absolute -bottom-8 -left-6 h-24 w-24 rounded-full bg-white/10" />
      <div className="relative text-white drop-shadow-sm [&>svg]:h-[var(--s)] [&>svg]:w-[var(--s)]" style={{ ["--s" as any]: `${size}px` }}>{a.icon}</div>
    </div>
  );
}

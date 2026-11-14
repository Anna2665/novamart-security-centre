import { create } from "zustand";

export interface Product {
  id: number; sku: string; name: string; category: string; price: number | null; stock: number; description: string;
  rating: number; reviews: number; price_verified: boolean; available: boolean; reviews_list?: Review[];
}
export interface Review { id: number; author: string; rating: number; body: string; created_at: string }
export interface Security {
  attack: string; result: "blocked" | "neutralised" | "breach"; by?: string | null; payload?: string; message?: string;
  query?: string; leaked?: any[]; error?: string | null; detected?: boolean; lab_run?: string | null; product?: string;
}

export const PAYMENTS = [
  { id: "UPI", label: "UPI", hint: "Pay instantly with any UPI app (demo — no money moves)." },
  { id: "Card", label: "Credit / debit card", hint: "Demo only. Never type a real card number here." },
  { id: "Cash on delivery", label: "Cash on delivery", hint: "Pay when the parcel arrives." },
];

export interface CartLine { id: number; sku: string; name: string; price: number; qty: number; category: string }
interface CartState {
  lines: CartLine[];
  add: (p: { id: number; sku: string; name: string; price: number; category: string }, qty?: number) => void;
  setQty: (id: number, qty: number) => void;
  remove: (id: number) => void;
  clear: () => void;
}
const KEY = "novamart_cart";
const load = (): CartLine[] => { try { const v = JSON.parse(localStorage.getItem(KEY) ?? "[]"); return Array.isArray(v) ? v : []; } catch { return []; } };
const save = (l: CartLine[]) => { try { localStorage.setItem(KEY, JSON.stringify(l)); } catch { /* storage unavailable */ } };

export const useCart = create<CartState>((set, get) => ({
  lines: load(),
  add: (p, qty = 1) => {
    const lines = [...get().lines];
    const i = lines.findIndex((l) => l.id === p.id);
    if (i >= 0) lines[i] = { ...lines[i], qty: Math.min(10, lines[i].qty + qty) };
    else lines.push({ ...p, qty: Math.min(10, qty) });
    save(lines); set({ lines });
  },
  setQty: (id, qty) => { const lines = get().lines.map((l) => (l.id === id ? { ...l, qty: Math.max(1, Math.min(10, qty)) } : l)); save(lines); set({ lines }); },
  remove: (id) => { const lines = get().lines.filter((l) => l.id !== id); save(lines); set({ lines }); },
  clear: () => { save([]); set({ lines: [] }); },
}));

export const cartCount = (l: CartLine[]) => l.reduce((a, b) => a + b.qty, 0);
export const cartTotal = (l: CartLine[]) => l.reduce((a, b) => a + b.qty * b.price, 0);

export const STATUS_LABEL: Record<string, { label: string; tone: "gn" | "am" | "rd" | "cy" | "mute" }> = {
  paid: { label: "Confirmed", tone: "gn" },
  review: { label: "Being checked", tone: "am" },
  cancelled: { label: "Cancelled", tone: "rd" },
  pending: { label: "Pending", tone: "cy" },
  shipped: { label: "Shipped", tone: "cy" },
  delivered: { label: "Delivered", tone: "gn" },
};

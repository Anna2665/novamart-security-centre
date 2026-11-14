import { create } from "zustand";
import { API_BASE, api, get, getToken, post, setToken, setUnauthorizedHandler } from "./lib/api";

export interface Toast { id: number; kind: "ok" | "err" | "warn" | "info"; title: string; msg?: string }
export interface RunView { run: any; active: number; done: number; ended: boolean; incident?: any }

interface S {
  user: any | null;
  booting: boolean;
  live: any | null;
  topology: { nodes: any[]; edges: any[] } | null;
  events: any[];
  run: RunView | null;
  wsOpen: boolean;
  bump: Record<string, number>;
  toasts: Toast[];
  health: { smtp_configured: boolean } | null;
  devEcho: boolean;
  init: () => Promise<void>;
  signedIn: (token: string, user: any) => void;
  logout: () => Promise<void>;
  toast: (kind: Toast["kind"], title: string, msg?: string) => void;
  dismiss: (id: number) => void;
  startRun: (run: any) => void;
  can: (perm: string) => boolean;
  refreshLive: () => Promise<void>;
}

let ws: WebSocket | null = null;
let wsTimer: ReturnType<typeof setTimeout> | null = null;
let ping: ReturnType<typeof setInterval> | null = null;
let localTimers: ReturnType<typeof setTimeout>[] = [];
let toastId = 1;

export const useStore = create<S>((set, getS) => ({
  user: null, booting: true, live: null, topology: null, events: [], run: null, wsOpen: false, bump: {}, toasts: [], health: null, devEcho: false,

  toast: (kind, title, msg) => {
    const id = toastId++;
    set((s) => ({ toasts: [...s.toasts.slice(-4), { id, kind, title, msg }] }));
    setTimeout(() => getS().dismiss(id), kind === "err" ? 8000 : 4800);
  },
  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
  can: (perm) => !!getS().user?.permissions?.includes(perm),

  init: async () => {
    setUnauthorizedHandler(() => {
      if (getS().user) getS().toast("warn", "Session ended", "Your session expired or was revoked. Please sign in again.");
      void getS().logout();
    });
    try { set({ health: await get("/health") }); } catch { /* server unreachable: login screen reports it */ }
    if (getToken()) {
      try {
        const me = await get("/auth/me");
        set({ user: { ...me, permissions: me.permissions } });
        if (me.role !== "customer") { connect(); await Promise.all([getS().refreshLive(), loadTopology()]); }
      } catch { setToken(null); }
    }
    set({ booting: false });
  },

  signedIn: (token, user) => {
    setToken(token);
    set({ user, booting: false });
    if (user.role !== "customer") { connect(); void getS().refreshLive(); void loadTopology(); }
  },

  logout: async () => {
    try { if (getToken()) await post("/auth/logout"); } catch { /* already invalid */ }
    setToken(null);
    if (wsTimer) clearTimeout(wsTimer);
    if (ping) clearInterval(ping);
    if (ws) { ws.onclose = null; ws.close(); ws = null; }
    clearLocal();
    set({ user: null, live: null, events: [], run: null, wsOpen: false, topology: null });
  },

  refreshLive: async () => {
    try { set({ live: await get("/sim/state") }); } catch { /* ignore */ }
  },

  startRun: (run) => {
    clearLocal();
    set({ run: { run, active: -1, done: 0, ended: false } });
    if (!getS().wsOpen) replayLocally(run);
  },
}));

async function loadTopology() {
  try { useStore.setState({ topology: await get("/sim/topology") }); } catch { /* ignore */ }
}

function clearLocal() { localTimers.forEach(clearTimeout); localTimers = []; }

/** Fallback when the WebSocket is down: replay the (already computed) run on a local timer. */
function replayLocally(run: any) {
  const d = (run.stage_delay ?? 1.7) * 1000;
  run.stages.forEach((_: any, i: number) => {
    localTimers.push(setTimeout(() => useStore.setState((s) => s.run && s.run.run.run_id === run.run_id ? { run: { ...s.run, active: i, done: i } } : s), 300 + i * d));
    localTimers.push(setTimeout(() => useStore.setState((s) => s.run && s.run.run.run_id === run.run_id ? { run: { ...s.run, active: -1, done: i + 1 } } : s), 300 + (i + 0.85) * d));
  });
  localTimers.push(setTimeout(() => {
    useStore.setState((s) => (s.run && s.run.run.run_id === run.run_id ? { run: { ...s.run, ended: true, done: run.stages.length, active: -1 } } : s));
    void useStore.getState().refreshLive();
    bumpKey("incident"); bumpKey("event");
  }, 300 + run.stages.length * d));
}

function bumpKey(k: string) { useStore.setState((s) => ({ bump: { ...s.bump, [k]: (s.bump[k] ?? 0) + 1 } })); }

function connect() {
  const tok = getToken();
  if (!tok || (ws && ws.readyState <= 1)) return;
  const wsBase = API_BASE ? API_BASE.replace(/^http/, "ws") : `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}`;
  ws = new WebSocket(`${wsBase}/api/ws?token=${encodeURIComponent(tok)}`);
  ws.onopen = () => {
    useStore.setState({ wsOpen: true });
    if (ping) clearInterval(ping);
    ping = setInterval(() => ws?.readyState === 1 && ws.send("ping"), 25000);
  };
  ws.onclose = () => {
    useStore.setState({ wsOpen: false });
    if (ping) clearInterval(ping);
    if (getToken()) wsTimer = setTimeout(connect, 2500);
  };
  ws.onmessage = (m) => {
    let msg: any;
    try { msg = JSON.parse(m.data); } catch { return; }
    const d = msg.data;
    switch (msg.type) {
      case "hello": useStore.setState({ live: d.state, events: d.events }); break;
      case "state": useStore.setState({ live: d }); break;
      case "event": useStore.setState((s) => ({ events: [d, ...s.events].slice(0, 300) })); bumpKey("event"); break;
      case "incident": bumpKey("incident"); break;
      case "audit": bumpKey("audit"); break;
      case "sim.start":
        clearLocal();
        useStore.setState((s) => (s.run?.run.run_id === d.run_id ? s : { run: { run: d, active: -1, done: 0, ended: false } }));
        break;
      case "sim.stage":
        useStore.setState((s) => {
          if (!s.run || s.run.run.run_id !== d.run_id) return s;
          return d.phase === "start" ? { run: { ...s.run, active: d.index, done: d.index } } : { run: { ...s.run, active: -1, done: d.index + 1 } };
        });
        break;
      case "sim.end":
        useStore.setState((s) => (s.run && s.run.run.run_id === d.run_id ? { run: { ...s.run, ended: true, done: s.run.run.stages.length, active: -1, incident: d.incident } } : s));
        bumpKey("incident"); bumpKey("backup"); bumpKey("db");
        break;
      case "backup": bumpKey("backup"); break;
    }
  };
}

export { api };

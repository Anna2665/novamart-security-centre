"""Shared live state: node statuses, defence switches, CIA impacts and history. One source of truth for REST + WebSocket."""
import random
import threading
import time
from datetime import datetime, timedelta, timezone

from ..bus import bus
from ..db import session_scope
from ..models import KV
from ..sim.defences import IDS as DEFENCE_IDS, pillar_baseline
from ..sim.topology import NODES

STATUSES = ("healthy", "under_attack", "compromised", "protected", "isolated", "degraded")


class LiveState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.reset(seed_history=True)

    def reset(self, seed_history: bool = False) -> None:
        with self.lock:
            self.nodes = {k: {"status": "healthy", "note": ""} for k in NODES}
            self.defences = {d: True for d in DEFENCE_IDS}
            self.impacts: list[dict] = []
            self.history: list[dict] = _seed_history() if seed_history else []
            self.running: dict | None = None
            self.speed = 1.0
            self.last_run: dict | None = None


def _seed_history() -> list[dict]:
    rng = random.Random(7)
    now = datetime.now(timezone.utc)
    out = []
    for i in range(48, 0, -1):
        dip = lambda: max(0, rng.gauss(0, 1.6)) + (rng.random() < 0.08) * rng.uniform(3, 8)  # noqa: E731
        out.append({"ts": (now - timedelta(minutes=30 * i)).isoformat(), "C": round(97 - dip(), 1), "I": round(98 - dip(), 1),
                    "A": round(98 - dip(), 1), "simulated": True})
    return out


live = LiveState()


# ---- defences ------------------------------------------------------------------------------------------------------
def mode() -> str:
    vals = list(live.defences.values())
    return "enabled" if all(vals) else "disabled" if not any(vals) else "custom"


def set_defence(did: str, on: bool) -> None:
    with live.lock:
        if did not in live.defences:
            raise KeyError(did)
        live.defences[did] = on
    changed()


def set_all_defences(on: bool) -> None:
    with live.lock:
        for k in live.defences:
            live.defences[k] = on
    changed()


# ---- nodes ---------------------------------------------------------------------------------------------------------
def set_node(node: str, status: str, note: str = "") -> None:
    with live.lock:
        if node in live.nodes:
            live.nodes[node] = {"status": status, "note": note}


def settle_run_nodes() -> None:
    """After a run: transient 'protected'/'under_attack' flashes settle back to healthy; compromised/isolated persist."""
    with live.lock:
        for n in live.nodes.values():
            if n["status"] in ("protected", "under_attack"):
                n["status"], n["note"] = "healthy", ""


# ---- CIA -----------------------------------------------------------------------------------------------------------
def add_impact(run_id: str, scenario: str, C: float, I: float, A: float) -> None:
    with live.lock:
        live.impacts.append({"run_id": run_id, "scenario": scenario, "C": C, "I": I, "A": A, "ts": time.time(), "resolved": False})


def resolve_impacts(run_id: str | None = None) -> int:
    n = 0
    with live.lock:
        for i in live.impacts:
            if not i["resolved"] and (run_id is None or i["run_id"] == run_id):
                i["resolved"] = True
                n += 1
    return n


def resolve_pillar(run_id: str | None, pillars: str) -> None:
    """Partial remediation, e.g. restoring a tampered record clears the integrity part of an impact only."""
    with live.lock:
        for i in live.impacts:
            if not i["resolved"] and (run_id is None or i["run_id"] == run_id):
                for p in pillars:
                    i[p] = 0
                if not (i["C"] or i["I"] or i["A"]):
                    i["resolved"] = True


def cia() -> dict:
    with live.lock:
        base = pillar_baseline(live.defences)
        imp = {p: round(sum(i[p] for i in live.impacts if not i["resolved"]), 1) for p in "CIA"}
        # availability also reflects nodes that are down right now
        down = sum(1 for n in live.nodes.values() if n["status"] in ("compromised", "isolated", "degraded"))
        score = {p: round(max(0.0, min(100.0, base[p] - imp[p] - (down * 1.5 if p == "A" else 0))), 1) for p in "CIA"}
        return {**score, "baseline": base, "impact": imp, "posture": round(sum(base.values()) / 3, 1),
                "overall": round(sum(score.values()) / 3, 1)}


def record_history(simulated: bool = False) -> None:
    c = cia()
    with live.lock:
        live.history.append({"ts": datetime.now(timezone.utc).isoformat(), "C": c["C"], "I": c["I"], "A": c["A"], "simulated": simulated})
        del live.history[:-400]


def active_impacts() -> list[dict]:
    with live.lock:
        return [i for i in live.impacts if not i["resolved"]]


# ---- snapshot / persistence ------------------------------------------------------------------------------------------
def snapshot() -> dict:
    with live.lock:
        counts: dict[str, int] = {}
        for n in live.nodes.values():
            counts[n["status"]] = counts.get(n["status"], 0) + 1
        return {"nodes": {k: dict(v) for k, v in live.nodes.items()}, "defences": dict(live.defences), "mode": mode(),
                "cia": cia(), "node_counts": counts, "running": live.running, "speed": live.speed,
                "active_impacts": len(active_impacts())}


def changed(history: bool = True) -> None:
    if history:
        record_history()
    save()
    bus.publish("state", snapshot())


def save() -> None:
    with live.lock:
        data = {"nodes": live.nodes, "defences": live.defences, "impacts": live.impacts[-60:], "history": live.history[-400:], "speed": live.speed}
    try:
        with session_scope() as db:
            row = db.get(KV, "live_state")
            if row:
                row.value, row.updated_at = data, time.time()
            else:
                db.add(KV(key="live_state", value=data, updated_at=time.time()))
    except Exception:  # persistence is best-effort, never break a request
        pass


def load() -> None:
    with session_scope() as db:
        row = db.get(KV, "live_state")
        if not row:
            return
        with live.lock:
            v = row.value
            live.nodes.update({k: x for k, x in v.get("nodes", {}).items() if k in NODES})
            live.defences.update({k: x for k, x in v.get("defences", {}).items() if k in live.defences})
            live.impacts = v.get("impacts", [])
            live.history = v.get("history") or live.history
            live.speed = v.get("speed", 1.0)

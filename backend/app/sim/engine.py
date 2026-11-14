"""Runs a scenario through the defence engine, then replays it stage-by-stage over the WebSocket."""
import secrets
import threading
import time
from datetime import datetime, timezone

from ..bus import bus
from ..db import session_scope
from ..models import SimRun
from ..services import audit, events, incidents, state
from .ctx import Ctx
from .defences import IDS
from .scenarios import BY_ID, SCENARIOS

STAGE_DELAY = 1.7  # seconds per stage at 1x
_cancel = threading.Event()


class Busy(Exception):
    pass


def mode_of(defences: dict[str, bool]) -> str:
    v = [bool(defences.get(d)) for d in IDS]
    return "enabled" if all(v) else "disabled" if not any(v) else "custom"


def build_run(scenario_id: str, defences: dict[str, bool], dry: bool = False, params: dict | None = None) -> dict:
    scen = BY_ID[scenario_id]
    ctx = Ctx(scen, defences, dry, params)
    scen.run(ctx)
    ctx.finish()
    frac = ctx.fraction if ctx.fraction is not None else {"blocked": 0.0, "contained": 0.45, "breach": 1.0}[ctx.result]
    impact = {p: round(scen.impact[p] * frac, 1) for p in "CIA"}
    top = max(impact.values())
    sev = {"blocked": "low", "contained": "high" if top >= 35 else "medium", "breach": "critical" if top >= 55 else "high"}[ctx.result]
    det = ctx.blocked_by or ", ".join(dict.fromkeys(ctx.detected_by + ctx.defence_used)) or "None — undetected"
    last = max((s for s in ctx.stages if s.status != "skipped"), key=lambda s: s.index)
    return {"run_id": "RUN-" + secrets.token_hex(4).upper(), "scenario_id": scen.id, "name": scen.name, "attack_type": scen.attack_type,
            "started_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z", "dry": dry, "mode": mode_of(defences),
            "defences": dict(defences), "result": ctx.result, "detected": bool(ctx.blocked_by or ctx.detected_by or ctx.defence_used), "severity": sev,
            "summary": ctx.summary, "detection": det, "defence_used": list(dict.fromkeys(ctx.defence_used)), "impact": impact,
            "impact_potential": scen.impact, "metrics": ctx.metrics, "source": scen.source, "target": scen.target,
            "source_node": scen.stages[0][3][0], "target_node": last.path[-1], "stage_delay": STAGE_DELAY,
            "stages": [s.to_dict() for s in ctx.stages]}


def execute(scenario_id: str, params: dict | None, actor: str, defences: dict[str, bool] | None = None) -> dict:
    if scenario_id not in BY_ID:
        raise KeyError("unknown scenario")
    with state.live.lock:
        if state.live.running:
            raise Busy("A simulation is already running — wait for it to finish or reset.")
        run = build_run(scenario_id, defences or dict(state.live.defences), False, params)
        state.live.running = {"run_id": run["run_id"], "scenario_id": scenario_id, "stage": -1, "total": len(run["stages"])}
    with session_scope() as db:
        db.add(SimRun(id=run["run_id"], scenario_id=scenario_id, result=run["result"], mode=run["mode"], detected=run["detected"],
                      severity=run["severity"], defences=run["defences"], payload=run))
    audit.log(actor, "sim.run", scenario_id, {"run": run["run_id"], "mode": run["mode"], "result": run["result"]})
    _cancel.clear()
    threading.Thread(target=_replay, args=(run,), daemon=True, name=f"replay-{run['run_id']}").start()
    return run


def cancel() -> None:
    _cancel.set()


def _sleep(sec: float) -> bool:
    end = time.time() + sec
    while time.time() < end:
        if _cancel.is_set():
            return False
        time.sleep(0.05)
    return True


def _replay(run: dict) -> None:
    try:
        delay = STAGE_DELAY / max(state.live.speed, 0.1)
        bus.publish("sim.start", run)
        for st in run["stages"]:
            if st["status"] == "skipped":
                continue
            with state.live.lock:
                if state.live.running:
                    state.live.running["stage"] = st["index"]
            for n, s in st["starts"].items():
                if state.live.nodes[n]["status"] not in ("compromised", "isolated", "degraded"):
                    state.set_node(n, s)
            bus.publish("sim.stage", {"run_id": run["run_id"], "index": st["index"], "phase": "start"})
            bus.publish("state", state.snapshot())
            if not _sleep(delay * 0.55):
                break
            for n, s in st["ends"].items():
                state.set_node(n, s)
            bus.publish("sim.stage", {"run_id": run["run_id"], "index": st["index"], "phase": "end", "status": st["status"]})
            bus.publish("state", state.snapshot())
            if not _sleep(delay * 0.45):
                break
        else:
            _sleep(delay * 0.6)
            _finish(run)
            return
    finally:
        with state.live.lock:
            state.live.running = None
        bus.publish("state", state.snapshot())


def _finish(run: dict) -> None:
    imp = run["impact"]
    if run["result"] != "blocked":  # a stopped attack leaves no damage to clean up (and opens no incident that could clear it)
        state.add_impact(run["run_id"], run["scenario_id"], imp["C"], imp["I"], imp["A"])
    state.settle_run_nodes()
    # events: one per triggered defence + one summary (the summary is what the dashboard counters count)
    for st in run["stages"]:
        for ch in st["checks"]:
            if ch["outcome"] in ("blocked", "alerted", "throttled", "recovered"):
                events.emit(run["attack_type"], st["path"][0], st["path"][-1], "medium" if ch["outcome"] == "alerted" else "low", ch["name"],
                            {"blocked": "Blocked", "alerted": "Alert raised", "throttled": "Rate limited", "recovered": "Auto-recovered"}[ch["outcome"]],
                            "blocked" if ch["outcome"] == "blocked" else "detected", "user_run", True, run["run_id"],
                            {"kind": "guard", "detail": ch["detail"], "stage": st["title"]})
    ev = events.emit(run["attack_type"], run["source_node"], run["target_node"], run["severity"], run["detection"],
                     {"blocked": "Blocked", "contained": "Contained / recovered", "breach": "None — breach in progress"}[run["result"]],
                     run["result"], "user_run", True, run["run_id"],
                     {"kind": "run_summary", "summary": run["summary"], "impact": imp, "defence_used": run["defence_used"], "mode": run["mode"]})
    inc = incidents.create_from_run(run) if run["result"] in ("contained", "breach") else None
    state.changed()
    with state.live.lock:
        state.live.last_run = {"run_id": run["run_id"], "scenario_id": run["scenario_id"], "result": run["result"], "ts": time.time()}
    bus.publish("sim.end", {"run_id": run["run_id"], "result": run["result"], "summary": run["summary"], "incident": inc, "event": ev})


def catalog() -> list[dict]:
    return [{"id": s.id, "name": s.name, "tag": s.tag, "attack_type": s.attack_type, "short": s.short, "description": s.description,
             "source": s.source, "target": s.target, "impact": s.impact, "defences": s.defences, "detection": s.detection,
             "mitre": [{"id": a, "name": b} for a, b in s.mitre],
             "stages": [{"id": i, "title": t, "description": d, "path": p} for i, t, d, p in s.stages]} for s in SCENARIOS]

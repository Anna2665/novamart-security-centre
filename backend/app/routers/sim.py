from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from ..db import session_scope
from ..deps import Principal, get_principal, require
from ..models import SimRun
from ..services import audit, seed, state
from ..sim import engine
from ..sim.defences import BY_ID, DEFENCES, IDS
from ..sim.topology import EDGES, NODES

router = APIRouter(prefix="/sim", tags=["simulation"])


@router.get("/scenarios")
def scenarios(p: Principal = Depends(get_principal)):
    return engine.catalog()


@router.get("/topology")
def topology(p: Principal = Depends(get_principal)):
    return {"nodes": [{"id": k, **{x: v for x, v in n.items()}} for k, n in NODES.items()], "edges": [{"source": a, "target": b} for a, b in EDGES]}


@router.get("/state")
def get_state(p: Principal = Depends(get_principal)):
    return state.snapshot()


@router.get("/defences")
def defences(p: Principal = Depends(get_principal)):
    return {"defences": [{**d, "enabled": state.live.defences[d["id"]]} for d in DEFENCES], "mode": state.mode()}


class Toggle(BaseModel):
    enabled: bool


@router.put("/defences/{did}")
def toggle(did: str, body: Toggle, p: Principal = Depends(require("sim:configure"))):
    if did not in BY_ID:
        raise HTTPException(404, "unknown defence")
    state.set_defence(did, body.enabled)
    audit.log(p.username, "defence.toggle", did, {"enabled": body.enabled})
    return {"id": did, "enabled": body.enabled, "mode": state.mode()}


@router.post("/mode")
def set_mode(body: Toggle, p: Principal = Depends(require("sim:configure"))):
    state.set_all_defences(body.enabled)
    audit.log(p.username, "defence.mode", "all", {"enabled": body.enabled})
    return {"mode": state.mode()}


class RunIn(BaseModel):
    scenario_id: str
    params: dict | None = None


@router.post("/run")
def run(body: RunIn, p: Principal = Depends(require("sim:run"))):
    try:
        return engine.execute(body.scenario_id, body.params, p.username)
    except engine.Busy as e:
        raise HTTPException(409, str(e)) from e
    except KeyError as e:
        raise HTTPException(404, "unknown scenario") from e


@router.post("/compare")
def compare(body: RunIn, p: Principal = Depends(require("sim:run"))):
    """Dry-run the same attack with ALL defences off and ALL on — no side effects, nothing is recorded."""
    if body.scenario_id not in engine.BY_ID:
        raise HTTPException(404, "unknown scenario")
    return {"off": engine.build_run(body.scenario_id, {d: False for d in IDS}, True, body.params),
            "on": engine.build_run(body.scenario_id, {d: True for d in IDS}, True, body.params)}


@router.post("/reset")
def reset(p: Principal = Depends(require("sim:configure"))):
    seed.reset_data()
    audit.log(p.username, "sim.reset", "", {})
    return state.snapshot()


class Speed(BaseModel):
    speed: float


@router.put("/speed")
def speed(body: Speed, p: Principal = Depends(require("sim:configure"))):
    state.live.speed = max(0.25, min(4.0, body.speed))
    state.save()
    return {"speed": state.live.speed}


@router.get("/runs")
def runs(limit: int = 30, p: Principal = Depends(get_principal)):
    with session_scope() as db:
        return [{"run_id": r.id, "ts": r.ts.replace(tzinfo=None).isoformat() + "Z", "scenario_id": r.scenario_id, "result": r.result, "mode": r.mode,
                 "severity": r.severity, "detected": r.detected} for r in db.scalars(select(SimRun).order_by(SimRun.ts.desc()).limit(limit)).all()]


@router.get("/runs/{rid}")
def run_detail(rid: str, p: Principal = Depends(get_principal)):
    with session_scope() as db:
        r = db.get(SimRun, rid)
        if not r:
            raise HTTPException(404, "run not found")
        return r.payload

"""Incident response lifecycle: Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned."""
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from ..bus import bus
from ..db import session_scope
from ..models import Incident
from ..security import tokens
from ..sim.scenarios import BY_ID as SCEN
from ..sim.topology import NODES
from . import audit, backup, dbsec, state

PHASES = ["Preparation", "Identification", "Containment", "Eradication", "Recovery", "Lessons Learned"]


def _iso(ts: datetime) -> str:
    return (ts.replace(tzinfo=None) if ts.tzinfo is None else ts.astimezone(timezone.utc).replace(tzinfo=None)).isoformat() + "Z"


def to_dict(i: Incident) -> dict[str, Any]:
    tasks = i.checklist
    return {"id": i.id, "code": i.code, "ts": _iso(i.ts), "updated_at": _iso(i.updated_at), "title": i.title, "severity": i.severity,
            "status": i.status, "phase": i.phase, "phase_name": PHASES[min(i.phase, 5)], "phases": PHASES, "detection_source": i.detection_source,
            "affected_assets": i.affected_assets, "checklist": tasks, "timeline": i.timeline, "audit": i.audit, "run_id": i.run_id,
            "scenario_id": i.scenario_id, "notes": i.notes,
            "progress": {"done": sum(t["done"] for t in tasks), "total": len(tasks)}}


def _checklist(scen, run: dict) -> list[dict]:
    chain = audit.verify_chain()
    bk = backup.status()
    items: list[tuple[int, str, str | None, bool]] = [
        (0, "Incident response plan and on-call roster on file", None, True),
        (0, "Logging verified: audit hash-chain intact", None, chain["valid"]),
        (0, "A verified backup exists (verify_backup)", "verify_backup", bk["verified_count"] > 0),
        (1, "Triage: confirm the alert is genuine", None, False),
        (1, "Identify affected assets (listed on this incident)", None, False),
        (1, f"Classify severity ({run['severity'].upper()}) and notify stakeholders", None, False),
        (1, "Preserve evidence (audit log + event timeline)", None, False),
    ]
    for ph, key in ((2, "contain"), (3, "eradicate"), (4, "recover")):
        for title, action in scen.response.get(key, []):
            items.append((ph, title, None if action == "none" else action, False))
    if not any(a == "integrity_scan" for _, _, a, _ in items):
        items.append((4, "Verify no tampering remains (integrity scan)", "integrity_scan", False))
    items += [(5, "Document root cause and timeline", None, False), (5, "Update controls, policies and runbooks", None, False),
              (5, "Brief the team / schedule a tabletop exercise", None, False)]
    return [{"id": f"t{n}", "phase": ph, "title": t, "action": a, "done": d, "result": "auto-verified" if d else "", "by": "system" if d else "", "at": ""}
            for n, (ph, t, a, d) in enumerate(items)]


def create_from_run(run: dict) -> dict:
    scen = SCEN[run["scenario_id"]]
    t0 = datetime.fromisoformat(run["started_at"].rstrip("Z"))
    gap = run.get("stage_delay", 1.7)
    timeline = [{"ts": _iso(t0 + timedelta(seconds=i * gap)), "kind": s["status"], "text": f"{s['title']}: " + (s["logs"][-1]["msg"] if s["logs"] else s["description"])}
                for i, s in enumerate(run["stages"]) if s["status"] != "skipped"]
    timeline.append({"ts": _iso(datetime.now(timezone.utc)), "kind": "incident", "text": f"Incident opened — result: {run['result'].upper()} — detected by: {run['detection']}"})
    nodes = []
    for s in run["stages"]:
        for n, st in {**s["ends"]}.items():
            if st in ("compromised", "degraded") and n not in nodes:
                nodes.append(n)
    if not nodes:
        nodes = [run["stages"][-1]["path"][-1]]
    checklist = _checklist(scen, run)
    phase = 0 if any(not t["done"] for t in checklist if t["phase"] == 0) else 1
    with session_scope() as db:
        inc = Incident(code="INC-PENDING", title=f"{scen.name}: {run['summary'][:140]}", severity=run["severity"], status="open", phase=phase,
                       detection_source=run["detection"], affected_assets=[{"id": n, "label": NODES[n]["label"]} for n in nodes],
                       checklist=checklist, timeline=timeline, audit=[], run_id=run["run_id"], scenario_id=run["scenario_id"], notes="")
        db.add(inc)
        db.flush()
        inc.code = f"INC-{inc.id:04d}"
        out = to_dict(inc)
    audit.log("system", "incident.open", out["code"], {"run": run["run_id"], "severity": out["severity"]})
    bus.publish("incident", out)
    return out


def list_all() -> list[dict]:
    with session_scope() as db:
        return [to_dict(i) for i in db.scalars(select(Incident).order_by(Incident.id.desc())).all()]


def get(iid: int) -> dict:
    with session_scope() as db:
        i = db.get(Incident, iid)
        if not i:
            raise KeyError("incident not found")
        return to_dict(i)


def _stamp(i: Incident, actor: str, text: str, kind: str = "action") -> None:
    now = datetime.now(timezone.utc)
    i.timeline = [*i.timeline, {"ts": _iso(now), "kind": kind, "text": text}]
    i.audit = [*i.audit, {"ts": _iso(now), "actor": actor, "text": text}]
    i.updated_at = now


def perform_action(action: str, inc: Incident, actor: str, jti: str | None) -> tuple[bool, str]:
    kind, _, arg = action.partition(":")
    try:
        if kind == "verify_backup":
            st = backup.status()
            res = backup.verify_backup(st["backups"][0]["id"], actor) if st["backups"] else backup.create_backup("IR snapshot", "auto", actor)
            return res["status"] == "verified", f"Backup {res['id']} verification: {res['status']}"
        if kind == "isolate":
            state.set_node(arg, "isolated", "isolated by responder")
            state.changed()
            return True, f"{NODES[arg]['label']} isolated from the network (all links cut)"
        if kind == "unisolate":
            state.set_node(arg, "healthy")
            state.changed()
            return True, f"{NODES[arg]['label']} returned to production"
        if kind == "revoke_sessions":
            tokens.revoke_all_sessions(jti)
            return True, "All other active sessions revoked (tokens issued before now rejected)"
        if kind == "enable_defence":
            state.set_defence(arg, True)
            return True, f"Defence '{arg}' enabled"
        if kind == "restore_db":
            res = dbsec.restore_all(actor)
            state.resolve_pillar(inc.run_id, "I")
            state.changed()
            return True, f"{len(res)} record(s) restored from signed trusted versions" if res else "No tampered records found — nothing to restore"
        if kind == "restore_backup":
            res = backup.restore(None, actor)
            return True, f"Restored {res['files_restored']} files from {res['backup']} (decrypt ✔ hash ✔ signature ✔)"
        if kind == "integrity_scan":
            res = dbsec.scan()
            return res["tampered"] == [], (f"Scanned {res['total']} records — all hashes and signatures valid" if not res["tampered"]
                                           else f"{len(res['tampered'])} record(s) still fail verification — restore first")
        if kind in ("block_ip", "lock_account", "rotate_keys"):
            msg = {"block_ip": "Attacker source ranges added to the firewall deny list", "lock_account": "Targeted account locked pending reset",
                   "rotate_keys": "Credentials / keys rotation ticket executed"}[kind]
            return True, msg + " (simulated action, recorded in audit log)"
    except Exception as e:  # surface the reason to the responder
        return False, f"Action failed: {e}"
    return True, "Recorded"


def toggle_task(iid: int, task_id: str, actor: str, jti: str | None) -> dict:
    fail: str | None = None
    with session_scope() as db:
        i = db.get(Incident, iid)
        if not i:
            raise KeyError("incident not found")
        tasks = [dict(t) for t in i.checklist]
        t = next((x for x in tasks if x["id"] == task_id), None)
        if not t:
            raise KeyError("task not found")
        if t["phase"] > i.phase:
            raise ValueError("Complete the current phase first.")
        if t["done"]:
            t.update(done=False, result="", by="", at="")
            _stamp(i, actor, f"Re-opened task: {t['title']}")
        else:
            ok, msg = (True, "Completed manually")
            if t["action"]:
                ok, msg = perform_action(t["action"], i, actor, jti)
            if not ok:
                fail = msg
                _stamp(i, actor, f"Task failed — {t['title']}: {msg}", "warn")
            else:
                t.update(done=True, result=msg, by=actor, at=_iso(datetime.now(timezone.utc)))
                _stamp(i, actor, f"{t['title']} — {msg}")
        i.checklist = tasks
        out = to_dict(i)
    if fail:
        audit.log(actor, "incident.task_failed", out["code"], {"task": t["title"], "reason": fail})
        bus.publish("incident", out)
        raise ValueError(fail)
    audit.log(actor, "incident.task", out["code"], {"task": t["title"], "done": t["done"]})
    bus.publish("incident", out)
    return out


def advance(iid: int, actor: str) -> dict:
    with session_scope() as db:
        i = db.get(Incident, iid)
        if not i:
            raise KeyError("incident not found")
        if i.status == "resolved":
            raise ValueError("Incident already resolved.")
        pending = [t["title"] for t in i.checklist if t["phase"] == i.phase and not t["done"]]
        if pending:
            raise ValueError(f"{len(pending)} task(s) still open in {PHASES[i.phase]}: " + "; ".join(pending[:3]))
        finished = i.phase
        if finished == 2:
            i.status = "contained"
        if finished == 4:
            state.resolve_impacts(i.run_id)
            for n, v in list(state.live.nodes.items()):
                if v["status"] in ("compromised", "degraded", "isolated") and any(a["id"] == n for a in i.affected_assets):
                    state.set_node(n, "healthy")
            state.changed()
        if finished == 5:
            if not i.notes.strip():
                raise ValueError("Write the lessons-learned notes before closing the incident.")
            i.status = "resolved"
            _stamp(i, actor, "Incident closed — lessons learned recorded", "incident")
        else:
            i.phase = finished + 1
            _stamp(i, actor, f"Phase complete: {PHASES[finished]} → now {PHASES[i.phase]}", "phase")
        out = to_dict(i)
    audit.log(actor, "incident.advance", out["code"], {"phase": out["phase_name"], "status": out["status"]})
    bus.publish("incident", out)
    return out


def add_notes(iid: int, text: str, actor: str) -> dict:
    with session_scope() as db:
        i = db.get(Incident, iid)
        if not i:
            raise KeyError("incident not found")
        i.notes = text[:4000]
        _stamp(i, actor, "Lessons-learned notes updated", "note")
        out = to_dict(i)
    bus.publish("incident", out)
    return out

"""Scenario execution context: records stages, defence checks, node effects and evidence while a scenario evaluates its rules."""
from dataclasses import dataclass, field
from typing import Any, Callable

from .defences import BY_ID

# ---- evidence block helpers ---------------------------------------------------------------------------------------------
def code(title: str, text: str, tone: str = "") -> dict: return {"type": "code", "title": title, "text": text, "tone": tone}
def kv(title: str, items: list) -> dict: return {"type": "kv", "title": title, "items": [list(i) for i in items]}
def table(title: str, columns: list[str], rows: list) -> dict: return {"type": "table", "title": title, "columns": columns, "rows": rows}
def compare(title: str, left: dict, right: dict) -> dict: return {"type": "compare", "title": title, "left": left, "right": right}
def series(title: str, x: list, lines: list[dict], unit: str = "") -> dict: return {"type": "series", "title": title, "x": x, "lines": lines, "unit": unit}


@dataclass
class Scenario:
    id: str
    name: str
    tag: str
    attack_type: str
    short: str
    description: str
    source: str
    target: str
    impact: dict[str, int]
    stages: list[tuple[str, str, str, list[str]]]  # id, title, description, node path
    defences: list[str]
    detection: str
    mitre: list[tuple[str, str]]
    response: dict[str, list[tuple[str, str]]]  # contain / eradicate / recover -> [(title, action)]
    run: Callable[["Ctx"], None] = None  # type: ignore[assignment]
    params_hint: dict[str, Any] = field(default_factory=dict)


@dataclass
class StageRec:
    index: int
    id: str
    title: str
    description: str
    path: list[str]
    status: str = "pending"  # pending | active | succeeded | detected | blocked | skipped
    logs: list[dict] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)
    starts: dict[str, str] = field(default_factory=dict)
    ends: dict[str, str] = field(default_factory=dict)
    evidence: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class Ctx:
    def __init__(self, scen: Scenario, defences: dict[str, bool], dry: bool = False, params: dict | None = None) -> None:
        self.scen, self.defences, self.dry, self.params = scen, dict(defences), dry, params or {}
        self.stages = [StageRec(i, s[0], s[1], s[2], list(s[3])) for i, s in enumerate(scen.stages)]
        self.cur: StageRec | None = None
        self.blocked_by: str | None = None
        self.blocked_stage: int | None = None
        self.detected_by: list[str] = []
        self.defence_used: list[str] = []
        self.result: str | None = None
        self.summary = ""
        self.fraction: float | None = None
        self.metrics: dict[str, Any] = {}
        self.final_evidence: list[dict] = []

    # -- helpers
    def on(self, d: str) -> bool:
        return bool(self.defences.get(d))

    def stage(self, i: int) -> StageRec:
        if self.cur and self.cur.status == "active":
            self._close(self.cur)
        self.cur = self.stages[i]
        self.cur.status = "active"
        self.cur.starts = {n: "under_attack" for n in self.cur.path[1:]}
        return self.cur

    def _close(self, st: StageRec) -> None:
        st.status = "detected" if any(c["outcome"] == "alerted" for c in st.checks) else "succeeded"

    def log(self, level: str, msg: str) -> None:
        self.cur.logs.append({"level": level, "msg": msg})

    def evidence(self, block: dict) -> None:
        self.cur.evidence.append(block)

    def hit(self, node: str) -> None: self.cur.ends[node] = "compromised"
    def protect(self, node: str) -> None: self.cur.ends[node] = "protected"
    def degrade(self, node: str) -> None: self.cur.ends[node] = "degraded"
    def isolate(self, node: str) -> None: self.cur.ends[node] = "isolated"
    def heal(self, node: str) -> None: self.cur.ends[node] = "healthy"

    def check(self, defence: str, outcome: str, detail: str, name: str | None = None) -> None:
        self.cur.checks.append({"defence": defence, "name": name or BY_ID[defence]["name"], "outcome": outcome, "detail": detail})
        if outcome in ("blocked", "throttled", "alerted", "recovered"):
            self.defence_used.append(name or BY_ID[defence]["name"])

    def guard(self, defence: str, triggered: bool, ok_msg: str, block_msg: str, *, node: str | None = None,
              detect_only: bool = False, name: str | None = None) -> bool:
        """Evaluate a defence rule. Returns True when the stage is blocked (scenario normally returns)."""
        meta = BY_ID[defence]
        nm = name or meta["name"]
        if not self.on(defence):
            self.cur.checks.append({"defence": defence, "name": nm, "outcome": "inactive", "detail": f"{meta['name']} is OFF — rule not evaluated"})
            return False
        if not triggered:
            self.cur.checks.append({"defence": defence, "name": nm, "outcome": "passed", "detail": ok_msg})
            return False
        if detect_only:
            self.check(defence, "alerted", block_msg, nm)
            self.detected_by.append(nm)
            return False
        self.check(defence, "blocked", block_msg, nm)
        self.cur.status = "blocked"
        self.blocked_by, self.blocked_stage, self.result = nm, self.cur.index, "blocked"
        self.protect(node or meta["nodes"][0])
        return True

    def conclude(self, result: str, summary: str, fraction: float | None = None) -> None:
        self.result, self.summary = result, summary
        if fraction is not None:
            self.fraction = fraction

    def finish(self) -> None:
        if self.cur and self.cur.status == "active":
            self._close(self.cur)
        for st in self.stages:
            if st.status == "pending":
                st.status = "skipped"
        if self.result is None:
            self.result = "breach"
        if not self.summary:
            self.summary = (f"Blocked at stage {self.blocked_stage + 1} by {self.blocked_by}." if self.result == "blocked"
                            else f"Attack completed: {self.scen.short}")

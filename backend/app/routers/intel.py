from collections import Counter

from fastapi import APIRouter, Depends

from ..deps import Principal, get_principal
from ..services import events
from ..sim.scenarios import SCENARIOS

router = APIRouter(prefix="/intel", tags=["threat-intel"])

IOCS = [("ip", "198.51.100.23", "SQLi scanner", "high", 94), ("ip", "198.51.100.77", "Credential-stuffing botnet node", "high", 91),
        ("ip", "203.0.113.45", "Port scanner", "low", 70), ("ip", "203.0.113.130", "DDoS reflector", "medium", 83),
        ("domain", "novamart-verify.example", "Phishing landing page", "high", 96), ("domain", "free-coupons.example", "CSRF lure site", "medium", 88),
        ("domain", "exfil.evil.example", "Exfiltration endpoint", "critical", 97), ("url", "https://evil.example/c?=", "XSS cookie collector", "high", 90),
        ("hash", "9f2c…e41a (SHA-256)", "Ransomware loader (sandbox sample)", "critical", 99), ("hash", "b71d…03fc (SHA-256)", "Credential-harvesting kit", "medium", 76)]
ACTORS = [{"name": "SilentCart", "motive": "Financial — card & account fraud", "ttp": ["Credential stuffing", "Phishing", "CSRF"], "targets": "E-commerce checkout and loyalty wallets"},
          {"name": "ByteHarvest", "motive": "Data theft & resale", "ttp": ["SQL injection", "Data exfiltration", "Privilege escalation"], "targets": "Customer databases"},
          {"name": "LockBloom", "motive": "Extortion", "ttp": ["Ransomware", "Lateral movement"], "targets": "Admin workstations, file servers"}]
GEO = [("Region A", 28), ("Region B", 21), ("Region C", 17), ("Region D", 12), ("Region E", 9), ("Other / TOR exit nodes", 13)]


@router.get("/overview")
def overview(p: Principal = Depends(get_principal)):
    evs = events.recent(500)
    freq = Counter(e["attack_type"] for e in evs if (e.get("details") or {}).get("kind") != "guard")
    total = max(1, sum(freq.values()))
    matrix = []
    for s in SCENARIOS:
        like = min(5, 1 + round(5 * freq.get(s.attack_type, 0) / total * 3))
        impact = min(5, max(1, round(max(s.impact.values()) / 20)))
        matrix.append({"id": s.id, "name": s.name, "likelihood": like, "impact": impact, "score": like * impact})
    return {"mitre": [{"technique": a, "name": b, "scenario": s.name, "scenario_id": s.id} for s in SCENARIOS for a, b in s.mitre],
            "risk_matrix": sorted(matrix, key=lambda r: -r["score"]), "iocs": [{"type": t, "value": v, "description": d, "severity": sev, "confidence": c, "simulated": True} for t, v, d, sev, c in IOCS],
            "actors": ACTORS, "geo": [{"region": r, "percent": v} for r, v in GEO], "top_types": events.distribution()[:8],
            "disclaimer": "All indicators, actors and origins are fictional demonstration data (documentation IP ranges, .example domains)."}

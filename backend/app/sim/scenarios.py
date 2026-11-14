from .scenarios_a import SCENARIOS_A
from .scenarios_b import SCENARIOS_B

SCENARIOS = SCENARIOS_A + SCENARIOS_B
BY_ID = {s.id: s for s in SCENARIOS}
assert len(SCENARIOS) == 12

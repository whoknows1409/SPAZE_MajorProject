"""
Offline replay of the agent's RSSI decision pipeline on recorded traces.

Uses the agent's own filter classes so the deployed configuration is
reproduced exactly, and composes variants for the ablation study.
"""

import sys
from dataclasses import dataclass, replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from agent.ble_scanner.filters import (  # noqa: E402
    EMAFilter, GracePeriod, HysteresisFilter, KalmanFilter, ProximityState,
)

IN, OUT = ProximityState.IN_RANGE, ProximityState.OUT_OF_RANGE


@dataclass(frozen=True)
class Variant:
    name: str
    use_ema: bool = True
    alpha: float = 0.3
    use_kalman: bool = True
    q: float = 1.0
    r: float = 5.0
    authorize: float = -75.0
    deauthorize: float = -82.0     # == authorize -> no hysteresis (single threshold)
    grace: int = 5
    timeout: float = 5.0


DEPLOYED = Variant("deployed")

ABLATION = [
    Variant("raw threshold", use_ema=False, use_kalman=False, authorize=-78.5, deauthorize=-78.5, grace=1),
    Variant("EMA only", use_kalman=False),
    Variant("Kalman only", use_ema=False),
    Variant("no hysteresis", authorize=-78.5, deauthorize=-78.5),
    Variant("grace 1", grace=1),
    Variant("grace 3", grace=3),
    DEPLOYED,
    Variant("grace 7", grace=7),
]


def sweep():
    out = []
    for kal in (True, False):
        for alpha in (0.1, 0.2, 0.3, 0.5, 0.7, 1.0):
            for grace in (1, 3, 5, 7):
                for deauth in (-75.0, -78.0, -82.0, -86.0):
                    out.append(Variant(f"a{alpha}_g{grace}_d{int(deauth)}_k{int(kal)}",
                                       alpha=alpha, use_ema=alpha < 1.0, use_kalman=kal,
                                       grace=grace, deauthorize=deauth))
    return out


def replay(readings, v: Variant, init_state, t_end=None):
    """
    readings: iterable of (t, rssi) sorted by t.
    Returns a list of (t, new_state) transitions (no-reading timeout included).
    """
    ema = EMAFilter(v.alpha)
    kal = KalmanFilter(v.q, v.r)
    hyst = HysteresisFilter(v.authorize, v.deauthorize)
    grace = GracePeriod(v.grace)
    state = init_state
    last_t = None
    transitions = []
    for t, rssi in readings:
        if last_t is not None and state == IN and t - last_t > v.timeout:
            state = OUT
            transitions.append((last_t + v.timeout, OUT))
            grace.reset()
        x = ema.update(rssi) if v.use_ema else rssi
        x = kal.update(x) if v.use_kalman else x
        new = grace.evaluate(hyst.evaluate(x, state), state)
        if new != state:
            state = new
            transitions.append((t, new))
        last_t = t
    if t_end is not None and last_t is not None and state == IN and t_end - last_t > v.timeout:
        transitions.append((last_t + v.timeout, OUT))
    return transitions


def state_at(transitions, init_state, t):
    st = init_state
    for tt, s in transitions:
        if tt > t:
            break
        st = s
    return st


def evaluate(v: Variant, sessions, horizon=60.0):
    """
    Continuous replay of whole sessions (state carries over between trials).

    sessions: list of dicts with
        readings   [(t, rssi), ...] for the full session
        leaves     [t, ...]  walker starts leaving   (vault should lock)
        approaches [t, ...]  walker starts returning (vault should unlock)
        seated     [(t_start, t_end), ...] badge owner working at the desk
    """
    dep, arr = [], []
    pre_locked = premature_unlock = false_unlocks_away = 0
    seated_locks, seated_h = 0, 0.0
    for ses in sessions:
        rd = ses["readings"]
        if not rd:
            continue
        tr = replay(rd, v, IN, t_end=rd[-1][0])
        outs = [t for t, s in tr if s == OUT]
        ins = [t for t, s in tr if s == IN]
        for tl in ses.get("leaves", []):
            if state_at(tr, IN, tl) == OUT:
                pre_locked += 1
                continue
            nxt = [t - tl for t in outs if tl < t <= tl + horizon]
            dep.append(nxt[0] if nxt else None)
        # away periods: from each leave to the following approach
        aps = sorted(ses.get("approaches", []))
        for tl in ses.get("leaves", []):
            ta = next((a for a in aps if a > tl), None)
            if ta is None:
                continue
            first_out = next((t for t in outs if tl < t < ta), None)
            if first_out is not None:
                false_unlocks_away += sum(1 for t in ins if first_out < t < ta)
        for ta in aps:
            if state_at(tr, IN, ta) == IN:
                premature_unlock += 1
                continue
            nxt = [t - ta for t in ins if ta < t <= ta + horizon]
            arr.append(nxt[0] if nxt else None)
        for ts, te in ses.get("seated", []):
            seated_locks += sum(1 for t in outs if ts <= t <= te)
            seated_h += (te - ts) / 3600.0
    return {"departure": dep, "arrival": arr, "pre_locked": pre_locked,
            "premature_unlock": premature_unlock, "false_unlocks_away": false_unlocks_away,
            "false_locks": seated_locks, "seated_h": seated_h,
            "false_locks_per_h": seated_locks / seated_h if seated_h else float("nan")}

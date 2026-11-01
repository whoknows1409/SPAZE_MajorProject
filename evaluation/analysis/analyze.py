#!/usr/bin/env python3
"""
SPAZE / PAKL - analysis of all experiment data -> results.json, figures, LaTeX tables.

  python evaluation/analysis/analyze.py
  SPAZE_DATA=/path/to/other/data ... analyze.py      (e.g. a synthetic dry run)

Each section runs only if its data exists; missing sections are reported, not faked.
"""

import json
import math
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import style  # noqa: E402
from style import AQUA, BLUE, DOUBLE, INK2, MUTED, ORANGE, SINGLE, plt, save  # noqa: E402
from replay import ABLATION, DEPLOYED, evaluate, sweep  # noqa: E402

RP = Path(__file__).resolve().parents[1]
DATA = Path(os.environ.get("SPAZE_DATA", RP / "data"))
OUT = Path(os.environ.get("SPAZE_OUT", RP / "analysis" / "out"))
_PAPER = RP / "paper" if (RP / "paper").is_dir() else OUT          # figures/tables go next to the results without the paper
FIG = Path(os.environ.get("SPAZE_FIG", _PAPER / "figures"))
TAB = Path(os.environ.get("SPAZE_TAB", _PAPER / "tables"))
for p in (OUT, FIG, TAB):
    p.mkdir(parents=True, exist_ok=True)

R = {"data_dir": os.path.relpath(DATA, RP.parent), "sections": {}}


def note(section, msg):
    R["sections"].setdefault(section, {})["status"] = msg
    print(f"[{section}] {msg}")


def stats(x):
    x = np.asarray([v for v in x if v is not None and not (isinstance(v, float) and math.isnan(v))], float)
    if x.size == 0:
        return {"n": 0}
    return {"n": int(x.size), "mean": float(x.mean()), "sd": float(x.std(ddof=1)) if x.size > 1 else 0.0,
            "median": float(np.median(x)), "p25": float(np.percentile(x, 25)),
            "p75": float(np.percentile(x, 75)), "p95": float(np.percentile(x, 95)),
            "min": float(x.min()), "max": float(x.max())}


def fmt_med(s, scale=1.0, nd=1):
    if not s or s.get("n", 0) == 0:
        return "--"
    return f"{s['median']*scale:.{nd}f} [{s['p25']*scale:.{nd}f}, {s['p75']*scale:.{nd}f}]"


def _head(cell):
    """Header cell; "first|second" is set on two stacked lines to keep columns narrow."""
    if "|" not in cell:
        return cell
    return r"\begin{tabular}[b]{@{}c@{}}" + r"\\".join(cell.split("|")) + r"\end{tabular}"


def write_table(name, header, rows, caption, label, colspec=None, size="small", full_width=False):
    """full_width: tabularx over the line width, so X columns wrap instead of overflowing."""
    colspec = colspec or "l" + "r" * (len(header) - 1)
    env = "tabularx" if full_width else "tabular"
    width = r"{\linewidth}" if full_width else ""
    lines = [r"\begin{table}[t]", r"\centering", "\\" + size,
             rf"\caption{{{caption}}}", rf"\label{{{label}}}",
             rf"\begin{{{env}}}{width}{{{colspec}}}", r"\toprule",
             " & ".join(_head(h) for h in header) + r" \\", r"\midrule"]
    lines += [" & ".join(str(c) for c in r) + r" \\" for r in rows]
    lines += [r"\bottomrule", rf"\end{{{env}}}", r"\end{table}"]
    (TAB / f"{name}.tex").write_text("\n".join(lines) + "\n")


def load_trace(path):
    if not path.exists():
        return None
    df = pd.read_csv(path)
    df["data"] = df["data"].fillna("{}").map(json.loads)
    return df


def events(df, name):
    return df[df["event"] == name]


def rssi_series(df):
    r = events(df, "rssi")
    return np.column_stack([r["t"].to_numpy(), r["data"].map(lambda d: d["raw"]).to_numpy()]) \
        if len(r) else np.empty((0, 2))


def window(arr, t0, t1):
    m = (arr[:, 0] >= t0) & (arr[:, 0] <= t1)
    return [(float(t), float(v)) for t, v in arr[m]]


# ======================================================================
# Field logs (audit trail of real use, Apr-Sep 2026)
# ======================================================================

def field_logs():
    f = DATA / "field_logs" / "audit_logs.csv"
    if not f.exists():
        return note("field_logs", "missing")
    df = pd.read_csv(f, parse_dates=["timestamp_utc"]).sort_values("timestamp_utc")
    unl = df[df.action == "vault_unlock"]
    lck = df[df.action == "vault_lock"]
    kd = df[df.action == "keys_delivered"]
    sessions = []
    for t in unl.timestamp_utc:
        nxt = lck[lck.timestamp_utc > t].timestamp_utc
        if len(nxt):
            sessions.append((nxt.iloc[0] - t).total_seconds())
    k2u = []
    for t in unl.timestamp_utc:
        prev = kd[kd.timestamp_utc <= t].timestamp_utc
        if len(prev):
            d = (t - prev.iloc[-1]).total_seconds()
            if d < 10:
                k2u.append(d * 1000)
    dlp_actions = ["clipboard_cleared", "upload_blocked", "exfiltration_blocked",
                   "screenshot_blocked", "usb_blocked", "print_blocked", "exfiltration_detected"]
    counts = {a: int((df.action == a).sum()) for a in dlp_actions if (df.action == a).sum()}
    days = sorted(set(unl.timestamp_utc.dt.date.astype(str)))
    res = {
        "rows": int(len(df)), "first": str(df.timestamp_utc.min()), "last": str(df.timestamp_utc.max()),
        "unlocks": int(len(unl)), "locks": int(len(lck)), "active_days": len(days),
        "session_s": stats([s for s in sessions if s < 6 * 3600]),
        "sessions_over_6h_excluded": int(sum(s >= 6 * 3600 for s in sessions)),
        "keys_to_unlock_ms": stats(k2u),
        "unlock_rssi_dbm": stats(unl.rssi_value.dropna()),
        "dlp_event_counts": counts,
        "denied_requests": int((df.action == "key_request_denied").sum()),
    }
    R["sections"]["field_logs"] = res
    note("field_logs", "ok")

    rows = [[a.replace("_", r"\_"), n] for a, n in sorted(counts.items(), key=lambda x: -x[1])]
    write_table("field_dlp_counts", ["Event", "Count"], rows,
                f"Guard events recorded in the audit trail during {res['active_days']} days of "
                f"prototype use ({res['first'][:10]} to {res['last'][:10]}).", "tab:field")


# ======================================================================
# E1 - RSSI vs distance
# ======================================================================

def e1():
    f = DATA / "e1_rssi" / "rssi.csv"
    if not f.exists():
        return note("e1_rssi", "missing")
    df = pd.read_csv(f)
    df = df[df.label != "smoke"]
    out = {}
    for lab, g in df.groupby("label"):
        out[lab] = stats(g.rssi)
        dt = np.diff(g.t_host.to_numpy())
        out[lab]["sample_interval_s"] = float(np.median(dt)) if len(dt) else None
    front = df[df.label.str.endswith("_front")].copy()
    fit = None
    if len(front):
        front["d"] = front.label.str.extract(r"d([\d.]+)_")[0].astype(float)
        x = np.log10(front.d.to_numpy())
        A = np.vstack([np.ones_like(x), -10 * x]).T
        (p0, n), *_ = np.linalg.lstsq(A, front.rssi.to_numpy(float), rcond=None)
        pred = p0 - 10 * n * x
        resid = front.rssi.to_numpy(float) - pred
        fit = {"rssi_1m": float(p0), "path_loss_exp": float(n), "resid_sd": float(resid.std(ddof=1))}
        # distances at which the mean RSSI crosses the thresholds
        fit["d_at_authorize"] = float(10 ** ((p0 - DEPLOYED.authorize) / (10 * n)))
        fit["d_at_deauthorize"] = float(10 ** ((p0 - DEPLOYED.deauthorize) / (10 * n)))
    R["sections"]["e1_rssi"] = {"labels": out, "fit": fit, "n_samples": int(len(df))}
    note("e1_rssi", "ok")

    if len(front):
        fig, ax = plt.subplots(figsize=SINGLE)
        ds = sorted(front.d.unique())
        data = [front[front.d == d].rssi.to_numpy() for d in ds]
        bp = ax.boxplot(data, positions=ds, widths=0.18, patch_artist=True, showfliers=False,
                        medianprops={"color": BLUE, "linewidth": 1.5},
                        boxprops={"facecolor": "white", "edgecolor": INK2, "linewidth": 0.6},
                        whiskerprops={"color": INK2, "linewidth": 0.6}, capprops={"color": INK2, "linewidth": 0.6})
        back = df[df.label.str.endswith("_back")].copy()
        if len(back):
            back["d"] = back.label.str.extract(r"d([\d.]+)_")[0].astype(float)
            bm = back.groupby("d").rssi.median()
            ax.plot(bm.index + 0.12, bm.values, "s", color=ORANGE, label="back to anchor (median)", markersize=5)
        dd = np.linspace(min(ds), max(ds), 100)
        ax.plot(dd, fit["rssi_1m"] - 10 * fit["path_loss_exp"] * np.log10(dd), color=BLUE, linewidth=1,
                label=f"log-distance fit (n = {fit['path_loss_exp']:.2f})")
        # labels just above each line, between 3 and 6 m where no box reaches above -82 dBm
        lx = 3.3 if max(ds) >= 5 else min(ds)
        # British spelling, as in the paper's text; proper minus sign
        for thr, lab in ((DEPLOYED.authorize, "authorise"), (DEPLOYED.deauthorize, "deauthorise")):
            ax.axhline(thr, color=MUTED, linestyle="--", linewidth=0.8)
            ax.text(lx, thr + 0.5, f"{lab} {thr:.0f} dBm".replace("-", "\u2212"), ha="left", va="bottom",
                    fontsize=6.5, color=INK2)
        ax.set_xlabel("Badge–anchor distance (m)")
        ax.set_ylabel("RSSI (dBm)")
        ax.set_xticks(ds)
        ax.set_xticklabels([f"{d:g}" for d in ds])
        ax.legend(loc="upper right")
        save(fig, FIG, "fig_rssi_distance")


# ======================================================================
# E2/E3 - live latencies from agent traces + markers
# ======================================================================

def live_trials(session):
    tr = load_trace(DATA / f"trace_{session}.csv")
    mk = DATA / "e2_walk" / f"markers_{session}.csv"
    if tr is None or not mk.exists():
        return None, None, None
    m = pd.read_csv(mk)
    bad = set(m[(m.marker == "note")].trial)
    ev = {n: events(tr, n).t.to_numpy() for n in
          ["state_change", "lock_start", "lock_done", "unlock_start", "keys_received", "unlock_done", "forced_lock",
           "cr_result"]}
    sc = events(tr, "state_change")
    new_state = sc["data"].map(lambda d: d.get("new")).to_numpy()
    s_out = sc["t"].to_numpy()[new_state == "out_of_range"]
    s_in = sc["t"].to_numpy()[new_state == "in_range"]

    fl = events(tr, "forced_lock")
    fl_t = fl["t"].to_numpy()
    fl_reason = fl["data"].map(lambda d: d.get("reason", "")).to_numpy()
    marks = np.sort(m[m.marker.isin(["leave", "approach"])].t.to_numpy())

    def nxt(arr, t0, horizon=90):
        # search only until the next leave/approach marker, so events never leak between trials
        later = marks[marks > t0]
        end = min(t0 + horizon, later[0]) if len(later) else t0 + horizon
        a = arr[(arr > t0) & (arr <= end)]
        return float(a[0]) if len(a) else None

    rows = []
    for _, r in m[m.marker.isin(["leave", "approach"])].iterrows():
        t0 = r.t
        if r.marker == "leave":
            # the lock is decided either by proximity (state change) or by the
            # server side (lease/presence/CR failure -> forced_lock), whichever is first
            dp, df_ = nxt(s_out, t0), nxt(fl_t, t0)
            d = min(x for x in (dp, df_) if x) if (dp or df_) else None
            trigger = None
            if d is not None:
                trigger = "proximity" if d == dp else str(fl_reason[fl_t == df_][0])
            ls = nxt(ev["lock_start"], t0)
            ld = nxt(ev["lock_done"], t0)
            rows.append({"trial": r.trial, "kind": "leave", "bad": r.trial in bad, "trigger": trigger,
                         "decision_s": d - t0 if d else None, "lock_start_s": ls - t0 if ls else None,
                         "total_s": ld - t0 if ld else None, "proc_s": (ld - ls) if (ld and ls) else None})
        else:
            d = nxt(s_in, t0)
            us = nxt(ev["unlock_start"], t0)
            kr = nxt(ev["keys_received"], t0)
            ud = nxt(ev["unlock_done"], t0)
            cr = nxt(ev["cr_result"], us) if us else None
            cr = cr if (cr and kr and cr < kr) else None      # challenge answered before the key request
            rows.append({"trial": r.trial, "kind": "approach", "bad": r.trial in bad,
                         "decision_s": d - t0 if d else None, "total_s": ud - t0 if ud else None,
                         "keyfetch_ms": (kr - us) * 1000 if (kr and us) else None,
                         "cr_ms": (cr - us) * 1000 if cr else None,
                         "request_ms": (kr - (cr or us)) * 1000 if (kr and us) else None,
                         "decrypt_ms": (ud - kr) * 1000 if (ud and kr) else None})
    return pd.DataFrame(rows), tr, m


def e2_live():
    res = {}
    for session in ("pakl", "baseline"):
        df, tr, m = live_trials(session)
        if df is None or df.empty:
            continue
        ok = df[~df.bad]
        lv, ap = ok[ok.kind == "leave"], ok[ok.kind == "approach"]
        res[session] = {
            "trials_leave": int(len(lv)), "trials_approach": int(len(ap)),
            "excluded_trials": int(df.bad.sum() // 2 if len(df) else 0),
            "missed_lock": int(lv.total_s.isna().sum()), "missed_unlock": int(ap.total_s.isna().sum()),
            "leave_decision_s": stats(lv.decision_s), "leave_total_s": stats(lv.total_s),
            "lock_procedure_s": stats(lv.proc_s),
            "lock_trigger": lv.trigger.value_counts().to_dict() if "trigger" in lv else {},
            "approach_decision_s": stats(ap.decision_s), "approach_total_s": stats(ap.total_s),
            "keyfetch_ms": stats(ap.keyfetch_ms), "decrypt_ms": stats(ap.decrypt_ms),
            "cr_ms": stats(ap.cr_ms.dropna()), "request_ms": stats(ap.request_ms),
        }
        if tr is not None:
            # lease statistics only for this session's trials, not the whole trace file
            tr = tr[(tr.t >= m.t.min() - 30) & (tr.t <= m.t.max() + 60)]
            rtt = events(tr, "lease_renew_ok").data.map(lambda d: d.get("rtt_ms")).dropna()
            res[session]["lease_rtt_ms"] = stats(rtt)
            res[session]["lease_renewals_ok"] = int(len(rtt))
            res[session]["lease_renewals_failed"] = int(len(events(tr, "lease_renew_error")) +
                                                        len(events(tr, "lease_renew_denied")))
            # slow-but-genuine CR answers that were retried (server allows one retry per renewal)
            res[session]["lease_cr_retries"] = int(len(events(tr, "lease_renew_retry")))
        df.to_csv(OUT / f"e2_trials_{session}.csv", index=False)
    if not res:
        return note("e2_live", "missing")
    R["sections"]["e2_live"] = res
    note("e2_live", "ok")

    rows = []
    names = [("leave_decision_s", "Departure: proximity decision (s)", 1),
             ("leave_total_s", "Departure: vault locked (s)", 1),
             ("lock_procedure_s", "Lock procedure (s)", 1),
             ("approach_decision_s", "Arrival: proximity decision (s)", 1),
             ("approach_total_s", "Arrival: vault unlocked (s)", 1),
             ("cr_ms", "Arrival: challenge--response (ms)", 1),
             ("request_ms", "Arrival: key request incl. TLS (ms)", 1),
             ("decrypt_ms", "Decrypt + mount + guards (ms)", 1)]
    for k, lab, sc in names:
        rows.append([lab] + [fmt_med(res.get(s, {}).get(k), sc) for s in ("baseline", "pakl")])
    write_table("live_latency", ["Metric (median [IQR])", "Original", "Full system"], rows,
                "End-to-end latencies in the walk-away and return trials (10 per configuration). "
                "Departure times are measured from standing up, arrival times from the return alarm; "
                "the full system is \\pakl\\ with challenge--response and the guardian.", "tab:latency")


# ======================================================================
# Ablation of the proximity decision pipeline (replay of recorded RSSI)
# ======================================================================

def ablation():
    sessions = []
    for session in ("pakl", "baseline"):
        tr = load_trace(DATA / f"trace_{session}.csv")
        mk = DATA / "e2_walk" / f"markers_{session}.csv"
        if tr is None:
            continue
        arr = rssi_series(tr)
        ses = {"name": session, "readings": [(float(t), float(v)) for t, v in arr],
               "leaves": [], "approaches": [], "seated": []}
        if mk.exists():
            m = pd.read_csv(mk)
            bad = set(m[m.marker == "note"].trial)
            ses["leaves"] = m[(m.marker == "leave") & ~m.trial.isin(bad)].t.tolist()
            ses["approaches"] = m[(m.marker == "approach") & ~m.trial.isin(bad)].t.tolist()
        st = DATA / "e2_walk" / "markers_seated.csv"
        if session == "pakl" and st.exists():
            sm = pd.read_csv(st)
            notes = sm[sm.marker == "note"].sort_values("t")
            starts = notes[notes.note.astype(str).str.lower().str.contains("start")].t.tolist()
            ends = notes[notes.note.astype(str).str.lower().str.contains("end")].t.tolist()
            ses["seated"] = list(zip(starts, ends))
        sessions.append(ses)
    n_dep = sum(len(s["leaves"]) for s in sessions)
    n_seat = sum(len(s["seated"]) for s in sessions)
    if not n_dep or not n_seat:
        return note("ablation", f"missing (departures={n_dep}, seated windows={n_seat})")

    H = 60.0

    def summarise(v):
        ev = evaluate(v, sessions, horizon=H)
        d = [x for x in ev["departure"] if x is not None]
        a = [x for x in ev["arrival"] if x is not None]
        d_cens = [x if x is not None else H for x in ev["departure"]]
        return {"name": v.name, "departure_s": stats(d), "departure_censored_median": float(np.median(d_cens)) if d_cens else None,
                "missed_departures": len(ev["departure"]) - len(d), "pre_locked": ev["pre_locked"],
                "arrival_s": stats(a), "missed_arrivals": len(ev["arrival"]) - len(a),
                "premature_unlock": ev["premature_unlock"], "false_unlocks_away": ev["false_unlocks_away"],
                "false_locks": ev["false_locks"], "false_locks_per_h": ev["false_locks_per_h"],
                "seated_h": ev["seated_h"], "variant": dict(v.__dict__)}

    abl = [summarise(v) for v in ABLATION]
    sw = [summarise(v) for v in sweep()]
    R["sections"]["ablation"] = {"variants": abl, "n_departures": n_dep,
                                 "n_arrivals": sum(len(s["approaches"]) for s in sessions),
                                 "seated_hours": abl[0]["seated_h"], "horizon_s": H}
    pd.DataFrame([{"name": s["name"], **s["variant"], "dep_median_censored": s["departure_censored_median"],
                   "missed_departures": s["missed_departures"], "arr_median": s["arrival_s"].get("median"),
                   "false_locks_per_h": s["false_locks_per_h"], "false_unlocks_away": s["false_unlocks_away"],
                   "premature_unlock": s["premature_unlock"]} for s in sw]).to_csv(OUT / "ablation_sweep.csv", index=False)
    note("ablation", "ok")

    rows = []
    for s in abl:
        rows.append([s["name"], fmt_med(s["departure_s"]), s["missed_departures"],
                     fmt_med(s["arrival_s"]), s["false_unlocks_away"] + s["premature_unlock"],
                     f"{s['false_locks_per_h']:.2f}"])
    write_table("ablation", ["Variant", "Departure|(s)", "Missed", "Arrival|(s)", "Unlocks|while away", "False|locks/h"],
                rows, f"Replay of recorded RSSI through pipeline variants ({n_dep} departures, "
                      f"{abl[0]['seated_h']:.2f} h of seated work). Delays are median [IQR] of detected "
                      f"events; missed = no lock within {H:.0f} s.", "tab:ablation", colspec="lrrrrr",
                size="footnotesize")

    # Trade-off figure (misses counted at the horizon so they cannot look fast)
    fig, ax = plt.subplots(figsize=SINGLE)
    sx = np.array([s["departure_censored_median"] for s in sw], float)
    sy = np.array([s["false_locks_per_h"] for s in sw], float)
    ax.scatter(sx, sy, s=9, color=MUTED, alpha=0.5, linewidths=0, label="parameter sweep")
    # Pareto frontier of the sweep (lower-left is better on both axes)
    order = np.argsort(sx)
    fx, fy, best = [], [], np.inf
    for i in order:
        if sy[i] < best:
            fx.append(sx[i]); fy.append(sy[i]); best = sy[i]
    ax.step(fx, fy, where="post", color=AQUA, linewidth=1.2, label="Pareto frontier")
    named = ["deployed", "raw threshold", "grace 1", "grace 7"]
    for s in abl:
        x, y = s["departure_censored_median"], s["false_locks_per_h"]
        col = BLUE if s["name"] == "deployed" else ORANGE
        ax.scatter([x], [y], s=26, color=col, edgecolors="white", linewidths=0.8, zorder=3)
    # labels above the points (never into the tick labels); points on the x axis
    # alternate between two heights in x order so neighbours do not collide
    lab = sorted((s for s in abl if s["name"] in named), key=lambda s: s["departure_censored_median"])
    k = 0
    for s in lab:
        y = s["false_locks_per_h"]
        if y < 0.5:
            off, ha = (0, 14 if k % 2 == 0 else 28), "center"
            k += 1
        else:
            off, ha = (6, 8), "left"
        ax.annotate(s["name"], (s["departure_censored_median"], y), xytext=off, ha=ha,
                    textcoords="offset points", fontsize=6.5, color=INK2,
                    arrowprops={"arrowstyle": "-", "color": MUTED, "lw": 0.5})
    ax.set_xlabel(f"Median departure-to-lock decision (s, misses = {H:.0f} s)")
    ax.set_ylabel("False locks per hour (seated)")
    ax.scatter([], [], s=26, color=ORANGE, label="ablation variants")
    ax.scatter([], [], s=26, color=BLUE, label="deployed")
    ax.legend(loc="upper right")
    save(fig, FIG, "fig_tradeoff")

    # Example departure trace (raw vs filtered) for the first departure
    ses = next(s for s in sessions if s["leaves"])
    t0 = ses["leaves"][0]
    rd = [x for x in ses["readings"] if t0 - 60 <= x[0] <= t0 + 40]
    if rd:
        from agent.ble_scanner.filters import EMAFilter, KalmanFilter
        e, k = EMAFilter(DEPLOYED.alpha), KalmanFilter(DEPLOYED.q, DEPLOYED.r)
        t = np.array([x[0] for x in rd]) - t0
        raw = np.array([x[1] for x in rd])
        filt = np.array([k.update(e.update(v)) for v in raw])
        fig, ax = plt.subplots(figsize=SINGLE)
        ax.plot(t, raw, color=MUTED, linewidth=0.8, marker="o", markersize=2, label="raw RSSI")
        ax.plot(t, filt, color=BLUE, linewidth=1.5, label="EMA + Kalman")
        for thr in (DEPLOYED.authorize, DEPLOYED.deauthorize):
            ax.axhline(thr, color=MUTED, linestyle="--", linewidth=0.8)
        ax.axvline(0, color=ORANGE, linewidth=1.0)
        ax.set_xlim(-20, 40)
        ax.text(0.5, 0.97, "walker leaves", transform=ax.get_xaxis_transform(), color=INK2, fontsize=6.5, va="top")
        ax.set_xlabel("Time relative to departure (s)")
        ax.set_ylabel("RSSI (dBm)")
        ax.legend(loc="lower left")
        save(fig, FIG, "fig_departure_example")


# ======================================================================
# E4 - security experiments
# ======================================================================

def _since_last_renewal(t_freeze, t_event):
    """Outage runs: time from the last successful lease renewal before each freeze to t_event."""
    f = DATA / "trace_pakl.csv"
    if not f.exists():
        return []
    tr = pd.read_csv(f)
    ok = np.sort(tr.loc[tr.event == "lease_renew_ok", "t"].to_numpy(float))
    out = []
    for tf, te in zip(t_freeze, t_event):
        i = np.searchsorted(ok, tf) - 1
        out.append(te - ok[i] if i >= 0 and not math.isnan(te) else None)
    return out


def e4():
    res = {}
    f = DATA / "e4_security" / "attacks.csv"
    if f.exists():
        df = pd.read_csv(f)
        tab = df.groupby(["attack", "server_mode", "outcome"]).size().unstack(fill_value=0)
        res["attacks"] = {f"{a}|{m}": {k: int(v) for k, v in row.items()} for (a, m), row in tab.iterrows()}
        names = {"A1_unsigned_request": "A1: unsigned request naming badge and host",
                 "A2a_signed_no_token": "A2: signed request, no token",
                 "A2b_signed_forged_token": "A2: signed request, forged token",
                 "A2c_signed_replayed_token": "A3: signed request, replayed genuine token"}
        rows = []
        for a in sorted(df.attack.unique()):
            r = [names.get(a, a.replace("_", r"\_"))]
            for mode in ("baseline", "pakl"):
                g = df[(df.attack == a) & (df.server_mode == mode)]
                if len(g):
                    rel = int((g.outcome == "KEYS_RELEASED").sum())
                    r.append(f"{rel}/{len(g)}")
                else:
                    r.append("--")
            rows.append(r)
        write_table("attacks", ["Attack", "Original:|keys released", "\\pakl:|keys released"], rows,
                    "Key-release attempts without a physically present badge.", "tab:attacks", colspec=r">{\raggedright\arraybackslash}X cc", full_width=True)
    # revocation.csv / outage.csv = first runs; *_v2.csv = after the lock reorder
    # (wipe first, guard threads joined afterwards)
    for f in sorted((DATA / "e4_security").glob("revocation*.csv")) + \
            sorted((DATA / "e4_security").glob("outage*.csv")):
        df = pd.read_csv(f)
        r = {"latency_s": stats(df.latency_ms / 1000.0), "reps": int(len(df)),
             "not_locked": int(df.latency_ms.isna().sum())}
        if {"t_lock_start", "t_lock_done"} <= set(df.columns):
            r["lock_procedure_s"] = stats(df.t_lock_done - df.t_lock_start)
        if {"t_revoke", "t_lease_denied"} <= set(df.columns):
            r["revoke_to_denied_s"] = stats(df.t_lease_denied - df.t_revoke)
        if "t_freeze" in df.columns and "t_forced_lock" in df.columns:
            r["last_renewal_to_lock_start_s"] = stats(_since_last_renewal(df.t_freeze, df.t_forced_lock))
        res[f.stem] = r
    f = DATA / "manual_results.csv"
    if f.exists():
        res["manual"] = pd.read_csv(f).fillna("").to_dict(orient="records")
    if not res:
        return note("e4_security", "missing")
    R["sections"]["e4_security"] = res
    note("e4_security", "ok")


# ======================================================================
# E5 - DLP guards
# ======================================================================

def e5():
    f = DATA / "e5_dlp" / "dlp.csv"
    if not f.exists():
        return note("e5_dlp", "missing")
    df = pd.read_csv(f)
    if "config" not in df:
        df["config"] = "userspace"
    res = {}
    for (cfg, t), g in df.groupby(["config", "test"]):
        blocked = g[g.outcome == "blocked"]
        res[f"{cfg}|{t}"] = {"config": cfg, "test": t, "reps": int(len(g)), "blocked": int(len(blocked)),
                             "open_denied": int((g.detail == "open_denied").sum()),
                             "latency_ms": stats(blocked.latency_ms.dropna())}
        if t.startswith("upload") and "bytes" in g:
            # bytes the test server received ("received/size"): what actually left the machine
            sent = g["bytes"].dropna().astype(str).str.split("/", expand=True).astype(float)
            res[f"{cfg}|{t}"]["bytes_sent"] = stats(sent[0])
            res[f"{cfg}|{t}"]["file_bytes"] = float(sent[1].max())
    fw = DATA / "e5_dlp" / "fs_watch.csv"
    if fw.exists():
        w = pd.read_csv(fw)
        life = w[(w.event == "disappear") & (w.label == "screenshot")].lifetime_ms.dropna()
        res["screenshot_file_lifetime_ms"] = stats(life)
    R["sections"]["e5_dlp"] = res
    note("e5_dlp", "ok")

    labels = {"clipboard": "Clipboard copy", "copy": "File copy (same name)", "copy_rename": "File copy (renamed)",
              "copy_hidden": "File copy (unwatched dir)", "upload_curl": "Upload via curl",
              "upload_python": "Upload via Python", "upload_pipe": "cat | curl upload"}
    def kib(b):
        return "0 B" if b < 1 else f"{b / 1024:.0f} KiB"

    def exposure(k, r):
        if r["open_denied"] == r["reps"] and r["reps"]:
            return "none (read refused)"
        if "bytes_sent" in r:
            sent = r["bytes_sent"]["median"]
            if sent < 1:
                return "none (read refused)"
            if sent >= r["file_bytes"]:
                return "whole file sent"
            return f"{kib(sent)} of {kib(r['file_bytes'])} sent"
        if r["blocked"] < r["reps"]:
            return "copy kept"
        what = "cleared" if k == "clipboard" else "copy deleted"
        return f"{what} after {r['latency_ms']['median']:.0f} ms"

    rows = []
    for k, lab in labels.items():
        row = [lab]
        for cfg in ("userspace", "guardian"):
            r = res.get(f"{cfg}|{k}")
            row.append("--" if r is None else f"{r['blocked']}/{r['reps']}; {exposure(k, r)}")
        rows.append(row)
    write_table("dlp", ["Exfiltration attempt", "User-space guards only", "With the guardian"],
                rows, "Scripted exfiltration attempts while the vault was unlocked, with the user-space guards "
                      "only and with the vault guardian added. Each cell gives the attempts stopped and what left "
                      "the vault before the attempt was stopped (median); \\emph{read refused} = the guardian's "
                      "kernel gate denied the open, so no data was read.",
                "tab:dlp", colspec=r">{\raggedright\arraybackslash}X ll", full_width=True)


# ======================================================================
# E7 - vault guardian (agent kill)
# ======================================================================

def e7():
    f = DATA / "e7_guardian" / "kill_bench.csv"
    if not f.exists():
        return note("e7_guardian", "missing")
    df = pd.read_csv(f)
    res = {}
    for cfg, g in df.groupby("config"):
        res[cfg] = {"reps": int(len(g)), "wipe_ms": stats(g.wipe_ms.dropna()),
                    "readable_after_3s": int(g.readable_after_3s.sum()),
                    "still_mounted": int(g.still_mounted.sum())}
    ev = DATA / "e7_guardian" / "guardian_events.csv"
    if ev.exists():
        e = pd.read_csv(ev)
        res["open_denied_events"] = int((e.event == "open_denied").sum())
        res["denied_executables"] = sorted(set(
            e[e.event == "open_denied"].detail.str.extract(r"exe=(\S+)")[0].dropna()))[:20]
    R["sections"]["e7_guardian"] = res
    note("e7_guardian", "ok")


# ======================================================================
# E8 - challenge-response RTT and emulated relays
# ======================================================================

def _e8_load(path):
    df = pd.read_csv(path)
    ok = df[(df.err.isna()) & (df.resp_ok == 1) & (df.att_ok == 1)].copy()
    ok["rtt_ms"] = ok.rtt_us / 1000.0
    return df, ok


def _e8_bound(legit, singles):
    """
    Bound from genuine data only: the 99th percentile of individual genuine
    exchanges, and never below the slowest genuine reported value; rounded up
    to 0.5 ms. With fastest-of-k reporting, a genuine badge is rejected only if
    all k exchanges exceed the bound.
    """
    return math.ceil(max(np.percentile(singles, 99), legit.max() + 0.25) * 2) / 2


def e8():
    runs = {}
    for k, name in ((1, "cr_bench.csv"), (3, "cr_bench_k3.csv")):
        f = DATA / "e8_relay" / name
        if f.exists():
            runs[k] = _e8_load(f)
    if not runs:
        return note("e8_relay", "missing")
    res = {"runs": {}}
    for k, (df, ok) in runs.items():
        legit = ok[ok.delay_ms == 0].rtt_ms.to_numpy()
        if len(legit) < 10:
            continue
        g0 = ok[ok.delay_ms == 0]
        if "rtts_us" in g0:
            singles = np.array([int(x) / 1000 for r in g0.rtts_us.dropna() for x in str(r).split(",")])
        else:
            singles = legit
        bound = _e8_bound(legit, singles)
        r = {"sent": int(len(df)), "answered": int(len(ok)),
             "invalid": int(((df.resp_ok == 0) | (df.att_ok == 0)).sum()),
             "legit_rtt_ms": stats(legit), "legit_single_exchange_ms": stats(singles),
             "p_single_above_bound": float((singles > bound).mean()),
             "bound_ms": bound, "per_delay": {}}
        for d, g in ok.groupby("delay_ms"):
            rtt = g.rtt_ms.to_numpy()
            r["per_delay"][int(d)] = {"n": int(len(rtt)), "rtt_ms": stats(rtt),
                                      "rejected": float((rtt > bound).mean())}
        res["runs"][k] = r
    if not res["runs"]:
        return note("e8_relay", "too few legitimate samples")
    deployed = 3 if 3 in res["runs"] else 1
    res["deployed_repeats"] = deployed
    res["bound_ms"] = res["runs"][deployed]["bound_ms"]   # used to set CR_MAX_RTT_US
    R["sections"]["e8_relay"] = res
    note("e8_relay", f"ok (bound from {'fastest of 3' if deployed == 3 else 'single exchange'})")

    ks = sorted(res["runs"])
    delays = sorted({d for k in ks for d in res["runs"][k]["per_delay"]})
    header = ["Added delay"]
    for k in ks:
        lab = "single" if k == 1 else f"fastest of {k}"
        header += [f"{lab}:|RTT (ms)", "rejected"]
    rows = []
    for d in delays:
        row = ["none (legitimate)" if d == 0 else f"{d} ms"]
        for k in ks:
            v = res["runs"][k]["per_delay"].get(d)
            row += ([fmt_med(v["rtt_ms"], 1.0, 1), f"{100 * v['rejected']:.1f}\\%"] if v else ["--", "--"])
        rows.append(row)
    bounds = "; ".join(f"{'single exchange' if k == 1 else f'fastest of {k}'}: {res['runs'][k]['bound_ms']:.1f}\\,ms"
                       for k in ks)
    write_table("relay", header, rows,
                "Challenge--response round-trip times measured by the anchor (median [IQR]) and the share "
                f"rejected at the bound ({bounds}), set from genuine answers only: the 99th percentile of "
                "individual genuine exchanges, and at least the slowest genuine value. Delays emulate the "
                "latency a relay adds.", "tab:relay", colspec="l" + "rr" * len(ks))

    ramp = ["#f6b391", "#f0905f", "#eb6834", "#c4501f", "#8f3a17", "#5e2610"]
    fig, axes = plt.subplots(1, len(ks), figsize=DOUBLE if len(ks) > 1 else SINGLE, sharex=True, sharey=True,
                             squeeze=False)
    for ax, k in zip(axes[0], ks):
        _, ok = runs[k]
        others = [d for d in sorted(ok.delay_ms.unique()) if d != 0]
        for i, d in enumerate([0] + others):
            rtt = np.sort(ok[ok.delay_ms == d].rtt_ms.to_numpy())
            if not len(rtt):
                continue
            y = np.arange(1, len(rtt) + 1) / len(rtt)
            col = BLUE if d == 0 else ramp[min(i - 1, len(ramp) - 1)]
            ax.step(rtt, y, where="post", color=col, linewidth=1.6 if d == 0 else 1.1,
                    label="legitimate" if d == 0 else f"+{int(d)} ms")
        bound = res["runs"][k]["bound_ms"]
        ax.axvline(bound, color=MUTED, linestyle=":", linewidth=1.0)
        ax.text(bound, 1.03, f"bound {bound:.1f} ms", color=INK2, fontsize=6.5, ha="center", va="bottom",
                transform=ax.get_xaxis_transform())
        ax.set_title("single exchange" if k == 1 else f"fastest of {k} exchanges", fontsize=8, pad=14)
        ax.set_xlim(left=0)
        ax.set_ylim(0, 1.0)
        ax.set_xlabel("Round-trip time measured by the anchor (ms)")
    axes[0][0].set_ylabel("Cumulative fraction")
    axes[0][-1].legend(loc="center left", bbox_to_anchor=(1.01, 0.5))
    save(fig, FIG, "fig_relay_cdf")


# ======================================================================
# E6 - overhead
# ======================================================================

def e6():
    res = {}
    f = DATA / "e6_overhead" / "crypto_bench.csv"
    if f.exists():
        res["crypto"] = pd.read_csv(f).to_dict(orient="records")
    f = DATA / "e6_overhead" / "resources.csv"
    if f.exists():
        df = pd.read_csv(f)
        res["resources"] = {lab: {"cpu_pct": stats(g.cpu_pct), "rss_mb": stats(g.rss_mb)}
                            for lab, g in df.groupby("label")}
    if not res:
        return note("e6_overhead", "missing")
    R["sections"]["e6_overhead"] = res
    note("e6_overhead", "ok")

    if "crypto" in res:
        c = pd.DataFrame(res["crypto"])
        rows = []
        for size in (64 << 10, 1 << 20, 10 << 20):
            e = c[(c.op == "aesgcm_encrypt") & (c.size_bytes == size)]
            d = c[(c.op == "aesgcm_decrypt") & (c.size_bytes == size)]
            if len(e) and len(d):
                lab = f"{size >> 10} KiB" if size < (1 << 20) else f"{size >> 20} MiB"
                rows.append([f"AES-256-GCM encrypt / decrypt, {lab}",
                             f"{float(e.median_us.iloc[0]):.0f} / {float(d.median_us.iloc[0]):.0f}",
                             f"{float(e.throughput_MBps.iloc[0]):.0f} / {float(d.throughput_MBps.iloc[0]):.0f} MB/s"])
        names = {"token_parse_verify": "Token parse + HMAC verify", "freshness_check": "Freshness check (Alg. 1)",
                 "request_sig_verify": "Request signature verify", "fek_wrap": "FEK wrap (AES-256-GCM)",
                 "fek_unwrap": "FEK unwrap"}
        for op, lab in names.items():
            r = c[c.op == op]
            if len(r):
                rows.append([lab, f"{float(r.median_us.iloc[0]):.2f}", "--"])
        if "resources" in res:
            for lab, v in res["resources"].items():
                rows.append([f"Agent CPU / RSS ({lab.replace('_', ' ')})",
                             f"{v['cpu_pct']['mean']:.1f}\\% / {v['rss_mb']['mean']:.0f} MB", "mean"])
        cpu = str(c.cpu.iloc[0]) if "cpu" in c else ""
        write_table("overhead", ["Operation", "Median|time ($\\mu$s)", "Throughput"], rows,
                    f"Cost of cryptographic and \\pakl\\ operations on the workstation ({cpu}).",
                    "tab:overhead", colspec=r">{\raggedright\arraybackslash}X rr", full_width=True)


if __name__ == "__main__":
    for fn in (field_logs, e1, e2_live, ablation, e4, e5, e6, e7, e8):
        try:
            fn()
        except Exception as ex:  # report, never fabricate
            note(fn.__name__, f"ERROR {type(ex).__name__}: {ex}")
    (OUT / "results.json").write_text(json.dumps(R, indent=2, default=str))
    print(f"-> {OUT / 'results.json'}")

# Evaluation

Experiment scripts, measurement data and analysis for the hardened system:
presence-attested key leasing (PAKL), anchor-attested challenge–response and the vault guardian.

## Layout

| Experiment | Scripts (`experiments/`) | Data (`data/`) |
|---|---|---|
| E1 signal characterisation | `rssi_logger.py`, `e1_session.sh` | `e1_rssi/rssi.csv` |
| E2 walk-away and return | `marker.py`, agent `--trace-csv` | `e2_walk/markers_*.csv`, `trace_baseline.csv`, `trace_pakl.csv` |
| E3 seated work | `marker.py` | `e2_walk/markers_seated.csv`, `trace_pakl.csv` |
| E4 attacks, revocation, outage | `attack_bench.py`, `revoke_bench.py`, `outage_bench.py`, `server_admin.py` | `e4_security/` (`*_v2.csv`: after the agent fixes) |
| E5 exfiltration attempts | `dlp_bench.py`, `fs_watch.py`, `usb_watch.py`, `note.py` | `e5_dlp/`, `manual_results.csv` |
| E6 overhead | `crypto_bench.py`, `resource_monitor.py` | `e6_overhead/` |
| E7 killing the agent | `kill_bench.py` | `e7_guardian/` |
| E8 relay detection | `cr_bench.py` | `e8_relay/cr_bench.csv` (single exchange), `cr_bench_k3.csv` (fastest of three) |
| Field logs | `export_audit_logs.py` | `field_logs/audit_logs.csv` |

`data/environment.txt` describes the room and setup. `common.py` holds helpers shared by the
scripts. Placeholders in the data: badge address `AA:BB:CC:DD:EE:FF`, home directory
`/home/user`, host name `HOST`.

## Reproducing the results

From the repository root, with Python 3.12, NumPy, pandas and Matplotlib:

```bash
python evaluation/analysis/analyze.py
```

This writes `analysis/out/results.json` (every number reported), per-trial tables, figures
and LaTeX tables. `analysis/replay.py` replays the recorded RSSI through the agent's own
filter classes for the pipeline variants and the 192-configuration parameter sweep.

The experiment scripts need the project's server, agent and firmware set up as described in
the main README (PAKL section); each script's header shows its usage.

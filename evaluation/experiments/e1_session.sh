#!/usr/bin/env bash
# E1 - badge signal strength vs distance, one person, guided by beeps.
# Agent must be stopped (the logger talks to the anchor directly).
#
#   bash evaluation/experiments/e1_session.sh          # facing positions up to 8 m, 60 s each
#   bash evaluation/experiments/e1_session.sh 6 60     # ... only up to 6 m, 60 s each
#
# Uses $PORT and $MAC when set; otherwise the defaults below.
set -e
cd "$(dirname "$0")/../.."
PORT=${PORT:-/dev/ttyACM0}
MAC=${MAC:?set MAC to the BLE address of the badge}
MAX=${1:-8}
SECS=${2:-60}
LOG=evaluation/experiments/rssi_logger.py
echo "Anchor port: $PORT   badge: $MAC"

record() {   # $1 = label, $2 = instruction
    read -r -p "Next: $2. Press Enter, then walk there " _
    python "$LOG" --port "$PORT" --mac "$MAC" --label "$1" --seconds "$SECS" --wait 15
    echo
}

for d in 0.5 1.0 1.5 2.0 2.5 3.0 4.0 5.0 6.0 7.0 8.0; do
    awk "BEGIN{exit !($d <= $MAX)}" || continue
    record "d${d}_front" "stand at $d m FACING the anchor"
done
for d in 1.0 2.0 3.0; do
    record "d${d}_back" "stand at $d m with your BACK to the anchor"
done
record desk_seated "sit at the desk as you normally work, badge on the lanyard"
echo "E1 finished: all positions recorded."

#!/usr/bin/env bash
# Install the SPAZE vault guardian as a root systemd service.
#   sudo bash guardian/install.sh            install + start
#   sudo bash guardian/install.sh --remove   stop + remove
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
USER_NAME="${SUDO_USER:?run via sudo from your normal account}"
if [ "${1:-}" = "--remove" ]; then
  systemctl disable --now spaze-guardian 2>/dev/null || true
  rm -f /etc/systemd/system/spaze-guardian.service
  systemctl daemon-reload
  echo "guardian removed (config kept in /etc/spaze)"; exit 0
fi
install -d -m 755 /opt/spaze/guardian /etc/spaze
install -m 755 "$HERE/spaze_guardian.py" /opt/spaze/guardian/spaze_guardian.py
if [ ! -f /etc/spaze/guardian.json ]; then
  sed "s/YOUR_LINUX_USER/$USER_NAME/g" "$HERE/guardian.example.json" > /etc/spaze/guardian.json
  chmod 644 /etc/spaze/guardian.json
fi
install -m 644 "$HERE/spaze-guardian.service" /etc/systemd/system/spaze-guardian.service
systemctl daemon-reload
systemctl enable --now spaze-guardian
sleep 1
systemctl --no-pager --lines=5 status spaze-guardian || true
echo "Guardian running. Events: /var/log/spaze-guardian.csv"
echo "Stop it before running the agent WITHOUT --guardian:  sudo systemctl stop spaze-guardian"

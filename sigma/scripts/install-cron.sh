#!/usr/bin/env bash
# Install AuthGraph Wazuh auto-deploy cron on the Wazuh manager.
#
# Usage (on Wazuh manager as root):
#   git clone -b sigma https://github.com/hackatonteam96-eng/Autograph.git /opt/Autograph
#   cd /opt/Autograph/sigma/scripts
#   sudo bash install-cron.sh
#
# Options via env:
#   CRON_SCHEDULE="0 2 * * *"     # default: daily 02:00
#   AUTHGRAPH_REPO_DIR=/opt/Autograph

set -euo pipefail

CRON_SCHEDULE="${CRON_SCHEDULE:-0 2 * * *}"
REPO_DIR="${AUTHGRAPH_REPO_DIR:-/opt/Autograph}"
INSTALL_PATH="/usr/local/bin/authgraph-deploy-wazuh.sh"
LOG_FILE="/var/log/authgraph-wazuh-deploy.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root: sudo bash install-cron.sh"
  exit 1
fi

echo "Installing deploy script → $INSTALL_PATH"
cp "$SCRIPT_DIR/deploy-wazuh.sh" "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"

touch "$LOG_FILE"
chmod 644 "$LOG_FILE"

CRON_LINE="$CRON_SCHEDULE $INSTALL_PATH >> $LOG_FILE 2>&1"
CRON_MARKER="# authgraph-wazuh-deploy"

# Remove old entry if present, add new
( crontab -l 2>/dev/null | grep -v "$CRON_MARKER" | grep -v "$INSTALL_PATH" || true
  echo "$CRON_LINE $CRON_MARKER"
) | crontab -

echo ""
echo "Installed."
echo "  Schedule:  $CRON_SCHEDULE"
echo "  Script:    $INSTALL_PATH"
echo "  Log:       $LOG_FILE"
echo "  Repo:      $REPO_DIR"
echo ""
echo "Run once now:"
echo "  sudo $INSTALL_PATH"
echo ""
echo "View log:"
echo "  tail -f $LOG_FILE"
echo ""
echo "Change schedule (example: every 6 hours):"
echo "  sudo CRON_SCHEDULE='0 */6 * * *' bash install-cron.sh"

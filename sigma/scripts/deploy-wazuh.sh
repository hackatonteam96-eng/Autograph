#!/usr/bin/env bash
# AuthGraph — Auto-deploy Sigma rules to Wazuh local_rules.xml
#
# Install on Wazuh manager (Linux):
#   sudo cp deploy-wazuh.sh /usr/local/bin/authgraph-deploy-wazuh.sh
#   sudo chmod +x /usr/local/bin/authgraph-deploy-wazuh.sh
#
# Cron (see install-cron.sh or README):
#   0 2 * * * /usr/local/bin/authgraph-deploy-wazuh.sh >> /var/log/authgraph-wazuh-deploy.log 2>&1

set -euo pipefail

# --- Config (override via env or edit defaults) ---
REPO_DIR="${AUTHGRAPH_REPO_DIR:-/opt/Autograph}"
BRANCH="${AUTHGRAPH_BRANCH:-sigma}"
OUTPUT_XML="${WAZUH_RULES_OUTPUT:-/var/ossec/etc/rules/local_rules.xml}"
LOG_TAG="authgraph-wazuh-deploy"
VENV_DIR="${AUTHGRAPH_VENV:-/opt/authgraph-venv}"

log() { echo "[$(date -Iseconds)] [$LOG_TAG] $*"; }
die() { log "ERROR: $*"; exit 1; }

# --- Must run as root for Wazuh paths and restart ---
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  die "Run as root: sudo $0"
fi

SCRIPTS_DIR="$REPO_DIR/sigma/scripts"
CONVERTER="$SCRIPTS_DIR/convert_sigma_to_wazuh.py"
REQUIREMENTS="$SCRIPTS_DIR/requirements.txt"

[[ -d "$REPO_DIR/.git" ]] || die "Repo not found at $REPO_DIR — clone Autograph first"
[[ -f "$CONVERTER" ]] || die "Converter not found: $CONVERTER"

PYTHON="python3"

setup_python() {
  if "$PYTHON" -c "import yaml" 2>/dev/null; then
    log "Python OK (pyyaml available)"
    return
  fi

  # Try venv first when ensurepip is available
  if python3 -m venv "$VENV_DIR" 2>/dev/null; then
    log "Using venv at $VENV_DIR"
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
    pip install -q -r "$REQUIREMENTS"
    PYTHON="$VENV_DIR/bin/python3"
    return
  fi

  # Broken partial venv from a failed run — remove and retry once
  if [[ -d "$VENV_DIR" ]]; then
    log "Removing incomplete venv at $VENV_DIR"
    rm -rf "$VENV_DIR"
    if python3 -m venv "$VENV_DIR" 2>/dev/null; then
      # shellcheck source=/dev/null
      source "$VENV_DIR/bin/activate"
      pip install -q -r "$REQUIREMENTS"
      PYTHON="$VENV_DIR/bin/python3"
      return
    fi
  fi

  log "venv not available — installing pyyaml via apt/pip"
  if command -v apt-get >/dev/null; then
    apt-get update -qq
    apt-get install -y -qq python3-yaml 2>/dev/null \
      || apt-get install -y -qq python3-pip 2>/dev/null \
      || true
  fi

  if "$PYTHON" -c "import yaml" 2>/dev/null; then
    log "Installed python3-yaml via apt"
    return
  fi

  if command -v pip3 >/dev/null; then
    pip3 install -q pyyaml 2>/dev/null \
      || pip3 install -q --break-system-packages pyyaml 2>/dev/null \
      || pip3 install -q -r "$REQUIREMENTS"
    if "$PYTHON" -c "import yaml" 2>/dev/null; then
      log "Installed pyyaml via pip3"
      return
    fi
  fi

  die "Cannot install pyyaml. Run: sudo apt install python3-yaml   OR   sudo apt install python3.10-venv && re-run"
}

setup_python

# --- Pull latest Sigma rules ---
log "Pulling $BRANCH from $REPO_DIR"
cd "$REPO_DIR"
git fetch origin "$BRANCH" --quiet
git checkout "$BRANCH" --quiet
git pull origin "$BRANCH" --quiet

BEFORE="$(git rev-parse HEAD)"

# --- Convert Sigma → Wazuh XML ---
log "Converting sigma/*.yml → $OUTPUT_XML"
"$PYTHON" "$CONVERTER" \
  --sigma-dir "$REPO_DIR/sigma" \
  --output "$OUTPUT_XML"

[[ -f "$OUTPUT_XML" ]] || die "Converter did not create $OUTPUT_XML"

# --- Validate XML (basic) ---
"$PYTHON" -c "import xml.etree.ElementTree as ET; ET.parse('$OUTPUT_XML')" \
  || die "Generated XML is invalid"

# --- Restart Wazuh only if repo changed or rules file is new ---
AFTER="$(git rev-parse HEAD)"
RULES_CHANGED=0
if [[ -f "${OUTPUT_XML}.prev" ]]; then
  if ! cmp -s "$OUTPUT_XML" "${OUTPUT_XML}.prev"; then
    RULES_CHANGED=1
  fi
else
  RULES_CHANGED=1
fi

cp "$OUTPUT_XML" "${OUTPUT_XML}.prev"

if [[ "$BEFORE" != "$AFTER" ]] || [[ "$RULES_CHANGED" -eq 1 ]]; then
  log "Rules updated (commit $AFTER) — restarting wazuh-manager"
  systemctl restart wazuh-manager
  sleep 3
  if systemctl is-active --quiet wazuh-manager; then
    log "wazuh-manager is active"
  else
    die "wazuh-manager failed to start — check journalctl -u wazuh-manager"
  fi
else
  log "No Sigma changes — skip restart"
fi

log "Done. Rules: $OUTPUT_XML ($(grep -c '<rule ' "$OUTPUT_XML" || echo 0) rules)"

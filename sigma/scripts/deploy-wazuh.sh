#!/usr/bin/env bash
# AuthGraph — Auto-deploy Sigma rules to Wazuh authgraph_rules.xml
#
# Does NOT overwrite local_rules.xml — uses separate authgraph_rules.xml + rule_include.

set -euo pipefail

REPO_DIR="${AUTHGRAPH_REPO_DIR:-/opt/Autograph}"
BRANCH="${AUTHGRAPH_BRANCH:-sigma}"
OUTPUT_XML="${WAZUH_RULES_OUTPUT:-/var/ossec/etc/rules/authgraph_rules.xml}"
OSSEC_CONF="${WAZUH_OSSEC_CONF:-/var/ossec/etc/ossec.conf}"
LOG_TAG="authgraph-wazuh-deploy"
VENV_DIR="${AUTHGRAPH_VENV:-/opt/authgraph-venv}"
RULE_INCLUDE="rules/authgraph_rules.xml"

log() { echo "[$(date -Iseconds)] [$LOG_TAG] $*"; }
die() { log "ERROR: $*"; exit 1; }

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  die "Run as root: sudo $0"
fi

SCRIPTS_DIR="$REPO_DIR/sigma/scripts"
CONVERTER="$SCRIPTS_DIR/convert_sigma_to_wazuh.py"
REQUIREMENTS="$SCRIPTS_DIR/requirements.txt"

[[ -d "$REPO_DIR/.git" ]] || die "Repo not found at $REPO_DIR"
[[ -f "$CONVERTER" ]] || die "Converter not found: $CONVERTER"

PYTHON="python3"

setup_python() {
  if "$PYTHON" -c "import yaml" 2>/dev/null; then
    log "Python OK (pyyaml available)"
    return
  fi
  if python3 -m venv "$VENV_DIR" 2>/dev/null; then
    log "Using venv at $VENV_DIR"
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
    pip install -q -r "$REQUIREMENTS"
    PYTHON="$VENV_DIR/bin/python3"
    return
  fi
  if [[ -d "$VENV_DIR" ]]; then
    rm -rf "$VENV_DIR"
  fi
  log "Installing python3-yaml via apt"
  apt-get update -qq
  apt-get install -y -qq python3-yaml || die "Run: sudo apt install python3-yaml"
}

ensure_rule_include() {
  if grep -q "authgraph_rules.xml" "$OSSEC_CONF" 2>/dev/null; then
    log "rule_include for authgraph_rules.xml already in ossec.conf"
    return
  fi
  log "Adding rule_include to $OSSEC_CONF"
  if grep -q "<ruleset>" "$OSSEC_CONF"; then
    sed -i "/<ruleset>/a\\  <rule_include>${RULE_INCLUDE}</rule_include>" "$OSSEC_CONF"
  else
    die "Cannot find <ruleset> in $OSSEC_CONF — add manually: <rule_include>${RULE_INCLUDE}</rule_include>"
  fi
}

test_wazuh_config() {
  if [[ -x /var/ossec/bin/wazuh-analysisd ]]; then
    log "Testing Wazuh config (wazuh-analysisd -t)"
    local logfile
    logfile="$(mktemp)"
    if ( cd /var/ossec && /var/ossec/bin/wazuh-analysisd -t ) >"$logfile" 2>&1; then
      tail -3 "$logfile"
      rm -f "$logfile"
      return 0
    fi
    tail -15 "$logfile"
    rm -f "$logfile"
    return 1
  elif [[ -x /var/ossec/bin/ossec-analysisd ]]; then
    ( cd /var/ossec && /var/ossec/bin/ossec-analysisd -t ) 2>&1 | tail -5
  else
    log "WARN: wazuh-analysisd not found — skipping config test"
    return 0
  fi
}

setup_python

log "Pulling $BRANCH from $REPO_DIR"
cd "$REPO_DIR"
git fetch origin "$BRANCH" --quiet
git checkout "$BRANCH" --quiet
git pull origin "$BRANCH" --quiet
BEFORE="$(git rev-parse HEAD)"

# Backup current rules if present
if [[ -f "$OUTPUT_XML" ]]; then
  cp "$OUTPUT_XML" "${OUTPUT_XML}.bak"
fi

log "Converting sigma/*.yml → $OUTPUT_XML"
"$PYTHON" "$CONVERTER" \
  --sigma-dir "$REPO_DIR/sigma" \
  --output "$OUTPUT_XML"

[[ -f "$OUTPUT_XML" ]] || die "Converter did not create $OUTPUT_XML"
chmod 640 "$OUTPUT_XML"
chown root:wazuh "$OUTPUT_XML" 2>/dev/null || chown root:ossec "$OUTPUT_XML" 2>/dev/null || true
log "Wrote $(grep -c '<rule ' "$OUTPUT_XML" || echo 0) rules to $OUTPUT_XML"
head -3 "$OUTPUT_XML" | while read -r line; do log "  $line"; done

"$PYTHON" -c "import xml.etree.ElementTree as ET; ET.parse('$OUTPUT_XML')" \
  || die "Generated XML is invalid"

ensure_rule_include

# Test BEFORE restart — restore backup on failure
if ! test_wazuh_config; then
  log "Config test FAILED — restoring previous rules if backup exists"
  if [[ -f "${OUTPUT_XML}.bak" ]]; then
    cp "${OUTPUT_XML}.bak" "$OUTPUT_XML"
    test_wazuh_config || true
  fi
  die "Wazuh rejected generated rules. Check: journalctl -xeu wazuh-manager | tail -30"
fi

AFTER="$(git rev-parse HEAD)"
RULES_CHANGED=0
if [[ -f "${OUTPUT_XML}.prev" ]] && cmp -s "$OUTPUT_XML" "${OUTPUT_XML}.prev"; then
  RULES_CHANGED=0
else
  RULES_CHANGED=1
fi
cp "$OUTPUT_XML" "${OUTPUT_XML}.prev"

if [[ "$BEFORE" != "$AFTER" ]] || [[ "$RULES_CHANGED" -eq 1 ]]; then
  log "Rules updated (commit $AFTER) — restarting wazuh-manager"
  systemctl restart wazuh-manager
  sleep 4
  if systemctl is-active --quiet wazuh-manager; then
    log "wazuh-manager is active"
  else
    if [[ -f "${OUTPUT_XML}.bak" ]]; then
      cp "${OUTPUT_XML}.bak" "$OUTPUT_XML"
      systemctl restart wazuh-manager || true
    fi
    die "wazuh-manager failed — run: journalctl -xeu wazuh-manager | tail -40"
  fi
else
  log "No Sigma changes — skip restart"
fi

log "Done. Rules: $OUTPUT_XML ($(grep -c '<rule ' "$OUTPUT_XML" || echo 0) rules)"

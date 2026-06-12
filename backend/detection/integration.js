/**
 * Thin adapter for Nazrin's dataStore — wire detection without editing route files.
 * Gular owns this file; Nazrin imports from ../detection/integration in dataStore.js.
 */

const path = require("path");
const fs = require("fs");
const {
  correlateAlerts,
  correlateAlert,
  getIdentityRisk,
  processWazuhPayload,
  explainAlert,
} = require("./index");

function loadAttackPath(dataDir) {
  const file = path.join(dataDir, "attack-path.json");
  try {
    if (fs.existsSync(file)) {
      return JSON.parse(fs.readFileSync(file, "utf8"));
    }
  } catch {
    /* use null */
  }
  return null;
}

/**
 * Enrich raw alerts with detection metadata and consistent risk scoring.
 * @param {object[]} alerts
 * @param {string} [dataDir]
 * @returns {object[]}
 */
function enrichAlerts(alerts, dataDir) {
  const attackPath = loadAttackPath(dataDir || path.resolve(__dirname, "../../data"));
  return correlateAlerts(alerts, attackPath);
}

/**
 * Score identity for GET /api/risk/:identity
 * @param {string} identity
 * @param {object[]} alerts
 * @param {string} [dataDir]
 */
function scoreIdentity(identity, alerts, dataDir) {
  const attackPath = loadAttackPath(dataDir || path.resolve(__dirname, "../../data"));
  return getIdentityRisk(identity, alerts, attackPath);
}

/**
 * Process Wazuh export file contents.
 * @param {unknown} payload
 * @param {string} [dataDir]
 */
function ingestWazuh(payload, dataDir) {
  const attackPath = loadAttackPath(dataDir || path.resolve(__dirname, "../../data"));
  return processWazuhPayload(payload, attackPath);
}

/**
 * Explain alert for docs/demo script.
 * @param {object} alert
 */
function explain(alert) {
  return explainAlert(alert);
}

module.exports = {
  enrichAlerts,
  enrichAlert: correlateAlert,
  scoreIdentity,
  ingestWazuh,
  explain,
};

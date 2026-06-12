/**
 * AuthGraph ITDR — Alert correlator.
 * Joins Sigma matching, event parsing, and risk scoring into incident-ready alerts.
 */

const { randomUUID } = require("crypto");
const { MITRE } = require("./constants");
const { parseKerberosEvent, parseKerberosEvents } = require("./event_parser");
const { detectKerberoasting, matchSigmaRule } = require("./sigma_matcher");
const { scoreRisk, buildEvidence, capRisk, severityFromRisk } = require("./risk_engine");

const DEFAULT_RESPONSE_ACTIONS = [
  "Reset service account password",
  "Disable RC4 Kerberos encryption",
  "Review SPN ownership",
  "Investigate source user session",
  "Rotate credentials for exposed service account",
];

/**
 * Generate a stable alert id.
 * @param {string} [prefix]
 * @returns {string}
 */
function generateAlertId(prefix = "alert") {
  const suffix = randomUUID().split("-")[0];
  return `${prefix}-${suffix}`;
}

/**
 * Merge detection indicators with attack path context for scoring.
 * @param {Record<string, boolean>} detectionIndicators
 * @param {string} targetIdentity
 * @param {object|null} attackPath
 * @returns {import('./risk_engine').RiskScoreResult}
 */
function scoreFromDetection(detectionIndicators, targetIdentity, attackPath = null) {
  return scoreRisk(targetIdentity, detectionIndicators, { attackPath });
}

/**
 * Build a full AuthGraph alert from correlated Kerberos events.
 * @param {unknown[]} rawEvents
 * @param {object} [options]
 * @param {object} [options.attackPath]
 * @param {string} [options.source]
 * @returns {object|null}
 */
function buildAlertFromEvents(rawEvents, options = {}) {
  const detection = detectKerberoasting(rawEvents);
  if (!detection.is_kerberoasting || !detection.primary) {
    return null;
  }

  const primary = detection.primary;
  const target = primary.target || "unknown";
  const indicators = {
    kerberoasting: true,
    rc4_encryption: detection.indicators.rc4_encryption,
    multiple_tgs: detection.indicators.multiple_tgs,
    service_account_spn: detection.indicators.service_account_spn,
    has_spn: detection.indicators.service_account_spn,
  };

  const scored = scoreFromDetection(indicators, target, options.attackPath || null);
  const evidence = buildEvidence(
    {
      ...indicators,
      privileged_link: scored.breakdown.some((b) => b.factor === "privileged_asset_link"),
      privileged_path: scored.breakdown.some((b) => b.factor === "privileged_path_full"),
    },
    { multiple_tgs_count: detection.multiple_tgs_count }
  );

  return {
    id: generateAlertId(),
    time: primary.time,
    source: options.source || "Wazuh",
    attack: "Kerberoasting",
    mitre: MITRE.KERBEROASTING,
    severity: scored.severity,
    risk: scored.risk,
    user: detection.source_user || primary.user,
    target,
    source_ip: primary.source_ip || "",
    host: primary.host || "",
    event_id: primary.event_id,
    evidence: evidence.length > 0 ? evidence : scored.evidence,
    response: [...DEFAULT_RESPONSE_ACTIONS],
    detection: {
      sigma_matched: true,
      indicators: detection.indicators,
      multiple_tgs_count: detection.multiple_tgs_count,
      risk_breakdown: scored.breakdown,
    },
  };
}

/**
 * Enrich an existing or partial alert with detection + risk scoring.
 * Preserves id/time if already set; recalculates risk/evidence when possible.
 * @param {object} rawAlert
 * @param {object} [options]
 * @param {object} [options.attackPath]
 * @param {unknown[]} [options.relatedEvents]
 * @returns {object}
 */
function correlateAlert(rawAlert, options = {}) {
  if (!rawAlert || typeof rawAlert !== "object") {
    throw new TypeError("correlateAlert expects an alert object");
  }

  const attackPath = options.attackPath || null;
  const relatedEvents = options.relatedEvents || [];

  let detection = null;
  if (relatedEvents.length > 0) {
    detection = detectKerberoasting(relatedEvents);
  } else if (rawAlert.event_id === 4769 || rawAlert.raw) {
    detection = detectKerberoasting([rawAlert]);
  }

  const target = String(rawAlert.target || detection?.primary?.target || "unknown").toLowerCase();
  const user = String(rawAlert.user || detection?.source_user || detection?.primary?.user || "unknown").toLowerCase();

  const indicators = detection
    ? {
        kerberoasting: detection.is_kerberoasting,
        rc4_encryption: detection.indicators.rc4_encryption,
        multiple_tgs: detection.indicators.multiple_tgs,
        service_account_spn: detection.indicators.service_account_spn,
      }
    : inferIndicatorsFromAlert(rawAlert);

  const scored = scoreFromDetection(indicators, target, attackPath);

  const evidence =
    Array.isArray(rawAlert.evidence) && rawAlert.evidence.length > 0
      ? rawAlert.evidence
      : buildEvidence(
          {
            ...indicators,
            privileged_link: scored.breakdown.some((b) => b.factor === "privileged_asset_link"),
            privileged_path: scored.breakdown.some((b) => b.factor === "privileged_path_full"),
          },
          { multiple_tgs_count: detection?.multiple_tgs_count }
        );

  const risk = rawAlert.risk ?? scored.risk;
  const severity = rawAlert.severity ?? severityFromRisk(risk);

  return {
    id: rawAlert.id || generateAlertId(),
    time: rawAlert.time || detection?.primary?.time || new Date().toISOString(),
    source: rawAlert.source || "Wazuh",
    attack: rawAlert.attack || "Kerberoasting",
    mitre: rawAlert.mitre || MITRE.KERBEROASTING,
    severity,
    risk: capRisk(risk),
    user,
    target,
    source_ip: rawAlert.source_ip || detection?.primary?.source_ip || "",
    host: rawAlert.host || detection?.primary?.host || "",
    event_id: rawAlert.event_id || 4769,
    evidence,
    response: Array.isArray(rawAlert.response) ? rawAlert.response : [...DEFAULT_RESPONSE_ACTIONS],
    detection: {
      sigma_matched: detection?.is_kerberoasting ?? matchSigmaRule(rawAlert).matched,
      indicators,
      multiple_tgs_count: detection?.multiple_tgs_count ?? 0,
      risk_breakdown: scored.breakdown,
      reason: scored.reason,
    },
  };
}

/**
 * Batch-enrich alerts (e.g. from sample-alerts.json or Wazuh export).
 * @param {object[]} alerts
 * @param {object} [attackPath]
 * @returns {object[]}
 */
function correlateAlerts(alerts, attackPath = null) {
  if (!Array.isArray(alerts)) return [];
  return alerts.map((alert) => correlateAlert(alert, { attackPath }));
}

/**
 * Process Wazuh manager export or agent JSON into AuthGraph alerts.
 * @param {unknown} payload - single alert, array, or { alerts: [] }
 * @param {object} [attackPath]
 * @returns {object[]}
 */
function processWazuhPayload(payload, attackPath = null) {
  let items = [];

  if (Array.isArray(payload)) {
    items = payload;
  } else if (payload?.alerts && Array.isArray(payload.alerts)) {
    items = payload.alerts;
  } else if (payload) {
    items = [payload];
  }

  const parsedEvents = parseKerberosEvents(items);
  const kerberosEvents = parsedEvents.length > 0 ? parsedEvents : items;

  const groupedByUser = new Map();
  for (const evt of kerberosEvents) {
    const parsed = evt.event_id ? evt : parseKerberosEvent(evt);
    if (!parsed) continue;
    const key = parsed.user || "unknown";
    if (!groupedByUser.has(key)) groupedByUser.set(key, []);
    groupedByUser.get(key).push(parsed);
  }

  const results = [];

  for (const [, events] of groupedByUser.entries()) {
    const built = buildAlertFromEvents(events, { attackPath, source: "Wazuh" });
    if (built) results.push(built);
  }

  if (results.length === 0) {
    return correlateAlerts(items.filter((i) => i.attack || i.event_id), attackPath);
  }

  return results;
}

/**
 * Infer indicator flags from alert fields when raw events are unavailable.
 * @param {object} alert
 * @returns {Record<string, boolean>}
 */
function inferIndicatorsFromAlert(alert) {
  const evidence = Array.isArray(alert.evidence) ? alert.evidence.join(" ").toLowerCase() : "";
  return {
    kerberoasting: alert.attack === "Kerberoasting" || Number(alert.event_id) === 4769,
    rc4_encryption: evidence.includes("rc4") || alert.encryption_type === "0x17",
    multiple_tgs: evidence.includes("multiple") && evidence.includes("tgs"),
    service_account_spn: evidence.includes("spn") || Boolean(alert.target),
  };
}

/**
 * Explain why an alert fired — for demo and judge walkthrough.
 * @param {object} alert
 * @returns {{ summary: string, sigma: string[], risk_factors: import('./risk_engine').RiskBreakdownItem[] }}
 */
function explainAlert(alert) {
  const correlated = correlateAlert(alert);
  const sigmaReasons = [];

  if (correlated.detection?.sigma_matched) {
    sigmaReasons.push("Sigma rule authgraph-kerberoasting-4769 matched");
    sigmaReasons.push("Event ID 4769 — Kerberos service ticket operation");
    if (correlated.detection.indicators?.rc4_encryption) {
      sigmaReasons.push("RC4 TicketEncryptionType (offline crackable)");
    }
    if (correlated.detection.indicators?.multiple_tgs) {
      sigmaReasons.push(`Multiple TGS requests (${correlated.detection.multiple_tgs_count}+)`);
    }
  }

  return {
    summary: correlated.detection?.reason || `Risk ${correlated.risk} (${correlated.severity})`,
    sigma: sigmaReasons,
    risk_factors: correlated.detection?.risk_breakdown || [],
    evidence: correlated.evidence,
  };
}

module.exports = {
  generateAlertId,
  buildAlertFromEvents,
  correlateAlert,
  correlateAlerts,
  processWazuhPayload,
  explainAlert,
  inferIndicatorsFromAlert,
};

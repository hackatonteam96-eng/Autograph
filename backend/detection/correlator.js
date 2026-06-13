/**
 * AuthGraph ITDR — Alert correlator.
 * Joins Sigma matching, event parsing, and risk scoring into incident-ready alerts.
 */

const { randomUUID, createHash } = require("crypto");
const { MITRE, AS_REP_EVENT_ID } = require("./constants");
const { parseKerberosEvent, parseKerberosEvents } = require("./event_parser");
const { detectKerberoasting, matchSigmaRule } = require("./sigma_matcher");
const { scoreRisk, buildEvidence, capRisk, severityFromRisk } = require("./risk_engine");
const { classifyWazuhItem, extractEncryptionFromRaw } = require("./wazuh_filter");

const DEFAULT_RESPONSE_ACTIONS = [
  "Reset service account password",
  "Disable RC4 Kerberos encryption",
  "Review SPN ownership",
  "Investigate source user session",
  "Rotate credentials for exposed service account",
];

const AS_REP_RESPONSE_ACTIONS = [
  "Disable pre-authentication not required on target account",
  "Reset compromised account password",
  "Review accounts with Do not require Kerberos preauth",
  "Investigate source user session",
  "Disable RC4 Kerberos encryption",
];

function pickField(obj, ...keys) {
  for (const key of keys) {
    if (obj?.[key] !== undefined && obj[key] !== null && obj[key] !== "") return obj[key];
  }
  return "";
}

function extractIdentityFromRaw(raw) {
  const nested = raw.data && typeof raw.data === "object" ? raw.data : {};
  const win = nested.win || raw.win || {};
  const eventData = win.eventdata || win.EventData || nested.eventdata || nested.EventData || {};
  const user = String(
    pickField(raw, "user", "AccountName", "TargetUserName", "SubjectUserName") ||
      pickField(eventData, "TargetUserName", "targetUserName", "AccountName", "SubjectUserName") ||
      pickField(nested, "user", "TargetUserName", "targetUserName") ||
      "unknown",
  ).toLowerCase();
  const host = String(
    pickField(raw, "host", "WorkstationName", "Computer") ||
      pickField(eventData, "WorkstationName", "workstationName", "Computer") ||
      pickField(raw.agent, "name") ||
      "unknown",
  );
  const sourceIp = String(
    pickField(raw, "source_ip", "IpAddress", "ip") ||
      pickField(eventData, "IpAddress", "ipAddress") ||
      pickField(raw.agent, "ip") ||
      "",
  );
  return { user, host, sourceIp };
}

function classifyAttackFromRaw(raw) {
  const ruleRaw = raw.rule;
  const desc =
    typeof ruleRaw === "string"
      ? ruleRaw
      : ruleRaw?.description || raw.attack || "";
  const d = String(desc).toLowerCase();
  const mitreIds = []
    .concat(ruleRaw?.mitre?.id || ruleRaw?.mitre?.technique || [])
    .flat()
    .map(String);

  if (
    d.includes("as-rep") ||
    d.includes("asrep") ||
    d.includes("as rep") ||
    mitreIds.some((id) => id.includes("T1558.004"))
  ) {
    return { attack: "AS-REP Roasting", mitre: MITRE.AS_REP_ROASTING, event_id: AS_REP_EVENT_ID };
  }
  if (d.includes("kerberoast") || mitreIds.some((id) => id.includes("T1558.003"))) {
    return { attack: "Kerberoasting", mitre: MITRE.KERBEROASTING, event_id: 4769 };
  }
  if (mitreIds.some((id) => id.startsWith("T1558"))) {
    return { attack: "Kerberos abuse", mitre: mitreIds.find((id) => id.startsWith("T1558")) || MITRE.KERBEROASTING, event_id: 4769 };
  }
  return { attack: "Identity threat", mitre: MITRE.KERBEROASTING, event_id: 4769 };
}

/**
 * Build alert from a single Wazuh item when batch Kerberos parsing fails (AS-REP, custom rules).
 */
function buildAlertFromWazuhItem(raw, options = {}) {
  if (!raw || typeof raw !== "object") return null;
  if (classifyWazuhItem(raw) !== "itdr") return null;

  const { attack, mitre, event_id } = classifyAttackFromRaw(raw);
  const { user, host, sourceIp } = extractIdentityFromRaw(raw);
  const etype = extractEncryptionFromRaw(raw);
  const isRc4 = etype === "0x17" || etype === 23 || String(etype).toLowerCase().includes("rc4");
  const target = user !== "unknown" ? user : String(pickField(raw, "target") || "unknown").toLowerCase();

  const indicators =
    attack === "AS-REP Roasting"
      ? {
          as_rep_roasting: true,
          rc4_encryption: isRc4,
          kerberoasting: false,
        }
      : {
          kerberoasting: true,
          rc4_encryption: isRc4,
          service_account_spn: Boolean(target && target !== "unknown"),
        };

  const scored = scoreFromDetection(indicators, target, options.attackPath || null);
  const evidence = buildEvidence(
    {
      ...indicators,
      privileged_link: scored.breakdown.some((b) => b.factor === "privileged_asset_link"),
      privileged_path: scored.breakdown.some((b) => b.factor === "privileged_path_full"),
    },
    {},
  );

  const timeRaw =
    pickField(raw, "time", "timestamp", "@timestamp") || new Date().toISOString();
  let time = new Date().toISOString();
  try {
    const d = new Date(timeRaw);
    if (!Number.isNaN(d.getTime())) time = d.toISOString();
  } catch {
    /* ignore */
  }

  return {
    id: stableAlertId([attack, target, user, host, String(event_id), String(etype)]),
    time,
    source: options.source || "Wazuh",
    attack,
    mitre,
    severity: scored.severity,
    risk: scored.risk,
    user,
    target,
    source_ip: sourceIp,
    host,
    event_id,
    evidence: evidence.length > 0 ? evidence : scored.evidence,
    response: attack === "AS-REP Roasting" ? [...AS_REP_RESPONSE_ACTIONS] : [...DEFAULT_RESPONSE_ACTIONS],
    detection: {
      sigma_matched: true,
      indicators,
      multiple_tgs_count: 0,
      risk_breakdown: scored.breakdown,
    },
  };
}

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
 * Deterministic id from incident fingerprint — survives reload/re-ingest.
 * @param {Array<string|number|undefined>} parts
 * @returns {string}
 */
function stableAlertId(parts) {
  const seed = parts.map((p) => String(p ?? "").toLowerCase()).join("|");
  if (!seed.replace(/\|/g, "")) return generateAlertId();
  return `alert-${createHash("sha256").update(seed).digest("hex").slice(0, 12)}`;
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
    id: stableAlertId([target, primary.user, primary.host, String(primary.event_id)]),
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

  const inferred = inferIndicatorsFromAlert(rawAlert);

  const indicators = detection?.is_kerberoasting
    ? {
        kerberoasting: true,
        rc4_encryption: detection.indicators.rc4_encryption,
        multiple_tgs: detection.indicators.multiple_tgs,
        service_account_spn: detection.indicators.service_account_spn,
      }
    : inferred;

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

  const risk = rawAlert.canonical_risk ?? rawAlert.risk ?? scored.risk;
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
      sigma_matched: detection?.is_kerberoasting || inferred.kerberoasting || matchSigmaRule(rawAlert).matched,
      indicators,
      multiple_tgs_count: detection?.multiple_tgs_count ?? (inferred.multiple_tgs ? 3 : 0),
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
    for (const item of items) {
      const built = buildAlertFromWazuhItem(item, { attackPath, source: "Wazuh" });
      if (built) results.push(built);
    }
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
    as_rep_roasting: alert.attack === "AS-REP Roasting" || Number(alert.event_id) === AS_REP_EVENT_ID,
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
  const indicators = correlated.detection?.indicators || {};
  const isAsRep = alert.attack === "AS-REP Roasting" || indicators.as_rep_roasting;
  const matched =
    correlated.detection?.sigma_matched ||
    indicators.kerberoasting ||
    indicators.as_rep_roasting ||
    alert.attack === "Kerberoasting" ||
    alert.attack === "AS-REP Roasting";

  if (matched) {
    if (isAsRep) {
      sigmaReasons.push("Sigma / Wazuh rule matched AS-REP roasting pattern");
      sigmaReasons.push("Event ID 4768 or pre-auth disabled account targeted");
    } else {
      sigmaReasons.push("Sigma rule authgraph-kerberoasting-4769 matched");
      sigmaReasons.push("Event ID 4769 — Kerberos service ticket operation");
    }
    if (indicators.rc4_encryption) {
      sigmaReasons.push("RC4 TicketEncryptionType (offline crackable)");
    }
    if (indicators.multiple_tgs) {
      sigmaReasons.push(`Multiple TGS requests (${correlated.detection?.multiple_tgs_count || 3}+)`);
    }
    if (indicators.service_account_spn) {
      sigmaReasons.push("Target service account exposes Kerberos SPN");
    }
  }

  return {
    summary: correlated.detection?.reason || `Risk ${correlated.risk} (${correlated.severity})`,
    sigma: sigmaReasons,
    risk_factors: correlated.detection?.risk_breakdown || [],
    evidence: correlated.evidence,
    mitre: correlated.mitre,
    confidence: matched ? "high" : "medium",
  };
}

module.exports = {
  generateAlertId,
  stableAlertId,
  buildAlertFromEvents,
  buildAlertFromWazuhItem,
  correlateAlert,
  correlateAlerts,
  processWazuhPayload,
  explainAlert,
  inferIndicatorsFromAlert,
};

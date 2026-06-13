/**
 * Classify Wazuh webhook payloads — ITDR identity threats (Kerberoasting, AS-REP, etc.).
 * Accepts Event 4769/4768, T1558.x, Yara weak-crypto, and custom AuthGraph rules.
 * Rejects sshd, syslog, and other non-identity-threat noise.
 */

const { KERBEROS_EVENT_ID, AS_REP_EVENT_ID } = require("./constants");
const {
  parseKerberosEvent,
  isWeakKerberosEncryption,
  encryptionTypeNumeric,
} = require("./event_parser");

function extractRuleMeta(raw) {
  if (!raw || typeof raw !== "object") return { description: "", mitreIds: [], level: 0, id: "" };
  const ruleRaw = raw.rule;
  const rule = ruleRaw && typeof ruleRaw === "object" ? ruleRaw : {};
  const descSource =
    typeof ruleRaw === "string"
      ? ruleRaw
      : rule.description || raw.attack || raw.full_log || "";
  const mitreIds = []
    .concat(rule.mitre?.id || rule.mitre?.technique || [])
    .flat()
    .map(String);
  return {
    description: String(descSource).toLowerCase(),
    mitreIds,
    level: Number(rule.level || 0),
    id: String(rule.id || ""),
  };
}

/** Deep-search payload for TicketEncryptionType / event 4769 (Yara custom formats). */
function extractEncryptionFromRaw(raw, depth = 0) {
  if (!raw || typeof raw !== "object" || depth > 6) return "";
  const keys = [
    "ticketEncryptionType",
    "TicketEncryptionType",
    "ticket_encryption_type",
    "encryption_type",
    "EncryptionType",
    "etype",
  ];
  for (const key of keys) {
    if (raw[key] !== undefined && raw[key] !== null && raw[key] !== "") {
      return raw[key];
    }
  }
  for (const val of Object.values(raw)) {
    if (val && typeof val === "object") {
      const found = extractEncryptionFromRaw(val, depth + 1);
      if (found !== "") return found;
    }
  }
  return "";
}

function extractEventIdFromRaw(raw, targetId, depth = 0) {
  if (!raw || typeof raw !== "object" || depth > 6) return 0;
  const keys = ["event_id", "eventID", "EventID", "eventId", "eventid"];
  for (const key of keys) {
    const n = Number(raw[key]);
    if (n === targetId) return n;
  }
  for (const val of Object.values(raw)) {
    if (val && typeof val === "object") {
      const found = extractEventIdFromRaw(val, targetId, depth + 1);
      if (found === targetId) return found;
    }
  }
  return 0;
}

function hasItdrKeywords(description) {
  const k = [
    "kerberoast",
    "kerberos",
    "4769",
    "4768",
    "tgs",
    "tgt",
    "as-rep",
    "asrep",
    "as rep",
    "pre-auth",
    "preauth",
    "pre authentication",
    "service ticket",
    "ticket encryption",
    "encryption type",
    "rc4",
    "spn",
    "t1558",
    "yara",
    "authgraph",
  ];
  return k.some((p) => description.includes(p));
}

function isAsRepDescription(description) {
  return (
    description.includes("as-rep") ||
    description.includes("asrep") ||
    description.includes("as rep") ||
    description.includes("without pre-auth") ||
    description.includes("preauthentication") ||
    description.includes("pre-authentication")
  );
}

/** @returns {'itdr'|'noise'|'unknown'} */
function classifyWazuhItem(raw) {
  if (!raw || typeof raw !== "object") return "unknown";

  if (raw.attack === "Kerberoasting" || raw.mitre === "T1558.003") return "itdr";
  if (raw.attack === "AS-REP Roasting" || raw.mitre === "T1558.004") return "itdr";

  const parsed = parseKerberosEvent(raw);
  if (parsed?.event_id === KERBEROS_EVENT_ID) return "itdr";

  const { description, mitreIds } = extractRuleMeta(raw);

  if (mitreIds.some((id) => id.includes("T1558"))) return "itdr";
  if (description.includes("kerberoast")) return "itdr";
  if (isAsRepDescription(description)) return "itdr";
  if (extractEventIdFromRaw(raw, AS_REP_EVENT_ID) === AS_REP_EVENT_ID) return "itdr";

  const etype = extractEncryptionFromRaw(raw);
  if (etype !== "" && isWeakKerberosEncryption(etype)) {
    if (
      extractEventIdFromRaw(raw, KERBEROS_EVENT_ID) === KERBEROS_EVENT_ID ||
      extractEventIdFromRaw(raw, AS_REP_EVENT_ID) === AS_REP_EVENT_ID ||
      hasItdrKeywords(description)
    ) {
      return "itdr";
    }
    const num = encryptionTypeNumeric(etype);
    if (num !== null && num > 0x07) return "itdr";
  }

  if (extractEventIdFromRaw(raw, KERBEROS_EVENT_ID) === KERBEROS_EVENT_ID && etype !== "") {
    return "itdr";
  }

  if (hasItdrKeywords(description) && (etype !== "" || description.includes("authgraph"))) return "itdr";

  const noisePatterns = [
    "sshd",
    "authentication failed",
    "failed password",
    "invalid user",
    "sudo",
    "pam_",
    "syslog",
    "disconnected from",
    "connection closed",
    "break-in attempt",
  ];
  if (noisePatterns.some((p) => description.includes(p))) return "noise";
  if (raw.attack && !String(raw.mitre || "").includes("T1558") && !hasItdrKeywords(description)) {
    return "noise";
  }

  return "unknown";
}

function classifyWazuhPayload(payload) {
  const items = Array.isArray(payload)
    ? payload
    : payload?.alerts && Array.isArray(payload.alerts)
      ? payload.alerts
      : payload
        ? [payload]
        : [];

  let hasItdr = false;
  let hasNoise = false;
  let hasUnknown = false;

  for (const item of items) {
    const kind = classifyWazuhItem(item);
    if (kind === "itdr") hasItdr = true;
    if (kind === "noise") hasNoise = true;
    if (kind === "unknown") hasUnknown = true;
  }

  if (hasItdr) return { accept: true, kind: "itdr", items };
  if (hasNoise) return { accept: false, kind: "noise", items, reason: "Non-ITDR alert (sshd/syslog) — ignored" };
  return {
    accept: false,
    kind: "unknown",
    items,
    reason: "Not an ITDR identity alert — need Kerberos/AS-REP rule, T1558, or AuthGraph detection",
  };
}

function isItdrAlert(alert) {
  if (!alert) return false;
  const mitre = String(alert.mitre || "");
  const attack = String(alert.attack || "");
  const eventId = Number(alert.event_id);
  return (
    attack === "Kerberoasting" ||
    mitre === "T1558.003" ||
    eventId === KERBEROS_EVENT_ID ||
    attack === "AS-REP Roasting" ||
    mitre === "T1558.004" ||
    eventId === AS_REP_EVENT_ID ||
    mitre.startsWith("T1558")
  );
}

/** @deprecated use isItdrAlert */
function isKerberoastingAlert(alert) {
  return isItdrAlert(alert);
}

function webhookPreview(raw) {
  if (!raw || typeof raw !== "object") return "";
  const meta = extractRuleMeta(raw);
  const etype = extractEncryptionFromRaw(raw);
  return JSON.stringify({
    rule: meta.description || meta.id,
    event_id: extractEventIdFromRaw(raw, KERBEROS_EVENT_ID) || extractEventIdFromRaw(raw, AS_REP_EVENT_ID) || undefined,
    etype: etype || undefined,
    agent: raw.agent?.name,
  }).slice(0, 280);
}

module.exports = {
  classifyWazuhPayload,
  classifyWazuhItem,
  isItdrAlert,
  isKerberoastingAlert,
  extractEncryptionFromRaw,
  webhookPreview,
};

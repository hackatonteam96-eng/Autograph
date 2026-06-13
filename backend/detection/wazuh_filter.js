/**
 * Classify Wazuh webhook payloads — ITDR Kerberoasting only.
 * Accepts Event 4769, T1558, Yara weak-crypto (etype > 0x07), and custom rule formats.
 * Rejects sshd, syslog, and other non-identity-threat noise.
 */

const { KERBEROS_EVENT_ID } = require("./constants");
const {
  parseKerberosEvent,
  isWeakKerberosEncryption,
  encryptionTypeNumeric,
} = require("./event_parser");

function extractRuleMeta(raw) {
  if (!raw || typeof raw !== "object") return { description: "", mitreIds: [], level: 0, id: "" };
  const rule = raw.rule && typeof raw.rule === "object" ? raw.rule : {};
  const mitreIds = []
    .concat(rule.mitre?.id || rule.mitre?.technique || [])
    .flat()
    .map(String);
  return {
    description: String(rule.description || raw.attack || "").toLowerCase(),
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

function extractEventIdFromRaw(raw, depth = 0) {
  if (!raw || typeof raw !== "object" || depth > 6) return 0;
  const keys = ["event_id", "eventID", "EventID", "eventId", "eventid"];
  for (const key of keys) {
    const n = Number(raw[key]);
    if (n === KERBEROS_EVENT_ID) return n;
  }
  for (const val of Object.values(raw)) {
    if (val && typeof val === "object") {
      const found = extractEventIdFromRaw(val, depth + 1);
      if (found === KERBEROS_EVENT_ID) return found;
    }
  }
  return 0;
}

function hasKerberosKeywords(description) {
  const k = [
    "kerberoast",
    "kerberos",
    "4769",
    "tgs",
    "service ticket",
    "ticket encryption",
    "encryption type",
    "rc4",
    "spn",
    "t1558",
    "yara",
  ];
  return k.some((p) => description.includes(p));
}

/** @returns {'kerberos'|'noise'|'unknown'} */
function classifyWazuhItem(raw) {
  if (!raw || typeof raw !== "object") return "unknown";

  if (raw.attack === "Kerberoasting" || raw.mitre === "T1558.003") return "kerberos";

  const parsed = parseKerberosEvent(raw);
  if (parsed?.event_id === KERBEROS_EVENT_ID) return "kerberos";

  const { description, mitreIds } = extractRuleMeta(raw);

  if (mitreIds.some((id) => id.includes("T1558"))) return "kerberos";
  if (description.includes("kerberoast")) return "kerberos";

  const etype = extractEncryptionFromRaw(raw);
  if (etype !== "" && isWeakKerberosEncryption(etype)) {
    if (extractEventIdFromRaw(raw) === KERBEROS_EVENT_ID || hasKerberosKeywords(description)) {
      return "kerberos";
    }
    const num = encryptionTypeNumeric(etype);
    if (num !== null && num > 0x07) return "kerberos";
  }

  if (extractEventIdFromRaw(raw) === KERBEROS_EVENT_ID && etype !== "") {
    return "kerberos";
  }

  if (hasKerberosKeywords(description) && etype !== "") return "kerberos";

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
  if (raw.attack && !String(raw.mitre || "").includes("T1558") && !hasKerberosKeywords(description)) {
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

  let hasKerberos = false;
  let hasNoise = false;
  let hasUnknown = false;

  for (const item of items) {
    const kind = classifyWazuhItem(item);
    if (kind === "kerberos") hasKerberos = true;
    if (kind === "noise") hasNoise = true;
    if (kind === "unknown") hasUnknown = true;
  }

  if (hasKerberos) return { accept: true, kind: "kerberos", items };
  if (hasNoise) return { accept: false, kind: "noise", items, reason: "Non-ITDR alert (sshd/syslog) — ignored" };
  return {
    accept: false,
    kind: "unknown",
    items,
    reason: "Not Kerberoasting — need Event 4769, T1558, or weak ticket encryption (etype > 0x07)",
  };
}

function isKerberoastingAlert(alert) {
  if (!alert) return false;
  return (
    alert.attack === "Kerberoasting" ||
    alert.mitre === "T1558.003" ||
    Number(alert.event_id) === KERBEROS_EVENT_ID
  );
}

function webhookPreview(raw) {
  if (!raw || typeof raw !== "object") return "";
  const meta = extractRuleMeta(raw);
  const etype = extractEncryptionFromRaw(raw);
  return JSON.stringify({
    rule: meta.description || meta.id,
    event_id: extractEventIdFromRaw(raw) || undefined,
    etype: etype || undefined,
    agent: raw.agent?.name,
  }).slice(0, 280);
}

module.exports = {
  classifyWazuhPayload,
  classifyWazuhItem,
  isKerberoastingAlert,
  extractEncryptionFromRaw,
  webhookPreview,
};

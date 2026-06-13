/**
 * Parses Windows Security Event 4769 and Wazuh-normalized payloads
 * into a canonical AuthGraph event shape.
 */

const { KERBEROS_EVENT_ID, RC4_ENCRYPTION_TYPES } = require("./constants");

/**
 * @typedef {Object} ParsedKerberosEvent
 * @property {number} event_id
 * @property {string} time
 * @property {string} user
 * @property {string} target
 * @property {string} service_name
 * @property {string|number} encryption_type
 * @property {boolean} is_rc4
 * @property {string} source_ip
 * @property {string} host
 * @property {string} status
 * @property {boolean} is_krbtgt
 * @property {boolean} has_spn
 * @property {Record<string, unknown>} raw
 */

function normalizeEncryptionType(value) {
  if (value === undefined || value === null) return "";
  const str = String(value).trim();
  if (str.startsWith("0x")) return str.toLowerCase();
  const num = Number(str);
  if (!Number.isNaN(num)) return `0x${num.toString(16)}`;
  return str.toLowerCase();
}

function isRc4Encryption(encryptionType) {
  const normalized = normalizeEncryptionType(encryptionType);
  return RC4_ENCRYPTION_TYPES.has(normalized) || RC4_ENCRYPTION_TYPES.has(String(encryptionType));
}

/** AES128/256 — strong, should not trigger Yara weak-crypto rule */
const STRONG_KERBEROS_ETYPES = new Set([0x11, 0x12, 17, 18]);

function encryptionTypeNumeric(encryptionType) {
  if (encryptionType === undefined || encryptionType === null || encryptionType === "") return null;
  const normalized = normalizeEncryptionType(encryptionType);
  if (normalized.startsWith("0x")) {
    const n = parseInt(normalized, 16);
    return Number.isNaN(n) ? null : n;
  }
  const n = Number(normalized);
  return Number.isNaN(n) ? null : n;
}

/** Yara/lab rule: ticket encryption 0x07 < etype (weak / RC4 / legacy) */
function isWeakKerberosEncryption(encryptionType) {
  if (isRc4Encryption(encryptionType)) return true;
  const num = encryptionTypeNumeric(encryptionType);
  if (num === null) return false;
  if (num <= 0x07) return false;
  if (STRONG_KERBEROS_ETYPES.has(num)) return false;
  return num > 0x07;
}

function extractServiceAccount(serviceName) {
  if (!serviceName) return "";
  const name = String(serviceName).trim();
  if (name.includes("/")) {
    return name.split("/").pop() || name;
  }
  if (name.includes("@")) {
    return name.split("@")[0] || name;
  }
  return name.replace(/^\$/, "");
}

function isKrbtgtService(serviceName) {
  if (!serviceName) return false;
  return String(serviceName).toLowerCase().includes("krbtgt");
}

function pickField(obj, ...keys) {
  for (const key of keys) {
    if (obj[key] !== undefined && obj[key] !== null && obj[key] !== "") {
      return obj[key];
    }
  }
  return "";
}

function parseTimestamp(raw) {
  const ts =
    pickField(raw, "time", "timestamp", "@timestamp", "eventtime", "EventTime") ||
    pickField(raw.data || {}, "timestamp", "utctime");

  if (ts) {
    const d = new Date(ts);
    if (!Number.isNaN(d.getTime())) return d.toISOString();
  }
  return new Date().toISOString();
}

/**
 * Parse a single event from Wazuh, Sigma, or raw Windows JSON.
 * @param {Record<string, unknown>} raw
 * @returns {ParsedKerberosEvent|null}
 */
function parseKerberosEvent(raw) {
  if (!raw || typeof raw !== "object") return null;

  const nested = raw.data && typeof raw.data === "object" ? raw.data : {};
  const win = nested.win && typeof nested.win === "object" ? nested.win : {};
  const winEvent = raw.win || raw.event || nested.win || nested.event || win || {};
  const system = winEvent.system || winEvent.System || win.system || win.System || {};
  const eventData =
    raw.EventData ||
    winEvent.EventData ||
    winEvent.eventdata ||
    nested.EventData ||
    nested.eventdata ||
    win.eventdata ||
    win.EventData ||
    {};

  const rule = raw.rule && typeof raw.rule === "object" ? raw.rule : {};
  const mitreIds = []
    .concat(rule.mitre?.id || rule.mitre?.technique || [])
    .flat()
    .map(String);

  const eventId = Number(
    pickField(raw, "event_id", "EventID", "eventId") ||
      pickField(nested, "event_id", "EventID") ||
      pickField(system, "eventID", "EventID", "event_id") ||
      pickField(winEvent, "System", "EventID") ||
      pickField(eventData, "EventID")
  );

  const isKerberosRule =
    mitreIds.some((id) => id.includes("T1558")) ||
    String(rule.description || "").toLowerCase().includes("kerberoast");

  if (eventId !== KERBEROS_EVENT_ID && !isKerberosRule) return null;

  const serviceName = String(
    pickField(raw, "service_name", "ServiceName", "service") ||
      pickField(eventData, "ServiceName", "serviceName", "Service") ||
      pickField(nested, "ServiceName", "serviceName")
  );

  const encryptionType =
    pickField(raw, "ticket_encryption_type", "TicketEncryptionType", "encryption_type") ||
    pickField(eventData, "TicketEncryptionType", "ticketEncryptionType", "TicketOptions") ||
    pickField(nested, "TicketEncryptionType", "ticketEncryptionType");

  const user = String(
    pickField(raw, "user", "AccountName", "TargetUserName", "SubjectUserName") ||
      pickField(eventData, "TargetUserName", "targetUserName", "AccountName", "accountName", "SubjectUserName") ||
      pickField(nested, "user", "TargetUserName", "targetUserName")
  ).toLowerCase();

  const target = extractServiceAccount(serviceName).toLowerCase();
  const sourceIp = String(
    pickField(raw, "source_ip", "IpAddress", "ip", "source") ||
      pickField(eventData, "IpAddress", "ipAddress") ||
      pickField(nested, "source_ip", "IpAddress", "ipAddress") ||
      pickField(raw.agent, "ip")
  );
  const host = String(
    pickField(raw, "host", "WorkstationName", "Computer", "hostname") ||
      pickField(eventData, "WorkstationName", "workstationName", "Computer") ||
      pickField(nested, "host", "WorkstationName", "workstationName") ||
      pickField(raw.agent, "name")
  );
  const status = String(pickField(raw, "status", "Status") || pickField(eventData, "Status"));

  return {
    event_id: KERBEROS_EVENT_ID,
    time: parseTimestamp(raw),
    user,
    target,
    service_name: serviceName,
    encryption_type: encryptionType,
    is_rc4: isRc4Encryption(encryptionType),
    is_weak_encryption: isWeakKerberosEncryption(encryptionType),
    source_ip: sourceIp,
    host,
    status,
    is_krbtgt: isKrbtgtService(serviceName),
    has_spn: Boolean(serviceName && !isKrbtgtService(serviceName)),
    raw,
  };
}

/**
 * Parse batch of events; ignores non-4769 entries.
 * @param {unknown[]} events
 * @returns {ParsedKerberosEvent[]}
 */
function parseKerberosEvents(events) {
  if (!Array.isArray(events)) return [];
  return events.map(parseKerberosEvent).filter(Boolean);
}

module.exports = {
  parseKerberosEvent,
  parseKerberosEvents,
  normalizeEncryptionType,
  isRc4Encryption,
  isWeakKerberosEncryption,
  encryptionTypeNumeric,
  extractServiceAccount,
  isKrbtgtService,
};

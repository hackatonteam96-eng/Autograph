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
  const winEvent = raw.win || raw.event || nested.win || nested.event || {};
  const eventData = raw.EventData || winEvent.EventData || nested.EventData || {};

  const eventId = Number(
    pickField(raw, "event_id", "EventID", "eventId") ||
      pickField(nested, "event_id", "EventID") ||
      pickField(winEvent, "System", "EventID") ||
      pickField(eventData, "EventID")
  );

  if (eventId !== KERBEROS_EVENT_ID) return null;

  const serviceName = String(
    pickField(raw, "service_name", "ServiceName", "service") ||
      pickField(eventData, "ServiceName", "Service") ||
      pickField(nested, "ServiceName")
  );

  const encryptionType =
    pickField(raw, "ticket_encryption_type", "TicketEncryptionType", "encryption_type") ||
    pickField(eventData, "TicketEncryptionType", "TicketOptions") ||
    pickField(nested, "TicketEncryptionType");

  const user = String(
    pickField(raw, "user", "AccountName", "TargetUserName", "SubjectUserName") ||
      pickField(eventData, "TargetUserName", "AccountName", "SubjectUserName") ||
      pickField(nested, "user")
  ).toLowerCase();

  const target = extractServiceAccount(serviceName).toLowerCase();
  const sourceIp = String(
    pickField(raw, "source_ip", "IpAddress", "ip", "source") ||
      pickField(eventData, "IpAddress") ||
      pickField(nested, "source_ip")
  );
  const host = String(
    pickField(raw, "host", "WorkstationName", "Computer", "hostname") ||
      pickField(eventData, "WorkstationName") ||
      pickField(nested, "host")
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
  extractServiceAccount,
  isKrbtgtService,
};

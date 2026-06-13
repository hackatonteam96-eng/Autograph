const fs = require("fs");
const path = require("path");
const { DATA_DIR } = require("../config");

const LOG_PATH = path.join(DATA_DIR, "event-log.json");
const MAX_ENTRIES = 500;

function readLog() {
  try {
    if (fs.existsSync(LOG_PATH)) {
      return JSON.parse(fs.readFileSync(LOG_PATH, "utf8"));
    }
  } catch (err) {
    console.warn("[eventLog] read failed:", err.message);
  }
  return [];
}

function writeLog(entries) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(LOG_PATH, JSON.stringify(entries.slice(0, MAX_ENTRIES), null, 2));
  } catch (err) {
    console.warn("[eventLog] write failed:", err.message);
  }
}

/**
 * @param {string} level info|warn|alert|action|ai|webhook|system
 * @param {string} message
 * @param {Record<string, unknown>} [meta]
 */
function appendEvent(level, message, meta = {}) {
  const entry = {
    id: `log-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    ts: new Date().toISOString(),
    level,
    message,
    ...meta,
  };
  const log = readLog();
  log.unshift(entry);
  writeLog(log);
  return entry;
}

function getEvents({ limit = 100, offset = 0, level, incidentId } = {}) {
  let log = readLog();
  if (level) log = log.filter((e) => e.level === level);
  if (incidentId) log = log.filter((e) => e.incident_id === incidentId);
  const total = log.length;
  const safeLimit = Math.min(Math.max(Number(limit) || 100, 1), MAX_ENTRIES);
  const safeOffset = Math.max(Number(offset) || 0, 0);
  const events = log.slice(safeOffset, safeOffset + safeLimit);
  return { total, events, limit: safeLimit, offset: safeOffset };
}

function clearLog() {
  writeLog([]);
  return { ok: true };
}

module.exports = { appendEvent, getEvents, clearLog, LOG_PATH };

/**
 * Lightweight request logging + security event log for demo and debugging.
 */
const { appendEvent } = require("../services/eventLog");

const LOGGED_ROUTES = [
  { method: "POST", prefix: "/api/webhook/", level: "webhook", label: "Webhook" },
  { method: "POST", prefix: "/api/contain/", level: "action", label: "Containment" },
  { method: "POST", prefix: "/api/simulate/", level: "system", label: "Simulation" },
  { method: "POST", prefix: "/api/ai/chat", level: "ai", label: "ARIA chat" },
];

function requestLogger(req, res, next) {
  const start = Date.now();
  res.on("finish", () => {
    const ms = Date.now() - start;
    const line = `[${new Date().toISOString()}] ${req.method} ${req.originalUrl} ${res.statusCode} ${ms}ms`;
    console.log(line);

    const match = LOGGED_ROUTES.find(
      (r) => req.method === r.method && req.originalUrl.startsWith(r.prefix),
    );
    if (match && res.statusCode >= 400) {
      appendEvent(match.level, `${match.label} ${req.method} ${req.originalUrl} → ${res.statusCode}`, {
        ms,
        status: res.statusCode,
      });
    }
  });
  next();
}

module.exports = requestLogger;

const express = require("express");
const cors = require("cors");
const os = require("os");
const {
  PORT,
  HOST,
  CORS_ORIGIN,
  AUTHGRAPH_LAN_HOST,
  RESEND_API_KEY,
  ITDR_REPORT_TO,
  ITDR_REPORT_FROM,
} = require("./config");
const requestLogger = require("./middleware/requestLogger");
const { errorHandler } = require("./middleware/errorHandler");

const healthRoutes = require("./routes/health");
const alertsRoutes = require("./routes/alerts");
const incidentsRoutes = require("./routes/incidents");
const attackPathRoutes = require("./routes/attackPath");
const riskRoutes = require("./routes/risk");
const containRoutes = require("./routes/contain");
const explainRoutes = require("./routes/explain");
const aiRoutes = require("./routes/ai");
const sigmaRoutes = require("./routes/sigma");
const webhookRoutes = require("./routes/webhook");
const simulateRoutes = require("./routes/simulate");
const verifyRoutes = require("./routes/verify");
const logsRoutes = require("./routes/logs");
const reportsRoutes = require("./routes/reports");
const geoRoutes = require("./routes/geo");

const app = express();

app.use(cors({ origin: CORS_ORIGIN === "*" ? true : CORS_ORIGIN.split(",") }));
app.use(express.json({ limit: "1mb" }));
app.use(requestLogger);

app.use("/api", healthRoutes);
app.use("/api", alertsRoutes);
app.use("/api", incidentsRoutes);
app.use("/api", attackPathRoutes);
app.use("/api", riskRoutes);
app.use("/api", containRoutes);
app.use("/api", explainRoutes);
app.use("/api", aiRoutes);
app.use("/api", sigmaRoutes);
app.use("/api", webhookRoutes);
app.use("/api", simulateRoutes);
app.use("/api", verifyRoutes);
app.use("/api", logsRoutes);
app.use("/api", reportsRoutes);
app.use("/api", geoRoutes);

app.get("/", (_req, res) => {
  res.json({
    service: "AuthGraph ITDR API",
    docs: "/api/health",
    endpoints: [
      "GET /api/health",
      "GET /api/alerts",
      "GET /api/alerts/:id",
      "GET /api/incidents",
      "GET /api/incidents/:id",
      "GET /api/attack-path",
      "GET /api/risk/:identity",
      "GET /api/explain/:incidentId",
      "POST /api/contain/:incidentId",
      "POST /api/reload",
      "GET /api/sigma",
      "GET /api/sigma/rules",
      "GET /api/verify",
      "GET /api/ai/respond/:incidentId",
      "POST /api/ai/chat",
      "POST /api/webhook/wazuh",
      "POST /api/simulate/kerberoast",
      "POST /api/simulate/reset",
      "GET /api/simulate/status",
      "GET /api/logs",
      "GET /api/reports/config",
      "GET /api/reports/:incidentId/preview",
      "POST /api/reports/:incidentId/send",
      "POST /api/reports/:incidentId/export",
    ],
  });
});

app.use((_req, res) => {
  res.status(404).json({ ok: false, error: "Not found" });
});

app.use(errorHandler);

function lanAddresses() {
  const addrs = new Set();
  if (AUTHGRAPH_LAN_HOST) addrs.add(AUTHGRAPH_LAN_HOST);
  for (const ifaces of Object.values(os.networkInterfaces())) {
    for (const iface of ifaces || []) {
      if (iface.family === "IPv4" && !iface.internal) addrs.add(iface.address);
    }
  }
  return [...addrs];
}

function logStartupUrls() {
  console.log(`AuthGraph ITDR API running at http://localhost:${PORT}`);
  console.log(`Health:  http://localhost:${PORT}/api/health`);
  console.log(`Alerts:  http://localhost:${PORT}/api/alerts`);
  if (HOST === "0.0.0.0" || HOST === "::") {
    for (const ip of lanAddresses()) {
      console.log(`LAN:     http://${ip}:${PORT}/api/health`);
      console.log(`Webhook: http://${ip}:${PORT}/api/webhook/wazuh`);
    }
  }
  console.log(`Dashboard (share): http://${AUTHGRAPH_LAN_HOST || "YOUR_LAN_IP"}:5173`);
  if (RESEND_API_KEY && ITDR_REPORT_TO) {
    const sandbox = (ITDR_REPORT_FROM || "").includes("onboarding@resend.dev");
    if (sandbox) {
      console.log(
        `[report] Resend SANDBOX — incident emails deliver only to ${ITDR_REPORT_TO} (Gmail). @vulnbase.org needs domain verification at resend.com/domains.`,
      );
    } else {
      console.log(`[report] Incident emails → ${ITDR_REPORT_TO} from ${ITDR_REPORT_FROM}`);
    }
  }
}

if (require.main === module) {
  const server = app.listen(PORT, HOST, () => {
    logStartupUrls();
  });

  function shutdown(signal) {
    console.log(`\n${signal} received — shutting down gracefully`);
    server.close(() => process.exit(0));
  }

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

module.exports = app;

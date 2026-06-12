const express = require("express");
const cors = require("cors");
const { PORT, HOST, CORS_ORIGIN } = require("./config");
const requestLogger = require("./middleware/requestLogger");
const { errorHandler } = require("./middleware/errorHandler");

const healthRoutes = require("./routes/health");
const alertsRoutes = require("./routes/alerts");
const incidentsRoutes = require("./routes/incidents");
const attackPathRoutes = require("./routes/attackPath");
const riskRoutes = require("./routes/risk");
const containRoutes = require("./routes/contain");
const explainRoutes = require("./routes/explain");

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
    ],
  });
});

app.use((_req, res) => {
  res.status(404).json({ ok: false, error: "Not found" });
});

app.use(errorHandler);

if (require.main === module) {
  const server = app.listen(PORT, HOST, () => {
    console.log(`AuthGraph ITDR API running at http://localhost:${PORT}`);
    console.log(`Health:  http://localhost:${PORT}/api/health`);
    console.log(`Alerts:  http://localhost:${PORT}/api/alerts`);
  });

  function shutdown(signal) {
    console.log(`\n${signal} received — shutting down gracefully`);
    server.close(() => process.exit(0));
  }

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

module.exports = app;

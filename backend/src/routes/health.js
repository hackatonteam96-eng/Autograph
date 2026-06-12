const express = require("express");
const dataStore = require("../store/dataStore");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.get("/health", asyncHandler((_req, res) => {
  const diagnostics = dataStore.getDiagnostics();
  res.json({
    ok: true,
    service: "AuthGraph ITDR API",
    version: "1.0.0",
    timestamp: new Date().toISOString(),
    detection: diagnostics.detection_module,
    data: {
      sample_alerts: diagnostics.sample_alerts,
      attack_path: diagnostics.attack_path,
      wazuh_real: diagnostics.wazuh_real,
    },
    incidents: {
      open: diagnostics.open_incidents,
      contained: diagnostics.contained_incidents,
    },
  });
}));

router.post("/reload", asyncHandler((_req, res) => {
  const data = dataStore.reloadFromDisk();
  res.json({
    ok: true,
    message: "Data reloaded from disk",
    alerts_count: data.alerts.length,
    incidents_count: data.incidents.length,
  });
}));

module.exports = router;

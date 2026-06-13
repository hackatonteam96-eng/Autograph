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
      wazuh_real: diagnostics.wazuh_kerberos,
      wazuh_kerberos: diagnostics.wazuh_kerberos,
      wazuh_file_present: diagnostics.wazuh_file_present,
    },
    incidents: {
      open: diagnostics.open_incidents,
      contained: diagnostics.contained_incidents,
      history: diagnostics.alert_history,
    },
    stats: {
      identities_monitored: diagnostics.identities_monitored,
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

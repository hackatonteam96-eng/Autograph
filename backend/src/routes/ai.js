const express = require("express");
const dataStore = require("../store/dataStore");
const { analyzeIncident, chatWithAnalyst } = require("../services/openrouter");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.get("/ai/respond/:incidentId", asyncHandler(async (req, res) => {
  const alert = dataStore.getAlertById(req.params.incidentId);
  if (!alert) {
    return res.status(404).json({ ok: false, error: "Incident not found" });
  }
  const analysis = await analyzeIncident(alert);
  res.json({
    incident_id: req.params.incidentId,
    ...analysis,
  });
}));

router.post("/ai/chat", asyncHandler(async (req, res) => {
  const {
    incident_id: incidentId,
    message,
    conversation_history: history,
    view_context: viewContext,
  } = req.body || {};
  if (!message?.trim()) {
    return res.status(400).json({ ok: false, error: "message required" });
  }
  const alert = incidentId ? dataStore.getAlertById(incidentId) : dataStore.getAlerts()[0];
  if (!alert) {
    return res.status(404).json({ ok: false, error: "No incident context" });
  }

  const diagnostics = dataStore.getDiagnostics();
  const extras = {
    attackPath: dataStore.loadAttackPath(),
    contained: diagnostics.contained_incidents > 0,
    viewContext: typeof viewContext === "string" ? viewContext.slice(0, 120) : undefined,
  };

  const { reply, model } = await chatWithAnalyst(alert, message.trim(), history, extras);
  res.json({ ok: true, reply, model, incident_id: alert.id });
}));

module.exports = router;

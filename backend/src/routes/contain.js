const express = require("express");
const dataStore = require("../store/dataStore");
const { previewPlaybookActions } = require("../services/playbookExecutor");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.post("/playbook/preview", asyncHandler((req, res) => {
  const actions = Array.isArray(req.body?.actions) ? req.body.actions.filter(Boolean) : [];
  const incidentId = req.body?.incident_id ? String(req.body.incident_id) : null;
  const alert = incidentId ? dataStore.getAlertById(incidentId) : req.body?.context;
  if (!alert) {
    return res.status(400).json({ ok: false, error: "incident_id or context required" });
  }
  const steps = previewPlaybookActions(actions, alert);
  res.json({ ok: true, steps });
}));

router.post("/contain/:incidentId", asyncHandler(async (req, res) => {
  const approved = Array.isArray(req.body?.actions) ? req.body.actions.filter(Boolean) : [];
  const result = await dataStore.contain(req.params.incidentId, approved);
  if (!result.ok) {
    return res.status(404).json(result);
  }
  res.json(result);
}));

module.exports = router;

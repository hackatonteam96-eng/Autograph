const express = require("express");
const dataStore = require("../store/dataStore");
const { analyzeIncident, chatWithAnalyst, OPENROUTER_CHAT_MODEL, OPENROUTER_REASONING_MODEL } = require("../services/openrouter");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.get("/ai/respond/:incidentId", asyncHandler(async (req, res) => {
  const alert = dataStore.getAlertById(req.params.incidentId);
  if (!alert) {
    return res.status(404).json({ ok: false, error: "Incident not found" });
  }

  const cached = dataStore.getAiEnrichment(req.params.incidentId);
  if (cached?.status === "ready" && cached.actions?.length) {
    return res.json({
      incident_id: req.params.incidentId,
      actions: cached.actions,
      action_details: cached.action_details,
      verdict: cached.verdict,
      headline: cached.headline,
      confidence: cached.confidence,
      urgency: cached.urgency,
      source: cached.source || "openrouter",
      model: cached.actions_model || OPENROUTER_REASONING_MODEL,
      summary_model: cached.summary_model || OPENROUTER_CHAT_MODEL,
      ai_status: cached.status,
    });
  }

  if (cached?.status === "pending") {
    return res.json({
      incident_id: req.params.incidentId,
      actions: alert.response || [],
      source: "pending",
      model: null,
      ai_status: "pending",
    });
  }

  const analysis = await analyzeIncident(alert);
  res.json({
    incident_id: req.params.incidentId,
    ...analysis,
    model: analysis.model || OPENROUTER_REASONING_MODEL,
    ai_status: "ready",
  });
}));

router.get("/ai/verdict/:incidentId", asyncHandler(async (req, res) => {
  const alert = dataStore.getAlertById(req.params.incidentId);
  if (!alert) {
    return res.status(404).json({ ok: false, error: "Incident not found" });
  }

  const cached = dataStore.getAiEnrichment(req.params.incidentId);
  res.json({
    incident_id: req.params.incidentId,
    ai_status: cached?.status || alert.ai_status || null,
    verdict: cached?.verdict || alert.ai_verdict || null,
    actions: cached?.actions || alert.ai_actions || null,
    summary_model: cached?.summary_model || alert.ai_summary_model || OPENROUTER_CHAT_MODEL,
    actions_model: cached?.actions_model || alert.ai_actions_model || OPENROUTER_REASONING_MODEL,
    enriched_at: cached?.enriched_at || alert.ai_enriched_at || null,
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
  const alert =
    (incidentId ? dataStore.getAlertById(incidentId) : null) ||
    dataStore.getPrimaryItdrAlert();
  if (!alert) {
    return res.status(404).json({ ok: false, error: "No ITDR incident context" });
  }

  const diagnostics = dataStore.getDiagnostics();
  const aiEnrichment = dataStore.getAiEnrichment(alert.id);
  const extras = {
    attackPath: dataStore.loadAttackPath(),
    contained: diagnostics.contained_incidents > 0 || alert.status === "contained",
    viewContext: typeof viewContext === "string" ? viewContext.slice(0, 120) : undefined,
    aiEnrichment,
  };

  const { reply, model } = await chatWithAnalyst(alert, message.trim(), history, extras);
  res.json({ ok: true, reply, model, incident_id: alert.id });
}));

module.exports = router;

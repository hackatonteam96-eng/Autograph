const express = require("express");
const { getEvents, clearLog } = require("../services/eventLog");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.get("/logs", asyncHandler((req, res) => {
  const limit = Math.min(Number(req.query.limit) || 100, 500);
  const level = req.query.level ? String(req.query.level) : undefined;
  const incidentId = req.query.incident_id ? String(req.query.incident_id) : undefined;
  const events = getEvents({ limit, level, incidentId });
  res.json({ ok: true, count: events.length, events });
}));

router.delete("/logs", asyncHandler((_req, res) => {
  clearLog();
  res.json({ ok: true, message: "Event log cleared" });
}));

module.exports = router;

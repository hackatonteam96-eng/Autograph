const express = require("express");
const { getEvents, clearLog } = require("../services/eventLog");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.get("/logs", asyncHandler((req, res) => {
  const limit = Math.min(Number(req.query.limit) || 100, 500);
  const offset = Math.max(Number(req.query.offset) || 0, 0);
  const level = req.query.level ? String(req.query.level) : undefined;
  const incidentId = req.query.incident_id ? String(req.query.incident_id) : undefined;
  const result = getEvents({ limit, offset, level, incidentId });
  res.json({
    ok: true,
    count: result.events.length,
    total: result.total,
    limit: result.limit,
    offset: result.offset,
    events: result.events,
  });
}));

router.delete("/logs", asyncHandler((_req, res) => {
  clearLog();
  res.json({ ok: true, message: "Event log cleared" });
}));

module.exports = router;

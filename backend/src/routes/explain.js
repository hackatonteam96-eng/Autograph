const express = require("express");
const dataStore = require("../store/dataStore");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

/** Demo endpoint — why did this incident fire? (for judges / Zahra walkthrough) */
router.get("/explain/:incidentId", asyncHandler((req, res) => {
  const explanation = dataStore.explainIncident(req.params.incidentId);
  if (!explanation) {
    return res.status(404).json({ ok: false, error: "Incident not found" });
  }
  res.json(explanation);
}));

module.exports = router;

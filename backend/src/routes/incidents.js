const express = require("express");
const dataStore = require("../store/dataStore");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.get("/incidents", asyncHandler((_req, res) => {
  res.json(dataStore.getIncidents());
}));

router.get("/incidents/:id", asyncHandler((req, res) => {
  const incident = dataStore.getIncidents().find((i) => i.id === req.params.id);
  if (!incident) {
    return res.status(404).json({ ok: false, error: "Incident not found" });
  }
  res.json(incident);
}));

module.exports = router;

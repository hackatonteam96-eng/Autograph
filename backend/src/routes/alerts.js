const express = require("express");
const dataStore = require("../store/dataStore");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.get("/alerts", asyncHandler((_req, res) => {
  res.json(dataStore.getAlerts());
}));

router.get("/alerts/:id", asyncHandler((req, res) => {
  const alert = dataStore.getAlertById(req.params.id);
  if (!alert) {
    return res.status(404).json({ ok: false, error: "Alert not found" });
  }
  res.json(alert);
}));

module.exports = router;

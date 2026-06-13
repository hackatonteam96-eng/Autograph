const express = require("express");
const dataStore = require("../store/dataStore");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.get("/attack-path", asyncHandler((req, res) => {
  const alertId = req.query.alert_id ? String(req.query.alert_id) : null;
  const alert = alertId ? dataStore.getAlertById(alertId) : dataStore.getPrimaryItdrAlert();
  res.json(dataStore.loadAttackPath(alert));
}));

module.exports = router;

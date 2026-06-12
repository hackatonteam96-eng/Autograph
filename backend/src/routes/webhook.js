const express = require("express");
const dataStore = require("../store/dataStore");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.post("/webhook/wazuh", asyncHandler((req, res) => {
  const result = dataStore.ingestWebhook(req.body);
  res.status(result.ok ? 200 : 400).json(result);
}));

module.exports = router;

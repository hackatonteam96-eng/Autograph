const express = require("express");
const dataStore = require("../store/dataStore");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.get("/attack-path", asyncHandler((_req, res) => {
  res.json(dataStore.loadAttackPath());
}));

module.exports = router;

const express = require("express");
const dataStore = require("../store/dataStore");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.post("/contain/:incidentId", asyncHandler((req, res) => {
  const result = dataStore.contain(req.params.incidentId);
  if (!result.ok) {
    return res.status(404).json(result);
  }
  res.json(result);
}));

module.exports = router;

const express = require("express");
const dataStore = require("../store/dataStore");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.post("/contain/:incidentId", asyncHandler(async (req, res) => {
  const approved = Array.isArray(req.body?.actions) ? req.body.actions.filter(Boolean) : [];
  const result = await dataStore.contain(req.params.incidentId, approved);
  if (!result.ok) {
    return res.status(404).json(result);
  }
  res.json(result);
}));

module.exports = router;

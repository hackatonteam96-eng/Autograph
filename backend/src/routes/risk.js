const express = require("express");
const dataStore = require("../store/dataStore");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.get("/risk/:identity", asyncHandler((req, res) => {
  const identity = decodeURIComponent(req.params.identity);
  res.json(dataStore.getRisk(identity));
}));

module.exports = router;

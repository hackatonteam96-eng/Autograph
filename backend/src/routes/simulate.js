const express = require("express");
const dataStore = require("../store/dataStore");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.post("/simulate/kerberoast", asyncHandler((_req, res) => {
  const result = dataStore.triggerKerberoastSimulation();
  res.json(result);
}));

router.post("/simulate/reset", asyncHandler((_req, res) => {
  const result = dataStore.resetSimulation();
  res.json(result);
}));

router.get("/simulate/status", asyncHandler((_req, res) => {
  res.json(dataStore.getSimulationStatus());
}));

module.exports = router;

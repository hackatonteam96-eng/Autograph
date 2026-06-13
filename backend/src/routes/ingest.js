const express = require("express");
const { asyncHandler } = require("../middleware/errorHandler");
const postureStore = require("../store/postureStore");

const router = express.Router();

/** POST /api/ingest — C# forwarder or PowerShell sends snapshot JSON */
router.post("/ingest", asyncHandler((req, res) => {
  const body = req.body;
  if (!body || !body.host) {
    return res.status(400).json({ ok: false, error: "Invalid snapshot: missing host" });
  }
  const result = postureStore.ingestSnapshot(body);
  res.json({ ok: true, ...result });
}));

/** GET /api/posture — CrowdStrike-style inventory & posture */
router.get("/posture", asyncHandler(async (req, res) => {
  const posture = await postureStore.getPosture();
  res.json(posture);
}));

module.exports = router;

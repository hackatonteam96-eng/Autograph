const express = require("express");
const dataStore = require("../store/dataStore");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

/** Blue team / Wazuh can ping this to verify reachability before POSTing alerts. */
router.get("/webhook/wazuh", (_req, res) => {
  res.json({
    ok: true,
    service: "AuthGraph Wazuh webhook",
    method: "POST alerts to this URL",
    endpoint: "/api/webhook/wazuh",
  });
});

router.post("/webhook/wazuh", asyncHandler((req, res) => {
  const preview = JSON.stringify(req.body)?.slice(0, 240) || "";
  console.log(`[webhook] Wazuh alert received (${preview}${preview.length >= 240 ? "…" : ""})`);

  const result = dataStore.ingestWebhook(req.body);
  if (result.ok) {
    console.log(`[webhook] Ingested kerberoast incident risk=${result.incident?.risk ?? "?"}`);
  } else {
    console.warn(`[webhook] Ingest failed: ${result.error}`);
  }

  res.status(result.ok ? 200 : 400).json(result);
}));

module.exports = router;

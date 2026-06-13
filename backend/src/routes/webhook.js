const express = require("express");
const dataStore = require("../store/dataStore");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.get("/webhook/wazuh", (_req, res) => {
  res.json({
    ok: true,
    service: "AuthGraph Wazuh webhook",
    method: "POST alerts to this URL",
    endpoint: "/api/webhook/wazuh",
    filter: "ITDR identity threats — Kerberoasting, AS-REP, T1558.x (sshd/syslog ignored)",
  });
});

router.post("/webhook/wazuh", asyncHandler((req, res) => {
  const preview = JSON.stringify(req.body)?.slice(0, 240) || "";
  console.log(`[webhook] Wazuh POST (${preview}${preview.length >= 240 ? "…" : ""})`);

  const result = dataStore.ingestWebhook(req.body);
  if (result.ignored) {
    return res.json(result);
  }
  if (result.ok) {
    console.log(`[webhook] ITDR incident ${result.incident?.attack} risk=${result.incident?.risk ?? "?"}`);
  } else {
    console.warn(`[webhook] Ingest failed: ${result.error}`);
  }

  res.status(result.ok ? 200 : 400).json(result);
}));

module.exports = router;

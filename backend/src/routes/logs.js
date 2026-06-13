const express = require("express");
const fs = require("fs");
const path = require("path");
const { DATA_DIR } = require("../config");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();
const LOGS_DIR = path.join(DATA_DIR, "logs");

function readText(file) {
  const p = path.join(LOGS_DIR, file);
  return fs.existsSync(p) ? fs.readFileSync(p, "utf8") : null;
}

function readJson(file) {
  const p = path.join(LOGS_DIR, file);
  if (!fs.existsSync(p)) return null;
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

/** GET /api/logs — full bundle for DeepSeek (no AI processing here) */
router.get("/logs", asyncHandler((_req, res) => {
  const bundle = readJson("bundle-for-ai.json");
  if (!bundle) {
    return res.status(404).json({ ok: false, error: "bundle-for-ai.json not found" });
  }
  res.json({ ok: true, source: "mock-lab-logs", bundle });
}));

/** GET /api/logs/raw — all log files separate (for C# forwarder testing) */
router.get("/logs/raw", asyncHandler((_req, res) => {
  res.json({
    ok: true,
    manifest: readJson("manifest.json"),
    dc: {
      ad_posture: readJson("dc/ad-posture.json"),
      security_events: readJson("dc/security-events.json"),
      dns_log: readText("dc/dns.log"),
    },
    client: {
      host_info: readJson("client/host-info.json"),
      security_events: readJson("client/security-events.json"),
      dns_log: readText("client/dns.log"),
      http_log: readText("client/http.log"),
    },
  });
}));

module.exports = router;

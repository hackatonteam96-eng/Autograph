const express = require("express");
const fs = require("fs");
const path = require("path");
const { DATA_DIR } = require("../config");
const dataStore = require("../store/dataStore");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

/**
 * End-to-end verification checklist for judges and CI.
 * Confirms detection logic, sigma rule, webhook path, and sample data.
 */
router.get("/verify", asyncHandler((_req, res) => {
  const checks = [];

  function add(name, pass, detail) {
    checks.push({ name, pass, detail });
  }

  try {
    const {
      matchSigmaRule,
      detectKerberoasting,
      buildAlertFromEvents,
      explainAlert,
    } = require("../../detection/index");

    const fixtures = path.join(__dirname, "../../detection/fixtures");
    const event4769 = JSON.parse(fs.readFileSync(path.join(fixtures, "event-4769-rc4.json"), "utf8"));
    const multiTgs = JSON.parse(fs.readFileSync(path.join(fixtures, "multiple-tgs-events.json"), "utf8"));
    const wazuhSample = JSON.parse(fs.readFileSync(path.join(fixtures, "wazuh-alert-4769-rc4.json"), "utf8"));

    const sigmaMatch = matchSigmaRule(event4769);
    add("Sigma rule matches RC4 Event 4769", sigmaMatch.matched, sigmaMatch.reasons?.[0] || "matched");

    const detection = detectKerberoasting(multiTgs);
    add("Multiple TGS burst detected", detection.is_kerberoasting && detection.indicators.multiple_tgs,
      `${detection.multiple_tgs_count} requests from ${detection.source_user}`);

    const attackPath = dataStore.loadAttackPath();
    const alert = buildAlertFromEvents(multiTgs, { attackPath, source: "Wazuh" });
    add("Correlator builds Kerberoasting alert", Boolean(alert?.attack === "Kerberoasting"),
      alert ? `risk ${alert.risk}, target ${alert.target}` : "no alert");

    const { processWazuhPayload } = require("../../detection/index");
    const wazuhIngested = processWazuhPayload(wazuhSample, attackPath);
    add("Wazuh webhook ingest", wazuhIngested.length > 0 && wazuhIngested[0].attack === "Kerberoasting",
      wazuhIngested[0] ? `parsed risk ${wazuhIngested[0].risk}` : "parse failed");

    const sample = dataStore.getAlerts()[0];
    if (sample) {
      const explanation = explainAlert(sample);
      add("Explain API breakdown", explanation.sigma.length >= 2 && explanation.risk_factors.length >= 4,
        `${explanation.sigma.length} sigma reasons, ${explanation.risk_factors.length} risk factors`);
    } else {
      add("Explain API breakdown", false, "no alerts loaded");
    }

    const sigmaKerb = path.join(__dirname, "../../../sigma/kerberoasting.yml");
    add("Sigma rule file on disk", fs.existsSync(sigmaKerb), sigmaKerb);

    const sigmaEntra = path.join(__dirname, "../../../sigma/entra-risky-signin.yml");
    add("Entra ID sigma rule in library", fs.existsSync(sigmaEntra), "authgraph-entra-risky-signin");

    add("Attack path graph", Boolean(attackPath?.nodes?.length >= 5),
      `${attackPath?.nodes?.length ?? 0} nodes, ${attackPath?.edges?.length ?? 0} edges`);

    add("Wazuh real capture", fs.existsSync(path.join(DATA_DIR, "wazuh-alert-real.json")),
      "data/wazuh-alert-real.json present");
  } catch (err) {
    add("Verification runner", false, err.message);
  }

  const passed = checks.filter((c) => c.pass).length;
  res.json({
    ok: passed === checks.length,
    passed,
    total: checks.length,
    checks,
    mvp: {
      kerberoasting_poc: checks.find((c) => c.name.includes("Correlator"))?.pass ?? false,
      sigma_rule: checks.find((c) => c.name.includes("Sigma rule matches"))?.pass ?? false,
      wazuh_alert: checks.find((c) => c.name.includes("webhook"))?.pass ?? false,
      attack_verification: checks.find((c) => c.name.includes("Multiple TGS"))?.pass ?? false,
    },
  });
}));

module.exports = router;

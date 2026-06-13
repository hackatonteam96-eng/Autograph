const express = require("express");
const fs = require("fs");
const path = require("path");
const { SIGMA_DIR } = require("../config");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

const RULE_META = {
  "kerberoasting.yml": {
    id: "authgraph-kerberoasting-4769",
    mitre: "T1558.003",
    title: "Possible Kerberoasting Activity",
    platform: "Active Directory",
    status: "active",
    event_id: 4769,
  },
  "entra-risky-signin.yml": {
    id: "authgraph-entra-risky-signin",
    mitre: "T1078.004",
    title: "Entra ID Risky Sign-In",
    platform: "Microsoft Entra ID",
    status: "active",
    event_id: null,
  },
  "dcsync-detection.yml": {
    id: "authgraph-dcsync-4662",
    mitre: "T1003.006",
    title: "Possible DCSync / Directory Replication Abuse",
    platform: "Active Directory",
    status: "library",
    event_id: 4662,
  },
};

function loadRules() {
  if (!fs.existsSync(SIGMA_DIR)) return [];
  return fs
    .readdirSync(SIGMA_DIR)
    .filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"))
    .sort()
    .map((filename) => {
      const filePath = path.join(SIGMA_DIR, filename);
      const yaml = fs.readFileSync(filePath, "utf8");
      const meta = RULE_META[filename] || {
        id: filename.replace(/\.ya?ml$/, ""),
        mitre: "—",
        title: filename,
        platform: "—",
        status: "library",
      };
      return { ...meta, filename, yaml };
    });
}

router.get("/sigma/rules", asyncHandler((_req, res) => {
  const rules = loadRules();
  res.json({
    count: rules.length,
    rules: rules.map(({ yaml, ...rest }) => rest),
  });
}));

router.get("/sigma", asyncHandler((req, res) => {
  const rules = loadRules();
  const id = req.query.id || "authgraph-kerberoasting-4769";
  const rule = rules.find((r) => r.id === id) || rules[0];
  if (!rule) {
    return res.status(404).json({ ok: false, error: "Sigma rule not found" });
  }
  res.json({
    id: rule.id,
    mitre: rule.mitre,
    title: rule.title,
    platform: rule.platform,
    yaml: rule.yaml,
  });
}));

module.exports = router;

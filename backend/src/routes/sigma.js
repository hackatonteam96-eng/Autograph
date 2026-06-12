const express = require("express");
const fs = require("fs");
const path = require("path");
const { SIGMA_DIR } = require("../config");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.get("/sigma", asyncHandler((_req, res) => {
  const rulePath = path.join(SIGMA_DIR, "kerberoasting.yml");
  if (!fs.existsSync(rulePath)) {
    return res.status(404).json({ ok: false, error: "Sigma rule not found" });
  }
  const yaml = fs.readFileSync(rulePath, "utf8");
  res.json({
    id: "authgraph-kerberoasting-4769",
    mitre: "T1558.003",
    title: "Possible Kerberoasting Activity",
    yaml,
  });
}));

module.exports = router;

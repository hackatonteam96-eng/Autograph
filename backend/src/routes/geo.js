const express = require("express");
const { lookupIpGeo, isPrivateIp } = require("../services/geoLookup");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.get("/geo/:ip", asyncHandler(async (req, res) => {
  const ip = decodeURIComponent(req.params.ip || "").trim();
  if (!ip) return res.status(400).json({ ok: false, error: "IP required" });

  if (isPrivateIp(ip)) {
    return res.json({
      ok: true,
      ip,
      private: true,
      found: false,
      city: "Lab network",
      country: "Private range",
      label: `${ip} · lab / private`,
    });
  }

  const geo = await lookupIpGeo(ip);
  if (!geo) {
    return res.json({ ok: true, ip, found: false, label: ip });
  }

  res.json({ ok: true, found: true, private: false, ...geo });
}));

module.exports = router;

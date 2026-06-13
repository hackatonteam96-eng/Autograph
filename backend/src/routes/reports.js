const express = require("express");
const dataStore = require("../store/dataStore");
const { ITDR_REPORT_TO, RESEND_API_KEY } = require("../config");
const {
  buildIncidentReportBundle,
  sendIncidentReport,
  queueIncidentReport,
  generateIncidentReport,
} = require("../services/incidentReport");
const {
  buildExecutivePdf,
  buildExecutiveDocx,
  exportFilename,
} = require("../services/executiveExport");
const { appendEvent } = require("../services/eventLog");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

router.get("/reports/config", asyncHandler((_req, res) => {
  const from = process.env.ITDR_REPORT_FROM || "AuthGraph ITDR <onboarding@resend.dev>";
  const sandboxFrom = from.includes("onboarding@resend.dev");
  const usingOrgDomain = /@vulnbase\.org/i.test(from) || /@vulnbase\.org/i.test(ITDR_REPORT_TO || "");
  res.json({
    ok: true,
    configured: Boolean(RESEND_API_KEY && ITDR_REPORT_TO),
    resend: Boolean(RESEND_API_KEY),
    from,
    recipient: ITDR_REPORT_TO || null,
    auto_send: process.env.ITDR_REPORT_AUTO !== "false",
    sandbox_mode: sandboxFrom,
    domain_required: usingOrgDomain && sandboxFrom,
    delivery_note: sandboxFrom
      ? `Resend sandbox: messages are accepted as "Sent" but only land in the Resend signup inbox (${ITDR_REPORT_TO || "your Resend account email"}). They do NOT arrive at @vulnbase.org until you verify vulnbase.org at resend.com/domains and set ITDR_REPORT_FROM to support@vulnbase.org.`
      : usingOrgDomain
        ? "Production mode: sending from @vulnbase.org (domain must be verified in Resend)."
        : null,
  });
}));

router.get("/reports/:incidentId/preview", asyncHandler(async (req, res) => {
  const alert = dataStore.getAlertById(req.params.incidentId);
  if (!alert) return res.status(404).json({ ok: false, error: "Incident not found" });

  const enrichment = dataStore.getAiEnrichment(alert.id) || {};
  const extras = {
    attackPath: dataStore.loadAttackPath(alert),
    contained: dataStore.getIncidentStatus(alert.id) === "contained",
    aiEnrichment: enrichment,
  };

  const forPrint = req.query.print === "1";
  const bundle = await buildIncidentReportBundle(alert, enrichment, extras);
  const html = forPrint ? bundle.htmlPrint : bundle.html;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(html);
}));

router.get("/reports/:incidentId", asyncHandler(async (req, res) => {
  const alert = dataStore.getAlertById(req.params.incidentId);
  if (!alert) return res.status(404).json({ ok: false, error: "Incident not found" });

  const enrichment = dataStore.getAiEnrichment(alert.id) || {};
  res.json({
    ok: true,
    incident_id: alert.id,
    report_meta: enrichment.report || null,
    configured: Boolean(RESEND_API_KEY && ITDR_REPORT_TO),
  });
}));

router.post("/reports/:incidentId/send", asyncHandler(async (req, res) => {
  const alert = dataStore.getAlertById(req.params.incidentId);
  if (!alert) return res.status(404).json({ ok: false, error: "Incident not found" });

  const enrichment = dataStore.getAiEnrichment(alert.id) || {};
  const to = req.body?.to ? String(req.body.to) : ITDR_REPORT_TO;
  const extras = {
    attackPath: dataStore.loadAttackPath(alert),
    contained: dataStore.getIncidentStatus(alert.id) === "contained",
    aiEnrichment: enrichment,
  };

  const result = await sendIncidentReport(alert, enrichment, extras, { to, force: true });
  dataStore.setReportMeta(alert.id, {
    status: "sent",
    to: result.to,
    subject: result.subject,
    resend_id: result.resend_id,
    sent_at: result.sent_at,
    report: result.report,
  });

  const { appendEvent } = require("../services/eventLog");
  appendEvent("system", `Incident report emailed to ${result.to}`, {
    incident_id: alert.id,
    subject: result.subject,
    resend_id: result.resend_id,
  });

  res.json({
    ok: true,
    ...result,
    preview_url: `/api/reports/${alert.id}/preview?print=1`,
  });
}));

router.post("/reports/:incidentId/queue", asyncHandler(async (req, res) => {
  const alert = dataStore.getAlertById(req.params.incidentId);
  if (!alert) return res.status(404).json({ ok: false, error: "Incident not found" });

  queueIncidentReport(dataStore, alert.id, { force: Boolean(req.body?.force), to: req.body?.to });
  res.json({ ok: true, message: "Report queued", incident_id: alert.id });
}));

router.post("/reports/:incidentId/export", asyncHandler(async (req, res) => {
  const format = String(req.body?.format || "pdf").toLowerCase();
  if (!["pdf", "docx"].includes(format)) {
    return res.status(400).json({ ok: false, error: "format must be pdf or docx" });
  }

  const alert = dataStore.getAlertById(req.params.incidentId);
  if (!alert) return res.status(404).json({ ok: false, error: "Incident not found" });

  const enrichment = dataStore.getAiEnrichment(alert.id) || {};
  const extras = {
    attackPath: dataStore.loadAttackPath(alert),
    contained: dataStore.getIncidentStatus(alert.id) === "contained",
    aiEnrichment: enrichment,
    executive: true,
    maxTokens: 2800,
  };

  const report = await generateIncidentReport(alert, extras);
  const buffer = format === "pdf"
    ? await buildExecutivePdf(alert, report)
    : await buildExecutiveDocx(alert, report);
  const filename = exportFilename(alert, format);
  const contentType = format === "pdf"
    ? "application/pdf"
    : "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

  appendEvent("ai", `Executive ${format.toUpperCase()} generated for ${alert.attack}`, {
    incident_id: alert.id,
    format,
    model: report.model || report.source || "fallback",
  });

  res.setHeader("Content-Type", contentType);
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  res.setHeader("X-Report-Source", report.source || "unknown");
  if (report.model) res.setHeader("X-Report-Model", report.model);
  res.send(buffer);
}));

module.exports = router;

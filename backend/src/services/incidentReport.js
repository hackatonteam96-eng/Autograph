const {
  RESEND_API_KEY,
  ITDR_REPORT_TO,
  ITDR_REPORT_FROM,
  ITDR_DASHBOARD_URL,
  OPENROUTER_API_KEY,
  OPENROUTER_REASONING_MODEL,
} = require("../config");
const { appendEvent } = require("./eventLog");
const {
  buildReportPrompt,
  REPORT_SYSTEM,
  parseJsonPayload,
} = require("./aria-skills");

/** @type {Set<string>} in-flight report generation */
const inFlight = new Set();

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function severityColor(label) {
  const s = String(label || "").toUpperCase();
  if (s === "CRITICAL") return "#ff5c5c";
  if (s === "HIGH") return "#f0b429";
  if (s === "MEDIUM") return "#5b9cf5";
  return "#2dd4a8";
}

function fallbackReport(alert, enrichment = {}) {
  const attack = alert.attack || "Identity threat";
  return {
    subject: `[${(alert.severity || "HIGH").toUpperCase()}] AuthGraph ITDR — ${attack} — ${alert.user} → ${alert.target}`,
    severity_label: (alert.severity || "high").toUpperCase(),
    executive_summary: enrichment.verdict
      || `${attack} detected involving ${alert.user} and ${alert.target}. Risk score ${alert.risk}/100 requires SOC review.`,
    technical_summary: `${attack} (${alert.mitre || "MITRE TBD"}) on ${alert.host}. Event ${alert.event_id}. Evidence: ${(alert.evidence || []).slice(0, 3).join("; ")}`,
    mitre: { id: alert.mitre || "T1558.003", name: attack, tactics: ["Credential Access"] },
    affected_identities: [
      { role: "source", name: alert.user, detail: "Suspected attacker / source account" },
      { role: "target", name: alert.target, detail: "Targeted identity or SPN" },
      { role: "host", name: alert.host, detail: `Domain controller / source host · ${alert.source_ip || "IP n/a"}` },
    ],
    evidence_highlights: alert.evidence?.length ? alert.evidence.slice(0, 6) : [`Event ${alert.event_id} on ${alert.host}`],
    blast_radius: enrichment.verdict || "Review attack path in AuthGraph dashboard for downstream privileged assets.",
    risk_rationale: `Risk ${alert.risk}/100 based on detection engine scoring and identity graph context.`,
    recommended_actions: (enrichment.action_details || enrichment.actions || alert.response || [])
      .slice(0, 5)
      .map((a, i) => ({
        priority: i + 1,
        action: typeof a === "string" ? a : a.action,
        owner: typeof a === "object" && a.owner ? a.owner : "SOC",
        rationale: typeof a === "object" && a.rationale ? a.rationale : "Standard ITDR response",
      })),
    timeline_utc: [
      { label: "Detection", detail: `${attack} alert ingested from ${alert.source || "Wazuh"}` },
      { label: "ARIA", detail: enrichment.headline || "AI enrichment completed" },
    ],
    indicators_of_compromise: [alert.user, alert.target, alert.host, alert.source_ip].filter(Boolean),
    false_positive_notes: "",
  };
}

async function callReasoningModel(messages, maxTokens = 1200) {
  const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${OPENROUTER_API_KEY}`,
      "Content-Type": "application/json",
      "HTTP-Referer": ITDR_DASHBOARD_URL,
      "X-Title": "AuthGraph ITDR",
    },
    body: JSON.stringify({
      model: OPENROUTER_REASONING_MODEL,
      temperature: 0.12,
      max_tokens: maxTokens,
      messages,
    }),
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`OpenRouter ${response.status}: ${errText.slice(0, 200)}`);
  }

  const payload = await response.json();
  return {
    text: payload.choices?.[0]?.message?.content?.trim() || "",
    model: payload.model || OPENROUTER_REASONING_MODEL,
  };
}

async function generateIncidentReport(alert, extras = {}) {
  const enrichment = extras.aiEnrichment || {};
  const fallback = fallbackReport(alert, enrichment);

  if (!OPENROUTER_API_KEY) {
    return { ...fallback, source: "fallback" };
  }

  try {
    const { text, model } = await callReasoningModel([
      { role: "system", content: REPORT_SYSTEM },
      { role: "user", content: buildReportPrompt(alert, extras) },
    ]);

    const parsed = parseJsonPayload(text);
    if (parsed?.executive_summary) {
      return { ...parsed, source: "openrouter", model };
    }

    return { ...fallback, source: "openrouter", model, raw: text?.slice(0, 500) };
  } catch (err) {
    console.warn("[report] AI generation failed:", err.message);
    return { ...fallback, source: "fallback", error: err.message };
  }
}

function renderReportHtml(alert, report, enrichment = {}, options = {}) {
  const sev = report.severity_label || "HIGH";
  const sevColor = severityColor(sev);
  const incidentId = alert.id || "unknown";
  const dashboardLink = `${ITDR_DASHBOARD_URL}?incident=${encodeURIComponent(incidentId)}`;
  const generatedAt = new Date().toISOString();
  const forPrint = Boolean(options.forPrint);

  const actionRows = (report.recommended_actions || [])
    .map(
      (a) => `
        <tr>
          <td style="padding:8px 10px;border-bottom:1px solid #1e293b;color:#94a3b8;width:32px;">${a.priority}</td>
          <td style="padding:8px 10px;border-bottom:1px solid #1e293b;color:#e2e8f0;">${escapeHtml(a.action)}</td>
          <td style="padding:8px 10px;border-bottom:1px solid #1e293b;color:#64748b;width:72px;">${escapeHtml(a.owner)}</td>
        </tr>`,
    )
    .join("");

  const evidenceList = (report.evidence_highlights || [])
    .map((e) => `<li style="margin:0 0 6px;color:#cbd5e1;">${escapeHtml(e)}</li>`)
    .join("");

  const identityRows = (report.affected_identities || [])
    .map(
      (id) => `
        <tr>
          <td style="padding:6px 10px;border-bottom:1px solid #1e293b;color:#64748b;text-transform:uppercase;font-size:11px;">${escapeHtml(id.role)}</td>
          <td style="padding:6px 10px;border-bottom:1px solid #1e293b;color:#e2e8f0;font-family:Consolas,monospace;">${escapeHtml(id.name)}</td>
          <td style="padding:6px 10px;border-bottom:1px solid #1e293b;color:#94a3b8;">${escapeHtml(id.detail)}</td>
        </tr>`,
    )
    .join("");

  const printCss = forPrint
    ? `@media print { body { background:#fff !important; } .card { break-inside: avoid; } }`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(report.subject || "AuthGraph ITDR Incident Report")}</title>
  <style>
    body { margin:0; padding:24px; background:#0b0f17; font-family:Segoe UI,system-ui,sans-serif; color:#e2e8f0; }
    .wrap { max-width:720px; margin:0 auto; }
    .card { background:#111827; border:1px solid #1e293b; border-radius:12px; padding:20px 22px; margin-bottom:16px; }
    h1 { margin:0 0 4px; font-size:20px; font-weight:700; }
    .meta { font-size:12px; color:#64748b; margin-bottom:16px; }
    h2 { margin:0 0 10px; font-size:13px; text-transform:uppercase; letter-spacing:0.06em; color:#64748b; }
    p { margin:0 0 10px; line-height:1.55; font-size:14px; color:#cbd5e1; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    .badge { display:inline-block; padding:3px 10px; border-radius:99px; font-size:11px; font-weight:700; letter-spacing:0.04em; }
    .risk { font-size:28px; font-weight:800; color:${sevColor}; }
    ul { margin:0; padding-left:18px; }
    .footer { font-size:11px; color:#475569; text-align:center; margin-top:20px; }
    a { color:#5b9cf5; }
    ${printCss}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px;">
        <div>
          <div class="badge" style="background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}55;">${escapeHtml(sev)}</div>
          <h1 style="margin-top:10px;">${escapeHtml(alert.attack || "Identity threat")} — ${escapeHtml(alert.user)} → ${escapeHtml(alert.target)}</h1>
          <div class="meta">Incident ${escapeHtml(incidentId)} · ${escapeHtml(generatedAt)} UTC · AuthGraph ITDR</div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:11px;color:#64748b;">Risk score</div>
          <div class="risk">${alert.risk ?? "—"}</div>
        </div>
      </div>
      <p style="font-size:15px;color:#f1f5f9;"><strong>Executive summary</strong><br/>${escapeHtml(report.executive_summary)}</p>
    </div>

    <div class="card">
      <h2>Technical summary</h2>
      <p>${escapeHtml(report.technical_summary)}</p>
      <p><strong>MITRE:</strong> ${escapeHtml(report.mitre?.id)} ${escapeHtml(report.mitre?.name)} (${(report.mitre?.tactics || []).map(escapeHtml).join(", ")})</p>
      <p><strong>Risk rationale:</strong> ${escapeHtml(report.risk_rationale)}</p>
      ${report.false_positive_notes ? `<p><strong>False positive notes:</strong> ${escapeHtml(report.false_positive_notes)}</p>` : ""}
    </div>

    <div class="card">
      <h2>Affected identities</h2>
      <table>${identityRows}</table>
    </div>

    <div class="card">
      <h2>Evidence</h2>
      <ul>${evidenceList}</ul>
    </div>

    <div class="card">
      <h2>Blast radius</h2>
      <p>${escapeHtml(report.blast_radius)}</p>
    </div>

    <div class="card">
      <h2>Recommended actions</h2>
      <table>
        <thead>
          <tr>
            <th style="text-align:left;padding:6px 10px;color:#64748b;font-size:11px;">#</th>
            <th style="text-align:left;padding:6px 10px;color:#64748b;font-size:11px;">Action</th>
            <th style="text-align:left;padding:6px 10px;color:#64748b;font-size:11px;">Owner</th>
          </tr>
        </thead>
        <tbody>${actionRows}</tbody>
      </table>
    </div>

    ${(report.indicators_of_compromise || []).length ? `
    <div class="card">
      <h2>Indicators</h2>
      <p style="font-family:Consolas,monospace;font-size:12px;">${report.indicators_of_compromise.map(escapeHtml).join(" · ")}</p>
    </div>` : ""}

    <div class="footer">
      <a href="${escapeHtml(dashboardLink)}">Open in AuthGraph dashboard</a>
      · Generated by ARIA (${escapeHtml(OPENROUTER_REASONING_MODEL)})
      ${forPrint ? "· Use browser Print → Save as PDF" : ""}
    </div>
  </div>
</body>
</html>`;
}

async function sendViaResend({ to, subject, html }) {
  if (!RESEND_API_KEY) {
    throw new Error("RESEND_API_KEY not configured");
  }
  if (!to) {
    throw new Error("ITDR_REPORT_TO not configured — set recipient email in backend/.env");
  }

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: ITDR_REPORT_FROM,
      to: Array.isArray(to) ? to : [to],
      subject,
      html,
    }),
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const msg = payload.message || payload.error || `Resend ${response.status}`;
    if (/only send testing emails to your own email/i.test(String(msg))) {
      throw new Error(
        `${msg} — With onboarding@resend.dev you must set ITDR_REPORT_TO to the email on your Resend account, or verify a domain you own at resend.com/domains and update ITDR_REPORT_FROM.`,
      );
    }
    throw new Error(msg);
  }
  return payload;
}

/**
 * Build report JSON + HTML for an incident.
 */
async function buildIncidentReportBundle(alert, enrichment = {}, extras = {}) {
  let report;
  try {
    report = await generateIncidentReport(alert, { ...extras, aiEnrichment: enrichment });
  } catch (err) {
    console.warn("[report] AI generation failed, using fallback:", err.message);
    report = fallbackReport(alert, enrichment);
    report._source = "fallback";
    report._error = err.message;
  }

  if (!report.subject) {
    report = { ...fallbackReport(alert, enrichment), ...report };
  }

  const html = renderReportHtml(alert, report, enrichment);
  const htmlPrint = renderReportHtml(alert, report, enrichment, { forPrint: true });

  return { report, html, htmlPrint, subject: report.subject };
}

/**
 * Send incident report email. Returns delivery metadata.
 */
async function sendIncidentReport(alert, enrichment = {}, extras = {}, options = {}) {
  const to = options.to || ITDR_REPORT_TO;
  const bundle = await buildIncidentReportBundle(alert, enrichment, extras);

  const delivery = await sendViaResend({
    to,
    subject: bundle.subject,
    html: bundle.html,
  });

  return {
    ok: true,
    to,
    subject: bundle.subject,
    resend_id: delivery.id,
    report: bundle.report,
    html: bundle.html,
    html_print: bundle.htmlPrint,
    sent_at: new Date().toISOString(),
  };
}

/**
 * Queue report for incident — deduped, non-blocking.
 */
function queueIncidentReport(dataStore, incidentId, options = {}) {
  if (inFlight.has(incidentId)) return;
  inFlight.add(incidentId);

  setImmediate(async () => {
    try {
      const alert = dataStore.getAlertById(incidentId);
      const enrichment = dataStore.getAiEnrichment(incidentId) || {};
      if (!alert) return;

      const existing = enrichment.report;
      if (existing?.status === "sent" && !options.force) return;

      const extras = {
        attackPath: dataStore.loadAttackPath(alert),
        contained: dataStore.getIncidentStatus(incidentId) === "contained",
      };

      const result = await sendIncidentReport(alert, enrichment, extras, options);

      dataStore.setReportMeta(incidentId, {
        status: "sent",
        to: result.to,
        subject: result.subject,
        resend_id: result.resend_id,
        sent_at: result.sent_at,
        report: result.report,
      });

      appendEvent("system", `Incident report emailed to ${result.to}`, {
        incident_id: incidentId,
        subject: result.subject,
        resend_id: result.resend_id,
      });
      console.log(`[report] Sent ${incidentId} → ${result.to} (${result.resend_id})`);
    } catch (err) {
      console.warn(`[report] Failed for ${incidentId}:`, err.message);
      dataStore.setReportMeta(incidentId, {
        status: "error",
        error: err.message,
        failed_at: new Date().toISOString(),
      });
      appendEvent("warn", `Incident report failed: ${err.message}`, { incident_id: incidentId });
    } finally {
      inFlight.delete(incidentId);
    }
  });
}

module.exports = {
  buildIncidentReportBundle,
  sendIncidentReport,
  queueIncidentReport,
  renderReportHtml,
  generateIncidentReport,
  fallbackReport,
  sendViaResend,
};

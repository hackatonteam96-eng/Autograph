const fs = require("fs");
const path = require("path");
const { DATA_DIR, ITDR_REPORT_AUTO } = require("../config");
const { appendEvent } = require("../services/eventLog");
const {
  enrichAlerts,
  scoreIdentity,
  ingestWazuh,
  explain: explainAlert,
} = require("../../detection/integration");
const { isItdrAlert, classifyWazuhPayload, webhookPreview } = require("../../detection/wazuh_filter");

const { buildAttackPathFromAlert } = require("../utils/attackPathBuilder");

/** Demo placeholder id — never shown in production UI */
const PLACEHOLDER_ALERT_ID = "alert-demo-placeholder";

const EMPTY_ATTACK_PATH = { nodes: [], edges: [] };

/** @type {Map<string, number>} throttle duplicate webhook ignore logs */
const ignoreLogThrottle = new Map();

function readJsonFile(filePath, fallback) {
  try {
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, "utf8");
      return JSON.parse(raw);
    }
  } catch (err) {
    console.warn(`[dataStore] Failed to read ${filePath}:`, err.message);
  }
  return fallback;
}

class DataStore {
  constructor() {
    this.alertsPath = path.join(DATA_DIR, "sample-alerts.json");
    this.attackPathFile = path.join(DATA_DIR, "attack-path.json");
    this.wazuhRealPath = path.join(DATA_DIR, "wazuh-alert-real.json");
    this.historyPath = path.join(DATA_DIR, "alert-history.json");
    this.statePath = path.join(DATA_DIR, "incident-state.json");

    /** @type {Map<string, { status: string; contained_at?: string; risk_before?: number; risk_after?: number; approved_actions?: string[]; execution?: unknown[] }>} */
    this.incidentState = new Map();

    /** @type {Map<string, { status: string; verdict?: string; actions?: string[]; summary_model?: string; actions_model?: string; enriched_at?: string; source?: string; error?: string }>} */
    this.aiEnrichment = new Map();

    /** @type {{ active: boolean; step: number; startedAt: number | null; risk: number }} */
    this.simulation = { active: false, step: 0, startedAt: null, risk: 12 };

    this.loadPersistedState();
  }

  isRealAlert(alert) {
    if (!alert?.id) return false;
    if (alert.id === PLACEHOLDER_ALERT_ID) return false;
    const hist = this.historyMeta(alert.id);
    const source = alert.ingest_source || hist?.ingest_source;
    if (source === "sample") return false;
    if (alert.user === "lowpriv.user" && alert.target === "svc-sql" && alert.host === "DC01") return false;
    return source === "webhook" || source === "simulation";
  }

  purgePlaceholderData() {
    const history = this.loadAlertHistory().filter((a) => this.isRealAlert(a));
    this.saveAlertHistory(history);
    for (const key of [...this.incidentState.keys()]) {
      if (key === PLACEHOLDER_ALERT_ID) this.incidentState.delete(key);
    }
    for (const key of [...this.aiEnrichment.keys()]) {
      if (key === PLACEHOLDER_ALERT_ID) this.aiEnrichment.delete(key);
    }
    this.persistState();
  }

  loadPersistedState() {
    const data = readJsonFile(this.statePath, { incidents: {}, ai: {} });
    if (data.incidents && typeof data.incidents === "object") {
      this.incidentState = new Map(Object.entries(data.incidents));
    }
    if (data.ai && typeof data.ai === "object") {
      this.aiEnrichment = new Map(Object.entries(data.ai));
    }
  }

  persistState() {
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      fs.writeFileSync(
        this.statePath,
        JSON.stringify(
          {
            incidents: Object.fromEntries(this.incidentState),
            ai: Object.fromEntries(this.aiEnrichment),
          },
          null,
          2,
        ),
      );
    } catch (err) {
      console.warn("[dataStore] persistState failed:", err.message);
    }
  }

  loadAlertHistory() {
    return readJsonFile(this.historyPath, []);
  }

  saveAlertHistory(alerts) {
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      fs.writeFileSync(this.historyPath, JSON.stringify(alerts.slice(0, 50), null, 2));
    } catch (err) {
      console.warn("[dataStore] saveAlertHistory failed:", err.message);
    }
  }

  upsertAlertHistory(alert, meta = {}) {
    const history = this.loadAlertHistory();
    const idx = history.findIndex((a) => a.id === alert.id);
    const isNew = idx < 0;
    const prev = idx >= 0 ? history[idx] : {};
    const incomingRisk = alert.risk != null ? Number(alert.risk) : null;
    const prevRisk = prev.canonical_risk != null ? Number(prev.canonical_risk) : null;
    let canonicalRisk = prevRisk;
    if (incomingRisk != null) {
      canonicalRisk = prevRisk != null ? Math.max(prevRisk, incomingRisk) : incomingRisk;
    }
    const ingestSource =
      meta.ingest_source === "webhook" || prev.ingest_source === "webhook"
        ? "webhook"
        : meta.ingest_source || prev.ingest_source || "sample";
    const entry = {
      ...prev,
      ...alert,
      risk: canonicalRisk ?? alert.risk,
      canonical_risk: canonicalRisk,
      ingested_at: new Date().toISOString(),
      ingest_source: ingestSource,
      last_webhook_at:
        meta.ingest_source === "webhook"
          ? new Date().toISOString()
          : prev.last_webhook_at || null,
    };
    if (idx >= 0) history[idx] = entry;
    else history.unshift(entry);
    this.saveAlertHistory(history);
    return { entry, isNew };
  }

  historyMeta(alertId) {
    return this.loadAlertHistory().find((a) => a.id === alertId) || null;
  }

  /**
   * Load raw alerts from disk or defaults, then run Wazuh ingest if applicable.
   */
  loadRawAlerts() {
    const history = this.loadAlertHistory().filter((a) => this.isRealAlert(a));
    const fromWazuh = readJsonFile(this.wazuhRealPath, null);

    let wazuhAlerts = [];
    if (fromWazuh) {
      const list = Array.isArray(fromWazuh) ? fromWazuh : [fromWazuh];
      if (list.length > 0) {
        const classification = classifyWazuhPayload(list);
        if (!classification.accept) {
          console.warn(`[dataStore] Removing stale non-ITDR wazuh capture: ${classification.reason}`);
          try { fs.unlinkSync(this.wazuhRealPath); } catch { /* ignore */ }
        } else {
          wazuhAlerts = ingestWazuh(list, DATA_DIR).filter(isItdrAlert);
        }
      }
    }

    const byId = new Map();
    for (const a of history) byId.set(a.id, a);
    for (const a of wazuhAlerts) byId.set(a.id, { ...byId.get(a.id), ...a, source: "Wazuh", ingest_source: "webhook" });

    return Array.from(byId.values()).sort(
      (a, b) => new Date(b.time || 0).getTime() - new Date(a.time || 0).getTime(),
    );
  }

  /**
   * Enrich alerts with Gular's detection engine (risk, evidence, sigma match).
   */
  loadAlerts() {
    const raw = this.loadRawAlerts();
    return enrichAlerts(raw, DATA_DIR);
  }

  loadAttackPath(forAlert = null) {
    const alert = forAlert || this.getPrimaryItdrAlert();
    if (alert) return buildAttackPathFromAlert(alert);
    const fromDisk = readJsonFile(this.attackPathFile, EMPTY_ATTACK_PATH);
    if (fromDisk.nodes?.length) return fromDisk;
    return EMPTY_ATTACK_PATH;
  }

  getAlerts() {
    return this.loadAlerts()
      .filter((a) => this.isRealAlert(a))
      .map((alert) => this.withIncidentStatus(alert));
  }

  getIncidents() {
    const score = (x) => new Date(x.last_webhook_at || x.time || 0).getTime();
    const alerts = [...this.getAlerts()].sort((a, b) => {
      const rank = (x) => (isItdrAlert(x) ? 0 : 1);
      const dr = rank(a) - rank(b);
      if (dr !== 0) return dr;
      return score(b) - score(a);
    });
    return alerts.map((alert) => ({
      ...alert,
      incident_id: alert.id,
      title: `${alert.attack} — ${alert.target}`,
      status: this.getIncidentStatus(alert.id),
    }));
  }

  getPrimaryItdrAlert() {
    const score = (x) => new Date(x.last_webhook_at || x.time || 0).getTime();
    const webhook = this.getAlerts()
      .filter((a) => a.ingest_source === "webhook" && isItdrAlert(a))
      .sort((a, b) => {
        if (a.status !== b.status) {
          if (a.status === "contained") return 1;
          if (b.status === "contained") return -1;
        }
        return score(b) - score(a);
      });
    if (webhook.length) return webhook[0];
    const alerts = this.getAlerts();
    return alerts.find(isItdrAlert) || alerts[0] || null;
  }

  getAlertById(incidentId) {
    return this.getAlerts().find((a) => a.id === incidentId) || null;
  }

  getIncidentStatus(incidentId) {
    return this.incidentState.get(incidentId)?.status || "open";
  }

  withIncidentStatus(alert) {
    const state = this.incidentState.get(alert.id);
    const ai = this.aiEnrichment.get(alert.id);
    const hist = this.historyMeta(alert.id);
    const contained = state?.status === "contained";
    const isWebhook = hist?.ingest_source === "webhook";
    const simActive = this.simulation.active && !isWebhook;
    const simRisk = this.getSimulatedRisk();
    const baseRisk = hist?.canonical_risk ?? alert.risk;

    return {
      ...alert,
      status: state?.status || (simActive ? "correlating" : "open"),
      risk: contained
        ? (state.risk_after ?? 32)
        : simActive
          ? simRisk
          : baseRisk,
      risk_before: contained ? (state.risk_before ?? baseRisk) : undefined,
      contained_at: state?.contained_at || null,
      simulation_active: simActive,
      demo_step: simActive ? this.getDemoStep() : alert.demo_step ?? 0,
      ingest_source: hist?.ingest_source || "sample",
      last_webhook_at: hist?.last_webhook_at || null,
      ai_status: ai?.status || null,
      ai_verdict: ai?.verdict || null,
      ai_headline: ai?.headline || null,
      ai_confidence: ai?.confidence || null,
      ai_urgency: ai?.urgency || null,
      ai_actions: ai?.actions || null,
      ai_action_details: ai?.action_details || null,
      ai_summary_model: ai?.summary_model || null,
      ai_actions_model: ai?.actions_model || null,
      ai_enriched_at: ai?.enriched_at || null,
    };
  }

  getDemoStep() {
    if (!this.simulation.active) return 0;
    const elapsed = Date.now() - (this.simulation.startedAt || Date.now());
    if (elapsed < 620) return 1;
    if (elapsed < 1240) return 2;
    if (elapsed < 1860) return 3;
    return 3;
  }

  getSimulatedRisk() {
    if (!this.simulation.active) return 12;
    const step = this.getDemoStep();
    return [12, 39, 64, 87][step] ?? 87;
  }

  getSimulationStatus() {
    return {
      active: this.simulation.active,
      step: this.getDemoStep(),
      risk: this.getSimulatedRisk(),
      timeline_count: this.simulation.active ? Math.min(this.getDemoStep() + 1, 5) : 0,
    };
  }

  triggerKerberoastSimulation() {
    const alert = this.getPrimaryItdrAlert();
    if (!alert) {
      return {
        ok: false,
        error: "No live Wazuh alert to analyze — trigger kerberoast in lab first",
      };
    }

    const hist = this.historyMeta(alert.id);
    const isWebhook = alert.ingest_source === "webhook" || hist?.ingest_source === "webhook";

    if (isWebhook) {
      this.aiEnrichment.delete(alert.id);
      this.startAiEnrichment(alert.id);
      appendEvent("system", "Re-analyzing live Wazuh alert with ARIA", {
        incident_id: alert.id,
        user: alert.user,
        target: alert.target,
      });
      return {
        ok: true,
        message: "Re-analyzing live alert",
        incident: this.getAlertById(alert.id),
        status: { active: false, step: 0, risk: hist?.canonical_risk ?? alert.risk, timeline_count: 0 },
      };
    }

    this.simulation = { active: true, step: 0, startedAt: Date.now(), risk: alert.risk ?? 12 };
    this.upsertAlertHistory(alert, { ingest_source: "simulation" });
    this.startAiEnrichment(alert.id);
    appendEvent("system", "Kerberoast simulation started", {
      incident_id: alert.id,
      user: alert.user,
      target: alert.target,
    });
    return {
      ok: true,
      message: "Simulation started",
      incident: this.getAlertById(alert.id),
      status: this.getSimulationStatus(),
    };
  }

  resetSimulation() {
    this.simulation = { active: false, step: 0, startedAt: null, risk: 12 };
    this.incidentState.clear();
    this.aiEnrichment.clear();
    this.clearWazuhCapture();
    this.purgePlaceholderData();
    try {
      if (fs.existsSync(this.statePath)) fs.unlinkSync(this.statePath);
    } catch { /* ignore */ }
    appendEvent("system", "Dashboard reset — placeholder and simulation state cleared");
    return { ok: true, message: "Demo reset" };
  }

  startAiEnrichment(incidentId) {
    const existing = this.aiEnrichment.get(incidentId);
    if (existing?.status === "ready" || existing?.status === "pending") return;

    const alert = this.getAlertById(incidentId);
    if (!alert) return;

    this.aiEnrichment.set(incidentId, { status: "pending" });

    const { enrichIncidentOnIngest } = require("../services/openrouter");
    const extras = {
      attackPath: this.loadAttackPath(alert),
      contained: this.getIncidentStatus(incidentId) === "contained",
    };
    enrichIncidentOnIngest(alert, extras)
      .then((result) => {
        this.aiEnrichment.set(incidentId, result);
        this.persistState();
        appendEvent("ai", `ARIA enriched incident ${incidentId}`, {
          incident_id: incidentId,
          headline: result.headline,
          actions: result.actions?.length ?? 0,
        });
        console.log(`[ai] Enriched ${incidentId} — flash verdict + pro actions`);

        if (ITDR_REPORT_AUTO) {
          const hist = this.historyMeta(incidentId);
          if (hist?.ingest_source === "webhook") {
            const { queueIncidentReport } = require("../services/incidentReport");
            queueIncidentReport(this, incidentId);
          }
        }
      })
      .catch((err) => {
        console.warn(`[ai] Enrichment failed for ${incidentId}:`, err.message);
        this.aiEnrichment.set(incidentId, {
          status: "error",
          error: err.message,
          verdict: `${alert.attack}: ${alert.user} → ${alert.target}. Risk ${alert.risk}/100.`,
          actions: alert.response || [],
        });
      });
  }

  getAiEnrichment(incidentId) {
    return this.aiEnrichment.get(incidentId) || null;
  }

  setReportMeta(incidentId, reportMeta) {
    const existing = this.aiEnrichment.get(incidentId) || {};
    this.aiEnrichment.set(incidentId, { ...existing, report: reportMeta });
    this.persistState();
  }

  ingestWebhook(payload) {
    try {
      const fs = require("fs");
      const list = Array.isArray(payload) ? payload : [payload];
      const classification = classifyWazuhPayload(list);

      if (!classification.accept) {
        console.log(`[webhook] Ignored (${classification.kind}): ${classification.reason}`);
        const preview = list[0] ? webhookPreview(list[0]) : "";
        const throttleKey = preview.slice(0, 100);
        const lastLogged = ignoreLogThrottle.get(throttleKey) || 0;
        if (Date.now() - lastLogged > 120000) {
          ignoreLogThrottle.set(throttleKey, Date.now());
          appendEvent("webhook", `Ignored (non-ITDR): ${classification.reason}`, {
            kind: classification.kind,
            preview,
          });
        }
        return {
          ok: true,
          ignored: true,
          kind: classification.kind,
          reason: classification.reason,
        };
      }

      fs.writeFileSync(this.wazuhRealPath, JSON.stringify(list.length === 1 ? list[0] : list, null, 2));
      const ingested = ingestWazuh(list, DATA_DIR).filter(isItdrAlert);
      if (ingested.length === 0) {
        try { fs.unlinkSync(this.wazuhRealPath); } catch { /* ignore */ }
        appendEvent("warn", "Webhook accepted but could not parse ITDR alert", {
          preview: list[0] ? webhookPreview(list[0]) : "",
        });
        return { ok: false, error: "Could not parse ITDR alert from Wazuh payload" };
      }
      this.simulation = { active: false, step: 0, startedAt: null, risk: ingested[0].risk ?? 87 };
      const incident = ingested[0];
      const { isNew } = this.upsertAlertHistory(incident, { ingest_source: "webhook" });
      this.startAiEnrichment(incident.id);
      appendEvent(isNew ? "alert" : "webhook", isNew
        ? `New ${incident.attack} alert from Wazuh/Yara webhook`
        : `Webhook update for existing incident ${incident.id}`, {
        incident_id: incident.id,
        user: incident.user,
        target: incident.target,
        risk: incident.risk,
        host: incident.host,
        attack: incident.attack,
        is_new: isNew,
      });
      console.log(`[webhook] ITDR ${incident.attack} ingested risk=${incident.risk} target=${incident.target} new=${isNew}`);
      return { ok: true, alerts: ingested.length, incident, itdr: true, is_new: isNew };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  clearWazuhCapture() {
    try {
      if (fs.existsSync(this.wazuhRealPath)) fs.unlinkSync(this.wazuhRealPath);
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  /**
   * Identity risk via Gular's risk engine.
   */
  getRisk(identity) {
    const alerts = this.getAlerts();
    const result = scoreIdentity(decodeURIComponent(identity), alerts, DATA_DIR);

    const state = this.incidentState.get(result.alert_id);
    if (state?.status === "contained" && result.alert_id) {
      return {
        ...result,
        risk: state.risk_after ?? result.risk,
        severity: "medium",
        reason: "Identity contained — residual risk reduced after response actions",
        status: "contained",
      };
    }

    return result;
  }

  /**
   * Judge-friendly explanation of why an incident fired.
   */
  explainIncident(incidentId) {
    const alert = this.getAlertById(incidentId);
    if (!alert) return null;

    const explanation = explainAlert(alert);
    return {
      incident_id: incidentId,
      alert_id: alert.id,
      attack: alert.attack,
      mitre: alert.mitre,
      summary: explanation.summary,
      sigma: explanation.sigma,
      risk_factors: explanation.risk_factors,
      evidence: explanation.evidence,
      confidence: explanation.confidence,
      risk: alert.risk,
      severity: alert.severity,
      target: alert.target,
      user: alert.user,
    };
  }

  async contain(incidentId, approvedActions = []) {
    const alert = this.getAlertById(incidentId);
    if (!alert) {
      return { ok: false, error: "Incident not found" };
    }

    const ai = this.aiEnrichment.get(incidentId);
    const executedActions = approvedActions.length > 0
      ? approvedActions
      : ai?.actions?.length
        ? ai.actions
        : alert.response?.length
          ? alert.response
          : [
              "Source user disabled",
              "Service account marked for password rotation",
              "RC4 disabled recommendation generated",
              "SOC ticket created",
            ];

    const existing = this.incidentState.get(incidentId);
    if (existing?.status === "contained") {
      return {
        ok: true,
        incident_id: incidentId,
        status: "contained",
        actions: existing.approved_actions || executedActions,
        execution: existing.execution || [],
        risk_before: existing.risk_before,
        risk_after: existing.risk_after,
        message: "Incident already contained",
        mode: require("../services/playbookExecutor").LAB_ENABLED ? "live" : "simulated",
      };
    }

    const { executePlaybook, LAB_ENABLED } = require("../services/playbookExecutor");
    const execution = await executePlaybook(executedActions, alert, incidentId);

    const riskBefore = alert.risk;
    const failed = execution.filter((e) => e.status === "failed").length;
    const riskAfter = failed > 0 ? Math.max(45, Math.round(riskBefore * 0.55)) : 32;

    this.incidentState.set(incidentId, {
      status: "contained",
      contained_at: new Date().toISOString(),
      risk_before: riskBefore,
      risk_after: riskAfter,
      approved_actions: executedActions,
      execution,
    });
    this.persistState();

    appendEvent("action", `Playbook recorded (copy-run) for ${incidentId}`, {
      incident_id: incidentId,
      actions: executedActions.length,
      mode: LAB_ENABLED ? "live" : "simulated",
      risk_before: riskBefore,
      risk_after: riskAfter,
    });

    return {
      ok: true,
      incident_id: incidentId,
      status: "contained",
      actions: executedActions,
      execution,
      risk_before: riskBefore,
      risk_after: riskAfter,
      mode: LAB_ENABLED ? "live" : "simulated",
    };
  }

  /** Reload data from disk — useful when Kanan drops real Wazuh JSON */
  reloadFromDisk() {
    return {
      alerts: this.getAlerts(),
      attack_path: this.loadAttackPath(),
      incidents: this.getIncidents(),
    };
  }

  /** Health diagnostics */
  getDiagnostics() {
    const detectionOk = (() => {
      try {
        require("../../detection/integration");
        return true;
      } catch {
        return false;
      }
    })();

    const kerberosCapture = (() => {
      if (!fs.existsSync(this.wazuhRealPath)) return false;
      try {
        const raw = JSON.parse(fs.readFileSync(this.wazuhRealPath, "utf8"));
        const list = Array.isArray(raw) ? raw : [raw];
        return classifyWazuhPayload(list).accept;
      } catch {
        return false;
      }
    })();

    return {
      data_dir: DATA_DIR,
      sample_alerts: fs.existsSync(this.alertsPath),
      attack_path: fs.existsSync(this.attackPathFile),
      wazuh_real: kerberosCapture,
      wazuh_kerberos: kerberosCapture,
      wazuh_file_present: fs.existsSync(this.wazuhRealPath),
      detection_module: detectionOk ? "ok" : "missing",
      open_incidents: this.getIncidents().filter((i) => i.status === "open").length,
      contained_incidents: this.getIncidents().filter((i) => i.status === "contained").length,
      alert_history: this.loadAlertHistory().length,
      identities_monitored: this.loadAttackPath().nodes?.length ?? 0,
    };
  }
}

module.exports = new DataStore();

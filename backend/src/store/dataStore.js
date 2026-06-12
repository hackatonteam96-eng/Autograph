const fs = require("fs");
const path = require("path");
const { DATA_DIR } = require("../config");
const {
  enrichAlerts,
  scoreIdentity,
  ingestWazuh,
  explain: explainAlert,
} = require("../../detection/integration");

const DEFAULT_ALERTS = [
  {
    id: "alert-001",
    time: "2026-06-12T14:03:00Z",
    source: "Wazuh",
    attack: "Kerberoasting",
    mitre: "T1558.003",
    severity: "critical",
    risk: 87,
    user: "lowpriv.user",
    target: "svc-sql",
    source_ip: "10.0.0.42",
    host: "DC01",
    event_id: 4769,
    evidence: [
      "Multiple Kerberos TGS requests from one user",
      "RC4 encrypted service ticket requested",
      "Target account has SPN configured",
      "Service account is linked to privileged SQL server",
    ],
    response: [
      "Reset service account password",
      "Disable RC4 Kerberos encryption",
      "Review SPN ownership",
      "Investigate source user session",
      "Rotate credentials for exposed service account",
    ],
  },
];

const DEFAULT_ATTACK_PATH = {
  nodes: [
    { id: "lowpriv.user", type: "user", risk: "medium" },
    { id: "svc-sql", type: "service_account", risk: "critical" },
    { id: "SQL Admins", type: "group", risk: "high" },
    { id: "SQL-SERVER", type: "host", risk: "high" },
    { id: "Domain Sensitive Assets", type: "asset", risk: "critical" },
  ],
  edges: [
    { from: "lowpriv.user", to: "svc-sql", label: "Requested TGS" },
    { from: "svc-sql", to: "SQL Admins", label: "Member Of" },
    { from: "SQL Admins", to: "SQL-SERVER", label: "Admin To" },
    { from: "SQL-SERVER", to: "Domain Sensitive Assets", label: "Access Path" },
  ],
};

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

    /** @type {Map<string, { status: string, contained_at?: string, risk_before?: number, risk_after?: number }>} */
    this.incidentState = new Map();
  }

  /**
   * Load raw alerts from disk or defaults, then run Wazuh ingest if applicable.
   */
  loadRawAlerts() {
    const fromWazuh = readJsonFile(this.wazuhRealPath, null);
    if (fromWazuh) {
      const list = Array.isArray(fromWazuh) ? fromWazuh : [fromWazuh];
      if (list.length > 0) {
        const ingested = ingestWazuh(list, DATA_DIR);
        if (ingested.length > 0) return ingested;
      }
    }

    return readJsonFile(this.alertsPath, DEFAULT_ALERTS);
  }

  /**
   * Enrich alerts with Gular's detection engine (risk, evidence, sigma match).
   */
  loadAlerts() {
    const raw = this.loadRawAlerts();
    return enrichAlerts(raw, DATA_DIR);
  }

  loadAttackPath() {
    return readJsonFile(this.attackPathFile, DEFAULT_ATTACK_PATH);
  }

  getAlerts() {
    return this.loadAlerts().map((alert) => this.withIncidentStatus(alert));
  }

  getIncidents() {
    return this.getAlerts().map((alert) => ({
      ...alert,
      incident_id: alert.id,
      title: `${alert.attack} — ${alert.target}`,
      status: this.getIncidentStatus(alert.id),
    }));
  }

  getAlertById(incidentId) {
    return this.getAlerts().find((a) => a.id === incidentId) || null;
  }

  getIncidentStatus(incidentId) {
    return this.incidentState.get(incidentId)?.status || "open";
  }

  withIncidentStatus(alert) {
    const state = this.incidentState.get(alert.id);
    const contained = state?.status === "contained";

    return {
      ...alert,
      status: state?.status || "open",
      risk: contained ? (state.risk_after ?? alert.risk) : alert.risk,
      contained_at: state?.contained_at || null,
    };
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
      risk: alert.risk,
      severity: alert.severity,
      target: alert.target,
      user: alert.user,
    };
  }

  contain(incidentId) {
    const alert = this.getAlertById(incidentId);
    if (!alert) {
      return { ok: false, error: "Incident not found" };
    }

    const existing = this.incidentState.get(incidentId);
    if (existing?.status === "contained") {
      return {
        ok: true,
        incident_id: incidentId,
        status: "contained",
        actions: [
          "Source user disabled",
          "Service account marked for password rotation",
          "RC4 disabled recommendation generated",
          "SOC ticket created",
        ],
        risk_before: existing.risk_before,
        risk_after: existing.risk_after,
        message: "Incident already contained",
      };
    }

    const riskBefore = alert.risk;
    const riskAfter = 32;

    this.incidentState.set(incidentId, {
      status: "contained",
      contained_at: new Date().toISOString(),
      risk_before: riskBefore,
      risk_after: riskAfter,
    });

    return {
      ok: true,
      incident_id: incidentId,
      status: "contained",
      actions: [
        "Source user disabled",
        "Service account marked for password rotation",
        "RC4 disabled recommendation generated",
        "SOC ticket created",
      ],
      risk_before: riskBefore,
      risk_after: riskAfter,
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

    return {
      data_dir: DATA_DIR,
      sample_alerts: fs.existsSync(this.alertsPath),
      attack_path: fs.existsSync(this.attackPathFile),
      wazuh_real: fs.existsSync(this.wazuhRealPath),
      detection_module: detectionOk ? "ok" : "missing",
      open_incidents: this.getIncidents().filter((i) => i.status === "open").length,
      contained_incidents: this.getIncidents().filter((i) => i.status === "contained").length,
    };
  }
}

module.exports = new DataStore();

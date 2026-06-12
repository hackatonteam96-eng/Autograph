/**
 * AuthGraph ITDR — Identity risk scoring engine.
 * Explainable scoring for Kerberoasting and related AD identity risk.
 */

const {
  RISK_WEIGHTS,
  SEVERITY_THRESHOLDS,
  EVIDENCE_MESSAGES,
  PRIVILEGED_GROUP_PATTERNS,
  MITRE,
} = require("./constants");

/**
 * @typedef {Object} RiskBreakdownItem
 * @property {string} factor
 * @property {number} points
 * @property {string} description
 */

/**
 * @typedef {Object} RiskScoreResult
 * @property {string} identity
 * @property {number} risk
 * @property {string} severity
 * @property {string} reason
 * @property {RiskBreakdownItem[]} breakdown
 * @property {string[]} evidence
 * @property {string} mitre
 */

function capRisk(score) {
  return Math.min(100, Math.max(0, Math.round(score)));
}

function severityFromRisk(risk) {
  if (risk >= SEVERITY_THRESHOLDS.critical) return "critical";
  if (risk >= SEVERITY_THRESHOLDS.high) return "high";
  if (risk >= SEVERITY_THRESHOLDS.medium) return "medium";
  return "low";
}

/**
 * Analyze attack path for privileged escalation potential from an identity.
 * @param {string} identity
 * @param {{ nodes?: Array<{id:string,type?:string,risk?:string}>, edges?: Array<{from:string,to:string,label?:string}> }} attackPath
 * @returns {{ full_path: boolean, linked: boolean, hops_to_critical: number, downstream_critical: string[] }}
 */
function analyzePrivilegedPath(identity, attackPath) {
  const nodes = attackPath?.nodes || [];
  const edges = attackPath?.edges || [];
  const nodeMap = new Map(nodes.map((n) => [n.id.toLowerCase(), n]));
  const startId = identity.toLowerCase();

  if (!nodeMap.has(startId)) {
    return { full_path: false, linked: false, hops_to_critical: Infinity, downstream_critical: [] };
  }

  const adjacency = new Map();
  for (const edge of edges) {
    const from = edge.from.toLowerCase();
    if (!adjacency.has(from)) adjacency.set(from, []);
    adjacency.get(from).push(edge.to);
  }

  const criticalNodes = [];
  const queue = [{ id: startId, hops: 0 }];
  const visited = new Set([startId]);
  let hopsToCritical = Infinity;

  while (queue.length > 0) {
    const { id, hops } = queue.shift();
    const node = nodeMap.get(id);
    if (node?.risk === "critical" && id !== startId) {
      criticalNodes.push(node.id);
      hopsToCritical = Math.min(hopsToCritical, hops);
    }

    for (const next of adjacency.get(id) || []) {
      const nextId = next.toLowerCase();
      if (!visited.has(nextId)) {
        visited.add(nextId);
        queue.push({ id: nextId, hops: hops + 1 });
      }
    }
  }

  const startNode = nodeMap.get(startId);
  const linkedGroup = (adjacency.get(startId) || []).some((target) => {
    const t = nodeMap.get(target.toLowerCase());
    return (
      t?.type === "group" &&
      (PRIVILEGED_GROUP_PATTERNS.some((p) => p.test(t.id)) || t.risk === "high" || t.risk === "critical")
    );
  });

  return {
    /** Short path (≤2 hops) to a critical asset — full privileged-path weight */
    full_path: criticalNodes.length > 0 && hopsToCritical <= 2,
    /** Service account or group linkage without confirmed short critical path */
    linked: linkedGroup || startNode?.type === "service_account",
    hops_to_critical: hopsToCritical,
    downstream_critical: criticalNodes,
  };
}

/**
 * Build evidence strings from detection indicators.
 * @param {Record<string, boolean>} indicators
 * @param {{ multiple_tgs_count?: number, target?: string }} context
 * @returns {string[]}
 */
function buildEvidence(indicators, context = {}) {
  const evidence = [];

  if (indicators.multiple_tgs || indicators.multiple_tgs_requests) {
    evidence.push(EVIDENCE_MESSAGES.multiple_tgs);
  }
  if (indicators.rc4_encryption || indicators.rc4) {
    evidence.push(EVIDENCE_MESSAGES.rc4);
  }
  if (indicators.service_account_spn || indicators.spn || indicators.has_spn) {
    evidence.push(EVIDENCE_MESSAGES.spn);
  }
  if (indicators.privileged_path) {
    evidence.push(EVIDENCE_MESSAGES.privileged_path);
  } else if (indicators.privileged_link || indicators.privileged_asset_link) {
    evidence.push(EVIDENCE_MESSAGES.privileged_link);
  }
  if (indicators.kerberoasting && evidence.length === 0) {
    evidence.push(EVIDENCE_MESSAGES.kerberoasting);
  }

  if (context.multiple_tgs_count && context.multiple_tgs_count >= 3 && !evidence.includes(EVIDENCE_MESSAGES.multiple_tgs)) {
    evidence.unshift(EVIDENCE_MESSAGES.multiple_tgs);
  }

  return [...new Set(evidence)];
}

/**
 * Score risk from detection indicators and optional attack path context.
 * @param {string} identity
 * @param {Record<string, boolean>} indicators
 * @param {{ attackPath?: object, multiple_tgs_count?: number }} [options]
 * @returns {RiskScoreResult}
 */
function scoreRisk(identity, indicators = {}, options = {}) {
  const breakdown = [];
  let total = 0;

  if (indicators.kerberoasting) {
    breakdown.push({
      factor: "kerberoasting",
      points: RISK_WEIGHTS.KERBEROASTING,
      description: "Kerberoasting alert — TGS requested for SPN-backed account",
    });
    total += RISK_WEIGHTS.KERBEROASTING;
  }

  if (indicators.rc4_encryption || indicators.rc4) {
    breakdown.push({
      factor: "rc4_encryption",
      points: RISK_WEIGHTS.RC4_ENCRYPTION,
      description: "RC4 ticket encryption enables offline cracking",
    });
    total += RISK_WEIGHTS.RC4_ENCRYPTION;
  }

  if (indicators.multiple_tgs || indicators.multiple_tgs_requests) {
    breakdown.push({
      factor: "multiple_tgs",
      points: RISK_WEIGHTS.MULTIPLE_TGS,
      description: "Burst of TGS requests from single user (spray pattern)",
    });
    total += RISK_WEIGHTS.MULTIPLE_TGS;
  }

  if (indicators.service_account_spn || indicators.spn || indicators.has_spn) {
    breakdown.push({
      factor: "service_account_spn",
      points: RISK_WEIGHTS.SERVICE_ACCOUNT_SPN,
      description: "Target account exposes Kerberos service principal (SPN)",
    });
    total += RISK_WEIGHTS.SERVICE_ACCOUNT_SPN;
  }

  const pathAnalysis = options.attackPath
    ? analyzePrivilegedPath(identity, options.attackPath)
    : null;

  if (pathAnalysis?.full_path) {
    breakdown.push({
      factor: "privileged_path_full",
      points: RISK_WEIGHTS.PRIVILEGED_PATH_FULL,
      description: `Confirmed path to critical asset (${pathAnalysis.downstream_critical.join(", ")})`,
    });
    total += RISK_WEIGHTS.PRIVILEGED_PATH_FULL;
  } else if (pathAnalysis?.linked || indicators.privileged_link) {
    breakdown.push({
      factor: "privileged_asset_link",
      points: RISK_WEIGHTS.PRIVILEGED_ASSET_LINK,
      description: "Service account linked to privileged SQL infrastructure",
    });
    total += RISK_WEIGHTS.PRIVILEGED_ASSET_LINK;
  }

  const risk = capRisk(total);
  const severity = severityFromRisk(risk);
  const evidence = buildEvidence(
    {
      ...indicators,
      privileged_path: pathAnalysis?.full_path,
      privileged_link: pathAnalysis?.linked,
    },
    options
  );

  let reason = "No Kerberoasting indicators for this identity";
  if (indicators.kerberoasting || risk >= SEVERITY_THRESHOLDS.high) {
    reason =
      severity === "critical"
        ? "Kerberoasting indicators detected against privileged service account"
        : "Kerberoasting indicators detected on identity";
  } else if (risk > 0) {
    reason = `Identity appears on attack path with elevated exposure`;
  }

  return {
    identity,
    risk,
    severity,
    reason,
    breakdown,
    evidence,
    mitre: MITRE.KERBEROASTING,
  };
}

/**
 * Score a source user involved in Kerberoasting (typically lower than target SPN account).
 * @param {string} identity
 * @param {RiskScoreResult} targetRisk
 * @returns {RiskScoreResult}
 */
function scoreSourceUserRisk(identity, targetRisk) {
  const derived = Math.max(0, targetRisk.risk - 25);
  return {
    identity,
    risk: capRisk(derived),
    severity: severityFromRisk(derived),
    reason: "Source user linked to Kerberoasting activity",
    breakdown: [
      {
        factor: "source_user_association",
        points: derived,
        description: `Derived from target risk (${targetRisk.identity}: ${targetRisk.risk})`,
      },
    ],
    evidence: targetRisk.evidence.filter((e) => e.includes("TGS") || e.includes("Kerberos")),
    mitre: MITRE.KERBEROASTING,
  };
}

/**
 * Resolve risk for any identity using alerts + attack path graph.
 * @param {string} identity
 * @param {object[]} alerts
 * @param {object} [attackPath]
 * @returns {RiskScoreResult & { source?: string, alert_id?: string }}
 */
function getIdentityRisk(identity, alerts = [], attackPath = null) {
  const id = identity.toLowerCase();
  const alertList = Array.isArray(alerts) ? alerts : [];

  const asTarget = alertList.find((a) => String(a.target).toLowerCase() === id);
  if (asTarget) {
    const indicators = alertToIndicators(asTarget);
    const scored = scoreRisk(id, indicators, { attackPath: attackPath || undefined });
    return {
      ...scored,
      risk: asTarget.risk ?? scored.risk,
      severity: asTarget.severity ?? scored.severity,
      reason: scored.reason,
      source: "alert",
      alert_id: asTarget.id,
    };
  }

  const asUser = alertList.find((a) => String(a.user).toLowerCase() === id);
  if (asUser) {
    const targetScored = scoreRisk(String(asUser.target).toLowerCase(), alertToIndicators(asUser), {
      attackPath: attackPath || undefined,
    });
    const sourceScored = scoreSourceUserRisk(id, targetScored);
    return { ...sourceScored, source: "alert", alert_id: asUser.id };
  }

  if (attackPath?.nodes) {
    const node = attackPath.nodes.find((n) => n.id.toLowerCase() === id);
    if (node) {
      const riskMap = { low: 25, medium: 45, high: 72, critical: 92 };
      const risk = riskMap[node.risk] ?? 50;
      return {
        identity: id,
        risk,
        severity: severityFromRisk(risk),
        reason: `Identity appears on attack path as ${node.type}`,
        breakdown: [{ factor: "attack_path_node", points: risk, description: `Graph node risk: ${node.risk}` }],
        evidence: [],
        mitre: MITRE.KERBEROASTING,
        source: "attack_path",
      };
    }
  }

  return {
    identity: id,
    risk: 0,
    severity: "low",
    reason: "No Kerberoasting indicators for this identity",
    breakdown: [],
    evidence: [],
    mitre: MITRE.KERBEROASTING,
    source: "none",
  };
}

/**
 * Derive indicator flags from a stored alert object.
 * @param {object} alert
 * @returns {Record<string, boolean>}
 */
function alertToIndicators(alert) {
  const evidence = Array.isArray(alert.evidence) ? alert.evidence : [];
  const text = evidence.join(" ").toLowerCase();

  return {
    kerberoasting: alert.attack === "Kerberoasting" || text.includes("kerberos"),
    rc4_encryption: text.includes("rc4"),
    multiple_tgs: text.includes("multiple") && text.includes("tgs"),
    service_account_spn: text.includes("spn"),
    privileged_link: text.includes("privileged") || text.includes("sql"),
    privileged_path: text.includes("sensitive") || text.includes("domain sensitive"),
  };
}

module.exports = {
  capRisk,
  severityFromRisk,
  analyzePrivilegedPath,
  buildEvidence,
  scoreRisk,
  scoreSourceUserRisk,
  getIdentityRisk,
  alertToIndicators,
};

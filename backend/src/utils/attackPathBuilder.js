/**
 * Build attack path graph from a live alert — no placeholder identities.
 */
function buildAttackPathFromAlert(alert) {
  if (!alert?.user || !alert?.target) {
    return { nodes: [], edges: [] };
  }

  const user = String(alert.user);
  const target = String(alert.target);
  const host = String(alert.host || "Target host");
  const targetRisk = alert.severity === "critical" || (alert.risk ?? 0) >= 80 ? "critical" : "high";

  return {
    nodes: [
      { id: user, type: "user", risk: "medium" },
      { id: target, type: "service_account", risk: targetRisk },
      { id: host, type: "host", risk: "high" },
    ],
    edges: [
      { from: user, to: target, label: "Requested TGS (4769)" },
      { from: target, to: host, label: "SPN registered on host" },
    ],
  };
}

module.exports = { buildAttackPathFromAlert };

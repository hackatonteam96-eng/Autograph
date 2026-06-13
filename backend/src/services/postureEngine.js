/**
 * Maps collector findings + events to CrowdStrike-style Inventory & Posture view.
 * Deterministic rules run first; AI adds narrative on top.
 */

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };

function normalizeSeverity(s) {
  const v = String(s || "low").toLowerCase();
  return ["high", "medium", "low"].includes(v) ? v : "low";
}

function detectKerberoastingFromEvents(events) {
  const tgs = (events || []).filter((e) => Number(e.event_id) === 4769);
  const rc4 = tgs.filter((e) => {
    const enc = e.data?.TicketEncryptionType || e.data?.ticketEncryptionType || "";
    return /^0x17$|^0x1$|^0x23$/i.test(String(enc));
  });
  const byUser = new Map();
  for (const e of rc4) {
    const user = e.data?.TargetUserName || e.data?.targetUserName || "unknown";
    byUser.set(user, (byUser.get(user) || 0) + 1);
  }
  const findings = [];
  if (rc4.length > 0) {
    findings.push({
      title: "Kerberoasting Activity Detected",
      severity: rc4.length >= 3 ? "high" : "medium",
      category: "risk",
      detail: `${rc4.length} RC4 TGS (4769) event(s) in snapshot`,
      source: "correlation",
    });
  }
  for (const [user, count] of byUser.entries()) {
    if (count >= 3) {
      findings.push({
        title: "Attack Path to a Privileged Account",
        severity: "medium",
        category: "risk",
        detail: `User ${user} requested ${count} RC4 service tickets`,
        source: "correlation",
      });
    }
  }
  return findings;
}

function mergeFindings(...lists) {
  const seen = new Set();
  const out = [];
  for (const list of lists) {
    for (const f of list || []) {
      const key = `${f.title}|${f.severity}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        title: f.title,
        severity: normalizeSeverity(f.severity),
        category: f.category || "posture",
        detail: f.detail || "",
        host: f.host || null,
        source: f.source || "collector",
      });
    }
  }
  return out.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

function buildPostureSummary(findings) {
  const counts = { high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return {
    total: findings.length,
    by_severity: counts,
    risk_score: Math.min(100, counts.high * 25 + counts.medium * 10 + counts.low * 3),
  };
}

function processSnapshots(snapshots) {
  const allEvents = snapshots.flatMap((s) => s.security_events || []);
  const collectorFindings = snapshots.flatMap((s) => s.findings || []);
  const correlated = detectKerberoastingFromEvents(allEvents);
  const findings = mergeFindings(collectorFindings, correlated);
  return {
    updated_at: new Date().toISOString(),
    hosts: snapshots.map((s) => ({ host: s.host, role: s.host_role, collected_at: s.collected_at })),
    summary: buildPostureSummary(findings),
    findings,
    event_counts: {
      security: allEvents.length,
      dns: snapshots.reduce((n, s) => n + (s.dns_events?.length || 0), 0),
      http: snapshots.reduce((n, s) => n + (s.http_events?.length || 0), 0),
    },
  };
}

module.exports = { processSnapshots, mergeFindings, buildPostureSummary };

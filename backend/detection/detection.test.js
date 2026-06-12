/**
 * AuthGraph ITDR — Detection module tests
 * Run: node backend/detection/detection.test.js
 */

const assert = require("assert");
const path = require("path");
const fs = require("fs");

const {
  parseKerberosEvent,
  matchSigmaRule,
  detectKerberoasting,
  scoreRisk,
  getIdentityRisk,
  correlateAlert,
  buildAlertFromEvents,
  explainAlert,
  analyzePrivilegedPath,
} = require("./index");

const FIXTURES = path.join(__dirname, "fixtures");
const DATA_DIR = path.resolve(__dirname, "../../data");

function loadJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed += 1;
    console.log(`  ✓ ${name}`);
  } catch (err) {
    failed += 1;
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.message}`);
  }
}

console.log("\nAuthGraph ITDR — Detection Tests\n");

test("parses Windows Event 4769 with RC4 encryption", () => {
  const raw = loadJson(path.join(FIXTURES, "event-4769-rc4.json"));
  const parsed = parseKerberosEvent(raw);
  assert.strictEqual(parsed.event_id, 4769);
  assert.strictEqual(parsed.is_rc4, true);
  assert.strictEqual(parsed.is_krbtgt, false);
  assert.ok(parsed.target.includes("sql") || parsed.target.length > 0);
});

test("Sigma rule matches RC4 TGS and excludes krbtgt", () => {
  const raw = loadJson(path.join(FIXTURES, "event-4769-rc4.json"));
  const result = matchSigmaRule(raw);
  assert.strictEqual(result.matched, true);
  assert.strictEqual(result.indicators.rc4_encryption, true);
  assert.strictEqual(result.indicators.not_krbtgt, true);

  const krbtgt = { ...raw, ServiceName: "krbtgt/CORP.LOCAL" };
  assert.strictEqual(matchSigmaRule(krbtgt).matched, false);
});

test("detects multiple TGS requests from same user", () => {
  const events = loadJson(path.join(FIXTURES, "multiple-tgs-events.json"));
  const detection = detectKerberoasting(events);
  assert.strictEqual(detection.is_kerberoasting, true);
  assert.strictEqual(detection.indicators.multiple_tgs, true);
  assert.ok(detection.multiple_tgs_count >= 3);
});

test("risk scoring produces 87 for canonical Kerberoasting scenario", () => {
  const attackPath = loadJson(path.join(DATA_DIR, "attack-path.json"));
  const indicators = {
    kerberoasting: true,
    rc4_encryption: true,
    multiple_tgs: true,
    service_account_spn: true,
  };
  const scored = scoreRisk("svc-sql", indicators, { attackPath });
  assert.strictEqual(scored.risk, 87);
  assert.strictEqual(scored.severity, "critical");
  assert.ok(scored.reason.includes("Kerberoasting"));
  assert.strictEqual(scored.breakdown.length, 5);
});

test("svc-sql uses privileged link (+2) for demo risk score of 87", () => {
  const attackPath = loadJson(path.join(DATA_DIR, "attack-path.json"));
  const pathInfo = analyzePrivilegedPath("svc-sql", attackPath);
  assert.strictEqual(pathInfo.full_path, false);
  assert.strictEqual(pathInfo.linked, true);

  const scored = scoreRisk("svc-sql", {
    kerberoasting: true,
    rc4_encryption: true,
    multiple_tgs: true,
    service_account_spn: true,
  }, { attackPath });

  assert.strictEqual(scored.risk, 87);
  const linkFactor = scored.breakdown.find((b) => b.factor === "privileged_asset_link");
  assert.ok(linkFactor);
});

test("SQL-SERVER identity gets full privileged path weight", () => {
  const attackPath = loadJson(path.join(DATA_DIR, "attack-path.json"));
  const pathInfo = analyzePrivilegedPath("SQL-SERVER", attackPath);
  assert.strictEqual(pathInfo.full_path, true);

  const scored = scoreRisk("SQL-SERVER", {
    kerberoasting: true,
    rc4_encryption: true,
    multiple_tgs: true,
    service_account_spn: true,
  }, { attackPath });

  const pathFactor = scored.breakdown.find((b) => b.factor === "privileged_path_full");
  assert.ok(pathFactor);
  assert.strictEqual(pathFactor.points, 20);
});

test("correlator builds alert from event batch", () => {
  const events = loadJson(path.join(FIXTURES, "multiple-tgs-events.json"));
  const attackPath = loadJson(path.join(DATA_DIR, "attack-path.json"));
  const alert = buildAlertFromEvents(events, { attackPath, source: "Wazuh" });
  assert.ok(alert);
  assert.strictEqual(alert.attack, "Kerberoasting");
  assert.strictEqual(alert.mitre, "T1558.003");
  assert.ok(alert.risk >= 85);
  assert.ok(Array.isArray(alert.evidence) && alert.evidence.length >= 3);
});

test("correlateAlert preserves shared JSON contract fields", () => {
  const sample = loadJson(path.join(DATA_DIR, "sample-alerts.json"))[0];
  const attackPath = loadJson(path.join(DATA_DIR, "attack-path.json"));
  const enriched = correlateAlert(sample, { attackPath });

  assert.strictEqual(enriched.id, "alert-001");
  assert.strictEqual(enriched.risk, 87);
  assert.strictEqual(enriched.severity, "critical");
  assert.strictEqual(enriched.user, "lowpriv.user");
  assert.strictEqual(enriched.target, "svc-sql");
  assert.strictEqual(enriched.event_id, 4769);
  assert.ok(enriched.evidence.length >= 4);
  assert.ok(enriched.response.length >= 4);
});

test("getIdentityRisk resolves target, source, and graph nodes", () => {
  const alerts = loadJson(path.join(DATA_DIR, "sample-alerts.json"));
  const attackPath = loadJson(path.join(DATA_DIR, "attack-path.json"));

  const target = getIdentityRisk("svc-sql", alerts, attackPath);
  assert.strictEqual(target.risk, 87);
  assert.strictEqual(target.severity, "critical");

  const source = getIdentityRisk("lowpriv.user", alerts, attackPath);
  assert.strictEqual(source.risk, 62);
  assert.ok(source.reason.includes("Source user"));

  const node = getIdentityRisk("SQL Admins", alerts, attackPath);
  assert.strictEqual(node.risk, 72);
  assert.strictEqual(node.source, "attack_path");
});

test("explainAlert returns judge-friendly breakdown", () => {
  const sample = loadJson(path.join(DATA_DIR, "sample-alerts.json"))[0];
  const explanation = explainAlert(sample);
  assert.ok(explanation.summary);
  assert.ok(explanation.sigma.length >= 2);
  assert.ok(explanation.risk_factors.length >= 4);
});

console.log(`\nResults: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);

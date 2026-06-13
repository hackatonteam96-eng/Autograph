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

const DEMO_ATTACK_PATH = {
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
  const attackPath = DEMO_ATTACK_PATH;
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
  const attackPath = DEMO_ATTACK_PATH;
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
  const attackPath = DEMO_ATTACK_PATH;
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
  const attackPath = DEMO_ATTACK_PATH;
  const alert = buildAlertFromEvents(events, { attackPath, source: "Wazuh" });
  assert.ok(alert);
  assert.strictEqual(alert.attack, "Kerberoasting");
  assert.strictEqual(alert.mitre, "T1558.003");
  assert.ok(alert.risk >= 85);
  assert.ok(Array.isArray(alert.evidence) && alert.evidence.length >= 3);
});

test("correlateAlert preserves shared JSON contract fields", () => {
  const sample = loadJson(path.join(FIXTURES, "wazuh-alert-4769-rc4.json"));
  const raw = {
    id: "alert-001",
    time: "2026-06-12T14:03:00Z",
    source: "Wazuh",
    attack: "Kerberoasting",
    user: "lab.user",
    target: "svc-test",
    host: "DC01",
    event_id: 4769,
    evidence: ["RC4 encrypted service ticket requested"],
    response: ["Reset service account password"],
  };
  const attackPath = DEMO_ATTACK_PATH;
  const enriched = correlateAlert(raw, { attackPath });

  assert.strictEqual(enriched.id, "alert-001");
  assert.ok(enriched.risk >= 50);
  assert.strictEqual(enriched.user, "lab.user");
  assert.strictEqual(enriched.target, "svc-test");
  assert.strictEqual(enriched.event_id, 4769);
  assert.ok(enriched.evidence.length >= 1);
});

test("getIdentityRisk resolves target, source, and graph nodes", () => {
  const alerts = [{
    id: "alert-t",
    attack: "Kerberoasting",
    user: "lab.user",
    target: "svc-sql",
    risk: 87,
    severity: "critical",
    event_id: 4769,
    evidence: ["RC4 encrypted service ticket requested", "Target account has SPN configured"],
  }];
  const attackPath = {
    nodes: [
      { id: "lab.user", type: "user", risk: "medium" },
      { id: "svc-sql", type: "service_account", risk: "critical" },
      { id: "SQL Admins", type: "group", risk: "high" },
    ],
    edges: [],
  };

  const target = getIdentityRisk("svc-sql", alerts, attackPath);
  assert.ok(target.risk >= 50);

  const source = getIdentityRisk("lab.user", alerts, attackPath);
  assert.ok(source.risk >= 40);
});

test("explainAlert returns judge-friendly breakdown", () => {
  const sample = {
    id: "alert-001",
    attack: "Kerberoasting",
    user: "lab.user",
    target: "svc-sql",
    risk: 87,
    severity: "critical",
    event_id: 4769,
    host: "DC01",
    source_ip: "10.0.0.1",
    evidence: ["RC4 encrypted service ticket requested", "Multiple Kerberos TGS requests from one user"],
  };
  const explanation = explainAlert(sample);
  assert.ok(explanation.summary);
  assert.ok(explanation.sigma.length >= 1);
  assert.ok(explanation.risk_factors.length >= 1);
});

test("wazuh filter accepts Yara weak encryption (etype > 0x07)", () => {
  const { classifyWazuhPayload } = require("./wazuh_filter");
  const yaraPayload = {
    rule: { description: "Kerberos weak ticket encryption", level: 10 },
    agent: { name: "DC01" },
    data: {
      win: {
        system: { eventID: "4769" },
        eventdata: {
          targetUserName: "attacker",
          serviceName: "MSSQLSvc/sql.corp:1433",
          ticketEncryptionType: "0x17",
        },
      },
    },
  };
  const result = classifyWazuhPayload(yaraPayload);
  assert.strictEqual(result.accept, true);
  assert.strictEqual(result.kind, "itdr");
});

test("wazuh filter accepts AS-REP roasting AuthGraph rule", () => {
  const { classifyWazuhPayload, isItdrAlert } = require("./wazuh_filter");
  const { buildAlertFromWazuhItem } = require("./correlator");
  const asRepPayload = {
    rule: "authgraph: as-rep roasting - single rc4 tgt without pre-authentication",
    etype: "0x17",
    agent: { name: "SERVER01" },
    user: "svc-mssql",
  };
  const classified = classifyWazuhPayload(asRepPayload);
  assert.strictEqual(classified.accept, true);
  assert.strictEqual(classified.kind, "itdr");
  const alert = buildAlertFromWazuhItem(asRepPayload, { source: "Wazuh" });
  assert.ok(alert);
  assert.strictEqual(alert.attack, "AS-REP Roasting");
  assert.strictEqual(alert.mitre, "T1558.004");
  assert.ok(isItdrAlert(alert));
});

console.log(`\nResults: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);

#!/usr/bin/env node
/**
 * AuthGraph ITDR — Detection CLI
 * Demo and debug tool for Gular's detection pipeline.
 *
 * Usage:
 *   node backend/detection/cli.js explain
 *   node backend/detection/cli.js correlate
 *   node backend/detection/cli.js events
 */

const path = require("path");
const fs = require("fs");
const {
  correlateAlert,
  correlateAlerts,
  buildAlertFromEvents,
  explainAlert,
  detectKerberoasting,
  getIdentityRisk,
} = require("./index");

const DATA_DIR = path.resolve(__dirname, "../../data");
const FIXTURES = path.join(__dirname, "fixtures");

function loadJson(relativePath) {
  const full = path.isAbsolute(relativePath) ? relativePath : path.join(process.cwd(), relativePath);
  return JSON.parse(fs.readFileSync(full, "utf8"));
}

function cmdExplain() {
  const sample = loadJson(path.join(DATA_DIR, "sample-alerts.json"))[0];
  const explanation = explainAlert(sample);
  console.log("\n=== Why did this alert fire? ===\n");
  console.log(`Summary: ${explanation.summary}\n`);
  console.log("Sigma logic:");
  explanation.sigma.forEach((s) => console.log(`  • ${s}`));
  console.log("\nRisk factors:");
  explanation.risk_factors.forEach((f) => console.log(`  • ${f.description} (+${f.points})`));
  console.log("\nEvidence:");
  explanation.evidence.forEach((e) => console.log(`  • ${e}`));
}

function cmdCorrelate() {
  const alerts = loadJson(path.join(DATA_DIR, "sample-alerts.json"));
  const attackPath = loadJson(path.join(DATA_DIR, "attack-path.json"));
  const enriched = correlateAlerts(alerts, attackPath);
  console.log(JSON.stringify(enriched, null, 2));
}

function cmdEvents() {
  const events = loadJson(path.join(FIXTURES, "multiple-tgs-events.json"));
  const attackPath = loadJson(path.join(DATA_DIR, "attack-path.json"));
  const detection = detectKerberoasting(events);
  const alert = buildAlertFromEvents(events, { attackPath });

  console.log("\n=== Kerberoasting Detection ===\n");
  console.log("Indicators:", detection.indicators);
  console.log("Multiple TGS count:", detection.multiple_tgs_count);
  console.log("\nGenerated alert:");
  console.log(JSON.stringify(alert, null, 2));

  if (alert) {
    const risk = getIdentityRisk(alert.target, [alert], attackPath);
    console.log("\nTarget identity risk:");
    console.log(JSON.stringify(risk, null, 2));
  }
}

function cmdRisk(identity) {
  const alerts = loadJson(path.join(DATA_DIR, "sample-alerts.json"));
  const attackPath = loadJson(path.join(DATA_DIR, "attack-path.json"));
  const result = getIdentityRisk(identity || "svc-sql", alerts, attackPath);
  console.log(JSON.stringify(result, null, 2));
}

const [,, command, arg] = process.argv;

switch (command) {
  case "explain":
    cmdExplain();
    break;
  case "correlate":
    cmdCorrelate();
    break;
  case "events":
    cmdEvents();
    break;
  case "risk":
    cmdRisk(arg);
    break;
  default:
    console.log(`AuthGraph ITDR Detection CLI

Commands:
  explain    Why alert-001 fired (judge walkthrough)
  correlate  Enrich sample-alerts.json with detection metadata
  events     Run detection on fixture 4769 events
  risk [id]  Score identity risk (default: svc-sql)
`);
}

/**
 * AuthGraph ITDR — API integration tests
 * Run: npm test (from backend/)
 */

const assert = require("assert");
const fs = require("fs");
const http = require("http");
const path = require("path");

const PORT = 8765;
process.env.PORT = String(PORT);
process.env.DATA_DIR = path.resolve(__dirname, "fixtures/data");

const wazuhCapture = path.join(process.env.DATA_DIR, "wazuh-alert-real.json");
if (fs.existsSync(wazuhCapture)) fs.unlinkSync(wazuhCapture);

const dataStore = require("../src/store/dataStore");
const app = require("../src/server");

let server;
let passed = 0;
let failed = 0;

function request(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: PORT,
        path,
        method,
        headers: payload
          ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) }
          : {},
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            resolve({ status: res.statusCode, body: data ? JSON.parse(data) : null });
          } catch {
            resolve({ status: res.statusCode, body: data });
          }
        });
      }
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function test(name, fn) {
  return fn()
    .then(() => {
      passed += 1;
      console.log(`  ✓ ${name}`);
    })
    .catch((err) => {
      failed += 1;
      console.error(`  ✗ ${name}`);
      console.error(`    ${err.message}`);
    });
}

async function run() {
  console.log("\nAuthGraph ITDR — API Tests\n");

  await new Promise((resolve) => {
    server = app.listen(PORT, "127.0.0.1", resolve);
  });

  dataStore.resetSimulation();

  await test("GET /api/health returns ok", async () => {
    const { status, body } = await request("GET", "/api/health");
    assert.strictEqual(status, 200);
    assert.strictEqual(body.ok, true);
    assert.strictEqual(body.detection, "ok");
  });

  await test("GET /api/alerts returns Kerberoasting alert", async () => {
    const { status, body } = await request("GET", "/api/alerts");
    assert.strictEqual(status, 200);
    assert.ok(Array.isArray(body));
    assert.strictEqual(body[0].id, "alert-001");
    assert.strictEqual(body[0].risk, 87);
    assert.strictEqual(body[0].attack, "Kerberoasting");
  });

  await test("GET /api/incidents returns incident with title", async () => {
    const { status, body } = await request("GET", "/api/incidents");
    assert.strictEqual(status, 200);
    assert.strictEqual(body[0].incident_id, "alert-001");
    assert.ok(body[0].title.includes("svc-sql"));
    assert.strictEqual(body[0].status, "open");
  });

  await test("GET /api/attack-path returns graph nodes and edges", async () => {
    const { status, body } = await request("GET", "/api/attack-path");
    assert.strictEqual(status, 200);
    assert.ok(body.nodes.length >= 3);
    assert.ok(body.edges.length >= 2);
  });

  await test("GET /api/risk/svc-sql returns critical risk 87", async () => {
    const { status, body } = await request("GET", "/api/risk/svc-sql");
    assert.strictEqual(status, 200);
    assert.strictEqual(body.risk, 87);
    assert.strictEqual(body.severity, "critical");
  });

  await test("GET /api/explain/alert-001 returns detection breakdown", async () => {
    const { status, body } = await request("GET", "/api/explain/alert-001");
    assert.strictEqual(status, 200);
    assert.ok(body.evidence.length >= 1);
    assert.ok(body.risk_factors.length >= 1);
  });

  await test("POST /api/contain/alert-001 returns containment response", async () => {
    const { status, body } = await request("POST", "/api/contain/alert-001");
    assert.strictEqual(status, 200);
    assert.strictEqual(body.ok, true);
    assert.strictEqual(body.status, "contained");
    assert.strictEqual(body.risk_before, 87);
    assert.strictEqual(body.risk_after, 32);
    assert.ok(Array.isArray(body.actions) && body.actions.length >= 4);
  });

  await test("GET /api/incidents/alert-001 shows contained status", async () => {
    const { status, body } = await request("GET", "/api/incidents/alert-001");
    assert.strictEqual(status, 200);
    assert.strictEqual(body.status, "contained");
    assert.strictEqual(body.risk, 32);
  });

  await test("dataStore reloadFromDisk works", async () => {
    const data = dataStore.reloadFromDisk();
    assert.ok(data.alerts.length >= 1);
    assert.ok(data.attack_path.nodes);
  });

  await test("GET /api/verify returns MVP checklist", async () => {
    const { status, body } = await request("GET", "/api/verify");
    assert.strictEqual(status, 200);
    assert.ok(body.checks.length >= 6);
    assert.strictEqual(body.mvp.kerberoasting_poc, true);
    assert.strictEqual(body.mvp.sigma_rule, true);
    assert.strictEqual(body.mvp.wazuh_alert, true);
    assert.strictEqual(body.mvp.attack_verification, true);
  });

  await test("GET /api/sigma/rules returns rule library", async () => {
    const { status, body } = await request("GET", "/api/sigma/rules");
    assert.strictEqual(status, 200);
    assert.ok(body.count >= 3);
    assert.ok(body.rules.some((r) => r.id === "authgraph-kerberoasting-4769"));
    assert.ok(body.rules.some((r) => r.platform === "Microsoft Entra ID"));
  });

  console.log(`\nResults: ${passed} passed, ${failed} failed\n`);

  server.close();
  process.exit(failed > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error(err);
  if (server) server.close();
  process.exit(1);
});

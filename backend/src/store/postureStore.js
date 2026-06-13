const fs = require("fs");
const path = require("path");
const { DATA_DIR } = require("../config");
const { processSnapshots } = require("../services/postureEngine");
const { enrichPosture } = require("../services/deepseek");
const dataStore = require("./dataStore");

const MOCK_DIR = path.join(DATA_DIR, "mock");
const SNAPSHOTS_DIR = path.join(DATA_DIR, "snapshots");
const POSTURE_FILE = path.join(DATA_DIR, "posture.json");

const USE_MOCK = process.env.USE_MOCK_DATA !== "false";

function readJson(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      return JSON.parse(fs.readFileSync(filePath, "utf8"));
    }
  } catch (err) {
    console.warn(`[postureStore] Failed to read ${filePath}:`, err.message);
  }
  return null;
}

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function loadMockSnapshots() {
  const files = ["dc-snapshot.json", "client-snapshot.json"];
  const out = [];
  for (const f of files) {
    const raw = readJson(path.join(MOCK_DIR, f));
    if (raw) out.push(raw);
  }
  return out;
}

class PostureStore {
  constructor() {
    /** @type {Map<string, object>} */
    this.snapshots = new Map();
    this.loadFromDisk();
  }

  loadFromDisk() {
    ensureDir(SNAPSHOTS_DIR);

    if (USE_MOCK) {
      for (const snap of loadMockSnapshots()) {
        this.snapshots.set(snap.host, snap);
      }
      if (this.snapshots.size > 0) return;
    }

    if (!fs.existsSync(SNAPSHOTS_DIR)) return;
    for (const file of fs.readdirSync(SNAPSHOTS_DIR)) {
      if (!file.endsWith(".json")) continue;
      const raw = readJson(path.join(SNAPSHOTS_DIR, file));
      if (raw?.host) this.snapshots.set(raw.host, raw);
    }
  }

  ingestSnapshot(snapshot) {
    ensureDir(SNAPSHOTS_DIR);
    const host = snapshot.host;
    this.snapshots.set(host, snapshot);
    fs.writeFileSync(
      path.join(SNAPSHOTS_DIR, `${host}.json`),
      JSON.stringify(snapshot, null, 2)
    );
    return { host, findings_count: (snapshot.findings || []).length };
  }

  async getPosture() {
    const list = [...this.snapshots.values()];
    const posture = processSnapshots(list);
    const alerts = dataStore.getAlerts();
    const ai = await enrichPosture(posture, alerts);

    const result = {
      ok: true,
      view: "inventory_and_posture",
      mode: USE_MOCK && list.some((s) => s.source === "mock") ? "mock" : "live",
      ...posture,
      ai,
    };

    try {
      fs.writeFileSync(POSTURE_FILE, JSON.stringify(result, null, 2));
    } catch { /* non-fatal */ }

    return result;
  }
}

module.exports = new PostureStore();

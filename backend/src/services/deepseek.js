/**
 * DeepSeek AI enrichment — uses mock response for hackathon demo.
 * Set DEEPSEEK_API_KEY to switch to live AI (startup improvement phase).
 */

const fs = require("fs");
const path = require("path");
const { DATA_DIR } = require("../config");

const DEEPSEEK_API_KEY = process.env.DEEPSEEK_API_KEY || "";
const DEEPSEEK_API_URL = process.env.DEEPSEEK_API_URL || "https://api.deepseek.com/chat/completions";
const DEEPSEEK_MODEL = process.env.DEEPSEEK_MODEL || "deepseek-chat";
const MOCK_AI_FILE = path.join(DATA_DIR, "mock", "ai-response.json");

function loadMockAi() {
  try {
    if (fs.existsSync(MOCK_AI_FILE)) {
      return JSON.parse(fs.readFileSync(MOCK_AI_FILE, "utf8"));
    }
  } catch { /* fall through */ }
  return null;
}

function fallbackRecommendations(posture) {
  return (posture.findings || []).slice(0, 6).map((f) => ({
    finding: f.title,
    action: defaultAction(f.title),
    priority: f.severity,
  }));
}

async function enrichPosture(posture, alerts = []) {
  const mock = loadMockAi();
  if (!DEEPSEEK_API_KEY) {
    return mock || {
      ai_enabled: false,
      source: "fallback",
      narrative: "Mock AI response not found. Using rule-based recommendations.",
      recommendations: fallbackRecommendations(posture),
    };
  }

  const prompt = `You are an AD Identity Threat Detection expert (ITDR).
Return JSON only:
{"narrative":"...","recommendations":[{"finding":"...","action":"...","priority":"high|medium|low"}]}

Posture: ${JSON.stringify(posture)}
Alerts: ${JSON.stringify(alerts.slice(0, 5))}`;

  try {
    const res = await fetch(DEEPSEEK_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${DEEPSEEK_API_KEY}`,
      },
      body: JSON.stringify({
        model: DEEPSEEK_MODEL,
        messages: [{ role: "user", content: prompt }],
        temperature: 0.2,
        response_format: { type: "json_object" },
      }),
    });

    if (!res.ok) throw new Error(`DeepSeek HTTP ${res.status}`);

    const data = await res.json();
    const parsed = JSON.parse(data.choices?.[0]?.message?.content || "{}");
    return {
      ai_enabled: true,
      source: "deepseek",
      narrative: parsed.narrative || null,
      recommendations: parsed.recommendations || fallbackRecommendations(posture),
    };
  } catch (err) {
    console.warn("[deepseek]", err.message);
    return mock || {
      ai_enabled: false,
      source: "fallback",
      narrative: null,
      recommendations: fallbackRecommendations(posture),
      error: err.message,
    };
  }
}

function defaultAction(title) {
  const map = {
    "Kerberoasting Activity Detected": "Disable source user, rotate service account passwords, disable RC4",
    "Compromised Password": "Force password reset and revoke active sessions",
    "Inadequate Password Policy": "Increase min length to 14+ and enable complexity",
    "SMB Signing Disabled": "Enable SMB signing via GPO",
    "LDAP Signing is not Required": "Set LDAPServerIntegrity=2 on DCs",
    "LDAPS Channel Binding is not Required": "Set LdapEnforceChannelBinding=2 on DCs",
    "Print Spooler Service Running": "Disable Print Spooler on domain controllers",
    "Attack Path to a Privileged Account": "Review ACLs and remove privileged paths",
    "KRBTGT password not changed for 180 days": "Rotate krbtgt per Microsoft guidance",
    "Privileged Endpoint Account": "Remove admin sessions from workstations",
  };
  return map[title] || "Investigate and remediate per policy";
}

module.exports = { enrichPosture, defaultAction };

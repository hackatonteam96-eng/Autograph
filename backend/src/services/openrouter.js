const {
  OPENROUTER_API_KEY,
  OPENROUTER_CHAT_MODEL,
  OPENROUTER_REASONING_MODEL,
} = require("../config");

const cache = new Map();

const GREETING_RE = /^(hi|hello|hey|yo|what'?s up|howdy|sup|hii|heyy|greetings|morning|evening|afternoon|how is it going|how'?s it going|how are you|how goes it|hows it going)\b/i;

const REASONING_RE = /\b(explain|why is|why are|contain|blast radius|attack path|walk me through|step.?by.?step|what should i|priorit|audit|analyze|investigate|recommend|remediation|mitigat|reasoning|break down|assess)\b/i;

function isGreeting(message) {
  const text = message.trim();
  if (GREETING_RE.test(text)) return true;
  return text.length <= 22 && /^(how|hey|hi|yo|sup|what)/i.test(text);
}

function needsReasoning(message) {
  return REASONING_RE.test(message.trim());
}

function pickChatModel(message) {
  return needsReasoning(message) ? OPENROUTER_REASONING_MODEL : OPENROUTER_CHAT_MODEL;
}

async function callOpenRouter({ model, messages, temperature, maxTokens }) {
  const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${OPENROUTER_API_KEY}`,
      "Content-Type": "application/json",
      "HTTP-Referer": "http://localhost:5173",
      "X-Title": "AuthGraph ITDR",
    },
    body: JSON.stringify({
      model,
      temperature,
      max_tokens: maxTokens,
      messages,
    }),
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`OpenRouter ${response.status}: ${errText.slice(0, 200)}`);
  }

  const payload = await response.json();
  return {
    text: payload.choices?.[0]?.message?.content?.trim() || "",
    model: payload.model || model,
  };
}

function buildIncidentBlock(alert, extras = {}) {
  const { attackPath, contained, viewContext } = extras;

  const detection = alert.detection || {};
  const riskBreakdown = Array.isArray(detection.risk_breakdown)
    ? detection.risk_breakdown.map((f) => `${f.factor} (+${f.points}): ${f.description}`).join("; ")
    : "";

  const pathLine = attackPath?.edges?.length
    ? attackPath.edges.map((e) => `${e.from} —[${e.label}]→ ${e.to}`).join("  |  ")
    : "";

  const lines = [
    "<INCIDENT_CONTEXT>",
    `Attack: ${alert.attack} (${alert.mitre})`,
    `Source user: ${alert.user}`,
    `Target identity: ${alert.target}`,
    `Host: ${alert.host}`,
    `Source IP: ${alert.source_ip || "n/a"}`,
    `Event ID: ${alert.event_id}`,
    `Risk score: ${alert.risk}/100 (${alert.severity || "n/a"})`,
    `Status: ${contained ? "CONTAINED" : alert.status || "open"}`,
    `Sigma matched: ${detection.sigma_matched ? "yes" : "no"}`,
    `Evidence: ${(alert.evidence || []).join("; ")}`,
    riskBreakdown ? `Risk factors: ${riskBreakdown}` : "",
    pathLine ? `Attack path: ${pathLine}` : "",
    alert.response?.length ? `Recommended playbook: ${alert.response.join("; ")}` : "",
    viewContext ? `Analyst is viewing: ${viewContext}` : "",
    "</INCIDENT_CONTEXT>",
  ].filter(Boolean);

  return lines.join("\n");
}

const ARIA_SYSTEM = `<role>
You are ARIA — AuthGraph's AI threat analyst for an ITDR SOC console. You're a seasoned identity security lead: direct, sharp, occasionally dry-witted. Never robotic.
</role>

<personality>
- Warm but professional — like a senior analyst on Slack, not a press release
- Short punchy sentences when urgency matters; relaxed tone for casual chat
- Never say "As an AI" or "I understand your concern"
</personality>

<brevity>
- GREETINGS / small talk ("hi", "how is it going"): max 2 sentences. Be human. Do NOT dump incident details unless asked.
- CASUAL follow-ups: answer the actual question first. Don't repeat the same Kerberoasting summary twice in one thread.
- TECHNICAL questions: 3-5 sentences max. Reference incident context only when relevant.
</brevity>

<conversation_rules>
- Read the full conversation history before replying
- NEVER re-introduce yourself after the first message
- NEVER repeat identical containment advice if you already said it in this thread
- If the user asks how you're doing, respond naturally — you can mention you're monitoring the incident in one short clause, not a full briefing
</conversation_rules>

<safety>
- No working exploit code. Conceptual attack mechanics only.
- Containment advice is fine: disable user, rotate passwords, audit SPNs.
</safety>`;

function buildPrompt(alert) {
  return `You are AuthGraph ITDR containment engine. An alert fired:
- Attack: ${alert.attack}
- MITRE: ${alert.mitre}
- User: ${alert.user}
- Target identity: ${alert.target}
- Host: ${alert.host}
- Event ID: ${alert.event_id}
- Risk score: ${alert.risk}/100
- Evidence: ${(alert.evidence || []).join("; ")}

Respond with exactly 4 priority-ordered containment actions as a JSON array of strings. No markdown, no preamble — only valid JSON like ["action 1","action 2","action 3","action 4"].`;
}

async function analyzeIncident(alert) {
  const cacheKey = `${alert.id}:${alert.risk}:${alert.status || "open"}`;
  if (cache.has(cacheKey)) return cache.get(cacheKey);

  const fallback = alert.response || [
    "Reset service account password",
    "Disable RC4 Kerberos encryption",
    "Review SPN ownership",
    "Investigate source user session",
  ];

  if (!OPENROUTER_API_KEY) {
    return { actions: fallback, source: "fallback", model: null };
  }

  try {
    const { text, model } = await callOpenRouter({
      model: OPENROUTER_REASONING_MODEL,
      temperature: 0.2,
      maxTokens: 400,
      messages: [
        { role: "system", content: "You output only valid JSON arrays of strings." },
        { role: "user", content: buildPrompt(alert) },
      ],
    });

    const match = text.match(/\[[\s\S]*\]/);
    const actions = match ? JSON.parse(match[0]) : fallback;
    const result = {
      actions: Array.isArray(actions) ? actions.slice(0, 5) : fallback,
      source: "openrouter",
      model,
      summary: `AI-analyzed ${alert.attack} against ${alert.target} with risk ${alert.risk}.`,
    };
    cache.set(cacheKey, result);
    return result;
  } catch (err) {
    console.warn("[openrouter]", err.message);
    const result = { actions: fallback, source: "fallback", model: OPENROUTER_REASONING_MODEL, error: err.message };
    cache.set(cacheKey, result);
    return result;
  }
}

async function chatWithAnalyst(alert, userMessage, conversationHistory = [], extras = {}) {
  const greeting = isGreeting(userMessage);
  const model = greeting ? OPENROUTER_CHAT_MODEL : pickChatModel(userMessage);

  const fallback = greeting
    ? "Doing alright — eyes on the board. What do you need?"
    : `On the Kerberoast: ${alert.user} → ${alert.target}, risk ${alert.risk}. Ask me anything specific.`;

  if (!OPENROUTER_API_KEY) return { reply: fallback, model: null };

  const messages = [{ role: "system", content: ARIA_SYSTEM }];

  const history = Array.isArray(conversationHistory)
    ? conversationHistory.slice(-20).filter((m) => m?.role && m?.content)
    : [];

  if (history.length > 0) {
    messages.push({
      role: "system",
      content: `[CONTEXT: Message #${history.length + 1} in this thread. Do NOT re-introduce yourself or repeat prior advice verbatim.]`,
    });
    for (const msg of history) {
      messages.push({ role: msg.role, content: msg.content });
    }
  }

  const incidentBlock = greeting
    ? `<BACKGROUND_ONLY_DO_NOT_RECITE_UNLESS_ASKED>\n${buildIncidentBlock(alert, extras)}\n</BACKGROUND_ONLY_DO_NOT_RECITE_UNLESS_ASKED>`
    : buildIncidentBlock(alert, extras);

  messages.push({
    role: "user",
    content: `${incidentBlock}\n\nAnalyst message: ${userMessage}`,
  });

  try {
    const { text, model: usedModel } = await callOpenRouter({
      model,
      temperature: greeting ? 0.5 : 0.35,
      maxTokens: greeting ? 120 : 400,
      messages,
    });
    return { reply: text || fallback, model: usedModel };
  } catch (err) {
    console.warn("[openrouter chat]", err.message);
    return { reply: fallback, model, error: err.message };
  }
}

module.exports = { analyzeIncident, chatWithAnalyst };

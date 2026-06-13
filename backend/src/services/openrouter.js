const {
  OPENROUTER_API_KEY,
  OPENROUTER_CHAT_MODEL,
  OPENROUTER_REASONING_MODEL,
  ITDR_DASHBOARD_URL,
} = require("../config");

const { formatAiReply } = require("./formatAiReply");
const {
  buildAriaSystemPrompt,
  buildIncidentBlock,
  buildVerdictPrompt,
  buildContainmentPrompt,
  pickGreetingReply,
  isOffTopic,
  VERDICT_SYSTEM,
  CONTAINMENT_SYSTEM,
  parseJsonPayload,
} = require("./aria-skills");

/** @type {Map<string, object>} */
const cache = new Map();

const MODEL_FLASH = "deepseek/deepseek-v4-flash";
const MODEL_PRO = "deepseek/deepseek-v4-pro";

const GREETING_RE = /^(hi|hello|hey|yo|what'?s up|howdy|sup|hii|heyy|greetings|good morning|good afternoon|good evening|morning|evening|afternoon|how is it going|how'?s it going|how are you|how goes it|hows it going|thanks|thank you|ok|okay|cool|cheers)\b[!.,?\s]*$/i;

const REASONING_RE = /\b(explain|why is|why are|why did|contain|blast radius|attack path|walk me through|step.?by.?step|what should i|priorit|audit|analyze|analyse|investigate|recommend|remediation|mitigat|reasoning|break down|assess|compare|difference|false positive|triage|executive|brief|summarize|summarise|how does|what happens|what if|who|impact|escalat|lateral|privilege|bloodhound|kerberos|4769|spn|rc4|crack|ticket|mitre|technique|playbook|first move|next step|urgent|critical)\b/i;

const PLAYBOOK_RE = /\b(powershell|```|copy-paste|copy paste|rewrite|Set-AD|Get-AD|complete rewrite|code block|lab ad|preauth|pre-auth)\b/i;

function isGreeting(message) {
  const text = message.trim();
  if (GREETING_RE.test(text)) return true;
  if (text.length <= 28 && /^(how|hey|hi|yo|sup|hello|thanks|thank)/i.test(text)) return true;
  return false;
}

function needsReasoning(message) {
  return REASONING_RE.test(message.trim()) || PLAYBOOK_RE.test(message.trim());
}

function isPlaybookRequest(message) {
  return PLAYBOOK_RE.test(message.trim());
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
      "HTTP-Referer": ITDR_DASHBOARD_URL,
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

function defaultActions(alert) {
  const user = alert?.user || "the source account";
  const target = alert?.target || "the exposed service account";
  const event = alert?.event_id || 4769;
  return [
    `Disable source account ${user} pending investigation`,
    `Force password rotation on ${target} (exposed SPN)`,
    "Disable RC4 Kerberos encryption via domain policy",
    `Open SOC ticket with Event ${event} evidence bundle and attack path`,
  ];
}

function fallbackVerdict(alert) {
  const attack = alert?.attack || "Identity threat";
  const isAsRep = attack.includes("AS-REP") || alert?.mitre === "T1558.004";
  return {
    headline: `${attack}: ${alert.user} → ${alert.target}`,
    verdict: isAsRep
      ? `${attack} detected: account ${alert.target} on ${alert.host} requested a Kerberos TGT without pre-authentication${alert.evidence?.some((e) => /rc4/i.test(e)) ? " using RC4 encryption" : ""}. Offline cracking is possible. Disable "Do not require Kerberos preauth" on the account, reset its password, and review accounts with pre-auth disabled.`
      : `${attack} detected: ${alert.user} requested a crackable Kerberos ticket for ${alert.target} on ${alert.host}. Risk ${alert.risk}/100. Rotate exposed credentials and review SPN exposure immediately.`,
    confidence: alert.risk >= 80 ? "high" : alert.risk >= 55 ? "medium" : "low",
    urgency: alert.risk >= 70 ? "immediate" : alert.risk >= 50 ? "elevated" : "monitor",
    technique: alert.mitre || (isAsRep ? "T1558.004" : "T1558.003"),
  };
}

function fallbackActionDetails(alert) {
  const isAsRep = alert?.attack?.includes("AS-REP") || alert?.mitre === "T1558.004";
  const base = alert.response?.length
    ? alert.response
    : isAsRep
      ? [
          "Disable pre-authentication not required on target account",
          "Reset compromised account password",
          "Review accounts with Do not require Kerberos preauth",
          "Disable RC4 Kerberos encryption",
        ]
      : defaultActions(alert);
  const label = isAsRep ? "AS-REP roasting containment" : `${alert?.attack || "ITDR"} containment`;
  return base.slice(0, 4).map((action, i) => ({
    priority: i + 1,
    action: typeof action === "string" ? action : action.action,
    rationale: `${label} — priority ${i + 1}`,
    owner: i === 0 ? "IAM" : i === 1 ? "AD Ops" : i === 2 ? "AD Ops" : "SOC",
  }));
}

async function summarizeIncident(alert, extras = {}) {
  const fallback = fallbackVerdict(alert);

  if (!OPENROUTER_API_KEY) {
    return { ...fallback, model: null, source: "fallback" };
  }

  try {
    const { text, model } = await callOpenRouter({
      model: OPENROUTER_CHAT_MODEL,
      temperature: 0.2,
      maxTokens: 320,
      messages: [
        { role: "system", content: VERDICT_SYSTEM },
        { role: "user", content: buildVerdictPrompt(alert, extras) },
      ],
    });

    const parsed = parseJsonPayload(text);
    if (parsed && (parsed.verdict || parsed.headline)) {
      return {
        headline: parsed.headline || fallback.headline,
        verdict: typeof parsed.verdict === "string" ? parsed.verdict : fallback.verdict,
        confidence: parsed.confidence || fallback.confidence,
        urgency: parsed.urgency || fallback.urgency,
        technique: parsed.technique || fallback.technique,
        model,
        source: "openrouter",
      };
    }

    if (text && !text.trim().startsWith("{")) {
      return { ...fallback, verdict: text, model, source: "openrouter" };
    }
  } catch (err) {
    console.warn("[openrouter summarize]", err.message);
    return { ...fallback, model: OPENROUTER_CHAT_MODEL, source: "fallback", error: err.message };
  }
}

async function analyzeIncident(alert, extras = {}) {
  const cacheKey = `${alert.id}:${alert.risk}:${alert.status || "open"}`;
  if (cache.has(cacheKey)) return cache.get(cacheKey);

  const fallbackDetails = fallbackActionDetails(alert);
  const fallback = {
    actions: fallbackDetails.map((d) => d.action),
    action_details: fallbackDetails,
  };

  if (!OPENROUTER_API_KEY) {
    return { ...fallback, source: "fallback", model: null };
  }

  try {
    const { text, model } = await callOpenRouter({
      model: OPENROUTER_REASONING_MODEL,
      temperature: 0.15,
      maxTokens: 700,
      messages: [
        { role: "system", content: CONTAINMENT_SYSTEM },
        { role: "user", content: buildContainmentPrompt(alert, extras) },
      ],
    });

    const parsed = parseJsonPayload(text);
    const details = Array.isArray(parsed?.actions)
      ? parsed.actions.slice(0, 5).map((a, i) => ({
          priority: a.priority ?? i + 1,
          action: a.action || fallbackDetails[i]?.action,
          rationale: a.rationale || "",
          owner: a.owner || "SOC",
        }))
      : fallbackDetails;

    const result = {
      actions: details.map((d) => d.action).filter(Boolean),
      action_details: details,
      source: "openrouter",
      model,
    };
    cache.set(cacheKey, result);
    return result;
  } catch (err) {
    console.warn("[openrouter analyze]", err.message);
    const result = { ...fallback, source: "fallback", model: OPENROUTER_REASONING_MODEL, error: err.message };
    cache.set(cacheKey, result);
    return result;
  }
}

/**
 * Full ingest enrichment: v4-flash verdict + v4-pro containment (parallel).
 */
async function enrichIncidentOnIngest(alert, extras = {}) {
  const [summary, analysis] = await Promise.all([
    summarizeIncident(alert, extras),
    analyzeIncident(alert, extras),
  ]);

  return {
    status: "ready",
    headline: summary.headline,
    verdict: summary.verdict,
    confidence: summary.confidence,
    urgency: summary.urgency,
    technique: summary.technique,
    actions: analysis.actions,
    action_details: analysis.action_details,
    summary_model: summary.model || OPENROUTER_CHAT_MODEL,
    actions_model: analysis.model || OPENROUTER_REASONING_MODEL,
    enriched_at: new Date().toISOString(),
    source: summary.source === "openrouter" || analysis.source === "openrouter" ? "openrouter" : "fallback",
  };
}

async function chatWithAnalyst(alert, userMessage, conversationHistory = [], extras = {}) {
  const greeting = isGreeting(userMessage);
  const offtopic = !greeting && isOffTopic(userMessage);
  const playbook = !greeting && isPlaybookRequest(userMessage);
  const reasoning = !greeting && (playbook || needsReasoning(userMessage));
  const mode = greeting ? "greeting" : offtopic ? "offtopic" : playbook ? "playbook" : "incident";

  if (greeting && !OPENROUTER_API_KEY) {
    return { reply: pickGreetingReply(), model: null };
  }

  if (greeting) {
    try {
      const { text, model: usedModel } = await callOpenRouter({
        model: OPENROUTER_CHAT_MODEL,
        temperature: 0.65,
        maxTokens: 80,
        messages: [
          { role: "system", content: buildAriaSystemPrompt("greeting") },
          {
            role: "user",
            content: `<mode_greeting>\nAnalyst message: ${userMessage.trim()}\n</mode_greeting>`,
          },
        ],
      });
      const reply = text?.trim();
      if (reply && !/\b(kerberoast|risk \d|4769|mitre|incident|alert)\b/i.test(reply)) {
        return { reply: formatAiReply(reply), model: usedModel };
      }
      return { reply: pickGreetingReply(), model: usedModel };
    } catch (err) {
      console.warn("[openrouter chat greeting]", err.message);
      return { reply: pickGreetingReply(), model: OPENROUTER_CHAT_MODEL };
    }
  }

  const model = playbook ? OPENROUTER_REASONING_MODEL : pickChatModel(userMessage);

  const attack = alert?.attack || "Identity threat";
  const fallback = playbook
    ? `I can draft lab PowerShell for ${attack} on ${alert.host} targeting ${alert.target}. Confirm the DC hostname (${alert.host}) and I will output audit, contain, remediate, and verify blocks with -Server on each Get/Set-AD command.`
    : reasoning
      ? `${attack} in flight: ${alert.user} → ${alert.target}, risk ${alert.risk}/100. Ask me about path, blast radius, or what to contain first.`
      : "What would you like to look at — path, containment, or executive brief?";

  if (!OPENROUTER_API_KEY) return { reply: fallback, model: null };

  const messages = [{ role: "system", content: buildAriaSystemPrompt(mode) }];

  const history = Array.isArray(conversationHistory)
    ? conversationHistory.slice(-20).filter((m) => m?.role && m?.content)
    : [];

  if (history.length > 0) {
    messages.push({
      role: "system",
      content: `[THREAD: Message #${history.length + 1}. Build on prior answers — never repeat verbatim.]`,
    });
    for (const msg of history) {
      messages.push({ role: msg.role, content: msg.content });
    }
  }

  const incidentBlock = buildIncidentBlock(alert, extras);

  messages.push({
    role: "user",
    content: `<mode_incident>\n${incidentBlock}\n\nAnalyst message: ${userMessage.trim()}\n</mode_incident>`,
  });

  const maxTokens = playbook ? 1800 : reasoning ? 700 : 320;

  try {
    const { text, model: usedModel } = await callOpenRouter({
      model,
      temperature: reasoning ? 0.25 : 0.4,
      maxTokens,
      messages,
    });
    return { reply: formatAiReply(text || fallback), model: usedModel };
  } catch (err) {
    console.warn("[openrouter chat]", err.message);
    return { reply: formatAiReply(fallback), model, error: err.message };
  }
}

module.exports = {
  MODEL_FLASH,
  MODEL_PRO,
  OPENROUTER_CHAT_MODEL,
  OPENROUTER_REASONING_MODEL,
  summarizeIncident,
  analyzeIncident,
  enrichIncidentOnIngest,
  chatWithAnalyst,
  buildIncidentBlock,
};

/** Normalize ARIA fields — backend may store raw JSON in ai_verdict on parse failures. */
export function parseStoredAiFields(raw: {
  ai_verdict?: string | null
  ai_headline?: string | null
  ai_confidence?: string | null
  ai_urgency?: string | null
}) {
  let headline = raw.ai_headline?.trim() || null
  let verdict = raw.ai_verdict?.trim() || null
  let confidence = raw.ai_confidence?.trim() || null
  let urgency = raw.ai_urgency?.trim() || null

  if (verdict?.startsWith('{')) {
    try {
      const repaired = verdict.replace(/,\s*([}\]])/g, '$1')
      const parsed = JSON.parse(repaired) as Record<string, string>
      if (parsed.headline && !headline) headline = String(parsed.headline)
      if (parsed.verdict) verdict = String(parsed.verdict)
      if (parsed.confidence && !confidence) confidence = String(parsed.confidence)
      if (parsed.urgency && !urgency) urgency = String(parsed.urgency)
    } catch {
      const m = verdict.match(/"verdict"\s*:\s*"((?:[^"\\]|\\.)*)"/)
      if (m) verdict = m[1].replace(/\\"/g, '"').replace(/\\n/g, '\n')
    }
  }

  if (headline?.startsWith('{')) headline = null

  return { headline, verdict, confidence, urgency }
}

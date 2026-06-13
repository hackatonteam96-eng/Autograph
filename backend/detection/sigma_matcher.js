/**
 * Programmatic implementation of sigma/kerberoasting.yml logic.
 * Evaluates individual and batched 4769 events for Kerberoasting indicators.
 */

const {
  KERBEROS_EVENT_ID,
  MULTIPLE_TGS_THRESHOLD,
} = require("./constants");
const { parseKerberosEvent, isKrbtgtService, isRc4Encryption, isWeakKerberosEncryption } = require("./event_parser");

/**
 * @typedef {Object} SigmaMatchResult
 * @property {boolean} matched
 * @property {string[]} reasons
 * @property {Record<string, boolean>} indicators
 */

function matchSigmaRule(rawEvent) {
  const parsed = parseKerberosEvent(rawEvent);
  const reasons = [];
  const indicators = {
    event_4769: false,
    service_ticket_requested: false,
    rc4_encryption: false,
    not_krbtgt: false,
    has_spn: false,
  };

  if (!parsed || parsed.event_id !== KERBEROS_EVENT_ID) {
    return { matched: false, reasons: ["Not a Kerberos TGS event (4769)"], indicators };
  }

  indicators.event_4769 = true;
  indicators.service_ticket_requested = true;
  reasons.push("Windows Event ID 4769 — Kerberos service ticket requested");

  if (parsed.is_krbtgt || isKrbtgtService(parsed.service_name)) {
    return {
      matched: false,
      reasons: [...reasons, "Filtered: krbtgt service (expected TGS, not TGT)"],
      indicators,
    };
  }

  indicators.not_krbtgt = true;

  if (!parsed.is_rc4 && !isRc4Encryption(parsed.encryption_type) && !parsed.is_weak_encryption && !isWeakKerberosEncryption(parsed.encryption_type)) {
    return {
      matched: false,
      reasons: [...reasons, "Strong Kerberos encryption — lower Kerberoasting confidence"],
      indicators,
    };
  }

  indicators.rc4_encryption = parsed.is_rc4 || isRc4Encryption(parsed.encryption_type);
  const weakLabel = indicators.rc4_encryption
    ? "RC4 encrypted service ticket requested (crackable offline)"
    : "Weak ticket encryption type (Yara: etype > 0x07)";
  reasons.push(weakLabel);

  if (parsed.has_spn) {
    indicators.has_spn = true;
    reasons.push(`Service principal targeted: ${parsed.service_name}`);
  }

  return {
    matched: true,
    reasons,
    indicators,
  };
}

/**
 * Detect multiple TGS requests from the same user within a time window.
 * @param {import('./event_parser').ParsedKerberosEvent[]} events
 * @param {string} [user]
 * @returns {{ detected: boolean, count: number, user: string }}
 */
function detectMultipleTgs(events, user) {
  const parsed = events.filter((e) => e.event_id === KERBEROS_EVENT_ID && !e.is_krbtgt);
  const byUser = new Map();

  for (const evt of parsed) {
    const u = evt.user || "unknown";
    byUser.set(u, (byUser.get(u) || 0) + 1);
  }

  if (user) {
    const count = byUser.get(user.toLowerCase()) || 0;
    return {
      detected: count >= MULTIPLE_TGS_THRESHOLD,
      count,
      user: user.toLowerCase(),
    };
  }

  let maxUser = "";
  let maxCount = 0;
  for (const [u, count] of byUser.entries()) {
    if (count > maxCount) {
      maxCount = count;
      maxUser = u;
    }
  }

  return {
    detected: maxCount >= MULTIPLE_TGS_THRESHOLD,
    count: maxCount,
    user: maxUser,
  };
}

/**
 * Full Kerberoasting detection across one or more events.
 * @param {unknown[]} rawEvents
 * @returns {{ is_kerberoasting: boolean, indicators: Record<string, boolean>, events: import('./event_parser').ParsedKerberosEvent[], primary: import('./event_parser').ParsedKerberosEvent|null }}
 */
function detectKerberoasting(rawEvents) {
  const events = Array.isArray(rawEvents)
    ? rawEvents.map((e) => parseKerberosEvent(e)).filter(Boolean)
    : [];

  const matchedEvents = events.filter((evt) => matchSigmaRule(evt).matched);
  const primary = matchedEvents[0] || events.find((e) => e.event_id === KERBEROS_EVENT_ID) || null;

  const multi = primary ? detectMultipleTgs(events, primary.user) : detectMultipleTgs(events);

  const indicators = {
    kerberoasting: matchedEvents.length > 0,
    rc4_encryption: matchedEvents.some((e) => e.is_rc4),
    multiple_tgs: multi.detected,
    service_account_spn: matchedEvents.some((e) => e.has_spn),
    event_4769: events.some((e) => e.event_id === KERBEROS_EVENT_ID),
  };

  return {
    is_kerberoasting: indicators.kerberoasting,
    indicators,
    events,
    primary,
    multiple_tgs_count: multi.count,
    source_user: multi.user || primary?.user || "",
  };
}

module.exports = {
  matchSigmaRule,
  detectMultipleTgs,
  detectKerberoasting,
};

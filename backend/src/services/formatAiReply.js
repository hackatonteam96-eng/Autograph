/**
 * Normalize AI reply text — clean stray markdown while preserving code blocks.
 */
function formatAiReply(text) {
  if (!text || typeof text !== "string") return "";

  let out = text.replace(/\r\n/g, "\n").trim();

  // Strip wrapping markdown fences around entire message
  out = out.replace(/^```(?:markdown|md|text)?\s*\n?([\s\S]*?)\n?```$/i, "$1").trim();

  // Normalize smart quotes
  out = out.replace(/[\u2018\u2019]/g, "'").replace(/[\u201C\u201D]/g, '"');

  return out;
}

module.exports = { formatAiReply };

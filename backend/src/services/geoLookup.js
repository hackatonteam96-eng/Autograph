/** @type {Map<string, { lat: number, lon: number, city: string, country: string, ts: number }>} */
const cache = new Map();
const TTL_MS = 60 * 60 * 1000;

function isPrivateIp(ip) {
  if (!ip || ip === "n/a") return true;
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return true;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  return false;
}

/**
 * Resolve city/region from public IP via ip-api.com (server-side, no API key).
 * Private/lab IPs return null — caller should use lab default coords.
 */
async function lookupIpGeo(ip) {
  const clean = String(ip || "").trim();
  if (isPrivateIp(clean)) return null;

  const cached = cache.get(clean);
  if (cached && Date.now() - cached.ts < TTL_MS) return cached;

  try {
    const response = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(clean)}?fields=status,message,country,regionName,city,lat,lon,query`,
      { signal: AbortSignal.timeout(4000) },
    );
    const data = await response.json();
    if (data.status !== "success") return null;

    const result = {
      ip: data.query || clean,
      lat: data.lat,
      lon: data.lon,
      city: data.city || data.regionName || "Unknown",
      region: data.regionName || "",
      country: data.country || "",
      label: [data.city, data.country].filter(Boolean).join(", ") || clean,
      ts: Date.now(),
    };
    cache.set(clean, result);
    return result;
  } catch (err) {
    console.warn("[geoLookup]", clean, err.message);
    return null;
  }
}

module.exports = { lookupIpGeo, isPrivateIp };

# AuthGraph ITDR — Detection Module (Gular)

Kerberoasting detection, Sigma rule logic, explainable risk scoring, and alert correlation for Active Directory identity threats.

## Structure

```
backend/detection/
  index.js           Public API — import this from the API layer
  constants.js       MITRE IDs, scoring weights, RC4 encryption types
  event_parser.js    Parse Windows 4769 / Wazuh JSON
  sigma_matcher.js   Programmatic sigma/kerberoasting.yml logic
  risk_engine.js     Explainable identity risk scoring (cap 100)
  correlator.js      Build and enrich AuthGraph alerts
  cli.js             Demo / debug CLI
  detection.test.js  Test suite
  fixtures/          Sample 4769 events

sigma/
  kerberoasting.yml  Wazuh/Sigma-compatible detection rule

data/
  sample-alerts.json Shared alert contract
  attack-path.json   BloodHound-style graph for path scoring
```

## Risk Scoring

| Factor | Points |
|--------|--------|
| Kerberoasting alert | +35 |
| RC4 encryption | +20 |
| Multiple TGS requests | +15 |
| Service account SPN | +15 |
| Privileged asset link | +2 |
| Full privileged path to critical asset | +20 |

**Demo scenario (`svc-sql`):** 35 + 20 + 15 + 15 + 2 = **87** (critical)

Full path to domain sensitive assets would score higher (capped at 100).

## Quick Start

```bash
# Run tests
node backend/detection/detection.test.js

# Judge walkthrough — why did the alert fire?
node backend/detection/cli.js explain

# Build alert from fixture events
node backend/detection/cli.js events

# Score an identity
node backend/detection/cli.js risk svc-sql
```

## Integration (for Nazrin — dataStore)

```javascript
const {
  correlateAlerts,
  getIdentityRisk,
  processWazuhPayload,
} = require("../detection");

// When loading alerts:
const raw = loadJson("data/sample-alerts.json");
const attackPath = loadJson("data/attack-path.json");
const alerts = correlateAlerts(raw, attackPath);

// Risk endpoint:
getIdentityRisk(identity, alerts, attackPath);

// Real Wazuh drop from Kanan:
processWazuhPayload(wazuhJson, attackPath);
```

## Sigma Rule

`sigma/kerberoasting.yml` detects:

- Windows Security **Event ID 4769**
- Service ticket requested
- **RC4** TicketEncryptionType (`0x17`, `0x1`, `0x23`)
- Service name **not** krbtgt

Correlator adds **multiple TGS from same user** (threshold: 3) for higher fidelity.

## Output Contract

Risk endpoint shape:

```json
{
  "identity": "svc-sql",
  "risk": 87,
  "severity": "critical",
  "reason": "Kerberoasting indicators detected against privileged service account"
}
```

Alert enrichment adds optional `detection` block (safe for frontend to ignore):

```json
{
  "detection": {
    "sigma_matched": true,
    "indicators": { "kerberoasting": true, "rc4_encryption": true },
    "risk_breakdown": [{ "factor": "kerberoasting", "points": 35, "description": "..." }]
  }
}
```

## Branch

```bash
git checkout detection-gular   # or: sigma
git pull origin detection-gular
git push origin detection-gular
```

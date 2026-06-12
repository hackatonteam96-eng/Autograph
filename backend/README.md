# AuthGraph ITDR — Backend API (Nazrin)

Production-ready Express API serving alerts, attack-path graph, identity risk scores, and containment actions to the frontend. Wired to **Gular's detection engine** for explainable Kerberoasting scoring.

## Quick start

```bash
cd backend
npm install
npm run dev
```

Server: **http://localhost:8000**

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | API index + endpoint list |
| GET | `/api/health` | Health + detection module status |
| GET | `/api/alerts` | All alerts (shared JSON contract) |
| GET | `/api/alerts/:id` | Single alert |
| GET | `/api/incidents` | Alerts as incidents + status |
| GET | `/api/incidents/:id` | Single incident |
| GET | `/api/attack-path` | BloodHound-style graph JSON |
| GET | `/api/risk/:identity` | Risk score for identity |
| GET | `/api/explain/:incidentId` | Why alert fired (demo/judges) |
| POST | `/api/contain/:incidentId` | Contain incident |
| POST | `/api/reload` | Reload data from disk |

## Data files (shared `data/`)

| File | Owner | Purpose |
|------|-------|---------|
| `data/sample-alerts.json` | Gular | Demo alert contract |
| `data/attack-path.json` | Gular | Attack path graph |
| `data/wazuh-alert-real.json` | Kanan | Real Wazuh export (optional override) |

Built-in defaults apply if files are missing — frontend always works.

## Environment

Copy `.env.example` to `.env`:

```bash
PORT=8000
DATA_DIR=../data
CORS_ORIGIN=*
```

## Demo flow (Hour 12 target)

```bash
# 1. Health check
curl http://localhost:8000/api/health

# 2. Load alert
curl http://localhost:8000/api/alerts

# 3. Risk score for service account
curl http://localhost:8000/api/risk/svc-sql

# 4. Attack path graph
curl http://localhost:8000/api/attack-path

# 5. Why did it fire?
curl http://localhost:8000/api/explain/alert-001

# 6. Contain
curl -X POST http://localhost:8000/api/contain/alert-001
```

## Contain response

```json
{
  "ok": true,
  "incident_id": "alert-001",
  "status": "contained",
  "actions": [
    "Source user disabled",
    "Service account marked for password rotation",
    "RC4 disabled recommendation generated",
    "SOC ticket created"
  ],
  "risk_before": 87,
  "risk_after": 32
}
```

## Tests

```bash
npm test              # API integration tests
npm run test:detection # Gular's detection unit tests
```

## Architecture

```
backend/
  src/
    server.js          Express app
    config.js          Port, DATA_DIR, CORS
    store/dataStore.js Data layer + Gular integration
    routes/            REST endpoints
    middleware/        Logging, error handling
  detection/           Gular's detection engine (sigma branch)
  test/api.test.js     API tests
```

## Branch

```bash
git checkout backend
git pull origin backend
git push origin backend
```

## Integration

- **Gular** (`sigma` branch): `backend/detection/` — risk engine, correlator, Sigma logic
- **Bahadur** (`frontend` branch): consumes this API; same JSON contract
- **Kanan** (`siem` branch): drops `data/wazuh-alert-real.json`; call `POST /api/reload`

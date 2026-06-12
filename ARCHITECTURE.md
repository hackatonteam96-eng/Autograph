# AuthGraph — Architecture

Simple view of how everything connects for the hackathon demo.

```
┌─────────────────────────────────────────────────────────────────┐
│  VMWARE LAB (Mr. Kanan)                                         │
│                                                                 │
│   [Attacker] ──kerberoast──▶ [DC01 / AD]                        │
│                                   │                             │
│                            Event 4769                           │
│                                   ▼                             │
│                          [Wazuh Agent]                          │
│                                   │                             │
│                                   ▼                             │
│                        [Wazuh Manager + Sigma]                  │
└───────────────────────────────┬─────────────────────────────────┘
                                │ POST /api/webhook/wazuh
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  BACKEND — localhost:8787 (Zahra / Nazrin)                      │
│                                                                 │
│   Detection engine → Risk score → PostgreSQL (prod) / JSON      │
│   OpenRouter AI → containment recommendations                   │
└───────────────────────────────┬─────────────────────────────────┘
                                │ GET /api/incidents
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  FRONTEND — localhost:5173 (Bahadur)                            │
│                                                                 │
│   Attack path graph · Risk ring · Timeline · Sigma · AI actions │
└─────────────────────────────────────────────────────────────────┘
```

## Local dev

```bash
# Terminal 1 — backend
cd backend && npm install && npm run dev

# Terminal 2 — frontend
cd frontend && npm install && npm run dev
```

Open **http://127.0.0.1:5173**

## Key API routes

| Route | Purpose |
|-------|---------|
| `GET /api/health` | Backend + detection status |
| `GET /api/incidents` | Live incidents for UI |
| `GET /api/attack-path` | BloodHound-style graph data |
| `GET /api/sigma` | Kerberoasting Sigma rule YAML |
| `GET /api/ai/respond/:id` | OpenRouter containment analysis |
| `POST /api/contain/:id` | Execute containment |
| `POST /api/simulate/kerberoast` | Demo trigger |
| `POST /api/webhook/wazuh` | Real Wazuh alert ingest |

## When Wazuh is ready

Kanan points Wazuh integration webhook to:

```
http://YOUR_LAPTOP_IP:8787/api/webhook/wazuh
```

Or drop alert JSON into `data/wazuh-alert-real.json` and call `POST /api/reload`.

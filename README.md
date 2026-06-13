# AuthGraph ITDR

Identity Threat Detection & Response — hackathon lab (1 DC + 1 client).

## Demo flow

```
data/logs/bundle-for-ai.json  →  Your DeepSeek AI  →  Posture UI (screenshot style)
Wazuh / sample-alerts         →  GET /api/alerts    →  Kerberoasting detection
POST /api/contain/:id         →  One-click response
```

## Lab logs (send to DeepSeek)

**Single file:** `data/logs/bundle-for-ai.json`

Or via API:
```
GET http://localhost:8000/api/logs
GET http://localhost:8000/api/logs/raw
```

See `data/logs/README.md` for evidence → expected findings mapping.

## Backend

```bash
cd backend && npm install && npm run dev
```

## Future (startup improvement)

- `collector/` — PowerShell + C# → live logs instead of mock
- Your DeepSeek service consumes `/api/logs` or `bundle-for-ai.json`

## Sigma rules

`sigma/kerberoasting/` — Wazuh detection rules

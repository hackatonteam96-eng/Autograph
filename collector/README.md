Mock lab logs for DeepSeek AI input — see `data/logs/README.md`.

**Hackathon:** use `data/logs/bundle-for-ai.json` — no collector needed yet.

## Architecture (target)

```
DC / Client
  → PowerShell (Collect-LabSnapshot.ps1 / Collect-ClientSnapshot.ps1)
  → C# AuthGraphForwarder.exe
  → POST /api/ingest
  → Backend correlate + DeepSeek AI
  → GET /api/posture
```

## Files

| File | Run on | Status |
|------|--------|--------|
| `powershell/Collect-LabSnapshot.ps1` | DC | Ready, not required for demo |
| `powershell/Collect-ClientSnapshot.ps1` | Client | Ready, not required for demo |
| `forwarder/Program.cs` | Any | Ready, not required for demo |

## When to enable (post-hackathon)

1. Set `USE_MOCK_DATA=false` in backend `.env`
2. Build forwarder: `dotnet build -c Release` in `forwarder/`
3. Run collectors on DC + client, forward to backend
4. Set `DEEPSEEK_API_KEY` for live AI

## Demo now

```bash
cd backend && npm run dev
curl http://localhost:8000/api/posture
```

Mock files: `data/logs/` — see `bundle-for-ai.json`

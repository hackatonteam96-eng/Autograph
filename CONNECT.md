# Connect VMware Lab → Wazuh → AuthGraph

Your lab and Sigma rules are ready. Follow these steps **in order**.

---

## What connects to what

```
┌──────────────────────────────────────────────────────────────────┐
│  VMWARE LAB (same host-only / LAN network)                       │
│                                                                  │
│  [Attacker VM]          [DC / Domain Controller]                 │
│   Kali or Win              Windows + AD                          │
│   you kerberoast here      Wazuh Agent installed                 │
│         │                        │                               │
│         │  Kerberos TGS          │ Event 4769 → Security log     │
│         └──────────►─────────────┘                               │
│                                   │                              │
│                          [Wazuh Manager VM]                      │
│                           Sigma rule loaded                      │
│                           Alert fires on match                   │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                    Option A: Webhook (best)
                    Option B: Alert file drop
                    Option C: Poll script
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  YOUR LAPTOP (Bahadur)                                           │
│                                                                  │
│  Backend  http://127.0.0.1:8787                                 │
│  Frontend http://127.0.0.1:5173                                 │
└──────────────────────────────────────────────────────────────────┘
```

---

## Step 0 — Start AuthGraph on your laptop

```powershell
cd C:\Users\Bahadur\Autograph
npm run install:all
npm run dev
```

Verify:
- Backend: http://127.0.0.1:8787/api/health → `"ok": true`
- Frontend: http://127.0.0.1:5173

Find your laptop IP (for Wazuh webhook):
```powershell
ipconfig
```
Use the IPv4 on the **same network as VMware** (often `192.168.x.x` on VMnet8).

---

## Step 1 — Confirm AD logging (Kanan / DC VM)

On the **Domain Controller**, Event Viewer → Windows Logs → Security → filter **Event ID 4769**.

Run a test kerberoast from attacker VM. You **must** see 4769 events before anything else matters.

Advanced Audit Policy on DC:
- **Account Logon → Kerberos Service Ticket Operations** = Success + Failure

---

## Step 2 — Wazuh agent on DC (Kanan)

1. Wazuh Manager running (VMware Linux VM)
2. Agent installed on Windows DC, status **Active**
3. Agent config collects Security log:
   ```xml
   <localfile>
     <location>Security</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```
4. Sigma rule deployed — your rule is at `sigma/kerberoasting.yml` in the repo

Test in Wazuh dashboard: run kerberoast → alert appears with level ≥ 12.

---

## Step 3 — Connect Wazuh → AuthGraph backend

### Option A — Webhook (recommended)

On **Wazuh Manager**, configure integration to POST alerts to your laptop:

```xml
<!-- /var/ossec/etc/ossec.conf — integration block -->
<integration>
  <name>custom-webhook</name>
  <hook_url>http://YOUR_LAPTOP_IP:8787/api/webhook/wazuh</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

Replace `YOUR_LAPTOP_IP` with your real IP (e.g. `192.168.56.1` if VMware host-only).

**Windows firewall** — allow inbound TCP 8787:
```powershell
New-NetFirewallRule -DisplayName "AuthGraph API" -Direction Inbound -LocalPort 8787 -Protocol TCP -Action Allow
```

Restart Wazuh manager after config change.

---

### Option B — Manual file drop (if webhook blocked)

1. Export alert JSON from Wazuh UI when kerberoast fires
2. Save as `data/wazuh-alert-real.json` in the repo
3. Call reload:
   ```powershell
   curl -X POST http://127.0.0.1:8787/api/reload
   ```
4. Frontend updates within 2 seconds (auto-poll)

Example minimal payload the backend understands:
```json
{
  "event_id": 4769,
  "AccountName": "lowpriv.user",
  "ServiceName": "MSSQLSvc/SQL-SERVER.corp.local:1433",
  "TicketEncryptionType": "0x17",
  "IpAddress": "10.0.0.42",
  "host": "DC01"
}
```

---

### Option C — Forward script on Wazuh VM (fallback)

On Wazuh Manager Linux VM, tail alerts and forward:

```bash
tail -F /var/ossec/logs/alerts/alerts.json | while read line; do
  echo "$line" | grep -q '"id":' && \
  curl -s -X POST http://YOUR_LAPTOP_IP:8787/api/webhook/wazuh \
    -H "Content-Type: application/json" \
    -d "$line"
done
```

---

## Step 4 — Run the attack (you, red team)

From **Attacker VM** with domain creds:

```bash
# Impacket
GetUserSPNs.py corp.local/lowpriv.user:'Password123' -dc-ip DC_IP -request

# Or Rubeus on Windows
Rubeus.exe kerberoast /outfile:hashes.txt
```

Expected chain:
1. 4769 on DC Security log
2. Wazuh agent ships log → Sigma matches
3. Webhook hits `POST /api/webhook/wazuh`
4. AuthGraph UI shows incident, risk 87, attack path, AI response

---

## Step 5 — Verify end-to-end

| Check | Where | Pass |
|-------|-------|------|
| Event 4769 | DC Event Viewer | ☐ |
| Wazuh alert | Wazuh dashboard | ☐ |
| Backend received | `GET /api/incidents` shows kerberoast | ☐ |
| UI live | Frontend incident banner turns critical | ☐ |
| Sigma | Rule panel shows `kerberoasting.yml` | ☐ |
| AI | Containment actions populate | ☐ |

Quick API test from laptop:
```powershell
curl http://127.0.0.1:8787/api/incidents
curl http://127.0.0.1:8787/api/health
```

Simulate without Wazuh (demo fallback):
```powershell
curl -X POST http://127.0.0.1:8787/api/simulate/kerberoast
```

---

## Network cheat sheet

| Machine | Typical IP | Role |
|---------|------------|------|
| VMware host (your laptop) | 192.168.56.1 | Runs AuthGraph API :8787 |
| Wazuh Manager | 192.168.56.x | Sends webhooks |
| Domain Controller | 192.168.56.x | AD + Wazuh agent |
| Attacker | 192.168.56.x | Kerberoast source |

All VMs must be on the **same VMnet** and able to reach your laptop IP on port **8787**.

---

## AI Analyst Copilot

Not a generic chatbot — built-in SOC assistant panel in the UI.

- Uses `POST /api/ai/chat` with incident context
- Ask: *"Why is this critical?"* · *"What should I do first?"* · *"Explain the attack path"*
- Runs on OpenRouter (DeepSeek) — already configured in `backend/.env`

---

## Demo day checklist

1. Start `npm run dev` on laptop **before** judges arrive
2. Confirm Wazuh agent green on DC
3. Run kerberoast live — don't use simulate button for judges
4. Have Wazuh dashboard open on second screen as proof
5. Record backup video of full chain working once

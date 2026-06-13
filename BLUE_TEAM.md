# Blue Team — Wazuh → AuthGraph

**Owner:** Kanan (Wazuh / DC) + Bahadur (AuthGraph laptop)

Wazuh already fires on **4769 + TicketEncryptionType 0x17** (RC4 kerberoasting). AuthGraph does **not** poll Wazuh. Your backend **listens** on port **8787** and Wazuh **pushes** alerts via HTTP POST (webhook).

---

## How it works (30 seconds)

```
Kerberoast on DC
  → Event 4769 (0x17) in Security log
  → Wazuh agent ships log to Manager
  → Sigma rule matches (T1558.003)
  → Wazuh Manager POSTs JSON to AuthGraph
  → Backend saves + parses alert
  → Frontend polls /api/incidents every 2s → UI goes critical
```

AuthGraph backend = **always-on HTTP server**. Webhook = **Wazuh calls you**, not the other way around. No cronjob on AuthGraph.

---

## Blue team checklist (Kanan — Wazuh Manager)

### 1. Confirm alert in Wazuh UI

- Run kerberoast from attacker VM
- Wazuh dashboard shows alert with **0x17** / kerberoasting rule
- Note alert level (should be ≥ 10)

### 2. Add webhook integration

Edit `/var/ossec/etc/ossec.conf` on **Wazuh Manager**:

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://BAHADUR_LAPTOP_IP:8787/api/webhook/wazuh</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

Replace `BAHADUR_LAPTOP_IP` with Bahadur’s IP on the **same network as VMware** (e.g. `192.168.56.1` on VMnet8).

Restart manager:

```bash
sudo systemctl restart wazuh-manager
# or
/var/ossec/bin/wazuh-control restart
```

### 3. Test connectivity FROM Wazuh VM

```bash
curl http://BAHADUR_LAPTOP_IP:8787/api/webhook/wazuh
```

Expected:

```json
{"ok":true,"service":"AuthGraph Wazuh webhook","method":"POST alerts to this URL"}
```

### 4. Test with sample POST (optional)

```bash
curl -X POST http://BAHADUR_LAPTOP_IP:8787/api/webhook/wazuh \
  -H "Content-Type: application/json" \
  -d @/path/to/alert-export.json
```

Or use the repo fixture:

```bash
curl -X POST http://BAHADUR_LAPTOP_IP:8787/api/webhook/wazuh \
  -H "Content-Type: application/json" \
  -d '{
    "rule":{"level":12,"description":"Kerberoasting","mitre":{"id":["T1558.003"]}},
    "agent":{"name":"DC01","ip":"10.0.0.10"},
    "data":{"win":{"system":{"eventID":"4769"},"eventdata":{
      "targetUserName":"lowpriv.user",
      "serviceName":"MSSQLSvc/SQL-SERVER.corp.local:1433",
      "ticketEncryptionType":"0x17",
      "ipAddress":"10.0.0.42"
    }}}
  }'
```

### 5. Fallback if webhook blocked

1. Export alert JSON from Wazuh UI  
2. Send file to Bahadur → save as `data/wazuh-alert-real.json`  
3. Bahadur runs: `curl -X POST http://127.0.0.1:8787/api/reload`

### 6. Fallback script (tail alerts)

On Wazuh Manager:

```bash
tail -F /var/ossec/logs/alerts/alerts.json | while read -r line; do
  echo "$line" | grep -q '"level"' || continue
  echo "$line" | grep -qi 'kerberoast\|T1558\|4769' || continue
  curl -s -X POST "http://BAHADUR_LAPTOP_IP:8787/api/webhook/wazuh" \
    -H "Content-Type: application/json" \
    -d "$line"
done
```

---

## Red / demo team (Bahadur — AuthGraph laptop)

### 1. Backend must listen on all interfaces

`backend/.env`:

```env
HOST=0.0.0.0
PORT=8787
```

### 2. Windows firewall

```powershell
New-NetFirewallRule -DisplayName "AuthGraph API" -Direction Inbound -LocalPort 8787 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "AuthGraph UI" -Direction Inbound -LocalPort 5173 -Protocol TCP -Action Allow
```

### 3. LAN access (judges / blue team on same network)

`backend/.env`:

```env
HOST=0.0.0.0
PORT=8787
AUTHGRAPH_LAN_HOST=10.249.162.244
ITDR_DASHBOARD_URL=http://10.249.162.244:5173
```

Frontend dev server binds `0.0.0.0:5173` (see `frontend/vite.config.ts`). Share this URL:

- **Dashboard:** http://10.249.162.244:5173  
- **API health:** http://10.249.162.244:8787/api/health  
- **Wazuh webhook:** http://10.249.162.244:8787/api/webhook/wazuh  

On your machine you can still use http://127.0.0.1:5173 — same stack.

### 4. Start stack

```powershell
cd C:\Users\Bahadur\Autograph
npm run dev
```

- Frontend (LAN): http://10.249.162.244:5173  
- Frontend (local): http://127.0.0.1:5173  
- Backend health: http://10.249.162.244:8787/api/health  

After a real webhook, health shows `"wazuh_real": true`.

### 5. Verify incident

```powershell
curl http://127.0.0.1:8787/api/incidents
```

### 6. Local webhook test (no Wazuh)

```powershell
.\scripts\test-wazuh-webhook.ps1
```

---

## Live demo script (judges)

1. Show AuthGraph UI — quiet state  
2. Kanan confirms Wazuh webhook configured  
3. Red team runs kerberoast  
4. Wazuh alert fires → POST to webhook  
5. Within ~2s UI shows **critical Kerberoasting**, risk score, attack path, ARIA  
6. Blue team clicks **Contain** in UI  

**Do not** use “Run attack” for the live chain — that’s simulate-only. Use real Wazuh POST.

---

## Incident email reports (Resend)

AuthGraph queues an HTML incident report after ARIA enrichment (`ITDR_REPORT_AUTO=true`).

### Current sandbox mode

`backend/.env` uses Resend's test sender `onboarding@resend.dev`. In this mode:

- Resend dashboard shows **Sent** / **Delivered**
- Mail goes **only** to the email you used to sign up for Resend: `support.vulnbase@gmail.com`
- Mail does **not** go to `support@vulnbase.org` (Zoho) until the domain is verified

**If you see "Sent" in Resend but nothing in Zoho:** open Gmail for `support.vulnbase@gmail.com` (Inbox, Spam, Promotions).

Check delivery status:

```powershell
curl http://127.0.0.1:8787/api/reports/config
```

### Production: `support@vulnbase.org`

1. In [Resend → Domains](https://resend.com/domains), add **vulnbase.org**
2. Add the DNS records Resend shows (SPF, DKIM, etc.) in **Zoho** DNS for vulnbase.org
3. Wait until Resend shows the domain as **Verified**
4. Update `backend/.env`:

```env
ITDR_REPORT_FROM=AuthGraph ITDR <support@vulnbase.org>
ITDR_REPORT_TO=support@vulnbase.org
```

5. Restart the backend

Manual resend for one incident:

```powershell
curl -X POST http://127.0.0.1:8787/api/reports/alert-8864a15bb1d6/send
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `curl` to laptop times out | Wrong IP, firewall, or `HOST=127.0.0.1` |
| Webhook 400 “Could not parse” | Send full Wazuh JSON; check `data.win.eventdata.ticketEncryptionType` = `0x17` |
| Wazuh alert but UI empty | Bahadur check `GET /api/incidents`; backend logs `[webhook] Ingested` |
| UI blank locally | Run `npm run dev`, hard refresh, use port **5173** only |
| Resend “Sent” but no email | Sandbox delivers to **Gmail signup address**, not `@vulnbase.org`; check Spam |
| “domain is not verified” | Complete Resend DNS setup for vulnbase.org before using `@vulnbase.org` |

---

## Who owns what

| Person | Owns |
|--------|------|
| **Kanan** | Wazuh Manager, agent on DC, Sigma deploy, webhook URL |
| **Bahadur** | AuthGraph backend + frontend, firewall 8787, demo driver |
| **Red team** | Kerberoast execution during demo |
| **Gular/Nazrin** | Detection engine, API (already in repo) |

# AuthGraph ITDR — Judge Demo Script (5 minutes)

**Team:** AuthGraph · **Theme:** Identity Threat Detection & Response (ITDR)  
**MVP:** Kerberoasting on Active Directory + Wazuh + Sigma + risk scoring + attack path

---

## Before judges arrive

```powershell
cd C:\Users\Bahadur\Autograph
npm run dev
# UI: http://127.0.0.1:5173  ·  API: http://127.0.0.1:8787
```

1. Backend running with `OPENROUTER_API_KEY` set (ARIA AI).
2. Windows firewall allows inbound **8787** (Wazuh webhook).
3. Wazuh `ossec.conf` webhook → `http://YOUR_LAPTOP_IP:8787/api/webhook/wazuh`
4. Run automated verification:

```powershell
.\scripts\verify-e2e.ps1
```

All MVP checks should pass. Open **Detection** tab — green **MVP verification** panel.

---

## 60-second pitch

> "AuthGraph is an ITDR platform for Active Directory and Entra ID. We detect Kerberoasting via Sigma on Event 4769, ingest Wazuh alerts in real time, correlate identity attack paths like BloodHound, score risk explainably, and ARIA AI recommends containment with analyst approval."

---

## Live demo flow (recommended)

| Step | Action | What judges see |
|------|--------|-----------------|
| 1 | Show idle Command tab | Pipeline armed, risk low |
| 2 | Run kerberoast from attacker VM (Rubeus/Impacket) | See `CONNECT.md` |
| 3 | Wazuh fires → webhook POST | **LIVE WAZUH** badge, toast, hero critical |
| 4 | Command tab | ARIA verdict, risk ring, attack path mini-graph |
| 5 | **Attack path** tab | BloodHound-style graph: user → SPN → SQL admins → assets |
| 6 | **Detection** tab | MVP verification ✓, "Why this fired", Sigma rule YAML |
| 7 | **Response** tab | Approve AI actions → Execute → Contained, risk drops |
| 8 | ARIA chat (bottom-right) | "Walk the attack path" / "Executive brief" |

### Kerberoast commands (attacker VM)

```bash
# Impacket
GetUserSPNs.py corp.local/lowpriv.user:'Password123' -dc-ip DC_IP -request

# Rubeus (Windows)
Rubeus.exe kerberoast /outfile:hashes.txt
```

### Fallback (no lab network)

```powershell
.\scripts\test-wazuh-webhook.ps1
# or UI: "Run attack" button (simulated)
```

---

## MVP requirements mapping

| Requirement | Evidence |
|-------------|----------|
| Kerberoasting PoC | Lab attack + `GET /api/verify` → `kerberoasting_poc: true` |
| One Sigma rule | `sigma/kerberoasting.yml` + Detection tab |
| Wazuh/SIEM alert | Webhook ingest + `wazuh_alert: true` |
| Attack verification | Detection tests + verify endpoint + "Why this fired" panel |

---

## API proof (optional live curl)

```powershell
curl http://127.0.0.1:8787/api/verify
curl http://127.0.0.1:8787/api/explain/alert-001
curl http://127.0.0.1:8787/api/sigma/rules
curl http://127.0.0.1:8787/api/incidents
```

---

## Sigma rule library

| Rule | Platform | MITRE |
|------|----------|-------|
| `authgraph-kerberoasting-4769` | Active Directory | T1558.003 |
| `authgraph-entra-risky-signin` | Microsoft Entra ID | T1078.004 |
| `authgraph-dcsync-4662` | Active Directory (library) | T1003.006 |

---

## Entra ID scope

Entra rule is in the **Sigma library** for cloud identity coverage (theme requirement). Live Entra sign-in ingest is roadmap; AD Kerberoasting is the live MVP path.

---

## Tests (run before presenting)

```powershell
cd backend
npm test
```

Expected: **10/10 detection tests** + **11/11 API tests** pass.

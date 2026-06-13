# AuthGraph ITDR — Sigma Rules

## Kerberoasting (tam suite)

**13 rule** → [`kerberoasting/`](./kerberoasting/README.md)

| # | Rule | Event |
|---|------|-------|
| 01 | Single RC4 TGS | 4769 |
| 02 | 5+ unique SPN / 5 min | 4769 correlation |
| 03 | 3+ TGS burst / 10 min | 4769 correlation |
| 04 | AES mass enumeration | 4769 correlation |
| 05 | High-value SPN target | 4769 |
| 06 | Honeypot SPN | 4769 |
| 07 | LDAP SPN discovery | 4662 |
| 08 | SPN modification | 5136 |
| 09 | PowerShell tools | 4104 |
| 10 | Process / CLI tools | 4688 |
| 11 | Failed TGS spray | 4769 correlation |
| 12 | TicketOptions variant | 4769 |
| 13 | Workstation SPN burst | 4769 correlation |

Primary entry: [`kerberoasting.yml`](./kerberoasting.yml)

## Wazuh import

1. Hər YAML-ı Wazuh Sigma converter və ya manual XML rule-a çevir
2. **Correlation rule-lar** (02, 03, 04, 11, 13) üçün Wazuh `frequency` + `same_field` / `different_field` istifadə et
3. DC agent + Kerberos audit policy aktiv olmalıdır

Ətraflı: [`kerberoasting/README.md`](./kerberoasting/README.md)

## Export shape

Alerts must match `data/sample-alerts.json` for frontend + API.

## Test locally

```bash
node backend/detection/cli.js explain
node backend/detection/detection.test.js
```

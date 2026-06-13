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

## Password spraying

**1 rule** → [`password-spraying.yml`](./password-spraying.yml)

| Rule | Event | Type |
|------|-------|------|
| Failed logon spray (5+ users / 5 min, same IP) | **4625** | correlation |

MITRE: **T1110.003** — one source IP, many distinct failed logons in a short window.

**DC audit policy:** Audit Logon → Failure

## AS-REP roasting

**6 rule** → [`asreproasting/`](./asreproasting/README.md)

| # | Rule | Event |
|---|------|-------|
| 01 | Single RC4 TGT, no preauth | 4768 |
| 02 | 3+ no-preauth accounts / 5 min | 4768 correlation |
| 03 | LDAP preauth-disabled enum | 4662 |
| 04 | PowerShell tools | 4104 |
| 05 | Process / CLI tools | 4688 |
| 06 | Honeypot no-preauth account | 4768 |

Primary entry: [`asreproasting.yml`](./asreproasting.yml)

MITRE: **T1558.004** — TGT issued without Kerberos pre-authentication (PreAuthType 0).

**DC audit policy:** Audit Kerberos Authentication Service → Success

## Golden Ticket

**6 rule** → [`golden-ticket/`](./golden-ticket/README.md)

| # | Rule | Event |
|---|------|-------|
| 01 | RC4 TGS to infrastructure SPN | 4769 |
| 02 | 10+ distinct SPNs / 10 min | 4769 correlation |
| 03 | Kerberos ticket validation failure | 4768/4769/4771 |
| 04 | PowerShell tools | 4104 |
| 05 | Process / CLI tools | 4688 |
| 06 | Honeypot privileged account TGS | 4769 |

Primary entry: [`golden-ticket.yml`](./golden-ticket.yml)

MITRE: **T1558.001** — forged Kerberos TGT (krbtgt hash) used for domain-wide access.

**DC audit policy:** Audit Kerberos Service Ticket Operations → Success + Failure

## Wazuh import

1. Hər YAML-ı Wazuh Sigma converter və ya manual XML rule-a çevir
2. **Correlation rule-lar** (kerberoasting 02, 03, 04, 11, 13; password-spraying.yml; asreproasting 02; golden-ticket 02) üçün Wazuh `frequency` + `same_field` / `different_field` istifadə et
3. DC agent + Kerberos / Logon audit policy aktiv olmalıdır

Ətraflı: [`kerberoasting/README.md`](./kerberoasting/README.md) · [`asreproasting/README.md`](./asreproasting/README.md) · [`golden-ticket/README.md`](./golden-ticket/README.md)

## Export shape

Alerts must match `data/sample-alerts.json` for frontend + API.

## Test locally

```bash
node backend/detection/cli.js explain
node backend/detection/detection.test.js
```

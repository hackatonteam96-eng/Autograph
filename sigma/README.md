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

## Brute force

**6 rule** → [`brute-force/`](./brute-force/README.md)

| # | Rule | Event |
|---|------|-------|
| 01 | Failed logon burst (same user + IP) | 4625 correlation |
| 02 | Distributed brute (one account, many IPs) | 4625 correlation |
| 03 | Kerberos pre-auth failure burst | 4771 correlation |
| 04 | RDP brute force | 4625 correlation |
| 05 | Privileged account targeting | 4625 correlation |
| 06 | Account lockout | 4740 |

Primary entry: [`brute-force.yml`](./brute-force.yml)

MITRE: **T1110.001** — many passwords against one account (vs spraying: one password, many accounts).

**DC audit policy:** Audit Logon → Failure; Kerberos Authentication Service → Failure

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

## Wazuh

Sigma YAML avtomatik Wazuh XML-ə çevrilir:

```bash
cd sigma/scripts && pip install -r requirements.txt
python convert_sigma_to_wazuh.py
sudo cp ../wazuh/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

Ətraflı: [`scripts/README.md`](./scripts/README.md) · [`WAZUH-DEPLOYMENT.md`](./WAZUH-DEPLOYMENT.md)

## Export shape

Alerts must match `data/sample-alerts.json` for frontend + API.

## Test locally

```bash
node backend/detection/cli.js explain
node backend/detection/detection.test.js
```

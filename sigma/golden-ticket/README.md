# AuthGraph ITDR — Golden Ticket Sigma Rule Suite

**6 qatlı** Golden Ticket detection — MITRE **T1558.001**.

## Deployment prioriteti (Wazuh)

| Priority | Rule | Fayl | Level |
|----------|------|------|-------|
| P0 | 10+ infrastructure TGS / 10 dəq | `02_lateral_tgs_burst_correlation.yml` | critical |
| P0 | Honeypot privileged account TGS | `06_honeypot_privileged_tgs.yml` | critical |
| P1 | Kerberos ticket validation failure | `03_kerberos_validation_failure.yml` | high |
| P1 | PowerShell tools 4104 | `04_powershell_tools_4104.yml` | high |
| P1 | Process tools 4688 | `05_process_tools_4688.yml` | high |
| P2 | Single RC4 infrastructure TGS | `01_rc4_infrastructure_tgs.yml` | medium |

## Detection layers

```
┌─────────────────────────────────────────────────────────────┐
│  PRECURSOR (forging / import)                               │
│  04 PowerShell │ 05 Process (Mimikatz, Rubeus, ticketer)   │
├─────────────────────────────────────────────────────────────┤
│  CORE (during use) — DC Event 4769                          │
│  01 RC4 infra TGS │ 02 Multi-SPN lateral burst              │
│  03 KDC validation failure (4768/4769/4771)                 │
├─────────────────────────────────────────────────────────────┤
│  TRAP (guaranteed catch)                                    │
│  06 Honeypot privileged account                             │
└─────────────────────────────────────────────────────────────┘
```

## Tələb olunan loglar

### Domain Controller (mütləq)
| Event | Audit policy |
|-------|--------------|
| **4769** | Audit Kerberos Service Ticket Operations → Success + Failure |
| **4768** | Audit Kerberos Authentication Service → Success + Failure |
| **4771** | Audit Kerberos Authentication Service → Failure |

### Clients / servers (tooling)
| Event | Audit policy |
|-------|--------------|
| **4104** | PowerShell Script Block Logging |
| **4688** | Audit Process Creation + command line |

## Golden Ticket indicator (4769)

| Signal | Meaning |
|--------|---------|
| RC4 TGS (`0x17`) to CIFS/LDAP/HOST | Forged TGT used for lateral movement |
| 10+ distinct SPNs / 10 min | Pass-the-Ticket spray across domain |
| KDC Status failure (4768/4769/4771) | Malformed or inconsistent forged ticket |
| Tooling: `kerberos::golden`, `Rubeus ptt` | Ticket forging / import on endpoint |

## Advanced hunt (SIEM correlation)

Golden tickets are forged **offline** — the DC never logs Event **4768** for that session.
Hunt pattern (implement in Wazuh/SIEM, not pure Sigma match):

> **4769** (TGS request) for user X from host Y **without** a preceding **4768** (TGT issued) within 1–10 hours.

Join fields: `TargetUserName` + `IpAddress` / `WorkstationName`.

## Honeypot setup (rule 06)

1. Create disabled decoy account (e.g. `svc-honeypot-da`) — never assign real use
2. Optionally add to a visible "Domain Admins" decoy group for attacker lure
3. Add username pattern to `06_honeypot_privileged_tgs.yml`
4. Any 4769 for this account = investigate immediately

## Remediation

If Golden Ticket is confirmed:

1. Isolate source hosts
2. Reset **krbtgt password twice** (with waiting period between per Microsoft guidance)
3. Re-issue KRBTGT keys and validate Kerberos across domain

## Wazuh correlation (rule 02)

- `frequency` ≥ 10
- `timeframe` 600s
- `same_field` = source IP + username
- `different_field` = service name (SPN)

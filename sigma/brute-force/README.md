# AuthGraph ITDR — Brute Force Sigma Rule Suite

**6 qatlı** brute force detection — MITRE **T1110.001** (Password Guessing).

## Brute force vs password spraying

| Attack | Pattern | Rule |
|--------|---------|------|
| **Brute force** | Many passwords → **one** account | `brute-force/` |
| **Password spray** | One password → **many** accounts | `password-spraying.yml` |

## Deployment prioriteti (Wazuh)

| Priority | Rule | Fayl | Level |
|----------|------|------|-------|
| P0 | RDP brute force burst | `04_rdp_brute_4625.yml` | high |
| P0 | Privileged account targeting | `05_admin_account_brute_4625.yml` | high |
| P1 | Failed logon burst (same IP) | `01_failed_logon_burst_4625.yml` | medium |
| P1 | Distributed single-account brute | `02_distributed_single_account_4625.yml` | high |
| P1 | Kerberos pre-auth brute | `03_kerberos_preauth_brute_4771.yml` | medium |
| P1 | Account lockout (4740) | `06_account_lockout_4740.yml` | high |

## Tələb olunan loglar (DC)

| Event | Audit policy |
|-------|--------------|
| **4625** | Audit Logon → Failure |
| **4771** | Audit Kerberos Authentication Service → Failure |
| **4740** | Audit Account Management → Failure (lockout) |

## Detection logic

```
Brute force (4625):  count(failures) by TargetUserName + IpAddress  > threshold
Distributed brute:     count(failures) by TargetUserName only        > threshold
Kerberos brute:        count(4771 0x18) by TargetUserName + IpAddress > threshold
```

**SubStatus filter:** `0xC000006A` (wrong password only) — excludes user-not-found noise from spraying.

## Wazuh correlation

| Rule | frequency | timeframe | same_field | group by |
|------|-----------|-----------|------------|----------|
| 01, 03, 04, 05 | ≥ threshold | 300s | IP + username | event count |
| 02 | ≥ 20 | 600s | username | event count |

Field paths: `data.win.eventdata.ipAddress`, `data.win.eventdata.targetUserName`

## Advanced hunt (SIEM)

**Success after brute force** — high priority:

> Multiple **4625** from IP X, then **4624** success for same user from IP X within 15 minutes.

Implement as ordered temporal correlation in Wazuh/SIEM (not pure Sigma match).

## Tuning

- Lower thresholds in high-security zones; raise on jump servers / VPN concentrators
- Exclude known scanner IPs via Wazuh `ignore` or Sigma `filter_*` blocks
- Pair rule **06** (4740) with **01–05** in alert triage playbooks

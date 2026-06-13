# AuthGraph ITDR — AS-REP Roasting Sigma Rule Suite

**6 qatlı** AS-REP Roasting detection — MITRE **T1558.004**.

## Deployment prioriteti (Wazuh)

| Priority | Rule | Fayl | Level |
|----------|------|------|-------|
| P0 | 3+ no-preauth TGT / 5 dəq, same IP | `02_multiple_accounts_correlation.yml` | critical |
| P0 | Honeypot no-preauth account | `06_honeypot_no_preauth.yml` | critical |
| P1 | PowerShell tools 4104 | `04_powershell_tools_4104.yml` | high |
| P1 | Process tools 4688 | `05_process_tools_4688.yml` | high |
| P2 | Single RC4 TGT no preauth | `01_single_asrep_rc4.yml` | medium |
| P2 | LDAP preauth-disabled enum 4662 | `03_ldap_preauth_enum_4662.yml` | medium |

## Detection layers

```
┌─────────────────────────────────────────────────────────────┐
│  PRECURSOR (before roast)                                   │
│  03 LDAP userAccountControl enum │ 04/05 Tool execution     │
├─────────────────────────────────────────────────────────────┤
│  CORE (during roast) — DC Event 4768                        │
│  01 Single no-preauth RC4 TGT │ 02 Multi-account burst     │
├─────────────────────────────────────────────────────────────┤
│  TRAP (guaranteed catch)                                    │
│  06 Honeypot DONT_REQ_PREAUTH account                       │
└─────────────────────────────────────────────────────────────┘
```

## Tələb olunan loglar (DC + client)

### Domain Controller (mütləq)
| Event | Audit policy |
|-------|--------------|
| **4768** | Audit Kerberos Authentication Service → Success |
| **4662** | Audit Directory Service Access → Success |

### Clients / servers (tooling)
| Event | Audit policy |
|-------|--------------|
| **4104** | PowerShell Script Block Logging (GPO) |
| **4688** | Audit Process Creation + command line |

## AS-REP indicator (4768)

| Field | Attack value |
|-------|--------------|
| PreAuthType | `0` (pre-authentication disabled) |
| ServiceName | `krbtgt` |
| TicketEncryptionType | `0x17` (RC4-HMAC) typical |
| Status | `0x0` (TGT issued) |

## Honeypot setup (rule 06)

1. Create disabled dummy AD user (e.g. `svc-honeypot-nopreauth`)
2. Set **Account does not require Kerberos preauthentication**
3. Add username pattern to `06_honeypot_no_preauth.yml` → `filter_honeypot`
4. Never use this account for legitimate auth

## Wazuh correlation (rule 02)

- `frequency` ≥ 3
- `timeframe` 300s
- `same_field` = `data.win.eventdata.ipAddress`
- `different_field` = `data.win.eventdata.targetUserName`

## Prevention

Audit and eliminate accounts with DONT_REQ_PREAUTH:

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

Require pre-authentication on all user accounts unless a documented exception exists.

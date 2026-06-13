# AuthGraph ITDR — Kerberoasting Sigma Rule Suite

**13 qatlı** Kerberoasting detection — heç bir hücum variantı qaçmasın.

## Deployment prioriteti (Wazuh)

| Priority | Rule | Fayl | Level |
|----------|------|------|-------|
| P0 | 5+ unique RC4 SPN / 5 dəq | `02_rc4_multiple_spn_correlation.yml` | critical |
| P0 | Honeypot SPN hit | `06_honeypot_spn_request.yml` | critical |
| P1 | 3+ RC4 TGS burst / 10 dəq | `03_rc4_multiple_tgs_same_user.yml` | high |
| P1 | Sensitive SPN (MSSQL, HTTP...) | `05_sensitive_spn_target.yml` | high |
| P1 | PowerShell tools 4104 | `09_powershell_kerberoast_tools_4104.yml` | high |
| P1 | Process tools 4688 | `10_process_kerberoast_tools_4688.yml` | high |
| P1 | Workstation SPN burst | `13_workstation_anomaly.yml` | high |
| P2 | Single RC4 TGS | `01_rc4_tgs_single.yml` | medium |
| P2 | AES mass enum (RC4 disabled AD) | `04_aes_tgs_enumeration.yml` | high |
| P2 | TicketOptions variant | `12_ticket_options_variant.yml` | medium |
| P2 | LDAP SPN discovery 4662 | `07_spn_ldap_discovery_4662.yml` | medium |
| P2 | SPN modification 5136 | `08_spn_modification_5136.yml` | medium |
| P2 | Failed TGS spray | `11_failed_tgs_spray.yml` | medium |

## Detection layers

```
┌─────────────────────────────────────────────────────────────┐
│  PRECURSOR (before roast)                                   │
│  07 LDAP SPN query │ 08 SPN modified │ 09/10 Tool execution │
├─────────────────────────────────────────────────────────────┤
│  CORE (during roast) — DC Event 4769                        │
│  01 Single RC4 │ 02 Multi-SPN │ 03 Burst │ 04 AES enum      │
│  05 Sensitive SPN │ 12 TicketOptions │ 13 Workstation       │
├─────────────────────────────────────────────────────────────┤
│  TRAP (guaranteed catch)                                    │
│  06 Honeypot SPN                                            │
├─────────────────────────────────────────────────────────────┤
│  FAILED ATTEMPTS                                            │
│  11 Failed TGS spray                                        │
└─────────────────────────────────────────────────────────────┘
```

## Tələb olunan loglar (DC + client)

### Domain Controller (mütləq)
| Event | Audit policy |
|-------|--------------|
| **4769** | Audit Kerberos Service Ticket Operations → Success |
| **4662** | Audit Directory Service Access → Success |
| **5136** | Audit Directory Service Changes → Success |

### Client / attacker host
| Event | Audit policy |
|-------|--------------|
| **4688** | Audit Process Creation → Success (+ command line) |
| **4104** | PowerShell Script Block Logging (GPO) |

## Ümumi filterlər (bütün 4769 rule-larda)

| Filter | Səbəb |
|--------|-------|
| `Status: 0x0` | Yalnız uğurlu TGS (roast üçün ticket lazımdır) |
| `ServiceName NOT krbtgt` | TGT deyil, TGS |
| `ServiceName NOT *$` | Machine account noise |
| `TargetUserName NOT *$@*` | Computer account Kerberos |

## Wazuh correlation qeydi

Sigma `count_distinct()` və `timeframe` Wazuh-da birbaşa işləməyə bilər.
**Rule 02, 03, 04, 11, 13** üçün Wazuh-da:

1. **Wazuh rules** — tək event filter (4769 + RC4)
2. **Wazuh MITRE / custom correlation** — eyni `TargetUserName` + 5 dəq pəncərədə 5+ fərqli `ServiceName`

Nümunə Wazuh frequency rule (02 üçün):

```xml
<rule id="100002" frequency="5" timeframe="300" level="15">
  <if_matched_sid>100001</if_matched_sid>
  <same_field>win.eventdata.targetUserName</same_field>
  <different_field>win.eventdata.serviceName</different_field>
  <description>Kerberoasting: Multiple unique RC4 SPNs from same user</description>
  <mitre><id>T1558.003</id></mitre>
</rule>
```

`100001` = əsas 4769 RC4 child rule.

## Honeypot quraşdırma (rule 06)

```powershell
# Dummy user + decoy SPN (heç bir real service yox)
New-ADUser -Name "svc-honeypot" -SamAccountName "svc-honeypot" -Enabled $true
setspn -A "HONEYPOT/fake.corp.local:9999" svc-honeypot
```

Rule 06-da `HONEYPOT/` öz domain adınıza uyğun dəyişin.

## Test

```bash
# Rubeus (approved lab only)
.\Rubeus.exe kerberoast /outfile:roast.txt

# PowerView
Get-DomainUser -SPN | Select SamAccountName, ServicePrincipalName
Invoke-Kerberoast

# setspn discovery
setspn -T corp.local -Q */*
```

Gözlənilən alertlər: **02** (critical), **01/03/05** (high/medium), **09/10** (tooling).

## AuthGraph API uyğunluğu

Alert export `data/sample-alerts.json` formatında olmalıdır.
Detection engine: `backend/detection/sigma_matcher.js` (rule 01/03 logic).

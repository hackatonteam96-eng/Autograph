# AuthGraph ITDR — Kerberoasting Sigma Rule

**Author:** Gular (Detection Lead)  
**MITRE:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/) — Steal or Forge Kerberos Tickets: Kerberoasting

## What it detects

| Condition | Rationale |
|-----------|-----------|
| Event ID **4769** | Kerberos **service ticket (TGS)** requested |
| TicketEncryptionType **RC4** (`0x17`, `0x1`, `0x23`) | Offline crackable ticket material |
| ServiceName **≠ krbtgt** | Targets service accounts, not domain TGT |
| *(Correlator)* **≥3 TGS** from same user | Spray / roast pattern vs one-off legacy RC4 |

## Files

- `sigma/kerberoasting.yml` — Sigma rule for SIEM import
- `backend/detection/sigma_matcher.js` — Same logic in code for AuthGraph API

## Wazuh / SIEM translation

Kanan can map fields to Wazuh rule `siem/wazuh-rule.xml`:

```xml
<rule id="100001" level="12">
  <if_sid>60103</if_sid>
  <field name="win.system.eventID">^4769$</field>
  <field name="win.eventdata.ticketEncryptionType">^0x17$|^0x1$|^0x23$</field>
  <field name="win.eventdata.serviceName">krbtgt</field>
  <description>Possible Kerberoasting - RC4 TGS request</description>
  <mitre><id>T1558.003</id></mitre>
</rule>
```

## Export shape

Alerts must match `data/sample-alerts.json` so Bahadur's frontend and Nazrin's API stay compatible.

## Test locally

```bash
node backend/detection/cli.js explain
node backend/detection/detection.test.js
```

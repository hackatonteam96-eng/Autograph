# AuthGraph Sigma Rule Library

ITDR detection rules for **Active Directory** and **Microsoft Entra ID**.

| File | ID | Platform | MITRE | MVP |
|------|-----|----------|-------|-----|
| `kerberoasting.yml` | authgraph-kerberoasting-4769 | Active Directory | T1558.003 | **Live** |
| `entra-risky-signin.yml` | authgraph-entra-risky-signin | Entra ID | T1078.004 | Library |
| `dcsync-detection.yml` | authgraph-dcsync-4662 | Active Directory | T1003.006 | Library |

## API

- `GET /api/sigma` — default kerberoasting rule YAML
- `GET /api/sigma?id=authgraph-entra-risky-signin` — specific rule
- `GET /api/sigma/rules` — library metadata

## Import to Wazuh

Copy `kerberoasting.yml` logic is already implemented in Wazuh manager rules or deploy via Sigma converter.

Based on [SigmaHQ kerberoasting rule](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_kerberoasting.yml).

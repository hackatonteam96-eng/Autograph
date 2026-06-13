# Lab Logs — DeepSeek AI Input

**No AI responses here.** Only raw DC + client logs. Send `bundle-for-ai.json` to your DeepSeek implementation.

## Files

| File | Host | Content |
|------|------|---------|
| `dc/ad-posture.json` | DC01 | Password policy, registry, services, accounts, ACLs |
| `dc/security-events.json` | DC01 | 4769 Kerberoasting, 4662 SPN query, 4624 |
| `dc/dns.log` | DC01 | DNS queries from client |
| `client/host-info.json` | WS-CLIENT01 | Logged-on users, local admins |
| `client/security-events.json` | WS-CLIENT01 | Rubeus, PowerShell, privileged logon |
| `client/dns.log` | WS-CLIENT01 | DNS client queries |
| `client/http.log` | WS-CLIENT01 | HTTP access lines |
| **`bundle-for-ai.json`** | Both | **Single file — send this to DeepSeek** |

## Evidence → Expected AI findings

| Log evidence | AI should detect |
|--------------|------------------|
| `credential_risk svc-sql breach` | Compromised Password (High) |
| `MinPasswordLength: 8` | Inadequate Password Policy (Medium) |
| `RequireSecuritySignature: 0` | SMB Signing Disabled (Medium) |
| `LdapEnforceChannelBinding: 0` | LDAPS Channel Binding not Required (Medium) |
| `attack_path_edges` + 4769 events | Attack Path to Privileged Account (Medium) |
| `Spooler Running` on DC | Print Spooler Service Running (Medium) |
| `LDAPServerIntegrity: 1` | LDAP Signing is not Required (Medium) |
| `acl GenericAll lowpriv.user` | Stealthy Privileges (Low) |
| `svc-sql + svc-backup same pwd date` | Duplicated Password (Low) |
| `labadmin 4624 LogonType 10 on client` | Privileged Endpoint Account (Low) |
| `krbtgt_password_age_days: 247` | KRBTGT password not changed for 180 days (Low) |

## Usage

```bash
# Read bundle and POST to your DeepSeek service
cat data/logs/bundle-for-ai.json
```

Or via API (if backend running):

```
GET http://localhost:8000/api/logs
```

## Future

Replace mock files with live output from `collector/powershell/` + C# forwarder.

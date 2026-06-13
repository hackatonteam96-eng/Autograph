import type { AttackPath } from '../api/client'

export const fallbackAttackPath: AttackPath = {
  nodes: [
    { id: 'lowpriv.user', type: 'user', risk: 'medium' },
    { id: 'svc-sql', type: 'service_account', risk: 'critical' },
    { id: 'SQL Admins', type: 'group', risk: 'high' },
    { id: 'SQL-SERVER', type: 'host', risk: 'high' },
    { id: 'Domain Sensitive Assets', type: 'asset', risk: 'critical' },
  ],
  edges: [
    { from: 'lowpriv.user', to: 'svc-sql', label: 'Requested TGS' },
    { from: 'svc-sql', to: 'SQL Admins', label: 'Member Of' },
    { from: 'SQL Admins', to: 'SQL-SERVER', label: 'Admin To' },
    { from: 'SQL-SERVER', to: 'Domain Sensitive Assets', label: 'Access Path' },
  ],
}

export const fallbackSigmaYaml = `title: Possible Kerberoasting Activity
id: authgraph-kerberoasting-4769
status: experimental
description: Detects Kerberoasting in Event 4769 with RC4 ticket encryption (0x17).
author: AuthGraph ITDR
date: 2026/06/12
tags:
  - attack.credential_access
  - attack.t1558.003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
  filter_rc4:
    TicketEncryptionType:
      - '0x17'
  condition: selection and filter_rc4
level: high
`

import type { Alert, AttackPath } from '../api/client'

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

export const fallbackDemoAlert: Alert = {
  id: 'alert-001',
  time: '2026-06-12T14:03:00Z',
  source: 'Wazuh',
  attack: 'Kerberoasting',
  mitre: 'T1558.003',
  severity: 'critical',
  risk: 87,
  user: 'lowpriv.user',
  target: 'svc-sql',
  source_ip: '10.0.0.42',
  host: 'DC01',
  event_id: 4769,
  evidence: [
    'Multiple Kerberos TGS requests from one user',
    'RC4 encrypted service ticket requested',
    'Target account has SPN configured',
    'Service account is linked to privileged SQL server',
  ],
  response: [
    'Reset service account password',
    'Disable RC4 Kerberos encryption',
    'Review SPN ownership',
    'Investigate source user session',
    'Rotate credentials for exposed service account',
  ],
  status: 'open',
}

/** Show full SOC demo on Vercel when backend is unreachable. */
export function shouldUseOfflineDemo() {
  if (import.meta.env.VITE_DEMO_MODE === 'true') return true
  if (!import.meta.env.PROD) return false
  const base = import.meta.env.VITE_API_BASE
  return !base || base === '/api'
}

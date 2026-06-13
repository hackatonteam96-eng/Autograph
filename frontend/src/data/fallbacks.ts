/**
 * The only fallback the live UI uses: the Sigma rule YAML shown when the
 * backend is briefly unreachable. No placeholder alerts or identities — the
 * dashboard renders exclusively from real Wazuh webhooks / lab simulation.
 */
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

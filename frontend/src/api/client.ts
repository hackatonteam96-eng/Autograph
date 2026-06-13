const API_BASE = import.meta.env.VITE_API_BASE || '/api'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...init?.headers },
    ...init,
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.error || `Request failed: ${response.status}`)
  }
  return response.json() as Promise<T>
}

export type Alert = {
  id: string
  time: string
  source: string
  attack: string
  mitre: string
  severity: string
  risk: number
  user: string
  target: string
  source_ip: string
  host: string
  event_id: number
  evidence: string[]
  response: string[]
  status?: string
  simulation_active?: boolean
  demo_step?: number
  detection?: {
    risk_breakdown?: { factor: string; points: number; description: string }[]
    sigma_matched?: boolean
  }
  ai_status?: string | null
  ai_verdict?: string | null
  ai_headline?: string | null
  ai_confidence?: string | null
  ai_urgency?: string | null
  ai_actions?: string[] | null
  ai_action_details?: { priority: number; action: string; rationale: string; owner: string }[] | null
  ai_summary_model?: string | null
  ai_actions_model?: string | null
  ai_enriched_at?: string | null
  ingest_source?: 'webhook' | 'simulation' | 'sample'
  last_webhook_at?: string | null
}

export type AttackPath = {
  nodes: { id: string; type: string; risk: string }[]
  edges: { from: string; to: string; label: string }[]
}

export type Health = {
  ok: boolean
  service: string
  detection: string
  data?: { wazuh_real?: boolean; wazuh_kerberos?: boolean; sample_alerts?: boolean; attack_path?: boolean }
  incidents: { open: number; contained: number; history?: number }
  stats?: { identities_monitored?: number }
}

export type EventLogEntry = {
  id: string
  ts: string
  level: 'info' | 'warn' | 'alert' | 'action' | 'ai' | 'webhook' | 'system'
  message: string
  incident_id?: string
  user?: string
  target?: string
  risk?: number
  command?: string
  status?: string
  preview?: string
  is_new?: boolean
}

export type ContainExecution = {
  action: string
  playbook_id: string
  description: string
  command: string
  status: 'simulated' | 'executed' | 'failed'
  message: string
  output?: string
}

export type SigmaRule = {
  id: string
  mitre: string
  title: string
  platform?: string
  yaml: string
}

export type SigmaRuleMeta = {
  id: string
  mitre: string
  title: string
  platform: string
  status: string
  filename: string
  event_id?: number | null
}

export type ExplainResponse = {
  incident_id: string
  attack: string
  mitre: string
  summary: string
  sigma: string[]
  risk_factors: { factor: string; points: number; description: string }[]
  evidence: string[]
  confidence?: string
  risk: number
  severity: string
  target: string
  user: string
}

export type VerifyCheck = { name: string; pass: boolean; detail: string }

export type VerifyResponse = {
  ok: boolean
  passed: number
  total: number
  checks: VerifyCheck[]
  mvp: {
    kerberoasting_poc: boolean
    sigma_rule: boolean
    wazuh_alert: boolean
    attack_verification: boolean
  }
}

export type AiResponse = {
  incident_id: string
  actions: string[]
  action_details?: { priority: number; action: string; rationale: string; owner: string }[]
  source: string
  model: string | null
  verdict?: string
  headline?: string
  confidence?: string
  urgency?: string
  summary_model?: string
  ai_status?: string
}

export type SimulationStatus = {
  active: boolean
  step: number
  risk: number
  timeline_count: number
}

export const api = {
  health: () => request<Health>('/health'),
  incidents: () => request<Alert[]>('/incidents'),
  incident: (id: string) => request<Alert>(`/incidents/${id}`),
  attackPath: (alertId?: string) =>
    request<AttackPath>(alertId ? `/attack-path?alert_id=${encodeURIComponent(alertId)}` : '/attack-path'),
  sigma: (id?: string) => request<SigmaRule>(id ? `/sigma?id=${encodeURIComponent(id)}` : '/sigma'),
  sigmaRules: () => request<{ count: number; rules: SigmaRuleMeta[] }>('/sigma/rules'),
  explain: (id: string) => request<ExplainResponse>(`/explain/${id}`),
  verify: () => request<VerifyResponse>('/verify'),
  contain: (id: string, actions?: string[]) =>
    request<{
      ok: boolean
      actions: string[]
      execution?: ContainExecution[]
      risk_after: number
      risk_before?: number
      mode?: 'live' | 'simulated'
    }>(`/contain/${id}`, {
      method: 'POST',
      body: actions?.length ? JSON.stringify({ actions }) : undefined,
    }),
  aiRespond: (id: string) => request<AiResponse>(`/ai/respond/${id}`),
  simulateKerberoast: () =>
    request<{ ok: boolean; status: SimulationStatus; incident?: Alert }>('/simulate/kerberoast', { method: 'POST' }),
  simulateReset: () => request<{ ok: boolean }>('/simulate/reset', { method: 'POST' }),
  simulateStatus: () => request<SimulationStatus>('/simulate/status'),
  logs: (params?: { limit?: number; level?: string; incident_id?: string }) => {
    const q = new URLSearchParams()
    if (params?.limit) q.set('limit', String(params.limit))
    if (params?.level) q.set('level', params.level)
    if (params?.incident_id) q.set('incident_id', params.incident_id)
    const qs = q.toString()
    return request<{ ok: boolean; count: number; events: EventLogEntry[] }>(`/logs${qs ? `?${qs}` : ''}`)
  },
  aiChat: (
    incidentId: string | undefined,
    message: string,
    conversationHistory?: { role: 'user' | 'assistant'; content: string }[],
    viewContext?: string,
  ) =>
    request<{ ok: boolean; reply: string; model?: string }>('/ai/chat', {
      method: 'POST',
      signal: AbortSignal.timeout(90000),
      body: JSON.stringify({
        incident_id: incidentId,
        message,
        conversation_history: conversationHistory,
        view_context: viewContext,
      }),
    }),
}

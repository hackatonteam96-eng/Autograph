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
}

export type AttackPath = {
  nodes: { id: string; type: string; risk: string }[]
  edges: { from: string; to: string; label: string }[]
}

export type Health = {
  ok: boolean
  service: string
  detection: string
  data?: { wazuh_real?: boolean; sample_alerts?: boolean; attack_path?: boolean }
  incidents: { open: number; contained: number }
}

export type SigmaRule = {
  id: string
  mitre: string
  title: string
  yaml: string
}

export type AiResponse = {
  incident_id: string
  actions: string[]
  source: string
  model: string | null
  summary?: string
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
  attackPath: () => request<AttackPath>('/attack-path'),
  sigma: () => request<SigmaRule>('/sigma'),
  contain: (id: string) => request<{ ok: boolean; actions: string[]; risk_after: number }>(`/contain/${id}`, { method: 'POST' }),
  aiRespond: (id: string) => request<AiResponse>(`/ai/respond/${id}`),
  simulateKerberoast: () => request<{ ok: boolean; status: SimulationStatus }>('/simulate/kerberoast', { method: 'POST' }),
  simulateReset: () => request<{ ok: boolean }>('/simulate/reset', { method: 'POST' }),
  simulateStatus: () => request<SimulationStatus>('/simulate/status'),
  aiChat: (
    incidentId: string | undefined,
    message: string,
    conversationHistory?: { role: 'user' | 'assistant'; content: string }[],
    viewContext?: string,
  ) =>
    request<{ ok: boolean; reply: string; model?: string }>('/ai/chat', {
      method: 'POST',
      signal: AbortSignal.timeout(60000),
      body: JSON.stringify({
        incident_id: incidentId,
        message,
        conversation_history: conversationHistory,
        view_context: viewContext,
      }),
    }),
}

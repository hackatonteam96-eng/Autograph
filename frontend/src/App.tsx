import { useCallback, useEffect, useRef, useState } from 'react'
import {
  ArrowClockwise,
  ChartLineUp,
  Fingerprint,
  GlobeHemisphereWest,
  Graph,
  Play,
  ShieldCheck,
  SquaresFour,
  TerminalWindow,
  WarningCircle,
  Lightning,
  Clock,
  Eye,
  Database,
  Cpu,
  Radioactive,
  Scroll,
} from '@phosphor-icons/react'
import { motion, AnimatePresence, useMotionValue, useSpring } from 'motion/react'
import AttackGraph from './components/AttackGraph'
import AttackPathPipeline from './components/AttackPathPipeline'
import AskAriaButton from './components/AskAriaButton'
import CodeBlock from './components/CodeBlock'
import FloatingCopilot from './components/FloatingCopilot'
import RiskPanel from './components/RiskPanel'
import TelemetryGlobe from './components/TelemetryGlobe'
import { api, type Alert, type AttackPath, type ContainExecution, type EventLogEntry, type ExplainResponse, type Health, type SigmaRuleMeta, type VerifyResponse } from './api/client'
import { formatLocalTime, formatLocalDateTime, formatRelative } from './utils/time'
import { parseStoredAiFields } from './utils/aiFields'
import { fallbackSigmaYaml } from './data/fallbacks'

type View = 'command' | 'path' | 'detection' | 'response' | 'telemetry' | 'logs'

const TOAST_STORAGE_KEY = 'authgraph:last-toast-incident'
const WEBHOOK_TOAST_KEY = 'authgraph:last-webhook-toast'

function markIncidentSeen(id: string, ref: React.MutableRefObject<string | null>) {
  ref.current = id
  try { sessionStorage.setItem(TOAST_STORAGE_KEY, id) } catch { /* private mode */ }
}

function markWebhookToastSeen(at: string, ref: React.MutableRefObject<string>) {
  ref.current = at
  try { sessionStorage.setItem(WEBHOOK_TOAST_KEY, at) } catch { /* private mode */ }
}

const NAV: { id: View; label: string; icon: typeof SquaresFour }[] = [
  { id: 'command',   label: 'Command',     icon: SquaresFour       },
  { id: 'path',      label: 'Attack path', icon: Graph             },
  { id: 'detection', label: 'Detection',   icon: TerminalWindow    },
  { id: 'response',  label: 'Response',    icon: ShieldCheck       },
  { id: 'logs',      label: 'Logs',        icon: Scroll            },
  { id: 'telemetry', label: 'Telemetry',   icon: GlobeHemisphereWest },
]

const PIPELINE = [
  { label: 'Active Directory', sub: '4768 / 4769' },
  { label: 'Wazuh SIEM', sub: 'ITDR rules' },
  { label: 'Sigma Rule', sub: 'T1558.x' },
  { label: 'AuthGraph', sub: 'Correlator' },
  { label: 'ARIA AI', sub: 'v4-flash / v4-pro' },
]

function isItdrAlert(a: Alert | null | undefined) {
  if (!a) return false
  const mitre = a.mitre ?? ''
  const attack = a.attack ?? ''
  const eid = a.event_id ?? 0
  return (
    attack === 'Kerberoasting' || mitre === 'T1558.003' || eid === 4769
    || attack === 'AS-REP Roasting' || mitre === 'T1558.004' || eid === 4768
    || mitre.startsWith('T1558')
  )
}

function pickPrimaryIncident(incidents: Alert[]) {
  const score = (i: Alert) => new Date(i.last_webhook_at || i.time || 0).getTime()
  const live = incidents
    .filter((i) => i.ingest_source === 'webhook' && isItdrAlert(i))
    .sort((a, b) => {
      if (a.status !== b.status) {
        if (a.status === 'contained') return 1
        if (b.status === 'contained') return -1
      }
      return score(b) - score(a)
    })
  if (live.length) return live[0]
  return incidents.find(isItdrAlert) ?? incidents[0] ?? null
}

function buildTimeline(alert: Alert | null, wazuhLive: boolean) {
  if (!alert) return []
  const base = formatLocalTime(alert.time)
  const enriched = formatLocalTime(alert.ai_enriched_at ?? alert.last_webhook_at ?? alert.time)
  return [
    { ts: base, text: `${alert.user} authenticates to domain` },
    { ts: base, text: `Target identity — ${alert.target}` },
    { ts: base, text: `${alert.attack} signal on ${alert.host} (Event ${alert.event_id})` },
    { ts: base, text: `Wazuh raises ${alert.attack} alert${wazuhLive ? ' · LIVE webhook' : ''}` },
    {
      ts: enriched,
      text: alert.ai_verdict
        ? 'ARIA verdict ready · deepseek-v4-flash + v4-pro'
        : 'AuthGraph correlates identity attack path',
    },
  ]
}

function AnimatedCounter({ value }: { value: number }) {
  const motionVal = useMotionValue(value)
  const spring = useSpring(motionVal, { stiffness: 60, damping: 18 })
  const [display, setDisplay] = useState(value)
  const prev = useRef(value)

  useEffect(() => {
    if (prev.current !== value) {
      motionVal.set(value)
      prev.current = value
    }
  }, [value, motionVal])

  useEffect(() => spring.on('change', (v) => setDisplay(Math.round(v))), [spring])

  return <>{display}</>
}

type KpiFilter = 'all' | 'open' | 'critical' | 'contained'

const LOGS_PAGE_SIZE = 25

export default function App() {
  const [view, setView] = useState<View>('command')
  const [connected, setConnected] = useState(false)
  const [wazuhLive, setWazuhLive] = useState(false)
  const [alert, setAlert] = useState<Alert | null>(null)
  const [incidents, setIncidents] = useState<Alert[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [healthData, setHealthData] = useState<Health | null>(null)
  const [eventLogs, setEventLogs] = useState<EventLogEntry[]>([])
  const [logsTotal, setLogsTotal] = useState(0)
  const [logsPage, setLogsPage] = useState(0)
  const [containExecution, setContainExecution] = useState<ContainExecution[]>([])
  const [containMode, setContainMode] = useState<'live' | 'simulated' | null>(null)
  const [copilotPrompt, setCopilotPrompt] = useState<{ text: string; key: number } | null>(null)
  const [simulating, setSimulating] = useState(false)
  const [attackPath, setAttackPath] = useState<AttackPath | null>(null)
  const [sigmaYaml, setSigmaYaml] = useState('')
  const [sigmaRules, setSigmaRules] = useState<SigmaRuleMeta[]>([])
  const [selectedSigmaId, setSelectedSigmaId] = useState('authgraph-kerberoasting-4769')
  const [explain, setExplain] = useState<ExplainResponse | null>(null)
  const [verify, setVerify] = useState<VerifyResponse | null>(null)
  const [aiActions, setAiActions] = useState<string[]>([])
  const [aiVerdict, setAiVerdict] = useState<string | null>(null)
  const [aiHeadline, setAiHeadline] = useState<string | null>(null)
  const [aiConfidence, setAiConfidence] = useState<string | null>(null)
  const [aiUrgency, setAiUrgency] = useState<string | null>(null)
  const [aiActionDetails, setAiActionDetails] = useState<{ priority: number; action: string; rationale: string; owner: string }[]>([])
  const [aiStatus, setAiStatus] = useState<string | null>(null)
  const [approvedActions, setApprovedActions] = useState<Set<string>>(new Set())
  const [toast, setToast] = useState<string | null>(null)
  const prevAlertId = useRef<string | null>(null)
  const initialLoadDone = useRef(false)
  const [contained, setContained] = useState(false)
  const [containActions, setContainActions] = useState<string[]>([])
  const [focusedNode, setFocusedNode] = useState<string | null>(null)
  const [, setDemoStep] = useState(0)
  const [riskScore, setRiskScore] = useState(12)
  const [timelineCount, setTimelineCount] = useState(0)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [clock, setClock] = useState('')
  const [kpiFilter, setKpiFilter] = useState<KpiFilter>('all')
  const [playbookFeedback, setPlaybookFeedback] = useState<'yes' | 'no' | null>(null)
  const lastWebhookToast = useRef<string>('')

  useEffect(() => {
    try {
      const seenId = sessionStorage.getItem(TOAST_STORAGE_KEY)
      if (seenId) prevAlertId.current = seenId
      const seenWebhook = sessionStorage.getItem(WEBHOOK_TOAST_KEY)
      if (seenWebhook) lastWebhookToast.current = seenWebhook
    } catch { /* private mode */ }
  }, [])
  const toastsSeen = useRef<Set<string>>(new Set())

  const applyAiFields = useCallback((inc: Alert) => {
    const ai = parseStoredAiFields(inc)
    if (ai.verdict) setAiVerdict(ai.verdict)
    if (ai.headline) setAiHeadline(ai.headline)
    if (ai.confidence) setAiConfidence(ai.confidence)
    if (ai.urgency) setAiUrgency(ai.urgency)
    if (inc.ai_actions?.length) setAiActions(inc.ai_actions)
    if (inc.ai_action_details?.length) setAiActionDetails(inc.ai_action_details)
    if (inc.ai_status) setAiStatus(inc.ai_status)
  }, [])

  const showNewAlertToast = useCallback((inc: Alert) => {
    setToast(`New ${inc.attack} alert — ${inc.user} → ${inc.target}`)
    window.setTimeout(() => setToast(null), 6000)
  }, [])

  const askAria = useCallback((prompt: string) => {
    setCopilotPrompt({ text: prompt, key: Date.now() })
  }, [])

  const applyIncident = useCallback((inc: Alert | null, all: Alert[]) => {
    setIncidents(all)
    if (!inc) {
      setAlert(null)
      return
    }
    setAlert(inc)
    setSelectedId(inc.id)
    setContained(inc.status === 'contained')
    setFocusedNode((f) => f ?? inc.target)
    applyAiFields(inc)
    if (inc.simulation_active) {
      setDemoStep(inc.demo_step ?? 0)
      setRiskScore(inc.risk)
      setTimelineCount(Math.min((inc.demo_step ?? 0) + 1, 5))
    } else if (isItdrAlert(inc)) {
      setRiskScore(inc.risk ?? 12)
      if ((inc.risk ?? 0) >= 70) {
        setDemoStep(3)
        setTimelineCount(5)
      } else if ((inc.risk ?? 0) >= 50) {
        setDemoStep(2)
        setTimelineCount(3)
      } else {
        setDemoStep(1)
        setTimelineCount(2)
      }
    }
  }, [applyAiFields])

  const selectIncident = useCallback(async (id: string) => {
    try {
      const inc = await api.incident(id)
      applyIncident(inc, incidents)
      setContained(inc.status === 'contained')
      setContainActions([])
      setApprovedActions(new Set())
      setContainExecution([])
      if (inc.ai_actions?.length) setAiActions(inc.ai_actions)
    } catch {
      const local = incidents.find((i) => i.id === id)
      if (local) applyIncident(local, incidents)
    }
  }, [applyIncident, incidents])

  const loadLogs = useCallback(async (page = logsPage) => {
    try {
      const r = await api.logs({ limit: LOGS_PAGE_SIZE, offset: page * LOGS_PAGE_SIZE })
      setEventLogs(r.events)
      setLogsTotal(r.total ?? r.events.length)
    } catch { /* offline */ }
  }, [logsPage])

  const refresh = useCallback(async () => {
    try {
      const [health, incidentList, path, sigma, rules, logsRes] = await Promise.all([
        api.health(),
        api.incidents(),
        api.attackPath(selectedId ?? undefined),
        api.sigma(selectedSigmaId),
        api.sigmaRules(),
        api.logs({ limit: LOGS_PAGE_SIZE, offset: logsPage * LOGS_PAGE_SIZE }),
      ])
      setEventLogs(logsRes.events)
      setLogsTotal(logsRes.total ?? logsRes.events.length)
      setHealthData(health)
      setConnected(health.ok)
      setWazuhLive(Boolean(health.data?.wazuh_kerberos ?? health.data?.wazuh_real))
      setAttackPath(path)
      setSigmaYaml(sigma.yaml)
      setSigmaRules(rules.rules)
      const preferred =
        selectedId && view === 'detection'
          ? incidentList.find((i) => i.id === selectedId) ?? pickPrimaryIncident(incidentList)
          : pickPrimaryIncident(incidentList)
      applyIncident(preferred ?? null, incidentList)
      if (preferred) {
        markIncidentSeen(preferred.id, prevAlertId)
        if (preferred.last_webhook_at) markWebhookToastSeen(preferred.last_webhook_at, lastWebhookToast)
      }
    } catch {
      setConnected(false)
      setSigmaYaml((current) => current || fallbackSigmaYaml)
    }
    finally {
      initialLoadDone.current = true
      setLoading(false)
    }
  }, [applyIncident, selectedSigmaId, selectedId, logsPage, view])

  useEffect(() => {
    if (!connected) return
    api.sigma(selectedSigmaId).then((s) => setSigmaYaml(s.yaml)).catch(() => undefined)
  }, [connected, selectedSigmaId])

  useEffect(() => {
    if (view !== 'detection' || !connected) return
    api.verify().then(setVerify).catch(() => undefined)
  }, [view, connected])

  useEffect(() => {
    loadLogs(logsPage)
    const id = window.setInterval(() => loadLogs(logsPage), 4000)
    return () => window.clearInterval(id)
  }, [loadLogs, logsPage])

  useEffect(() => {
    refresh()
    const poll = window.setInterval(async () => {
      try {
        const [status, incidents, health] = await Promise.all([api.simulateStatus(), api.incidents(), api.health()])
        setWazuhLive(Boolean(health.data?.wazuh_kerberos ?? health.data?.wazuh_real))
        if (status.active) {
          setSimulating(true)
          setDemoStep(status.step)
          setRiskScore(status.risk)
          setTimelineCount(status.timeline_count)
        } else {
          setSimulating(false)
        }
        setHealthData(health)
        loadLogs(logsPage).catch(() => undefined)
        const live = pickPrimaryIncident(incidents)
        if (live) {
          const pinnedOnDetection = Boolean(selectedId && view === 'detection')
          const toApply = pinnedOnDetection
            ? incidents.find((i) => i.id === selectedId) ?? live
            : live

          if (
            initialLoadDone.current
            && live.ingest_source === 'webhook'
            && live.last_webhook_at
            && live.last_webhook_at !== lastWebhookToast.current
            && isItdrAlert(live)
            && (live.risk ?? 0) >= 50
          ) {
            lastWebhookToast.current = live.last_webhook_at
            markWebhookToastSeen(live.last_webhook_at, lastWebhookToast)
            markIncidentSeen(live.id, prevAlertId)
            showNewAlertToast(live)
          }
          applyIncident(toApply, incidents)
          if (toApply.id) {
            api.attackPath(toApply.id).then(setAttackPath).catch(() => undefined)
          }
        } else {
          setIncidents(incidents)
          setAlert(null)
        }
      } catch { /* offline */ }
    }, 2000)
    return () => window.clearInterval(poll)
  }, [refresh, showNewAlertToast, applyIncident, selectedId, view, logsPage])

  useEffect(() => {
    const tick = () => {
      const now = new Date()
      setClock(now.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }))
    }
    tick()
    const id = window.setInterval(tick, 1000)
    return () => window.clearInterval(id)
  }, [])

  const hasIncident = Boolean(alert && isItdrAlert(alert) && ((alert.risk ?? 0) >= 50 || alert.ingest_source === 'webhook'))
  const hasLiveWebhook = incidents.some((i) => i.ingest_source === 'webhook')

  useEffect(() => {
    if (view !== 'response' || !alert?.id || !hasIncident || !connected) return
    api.aiRespond(alert.id).then((r) => {
      const ai = parseStoredAiFields({
        ai_verdict: r.verdict ?? null,
        ai_headline: r.headline ?? null,
        ai_confidence: r.confidence ?? null,
        ai_urgency: r.urgency ?? null,
      })
      if (r.actions?.length) setAiActions(r.actions)
      if (r.action_details?.length) setAiActionDetails(r.action_details)
      if (ai.verdict) setAiVerdict(ai.verdict)
      if (ai.headline) setAiHeadline(ai.headline)
      if (ai.confidence) setAiConfidence(ai.confidence)
      if (ai.urgency) setAiUrgency(ai.urgency)
      if (r.ai_status) setAiStatus(r.ai_status)
    }).catch(() => undefined)
  }, [view, alert?.id, hasIncident, connected])

  useEffect(() => {
    if (!alert?.id || !hasIncident || !connected) return
    api.explain(alert.id).then(setExplain).catch(() => undefined)
  }, [alert?.id, hasIncident, connected])

  useEffect(() => {
    if (!alert?.id || !hasIncident) return
    if (alert.ai_actions?.length) {
      setAiActions(alert.ai_actions)
      return
    }
    api.aiRespond(alert.id).then((r) => {
      const ai = parseStoredAiFields({
        ai_verdict: r.verdict ?? null,
        ai_headline: r.headline ?? null,
        ai_confidence: r.confidence ?? null,
        ai_urgency: r.urgency ?? null,
      })
      if (r.actions?.length) setAiActions(r.actions)
      if (r.action_details?.length) setAiActionDetails(r.action_details)
      if (ai.verdict) setAiVerdict(ai.verdict)
      if (ai.headline) setAiHeadline(ai.headline)
      if (ai.confidence) setAiConfidence(ai.confidence)
      if (ai.urgency) setAiUrgency(ai.urgency)
      if (r.ai_status) setAiStatus(r.ai_status)
    }).catch(() => undefined)
  }, [alert?.id, alert?.ai_actions, hasIncident])

  const incidentTimeline = buildTimeline(alert, wazuhLive)
  const timeline = incidentTimeline

  const openCount = healthData?.incidents?.open ?? incidents.filter((i) => i.ingest_source === 'webhook' && i.status !== 'contained').length
  const containedCount = healthData?.incidents?.contained ?? incidents.filter((i) => i.status === 'contained').length
  const identityCount = attackPath?.nodes.length ?? 0
  const realIncidents = incidents.filter((i) => i.ingest_source === 'webhook')
  const criticalCount = realIncidents.filter((i) => i.severity === 'critical' && i.status !== 'contained').length

  const logActivity = eventLogs.filter((e) => {
    const age = Date.now() - new Date(e.ts).getTime()
    return age < 60000 && (e.level === 'alert' || e.level === 'webhook')
  }).length

  const filteredIncidents = realIncidents.filter((inc) => {
    if (kpiFilter === 'open') return inc.status !== 'contained'
    if (kpiFilter === 'critical') return inc.severity === 'critical' && inc.status !== 'contained'
    if (kpiFilter === 'contained') return inc.status === 'contained'
    return true
  })

  const logsTotalPages = Math.max(1, Math.ceil(logsTotal / LOGS_PAGE_SIZE))
  const logsPageNumbers = (() => {
    const max = logsTotalPages
    if (max <= 7) return Array.from({ length: max }, (_, i) => i)
    const start = Math.max(0, Math.min(logsPage - 2, max - 5))
    return Array.from({ length: 5 }, (_, i) => start + i)
  })()

  function onKpiClick(filter: KpiFilter | 'pipeline') {
    if (filter === 'pipeline') {
      setView('logs')
      return
    }
    setKpiFilter(filter)
    setView('detection')
  }

  const riskAfter = contained
    ? Math.min(alert?.risk ?? riskScore, 32)
    : (alert?.risk ?? riskScore)
  const focus = focusedNode ?? alert?.target ?? attackPath?.nodes[0]?.id ?? ''
  const responseList = contained
    ? containActions
    : aiActions.length ? aiActions : alert?.response ?? []

  async function runSimulation() {
    if (busy || !hasLiveWebhook) return
    setBusy(true)
    setSimulating(true)
    setContained(false)
    setContainActions([])
    setContainExecution([])
    setContainMode(null)
    setApprovedActions(new Set())
    setAiVerdict(null)
    setAiHeadline(null)
    setAiConfidence(null)
    setAiUrgency(null)
    setAiStatus(null)
    setAiActions([])
    try {
      const r = await api.simulateKerberoast()
      setDemoStep(r.status?.step ?? 1)
      setRiskScore(r.status?.risk ?? 12)
      setTimelineCount(r.status?.timeline_count ?? 1)
      await refresh()
      setView('command')
      const inc = r.incident ?? alert
      if (inc) {
        markIncidentSeen(inc.id, prevAlertId)
        toastsSeen.current.add(inc.id)
      }
      setToast('Re-analyzing live Wazuh alert with ARIA…')
      window.setTimeout(() => setToast(null), 4000)
    } finally {
      setBusy(false)
    }
  }

  async function containIdentity() {
    if (!alert || busy || contained) return
    const toExecute = approvedActions.size > 0 ? [...approvedActions] : responseList
    if (!toExecute.length) return
    setBusy(true)
    try {
      const r = await api.contain(alert.id, toExecute)
      setContained(true)
      setDemoStep(4)
      setRiskScore(r.risk_after)
      setTimelineCount(5)
      setContainActions(r.actions)
      setContainExecution(r.execution ?? [])
      setContainMode(r.mode ?? 'simulated')
      setPlaybookFeedback(null)
      setToast(r.mode === 'live' ? 'Playbook executed on lab AD' : 'Playbook logged — copy PowerShell from Response tab and run in lab AD')
      window.setTimeout(() => setToast(null), 5000)
      await refresh()
    } finally {
      setBusy(false)
    }
  }

  function toggleActionApproval(action: string) {
    setApprovedActions((prev) => {
      const next = new Set(prev)
      if (next.has(action)) next.delete(action)
      else next.add(action)
      return next
    })
  }

  function approveAllActions() {
    setApprovedActions(new Set(responseList))
  }

  async function resetDemo() {
    if (busy) return
    setBusy(true)
    try {
      await api.simulateReset()
      setContained(false)
      setDemoStep(0)
      setRiskScore(12)
      setTimelineCount(0)
      setContainActions([])
      setContainExecution([])
      setContainMode(null)
      setPlaybookFeedback(null)
      setFocusedNode(null)
      setApprovedActions(new Set())
      setAiVerdict(null)
      setAiHeadline(null)
      setAiConfidence(null)
      setAiUrgency(null)
      setAiStatus(null)
      setAiActions([])
      setAiActionDetails([])
      try {
        sessionStorage.removeItem(TOAST_STORAGE_KEY)
        sessionStorage.removeItem(WEBHOOK_TOAST_KEY)
      } catch { /* ignore */ }
      await refresh()
    } finally {
      setBusy(false)
    }
  }

  function actionSubtext(i: number) {
    const detail = aiActionDetails[i]
    const attack = alert?.attack ?? 'ITDR'
    if (detail?.rationale && !/standard kerberoasting/i.test(detail.rationale)) {
      return `${detail.owner} · ${detail.rationale}`
    }
    if (detail?.owner) return `${detail.owner} · ${attack} · step ${i + 1}`
    return `${attack} · priority ${i + 1}`
  }

  function openPlaybookRefinement() {
    setPlaybookFeedback('no')
    const blocks = containExecution
      .map((ex) => `Action: ${ex.action}\n\`\`\`powershell\n${ex.command}\n\`\`\``)
      .join('\n\n')
    setCopilotPrompt({
      text: `The containment playbook for ${alert?.attack ?? 'this incident'} (target ${alert?.target}, host ${alert?.host}) needs a complete rewrite.

Current commands (incomplete for our lab):
${blocks}

Provide FULL copy-paste PowerShell for each action on ${alert?.host ?? 'the DC'}:
1. Audit — show current Kerberos pre-auth / SPN / encryption settings for ${alert?.target}
2. Contain — disable "Do not require Kerberos preauth" safely
3. Remediate — force password reset with verification
4. Verify — confirm the account is no longer AS-REP roastable

Use separate \`\`\`powershell code blocks. Include -Server '${alert?.host ?? 'SERVER01'}' on every Set/Get-AD* command.`,
      key: Date.now(),
    })
  }

  if (loading) {
    return (
      <div className="boot">
        <div className="boot__orb" />
        <img src="/logo111.png" alt="" className="boot__logo" />
        <span>Connecting to detection pipeline…</span>
      </div>
    )
  }

  return (
    <div className={`ag ${hasIncident && !contained ? 'ag--incident' : ''}`}>
      {/* ambient bg */}
      <div className="ag__bg" aria-hidden />

      <AnimatePresence>
        {toast && (
          <motion.div
            className="ag__toast"
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -12 }}
          >
            <WarningCircle size={18} weight="fill" />
            <span>{toast}</span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* topbar */}
      <header className="ag__header">
        <div className="ag__brand">
          <a className="ag__logo-link" href="/" aria-label="AuthGraph ITDR home">
            <img src="/logo111.png" alt="AuthGraph" className="ag__logo-img" />
          </a>
        </div>

        <div className="ag__kpis">
          {(wazuhLive || simulating || (connected && hasIncident && !simulating)) && (
            <div className="ag__env-status" aria-label="Environment status">
              {wazuhLive && <span className="ag__live-badge">LIVE WAZUH</span>}
              {!wazuhLive && connected && simulating && <span className="ag__demo-badge">SIMULATING</span>}
              {!wazuhLive && connected && hasIncident && !simulating && <span className="ag__demo-badge">DEMO DATA</span>}
            </div>
          )}
          <motion.button
            type="button"
            className={`kpi kpi--click ${kpiFilter === 'open' ? 'is-active' : ''} ${openCount > 0 ? 'kpi--alert' : ''}`}
            onClick={() => onKpiClick('open')}
            animate={openCount > 0 ? { boxShadow: ['0 0 0 0 rgba(255,92,92,0)', '0 0 0 8px rgba(255,92,92,0.12)', '0 0 0 0 rgba(255,92,92,0)'] } : {}}
            transition={{ repeat: Infinity, duration: 2.4 }}
          >
            <ChartLineUp size={15} />
            <span>Open</span>
            <b>{openCount}</b>
          </motion.button>
          <button
            type="button"
            className={`kpi kpi--click ${kpiFilter === 'critical' ? 'is-active' : ''} ${criticalCount > 0 ? 'kpi--critical' : ''}`}
            onClick={() => onKpiClick('critical')}
          >
            <WarningCircle size={15} />
            <span>Critical</span>
            <b>{criticalCount}</b>
          </button>
          <button
            type="button"
            className={`kpi kpi--click ${kpiFilter === 'contained' ? 'is-active' : ''}`}
            onClick={() => onKpiClick('contained')}
          >
            <ShieldCheck size={15} />
            <span>Contained</span>
            <b>{containedCount}</b>
          </button>
          <button
            type="button"
            className={`kpi kpi--click ${connected ? 'kpi--live' : ''}`}
            onClick={() => onKpiClick('pipeline')}
            title="View pipeline event log"
          >
            <span className="kpi__dot" />
            <span>Pipeline</span>
            <b>{connected ? 'Live' : 'Down'}</b>
          </button>
        </div>

        <div className="ag__toolbar">
          <button
            className="ag__btn ag__btn--ghost"
            onClick={resetDemo}
            disabled={busy}
            aria-label="Reset demo state"
            title="Clear contained/demo flags and reload incidents (keeps live Wazuh alerts)"
          >
            <ArrowClockwise size={14} />
          </button>
          <button
            className="ag__btn"
            onClick={runSimulation}
            disabled={busy || simulating || !hasLiveWebhook}
            title={hasLiveWebhook ? 'Re-run ARIA analysis on the latest live Wazuh alert' : 'Waiting for a live Wazuh ITDR webhook from your lab'}
          >
            <Play size={13} weight="fill" /> {simulating ? 'Analyzing…' : 'Re-analyze'}
          </button>
          <button
            className={`ag__btn ag__btn--contain ${contained ? 'is-done' : ''}`}
            onClick={containIdentity}
            disabled={!hasIncident || contained || busy || !responseList.length || (!contained && approvedActions.size === 0 && aiActions.length > 0)}
            title={!contained && approvedActions.size === 0 && aiActions.length > 0 ? 'Approve response actions first' : 'Copy commands from Response tab, run in lab AD, then mark playbook done'}
          >
            <ShieldCheck size={13} /> {contained ? 'Playbook recorded' : approvedActions.size ? `Mark done (${approvedActions.size})` : 'Response'}
          </button>
          <time className="ag__clock">{clock}</time>
        </div>
      </header>

      <div className="ag__shell">
        {/* sidebar nav */}
        <nav className="ag__nav" aria-label="Navigation">
          {NAV.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              type="button"
              className={view === id ? 'is-active' : ''}
              onClick={() => setView(id)}
            >
              <Icon size={19} weight={view === id ? 'fill' : 'duotone'} />
              <span>{label}</span>
              {id === 'command' && hasIncident && !contained && (
                <span className="nav__badge" />
              )}
              {id === 'logs' && eventLogs.length > 0 && view !== 'logs' && (
                <span className="nav__badge nav__badge--muted" />
              )}
            </button>
          ))}
        </nav>

        <main className="ag__main">
          <AnimatePresence mode="wait">
            <motion.div
              key={view}
              className="ag__view"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
            >

              {/* ── COMMAND ── */}
              {view === 'command' && (
                <div className="cmd">
                  {/* Hero */}
                  <section className={`cmd__hero ${hasIncident && !contained ? 'cmd__hero--critical' : ''} ${contained ? 'cmd__hero--ok' : ''}`}>
                    <div className="cmd__hero-bg" aria-hidden />
                    <div className="cmd__hero-grid">
                      <div className="cmd__hero-left">
                        <div className="cmd__hero-label">
                          {hasIncident && !contained
                            ? <><span className="pulse-dot" />Identity under attack</>
                            : contained
                              ? <><ShieldCheck size={14} weight="duotone" />Playbook recorded</>
                              : <><Eye size={14} weight="duotone" />Perimeter monitoring</>
                          }
                        </div>
                        <h1 className="cmd__hero-title">
                          {hasIncident
                            ? <><span className="cmd__hero-attack">{alert?.attack}</span><br />targeting <em>{alert?.target}</em></>
                            : 'Identity perimeter secure'}
                        </h1>
                        {hasIncident ? (
                          <div className="cmd__hero-tags">
                            <span><code>{alert?.user}</code></span>
                            <span>Event <code>{alert?.event_id}</code></span>
                            <span><code>{alert?.host}</code></span>
                            <span><code>{alert?.source_ip}</code></span>
                            <span className="cmd__mitre">MITRE <code>{alert?.mitre}</code></span>
                          </div>
                        ) : (
                          <p className="cmd__hero-sub">Wazuh · Sigma · AuthGraph pipeline armed. Run Kerberoasting or AS-REP in lab to trigger live detection.</p>
                        )}
                      </div>

                      <div className="cmd__hero-ring-wrap">
                        <svg width="140" height="140" viewBox="0 0 140 140" className="cmd__hero-ring">
                          <circle cx="70" cy="70" r="58" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
                          <motion.circle
                            cx="70" cy="70" r="58" fill="none"
                            stroke={hasIncident && !contained ? 'var(--red)' : contained ? 'var(--green)' : 'var(--blue)'}
                            strokeWidth="10" strokeLinecap="round"
                            strokeDasharray={364}
                            animate={{ strokeDashoffset: 364 - (364 * riskAfter) / 100 }}
                            transition={{ duration: 0.9, ease: [0.16, 1, 0.3, 1] }}
                            transform="rotate(-90 70 70)"
                          />
                        </svg>
                        <div className="cmd__hero-ring-label">
                          <strong><AnimatedCounter value={riskAfter} /></strong>
                          <span>risk score</span>
                        </div>
                      </div>
                    </div>
                  </section>

                  {/* Detection pipeline strip */}
                  <section className="cmd__pipeline glass-pane">
                    <div className="cmd__pipeline-inner">
                      {PIPELINE.map((step, i) => {
                        const live =
                          i === 1
                            ? wazuhLive || hasIncident
                            : i === 3
                              ? connected
                              : i === 4
                                ? hasIncident
                                : true
                        return (
                          <div key={step.label} className="cmd__pipe-step">
                            <div className={`cmd__pipe-node ${live ? 'is-live' : ''} ${hasIncident && i === PIPELINE.length - 1 && !contained ? 'is-pulse' : ''}`}>
                              <span className="cmd__pipe-dot" />
                              <strong>{step.label}</strong>
                              <em>{step.sub}</em>
                            </div>
                            {i < PIPELINE.length - 1 && <div className={`cmd__pipe-line ${live ? 'is-live' : ''}`} />}
                          </div>
                        )
                      })}
                    </div>
                  </section>

                  {hasIncident && (
                    <section className="glass-pane cmd__verdict">
                      <div className="pane-head">
                        <h2><Cpu size={13} weight="fill" /> ARIA verdict</h2>
                        <span>
                          {aiStatus === 'pending'
                            ? 'Analyzing · deepseek-v4-flash + v4-pro…'
                            : 'deepseek-v4-flash · deepseek-v4-pro'}
                        </span>
                      </div>
                      <div className="cmd__verdict-body">
                        {aiHeadline && <strong className="cmd__verdict-headline">{aiHeadline}</strong>}
                        <div className="cmd__verdict-meta">
                          {aiConfidence && <span className={`cmd__verdict-badge cmd__verdict-badge--${aiConfidence}`}>{aiConfidence} confidence</span>}
                          {aiUrgency && <span className={`cmd__verdict-badge cmd__verdict-badge--${aiUrgency}`}>{aiUrgency} urgency</span>}
                          {alert?.mitre && <span className="cmd__verdict-badge">{alert.mitre}</span>}
                        </div>
                        {aiStatus === 'pending' && !aiVerdict ? (
                          <p className="cmd__verdict-pending"><span className="pulse-dot" /> Correlating identity path and reasoning on blast radius…</p>
                        ) : aiVerdict ? (
                          <p className="cmd__verdict-text">{aiVerdict}</p>
                        ) : (
                          <p>{`${alert?.attack}: ${alert?.user} targeting ${alert?.target}. Risk ${alert?.risk}/100 — review containment actions.`}</p>
                        )}
                      </div>
                    </section>
                  )}

                  {/* Stat cards */}
                  <div className="cmd__stats">
                    {[
                      { icon: Fingerprint, label: 'Identities', val: String(identityCount), sub: 'in attack path graph', tone: '' },
                      { icon: TerminalWindow, label: 'Sigma rules', val: String(sigmaRules.length || 0), sub: 'AD + Entra library', tone: 'ok' },
                      { icon: Radioactive, label: 'MITRE', val: alert?.mitre ?? '—', sub: hasIncident ? 'technique mapped' : 'awaiting incident', tone: hasIncident ? 'warn' : '' },
                      { icon: Database, label: 'Events/min', val: String(logActivity || (hasIncident ? timelineCount * 12 : 0)), sub: connected ? 'from event log' : 'offline', tone: hasIncident ? 'crit' : '' },
                    ].map(({ icon: Icon, label, val, sub, tone }) => (
                      <motion.div key={label} className={`stat-card ${tone ? `stat-card--${tone}` : ''}`} whileHover={{ y: -2 }}>
                        <Icon size={18} weight="duotone" />
                        <div>
                          <span>{label}</span>
                          <strong>{val}</strong>
                          <em>{sub}</em>
                        </div>
                      </motion.div>
                    ))}
                  </div>

                  <div className="cmd__body">
                    <div className="cmd__main-col">
                      {attackPath && alert && (
                        <section className="glass-pane">
                          <div className="pane-head">
                            <h2><Graph size={13} weight="fill" /> Attack path</h2>
                            <button type="button" onClick={() => setView('path')}>Full graph →</button>
                          </div>
                          <AttackPathPipeline
                            attackPath={attackPath}
                            targetId={alert.target}
                            focusedId={focus}
                            onFocus={setFocusedNode}
                            hasIncident={hasIncident}
                            contained={contained}
                          />
                        </section>
                      )}

                      <section className="glass-pane cmd__telemetry-mini">
                        <div className="pane-head">
                          <h2><GlobeHemisphereWest size={13} weight="fill" /> Global telemetry</h2>
                          <button type="button" onClick={() => setView('telemetry')}>Expand →</button>
                        </div>
                        <TelemetryGlobe
                          active={hasIncident}
                          contained={contained}
                          user={alert?.user}
                          target={alert?.target}
                          host={alert?.host}
                          sourceIp={alert?.source_ip}
                        />
                      </section>

                      <div className="cmd__feed-row">
                        <section className="glass-pane">
                          <div className="pane-head">
                            <h2><Lightning size={13} weight="fill" /> Live activity</h2>
                            <span>{timelineCount}/{timeline.length}</span>
                          </div>
                          <ol className="activity-feed">
                            {timeline.map(({ ts, text }, i) => (
                              <motion.li key={`${ts}-${i}`} className={i < timelineCount ? 'is-done' : ''} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.05 }}>
                                <Clock size={12} weight="duotone" />
                                <time>{ts}</time>
                                <span>{text}</span>
                              </motion.li>
                            ))}
                          </ol>
                        </section>

                        {hasIncident && responseList.length > 0 && (
                          <section className="glass-pane">
                            <div className="pane-head">
                              <h2><Cpu size={13} weight="fill" /> AI response</h2>
                              <button type="button" onClick={() => setView('response')}>All actions →</button>
                            </div>
                            <ol className="cmd__ai-preview">
                              {responseList.slice(0, 3).map((a, i) => (
                                <li key={a}><span>{i + 1}</span>{a}</li>
                              ))}
                            </ol>
                          </section>
                        )}
                      </div>
                    </div>

                    <div className="cmd__right">
                      <section className="glass-pane cmd__risk-pane">
                        <div className="pane-head"><h2><ChartLineUp size={13} weight="fill" /> Identity risk</h2></div>
                        <RiskPanel alert={alert} score={riskAfter} focusedNode={focus} contained={contained} hasIncident={hasIncident} />
                      </section>
                    </div>
                  </div>
                </div>
              )}

              {/* ── ATTACK PATH ── */}
              {view === 'path' && attackPath && (
                <div className="path-layout">
                  {!alert && (
                    <p className="hint path-layout__hint">Select an alert from Detection → Alert inbox to reconstruct its path.</p>
                  )}
                  {alert && (
                  <>
                  <section className="glass-pane glass-pane--grow">
                    <div className="pane-head">
                      <h2>Attack path reconstruction</h2>
                      <span>{alert.attack} · {alert.user} → {alert.target} · click nodes to inspect</span>
                    </div>
                    <AttackGraph
                      attackPath={attackPath}
                      targetId={alert.target}
                      focusedId={focus}
                      onFocus={setFocusedNode}
                      hasIncident={hasIncident}
                      contained={contained}
                      height={380}
                    />
                  </section>
                  <aside className="glass-pane path-aside">
                    <div className="pane-head"><h2>Node detail</h2></div>
                    {(() => {
                      const node = attackPath.nodes.find((n) => n.id === focus)
                      if (!node) return <p className="hint">Click a node to inspect</p>
                      return (
                        <div className="path-node-detail">
                          <h3>{node.id}</h3>
                          <span className={`badge badge--${node.risk}`}>{node.risk} risk</span>
                          <p className="path-node-detail__type">{node.type.replace(/_/g, ' ')}</p>
                          <AskAriaButton
                            label="Explain this node"
                            prompt={`Explain the role of identity "${node.id}" (${node.type}) in this Kerberoasting attack path and why its risk is ${node.risk}.`}
                            onAsk={askAria}
                            disabled={!hasIncident}
                          />
                          <ul className="path-node-detail__edges">
                            {attackPath.edges.filter((e) => e.from === focus || e.to === focus).map((e) => (
                              <li key={`${e.from}-${e.to}`}>
                                <span>{e.from}</span>
                                <em>→ {e.label}</em>
                                <span>{e.to}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )
                    })()}
                  </aside>
                  </>
                  )}
                </div>
              )}

              {/* ── DETECTION ── */}
              {view === 'detection' && (
                <div className="detect-layout">
                  {verify && (
                    <section className="glass-pane span-2 detect-mvp">
                      <div className="pane-head">
                        <h2>MVP verification</h2>
                        <span className={verify.ok ? 'txt-ok' : 'txt-warn'}>
                          {verify.passed}/{verify.total} checks · {verify.ok ? 'All MVP requirements met' : 'Review failed checks'}
                        </span>
                      </div>
                      <div className="detect-mvp__grid">
                        {[
                          { key: 'kerberoasting_poc', label: 'Kerberoasting PoC' },
                          { key: 'sigma_rule', label: 'Sigma rule' },
                          { key: 'wazuh_alert', label: 'Wazuh / SIEM alert' },
                          { key: 'attack_verification', label: 'Attack verification' },
                        ].map(({ key, label }) => (
                          <div key={key} className={`detect-mvp__item ${verify.mvp[key as keyof typeof verify.mvp] ? 'is-pass' : 'is-fail'}`}>
                            <ShieldCheck size={16} weight={verify.mvp[key as keyof typeof verify.mvp] ? 'fill' : 'duotone'} />
                            <span>{label}</span>
                          </div>
                        ))}
                      </div>
                      <ul className="detect-verify-list">
                        {verify.checks.map((c) => (
                          <li key={c.name} className={c.pass ? 'is-pass' : 'is-fail'}>
                            <span>{c.pass ? '✓' : '○'}</span>
                            <div><strong>{c.name}</strong><em>{c.detail}</em></div>
                          </li>
                        ))}
                      </ul>
                    </section>
                  )}

                  {hasIncident && explain && (
                    <section className="glass-pane span-2 detect-explain">
                      <div className="pane-head">
                        <h2>Why this fired</h2>
                        <span>{explain.mitre} · {explain.confidence ?? 'high'} confidence</span>
                        <AskAriaButton
                          label="Explain detection"
                          prompt={`Explain why this ${explain.attack} alert fired for ${explain.user} → ${explain.target}. Reference the sigma chain and risk factors.`}
                          onAsk={askAria}
                          disabled={!hasIncident}
                        />
                      </div>
                      <p className="detect-explain__summary">{explain.summary}</p>
                      <div className="detect-explain__cols">
                        <div>
                          <h3>Sigma match chain</h3>
                          <ol>{explain.sigma.map((s) => <li key={s}>{s}</li>)}</ol>
                        </div>
                        <div>
                          <h3>Risk factors</h3>
                          <ul className="detect-risk-factors">
                            {explain.risk_factors.map((f) => (
                              <li key={f.factor}>
                                <span>{f.factor.replace(/_/g, ' ')}</span>
                                <strong>+{f.points}</strong>
                                <em>{f.description}</em>
                              </li>
                            ))}
                          </ul>
                        </div>
                        <div>
                          <h3>Evidence</h3>
                          <ul>{explain.evidence.map((e) => <li key={e}>{e}</li>)}</ul>
                        </div>
                      </div>
                    </section>
                  )}

                  <section className="glass-pane span-2">
                    <div className="pane-head">
                      <h2>Alert inbox</h2>
                      <span>
                        {filteredIncidents.length}/{realIncidents.length} live alerts
                        {kpiFilter !== 'all' ? ` · filter: ${kpiFilter}` : ''}
                        {' · '}select to analyze with ARIA
                      </span>
                      {kpiFilter !== 'all' && (
                        <button type="button" className="ag__btn ag__btn--ghost" onClick={() => setKpiFilter('all')}>Clear filter</button>
                      )}
                    </div>
                    <table className="data-table data-table--selectable">
                      <thead><tr><th></th><th>Time</th><th>Attack</th><th>Source</th><th>Actor</th><th>Target</th><th>Host</th><th>Risk</th><th>Status</th><th></th></tr></thead>
                      <tbody>
                        {filteredIncidents.length === 0
                          ? <tr><td colSpan={10} className="empty">No alerts match filter — try Run attack or Wazuh/Yara webhook</td></tr>
                          : filteredIncidents.map((inc) => (
                            <tr
                              key={inc.id}
                              className={inc.id === alert?.id ? 'is-active' : ''}
                              onClick={() => selectIncident(inc.id)}
                            >
                              <td><input type="radio" checked={inc.id === alert?.id} readOnly aria-label={`Select ${inc.id}`} /></td>
                              <td title={inc.time}>{formatLocalDateTime(inc.time)}</td>
                              <td>{inc.attack}</td>
                              <td><code>{inc.ingest_source ?? 'sample'}</code></td>
                              <td>{inc.user}</td>
                              <td>{inc.target}</td>
                              <td>{inc.host}</td>
                              <td><span className={`badge badge--${inc.severity}`}>{inc.id === alert?.id ? riskAfter : inc.risk}</span></td>
                              <td>{inc.status === 'contained' ? 'Contained' : inc.simulation_active ? 'Correlating' : 'Open'}</td>
                              <td>
                                <AskAriaButton
                                  label="Analyze"
                                  prompt={`Analyze alert ${inc.id}: ${inc.attack} from ${inc.user} targeting ${inc.target} on ${inc.host}. Risk ${inc.risk}.`}
                                  onAsk={(p) => { selectIncident(inc.id); askAria(p) }}
                                  disabled={false}
                                  className="ask-aria--table"
                                />
                              </td>
                            </tr>
                          ))
                        }
                      </tbody>
                    </table>
                  </section>

                  <section className="glass-pane">
                    <div className="pane-head"><h2>Selected incident</h2></div>
                    <table className="data-table">
                      <thead><tr><th>Time</th><th>Event</th><th>Actor</th><th>Target</th><th>Host</th><th>Risk</th><th>Status</th></tr></thead>
                      <tbody>
                        {alert
                          ? <tr className="is-active">
                              <td>{formatLocalDateTime(alert.time)}</td>
                              <td><code>{alert.event_id}</code></td>
                              <td>{alert.user}</td>
                              <td>{alert.target}</td>
                              <td>{alert.host}</td>
                              <td><span className={`badge badge--${alert.severity}`}>{riskAfter}</span></td>
                              <td>{contained ? 'Contained' : simulating ? 'Correlating' : 'Open'}</td>
                            </tr>
                          : <tr><td colSpan={7} className="empty">No incident selected</td></tr>
                        }
                      </tbody>
                    </table>
                  </section>
                  <section className="glass-pane">
                    <div className="pane-head"><h2>Attack timeline</h2></div>
                    <ol className="timeline-list">
                      {timeline.map(({ ts, text }, i) => (
                        <li key={`${ts}-${i}`} className={i < timelineCount ? 'is-done' : ''}>
                          <div className="timeline-list__dot" />
                          <time>{ts}</time>
                          <span>{text}</span>
                        </li>
                      ))}
                    </ol>
                  </section>
                  <section className="glass-pane span-2">
                    <div className="pane-head">
                      <h2>Sigma rule library</h2>
                      <span>{sigmaRules.length} rules · AD + Entra ID</span>
                    </div>
                    <div className="sigma-library">
                      {sigmaRules.map((rule) => (
                        <button
                          key={rule.id}
                          type="button"
                          className={`sigma-library__item ${selectedSigmaId === rule.id ? 'is-active' : ''}`}
                          onClick={() => setSelectedSigmaId(rule.id)}
                        >
                          <strong>{rule.title}</strong>
                          <span>{rule.platform}</span>
                          <em>{rule.mitre} · {rule.status}</em>
                        </button>
                      ))}
                    </div>
                    <pre className="code-block">{sigmaYaml || 'Loading…'}</pre>
                  </section>
                </div>
              )}

              {/* ── RESPONSE ── */}
              {view === 'response' && (
                <div className="response-layout response-layout--solo">
                  <section className="glass-pane glass-pane--response glass-pane--grow">
                    <div className="pane-head">
                      <h2>Response actions</h2>
                      <span>
                        {contained
                          ? `Recorded · ${containMode === 'live' ? 'live AD execution' : 'copy-run playbook'}`
                          : aiActions.length
                            ? 'Proposed · approve, copy commands, mark done'
                            : aiStatus === 'pending'
                              ? 'ARIA generating actions…'
                              : 'Waiting for incident'}
                      </span>
                    </div>
                    {!contained && aiActions.length > 0 && (
                      <div className="response-approve-bar">
                        <button type="button" className="ag__btn ag__btn--ghost" onClick={approveAllActions}>
                          Approve all
                        </button>
                        <span>{approvedActions.size}/{responseList.length} approved</span>
                      </div>
                    )}
                    <ol className="action-list action-list--wide">
                      {responseList.map((a, i) => (
                        <motion.li
                          key={a}
                          className={approvedActions.has(a) ? 'is-approved' : ''}
                          initial={{ opacity: 0, x: -12 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.07, ease: [0.16, 1, 0.3, 1] }}
                        >
                          {!contained && aiActions.length > 0 && (
                            <label className="action-approve">
                              <input
                                type="checkbox"
                                checked={approvedActions.has(a)}
                                onChange={() => toggleActionApproval(a)}
                              />
                            </label>
                          )}
                          <span>{i + 1}</span>
                          <div>
                            <strong>{a}</strong>
                            <small>{actionSubtext(i)}</small>
                          </div>
                          {contained && <ShieldCheck size={16} weight="fill" className="txt-ok" />}
                          {!contained && approvedActions.has(a) && <ShieldCheck size={16} weight="duotone" className="txt-ok" />}
                        </motion.li>
                      ))}
                    </ol>
                    {!hasIncident && <p className="hint">Run an attack demo or ingest a Wazuh ITDR webhook (Kerberoasting, AS-REP, etc.). Approve actions, copy PowerShell, run in lab AD, then Mark done.</p>}
                    {contained && containExecution.length > 0 && (
                      <div className="response-exec-log">
                        <h3>Playbook commands</h3>
                        <p className="hint">
                          {containMode === 'live'
                            ? 'Commands ran against lab AD.'
                            : 'Copy each block into PowerShell on your domain controller. Set LAB_AD_ENABLED=true in backend/.env only if you want automated execution.'}
                        </p>
                        <ol>
                          {containExecution.map((ex) => (
                            <li key={ex.playbook_id + ex.action} className={`response-exec-log__item response-exec-log__item--${ex.status}`}>
                              <strong>{ex.action}</strong>
                              <CodeBlock code={ex.command} lang="powershell" />
                              <span className="response-exec-log__status">{ex.status} — {ex.message}</span>
                            </li>
                          ))}
                        </ol>
                        {playbookFeedback === null && (
                          <div className="response-feedback">
                            <p>Are you satisfied with the playbook output?</p>
                            <div className="response-feedback__actions">
                              <button type="button" className="ag__btn" onClick={() => setPlaybookFeedback('yes')}>
                                Yes — looks good
                              </button>
                              <button
                                type="button"
                                className="ag__btn ag__btn--ghost"
                                onClick={openPlaybookRefinement}
                              >
                                No — refine with ARIA
                              </button>
                            </div>
                          </div>
                        )}
                        {playbookFeedback === 'yes' && (
                          <p className="response-feedback__ok">Playbook accepted. Incident stays marked as contained in the dashboard.</p>
                        )}
                        {playbookFeedback === 'no' && (
                          <p className="response-feedback__hint">ARIA opened with your refinement request — adjust commands in chat.</p>
                        )}
                      </div>
                    )}
                  </section>
                </div>
              )}

              {/* ── LOGS ── */}
              {view === 'logs' && (
                <div className="logs-layout">
                  <section className="glass-pane glass-pane--grow">
                    <div className="pane-head">
                      <h2>Security event log</h2>
                      <span>{logsTotal} events · page {logsPage + 1}/{logsTotalPages} · syncs every 4s</span>
                    </div>
                    <div className="logs-stream">
                      {eventLogs.length === 0
                        ? <p className="hint logs-stream__empty">No events on this page — try page 1 or run an attack / webhook.</p>
                        : eventLogs.map((ev) => (
                          <article key={ev.id} className={`logs-stream__row logs-stream__row--${ev.level}`}>
                            <div className="logs-stream__head">
                              <time title={ev.ts ?? ''}>{formatLocalDateTime(ev.ts)} <em>{formatRelative(ev.ts)}</em></time>
                              <span className={`logs-stream__level logs-stream__level--${ev.level}`}>{ev.level}</span>
                              <span className="logs-stream__msg">{ev.message}</span>
                              {ev.incident_id && (
                                <button type="button" className="logs-stream__link" onClick={() => { selectIncident(ev.incident_id!); setView('detection') }}>
                                  {ev.incident_id}
                                </button>
                              )}
                            </div>
                            {(ev.preview || ev.command) && (
                              <pre className="logs-stream__detail">{ev.command || ev.preview}</pre>
                            )}
                          </article>
                        ))
                      }
                    </div>
                    {logsTotal > LOGS_PAGE_SIZE && (
                      <nav className="logs-pagination" aria-label="Log pages">
                        <button
                          type="button"
                          className="ag__btn ag__btn--ghost"
                          disabled={logsPage === 0}
                          onClick={() => setLogsPage((p) => Math.max(0, p - 1))}
                        >
                          Prev
                        </button>
                        <div className="logs-pagination__pages">
                          {logsPageNumbers[0] > 0 && (
                            <>
                              <button type="button" className={`logs-pagination__num ${logsPage === 0 ? 'is-active' : ''}`} onClick={() => setLogsPage(0)}>1</button>
                              {logsPageNumbers[0] > 1 && <span className="logs-pagination__gap">…</span>}
                            </>
                          )}
                          {logsPageNumbers.map((n) => (
                            <button
                              key={n}
                              type="button"
                              className={`logs-pagination__num ${logsPage === n ? 'is-active' : ''}`}
                              onClick={() => setLogsPage(n)}
                            >
                              {n + 1}
                            </button>
                          ))}
                          {logsPageNumbers[logsPageNumbers.length - 1] < logsTotalPages - 1 && (
                            <>
                              <span className="logs-pagination__gap">…</span>
                              <button
                                type="button"
                                className={`logs-pagination__num ${logsPage === logsTotalPages - 1 ? 'is-active' : ''}`}
                                onClick={() => setLogsPage(logsTotalPages - 1)}
                              >
                                {logsTotalPages}
                              </button>
                            </>
                          )}
                        </div>
                        <button
                          type="button"
                          className="ag__btn ag__btn--ghost"
                          disabled={logsPage + 1 >= logsTotalPages}
                          onClick={() => setLogsPage((p) => Math.min(logsTotalPages - 1, p + 1))}
                        >
                          Next
                        </button>
                      </nav>
                    )}
                  </section>
                </div>
              )}

              {/* ── TELEMETRY ── */}
              {view === 'telemetry' && (
                <section className="glass-pane glass-pane--telemetry">
                  <div className="pane-head">
                    <h2>Global domain telemetry</h2>
                    <span>Live identity threat map · Wazuh + AD correlation</span>
                  </div>
                  <TelemetryGlobe
                    active={hasIncident}
                    contained={contained}
                    expanded
                    user={alert?.user}
                    target={alert?.target}
                    host={alert?.host}
                    sourceIp={alert?.source_ip}
                  />
                </section>
              )}

            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      <FloatingCopilot
        incidentId={alert?.id}
        disabled={!hasIncident}
        hasIncident={hasIncident}
        hideFab={view === 'telemetry'}
        viewContext={`${view} view`}
        incidentHeadline={aiHeadline}
        incidentVerdict={aiVerdict}
        incidentUser={alert?.user}
        incidentTarget={alert?.target}
        incidentRisk={alert?.risk}
        pendingPrompt={copilotPrompt}
        onPromptHandled={() => setCopilotPrompt(null)}
      />
    </div>
  )
}

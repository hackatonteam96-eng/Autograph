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
} from '@phosphor-icons/react'
import { motion, AnimatePresence, useMotionValue, useSpring } from 'motion/react'
import AttackGraph from './components/AttackGraph'
import AttackPathPipeline from './components/AttackPathPipeline'
import FloatingCopilot from './components/FloatingCopilot'
import RiskPanel from './components/RiskPanel'
import TelemetryGlobe from './components/TelemetryGlobe'
import { api, type Alert, type AttackPath } from './api/client'
import { fallbackAttackPath, fallbackDemoAlert, fallbackSigmaYaml, shouldUseOfflineDemo } from './data/fallbacks'

type View = 'command' | 'path' | 'detection' | 'response' | 'telemetry'

const NAV: { id: View; label: string; icon: typeof SquaresFour }[] = [
  { id: 'command',   label: 'Command',     icon: SquaresFour       },
  { id: 'path',      label: 'Attack path', icon: Graph             },
  { id: 'detection', label: 'Detection',   icon: TerminalWindow    },
  { id: 'response',  label: 'Response',    icon: ShieldCheck       },
  { id: 'telemetry', label: 'Telemetry',   icon: GlobeHemisphereWest },
]

const PIPELINE = [
  { label: 'Active Directory', sub: 'Event 4769' },
  { label: 'Wazuh SIEM', sub: '0x17 alert' },
  { label: 'Sigma Rule', sub: 'T1558.003' },
  { label: 'AuthGraph', sub: 'Correlator' },
  { label: 'ARIA AI', sub: 'v4-flash / v4-pro' },
]

const timeline = [
  { ts: '14:00:12', text: 'lowpriv.user authenticates to domain' },
  { ts: '14:01:44', text: 'SPN enumeration — svc-sql discovered' },
  { ts: '14:03:00', text: 'Burst of RC4 TGS requests hits DC01' },
  { ts: '14:03:04', text: 'Wazuh raises Kerberoasting alert (level 12)' },
  { ts: '14:03:09', text: 'AuthGraph correlates identity attack path' },
]

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

export default function App() {
  const [view, setView] = useState<View>('command')
  const [connected, setConnected] = useState(false)
  const [wazuhLive, setWazuhLive] = useState(false)
  const [alert, setAlert] = useState<Alert | null>(null)
  const [attackPath, setAttackPath] = useState<AttackPath | null>(null)
  const [sigmaYaml, setSigmaYaml] = useState('')
  const [aiActions, setAiActions] = useState<string[]>([])
  const [contained, setContained] = useState(false)
  const [containActions, setContainActions] = useState<string[]>([])
  const [focusedNode, setFocusedNode] = useState<string | null>(null)
  const [demoStep, setDemoStep] = useState(0)
  const [riskScore, setRiskScore] = useState(12)
  const [timelineCount, setTimelineCount] = useState(0)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [clock, setClock] = useState('')

  const refresh = useCallback(async () => {
    try {
      const [health, incidents, path, sigma] = await Promise.all([
        api.health(), api.incidents(), api.attackPath(), api.sigma(),
      ])
      setConnected(health.ok)
      setWazuhLive(Boolean(health.data?.wazuh_real))
      setAttackPath(path)
      setSigmaYaml(sigma.yaml)
      const current = incidents[0] ?? null
      setAlert(current)
      if (current) {
        setContained(current.status === 'contained')
        setFocusedNode((f) => f ?? current.target)
        if (current.simulation_active) {
          setDemoStep(current.demo_step ?? 0)
          setRiskScore(current.risk)
          setTimelineCount(Math.min((current.demo_step ?? 0) + 1, 5))
        }
      }
    } catch {
      setConnected(false)
      setAttackPath((current) => current ?? fallbackAttackPath)
      setSigmaYaml((current) => current || fallbackSigmaYaml)
      if (shouldUseOfflineDemo()) {
        setAlert(fallbackDemoAlert)
        setDemoStep(3)
        setRiskScore(fallbackDemoAlert.risk)
        setTimelineCount(5)
        setFocusedNode(fallbackDemoAlert.target)
        setAiActions(fallbackDemoAlert.response)
      }
    }
    finally { setLoading(false) }
  }, [])

  useEffect(() => {
    refresh()
    const poll = window.setInterval(async () => {
      try {
        const [status, incidents, health] = await Promise.all([api.simulateStatus(), api.incidents(), api.health()])
        setWazuhLive(Boolean(health.data?.wazuh_real))
        if (status.active) { setDemoStep(status.step); setRiskScore(status.risk); setTimelineCount(status.timeline_count) }
        const live = incidents[0]
        if (live && live.risk >= 70 && !live.simulation_active) {
          setDemoStep(3); setRiskScore(live.risk); setTimelineCount(5); setAlert(live)
        }
      } catch { /* offline */ }
    }, 2000)
    return () => window.clearInterval(poll)
  }, [refresh])

  useEffect(() => {
    const tick = () => setClock(new Date().toISOString().slice(11, 19) + ' UTC')
    tick()
    const id = window.setInterval(tick, 1000)
    return () => window.clearInterval(id)
  }, [])

  const hasIncident = demoStep > 0 || (alert?.risk ?? 0) >= 70 || wazuhLive

  useEffect(() => {
    if (!alert?.id || !hasIncident) return
    api.aiRespond(alert.id).then((r) => setAiActions(r.actions)).catch(() => undefined)
  }, [alert?.id, hasIncident])

  const riskAfter = contained ? 32 : riskScore
  const focus = focusedNode ?? alert?.target ?? 'svc-sql'
  const responseList = contained
    ? (containActions.length ? containActions : ['Source user disabled', 'Service account rotation queued', 'RC4 hardening applied', 'SOC ticket ITDR-001'])
    : aiActions.length ? aiActions : alert?.response ?? []

  async function runSimulation() {
    if (busy) return
    setBusy(true); setContained(false); setContainActions([])
    try { await api.simulateKerberoast(); await refresh(); setDemoStep(1); setTimelineCount(1); setView('command') }
    finally { setBusy(false) }
  }

  async function containIdentity() {
    if (!alert || busy || contained) return
    setBusy(true)
    try {
      const r = await api.contain(alert.id)
      setContained(true); setDemoStep(4); setRiskScore(r.risk_after); setTimelineCount(5); setContainActions(r.actions)
    } finally { setBusy(false) }
  }

  async function resetDemo() {
    if (busy) return
    setBusy(true)
    try {
      await api.simulateReset()
      setContained(false); setDemoStep(0); setRiskScore(12); setTimelineCount(0)
      setAiActions([]); setContainActions([]); setFocusedNode(null)
      await refresh()
    } finally { setBusy(false) }
  }

  if (loading) {
    return (
      <div className="boot">
        <div className="boot__orb" />
        <Fingerprint size={40} weight="duotone" className="boot__icon" />
        <strong>AuthGraph ITDR</strong>
        <span>Connecting to detection pipeline…</span>
      </div>
    )
  }

  return (
    <div className={`ag ${hasIncident && !contained ? 'ag--incident' : ''}`}>
      {/* ambient bg */}
      <div className="ag__bg" aria-hidden />

      {/* topbar */}
      <header className="ag__header">
        <div className="ag__brand">
          <div className="ag__logo"><Fingerprint size={22} weight="duotone" /></div>
          <div>
            <strong>AuthGraph</strong>
            <span>ITDR · VMware AD Lab</span>
          </div>
        </div>

        <div className="ag__kpis">
          <motion.div
            className={`kpi ${hasIncident && !contained ? 'kpi--alert' : ''}`}
            animate={hasIncident && !contained ? { boxShadow: ['0 0 0 0 rgba(255,92,92,0)', '0 0 0 8px rgba(255,92,92,0.12)', '0 0 0 0 rgba(255,92,92,0)'] } : {}}
            transition={{ repeat: Infinity, duration: 2.4 }}
          >
            <ChartLineUp size={15} />
            <span>Open</span>
            <b>{hasIncident && !contained ? 1 : 0}</b>
          </motion.div>
          <div className={`kpi ${hasIncident && !contained ? 'kpi--critical' : ''}`}>
            <WarningCircle size={15} />
            <span>Critical</span>
            <b>{hasIncident && !contained ? 1 : 0}</b>
          </div>
          <div className="kpi">
            <ShieldCheck size={15} />
            <span>Contained</span>
            <b>{contained ? 1 : 0}</b>
          </div>
          <div className={`kpi ${connected ? 'kpi--live' : ''}`}>
            <span className="kpi__dot" />
            <span>Pipeline</span>
            <b>{connected ? 'Live' : 'Down'}</b>
          </div>
        </div>

        <div className="ag__toolbar">
          <button className="ag__btn ag__btn--ghost" onClick={resetDemo} disabled={busy} aria-label="Reset">
            <ArrowClockwise size={14} />
          </button>
          <button className="ag__btn" onClick={runSimulation} disabled={busy}>
            <Play size={13} weight="fill" /> Run attack
          </button>
          <button
            className={`ag__btn ag__btn--contain ${contained ? 'is-done' : ''}`}
            onClick={containIdentity}
            disabled={!hasIncident || contained || busy}
          >
            <ShieldCheck size={13} /> {contained ? 'Contained' : 'Contain'}
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
                              ? <><ShieldCheck size={14} weight="duotone" />Threat neutralized</>
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
                          <p className="cmd__hero-sub">Wazuh · Sigma · AuthGraph pipeline armed. Run kerberoast in lab to trigger live detection.</p>
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

                  {/* Stat cards */}
                  <div className="cmd__stats">
                    {[
                      { icon: Fingerprint, label: 'Identities', val: '847', sub: 'monitored', tone: '' },
                      { icon: TerminalWindow, label: 'Sigma rules', val: '1', sub: 'kerberoasting active', tone: 'ok' },
                      { icon: Radioactive, label: 'MITRE', val: alert?.mitre ?? 'T1558.003', sub: 'technique mapped', tone: hasIncident ? 'warn' : '' },
                      { icon: Database, label: 'Events/min', val: hasIncident ? '142' : '12', sub: connected ? 'pipeline live' : 'offline', tone: hasIncident ? 'crit' : '' },
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
                        <TelemetryGlobe active={hasIncident} contained={contained} />
                      </section>

                      <div className="cmd__feed-row">
                        <section className="glass-pane">
                          <div className="pane-head">
                            <h2><Lightning size={13} weight="fill" /> Live activity</h2>
                            <span>{timelineCount}/{timeline.length}</span>
                          </div>
                          <ol className="activity-feed">
                            {timeline.map(({ ts, text }, i) => (
                              <motion.li key={ts} className={i < timelineCount ? 'is-done' : ''} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.05 }}>
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
              {view === 'path' && attackPath && alert && (
                <div className="path-layout">
                  <section className="glass-pane glass-pane--grow">
                    <div className="pane-head">
                      <h2>Attack path reconstruction</h2>
                      <span>Kerberoasting → lateral movement · click nodes to inspect</span>
                    </div>
                    <AttackGraph
                      attackPath={attackPath}
                      targetId={alert.target}
                      focusedId={focus}
                      onFocus={setFocusedNode}
                      hasIncident={hasIncident}
                      contained={contained}
                      height={520}
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
                </div>
              )}

              {/* ── DETECTION ── */}
              {view === 'detection' && (
                <div className="detect-layout">
                  <section className="glass-pane">
                    <div className="pane-head"><h2>Incident log</h2></div>
                    <table className="data-table">
                      <thead><tr><th>Time</th><th>Event</th><th>Actor</th><th>Target</th><th>Host</th><th>Risk</th><th>Status</th></tr></thead>
                      <tbody>
                        {hasIncident && alert
                          ? <tr className="is-active">
                              <td>{alert.time?.slice(11, 19)}</td>
                              <td><code>{alert.event_id}</code></td>
                              <td>{alert.user}</td>
                              <td>{alert.target}</td>
                              <td>{alert.host}</td>
                              <td><span className={`badge badge--${alert.severity}`}>{riskAfter}</span></td>
                              <td>{contained ? 'Contained' : 'Open'}</td>
                            </tr>
                          : <tr><td colSpan={7} className="empty">No incidents — run kerberoast or simulate</td></tr>
                        }
                      </tbody>
                    </table>
                  </section>
                  <section className="glass-pane">
                    <div className="pane-head"><h2>Attack timeline</h2></div>
                    <ol className="timeline-list">
                      {timeline.map(({ ts, text }, i) => (
                        <li key={ts} className={i < timelineCount ? 'is-done' : ''}>
                          <div className="timeline-list__dot" />
                          <time>{ts}</time>
                          <span>{text}</span>
                        </li>
                      ))}
                    </ol>
                  </section>
                  <section className="glass-pane span-2">
                    <div className="pane-head">
                      <h2>Sigma rule</h2>
                      <span>authgraph-kerberoasting-4769 · T1558.003</span>
                    </div>
                    <pre className="code-block">{sigmaYaml || 'Loading…'}</pre>
                  </section>
                </div>
              )}

              {/* ── RESPONSE ── */}
              {view === 'response' && (
                <div className="response-layout response-layout--solo">
                  <section className="glass-pane glass-pane--grow">
                    <div className="pane-head">
                      <h2>Response actions</h2>
                      <span>{contained ? 'Executed · deepseek-v4-pro' : aiActions.length ? 'AI · OpenRouter' : 'Playbook'}</span>
                    </div>
                    <ol className="action-list action-list--wide">
                      {responseList.map((a, i) => (
                        <motion.li
                          key={a}
                          initial={{ opacity: 0, x: -12 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.07, ease: [0.16, 1, 0.3, 1] }}
                        >
                          <span>{i + 1}</span>
                          <div>
                            <strong>{a}</strong>
                            <small>Priority {i + 1}</small>
                          </div>
                          {contained && <ShieldCheck size={16} weight="fill" className="txt-ok" />}
                        </motion.li>
                      ))}
                    </ol>
                    {!hasIncident && <p className="hint">Response actions appear when an incident is active. Use ARIA (bottom-right) for live analysis.</p>}
                  </section>
                </div>
              )}

              {/* ── TELEMETRY ── */}
              {view === 'telemetry' && (
                <section className="glass-pane glass-pane--telemetry">
                  <div className="pane-head">
                    <h2>Global domain telemetry</h2>
                    <span>Interactive · click pins · drag to rotate · scroll to zoom</span>
                  </div>
                  <TelemetryGlobe active={hasIncident} contained={contained} expanded />
                </section>
              )}

            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      <FloatingCopilot incidentId={alert?.id} disabled={!hasIncident} hasIncident={hasIncident} viewContext={`${view} view`} />
    </div>
  )
}

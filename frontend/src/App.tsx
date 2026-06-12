import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react'
import {
  ArrowClockwise,
  Broadcast,
  Circuitry,
  Clock,
  Crosshair,
  Database,
  Fingerprint,
  Fire,
  GearSix,
  Graph,
  House,
  Key,
  LockKey,
  Play,
  Pulse,
  ShieldCheck,
  ShieldWarning,
  Sparkle,
  TerminalWindow,
  UserCircle,
  Warning,
} from '@phosphor-icons/react'
import * as THREE from 'three'
import RepositoryGlobe from './RepositoryGlobe'
import alerts from '../../data/sample-alerts.json'
import attackPath from '../../data/attack-path.json'

type Alert = (typeof alerts)[number]
type PathNode = (typeof attackPath.nodes)[number]
type AttackNodeData = PathNode & { active?: boolean; contained?: boolean; live?: boolean }

const sigmaRule = `title: Suspicious Kerberoasting Activity
id: authgraph-kerberoast-4769
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
  filter_krbtgt:
    ServiceName: 'krbtgt'
  condition: selection and not filter_krbtgt
level: critical
tags:
  - attack.credential_access
  - attack.t1558.003`

const timeline = [
  ['14:00:12', 'lowpriv.user authenticates to domain'],
  ['14:01:44', 'SPN enumeration identifies svc-sql'],
  ['14:03:00', 'Burst of RC4 TGS requests reaches DC01'],
  ['14:03:04', 'Wazuh raises Kerberoasting alert'],
  ['14:03:09', 'AuthGraph maps privileged identity path'],
]

const positions: Record<string, { x: number; y: number }> = {
  'lowpriv.user': { x: 72, y: 168 },
  'svc-sql': { x: 318, y: 76 },
  'SQL Admins': { x: 580, y: 150 },
  'SQL-SERVER': { x: 822, y: 52 },
  'Domain Sensitive Assets': { x: 1055, y: 168 },
}

const iconForType = {
  user: UserCircle,
  service_account: Key,
  group: Graph,
  host: Database,
  asset: LockKey,
}

const simulationSteps = ['Waiting', 'Attack detected', 'Correlated', 'Critical', 'Contained'] as const
const riskSequence = [12, 39, 64, 87]

function AttackNode({ data }: NodeProps<Node<AttackNodeData>>) {
  const Icon = iconForType[data.type as keyof typeof iconForType] ?? Graph

  return (
    <div className={`attack-node risk-${data.risk} ${data.active ? 'is-active' : ''} ${data.contained ? 'is-contained' : ''} ${data.live ? 'is-live' : ''}`}>
      <Handle type="target" position={Position.Left} />
      <div className="node-orbit">
        <Icon size={21} weight="duotone" />
      </div>
      <div>
        <strong>{data.id}</strong>
        <span>{data.type.replace('_', ' ')}</span>
      </div>
      <Handle type="source" position={Position.Right} />
    </div>
  )
}

const nodeTypes = { attackNode: AttackNode }

type RawGlobePoint = { lon: number; lat: number; type: string }
type GlobeData = { points: RawGlobePoint[] }

function toSpherePosition(lon: number, lat: number, radius: number) {
  const phi = (90 - lat) * (Math.PI / 180)
  const theta = (lon + 180) * (Math.PI / 180)

  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta),
  )
}

function ThreatGlobe({ active, contained, expanded }: { active: boolean; contained: boolean; expanded: boolean }) {
  return <RepositoryGlobe active={active} contained={contained} expanded={expanded} />

  const mountRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    const mount = mountRef.current
    if (!mount) return

    let disposed = false
    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(38, mount.clientWidth / mount.clientHeight, 0.1, 100)
    camera.position.z = 4.35

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.8))
    renderer.setSize(mount.clientWidth, mount.clientHeight)
    mount.appendChild(renderer.domElement)

    const globeGroup = new THREE.Group()
    scene.add(globeGroup)

    const textureLoader = new THREE.TextureLoader()
    const earthTexture = textureLoader.load('/models/earth/earth-albedo.jpg')
    const nightTexture = textureLoader.load('/models/earth/earth-night_lights_modified.jpg')
    const cloudTexture = textureLoader.load('/models/earth/clouds-earth.jpg')

    const sphere = new THREE.Mesh(
      new THREE.SphereGeometry(1.42, 96, 96),
      new THREE.MeshPhongMaterial({
        map: earthTexture,
        emissiveMap: nightTexture,
        emissive: new THREE.Color(contained ? '#4de7c8' : '#ffaa44'),
        emissiveIntensity: active ? 1.8 : 0.85,
        shininess: 6,
      }),
    )
    globeGroup.add(sphere)

    const clouds = new THREE.Mesh(
      new THREE.SphereGeometry(1.445, 64, 64),
      new THREE.MeshPhongMaterial({
        map: cloudTexture,
        alphaMap: cloudTexture,
        transparent: true,
        opacity: expanded ? 0.14 : 0.08,
        depthWrite: false,
      }),
    )
    globeGroup.add(clouds)

    const atmosphere = new THREE.Mesh(
      new THREE.SphereGeometry(1.52, 96, 96),
      new THREE.MeshBasicMaterial({
        color: new THREE.Color('#68d7ff'),
        transparent: true,
        opacity: expanded ? 0.1 : 0.055,
        side: THREE.BackSide,
      }),
    )
    globeGroup.add(atmosphere)

    const dots = new THREE.Group()
    fetch('/data/globe-points.json')
      .then((response) => response.json())
      .then((data: GlobeData) => {
        if (disposed) return
        data.points
          .filter((point, index) => point.type === 'land' && index % (expanded ? 58 : 118) === 0)
          .slice(0, expanded ? 420 : 150)
          .forEach((point, index) => {
            const dot = new THREE.Mesh(
              new THREE.SphereGeometry(index % 37 === 0 ? 0.012 : 0.007, 8, 8),
              new THREE.MeshBasicMaterial({
                color: new THREE.Color(index % 37 === 0 && active ? '#ff4d6d' : '#4de7c8'),
                transparent: true,
                opacity: index % 37 === 0 && active ? 0.92 : 0.42,
              }),
            )
            dot.position.copy(toSpherePosition(point.lon, point.lat, 1.475))
            dots.add(dot)
          })
      })
      .catch(() => undefined)

    const threatPins = [
      { lon: 49.8, lat: 40.4, color: active && !contained ? '#ff4d6d' : '#4de7c8' },
      { lon: -77.0, lat: 38.9, color: '#4de7c8' },
      { lon: 13.4, lat: 52.5, color: '#ffaa44' },
    ]

    threatPins.forEach((pin) => {
      const dot = new THREE.Mesh(
        new THREE.SphereGeometry(expanded ? 0.025 : 0.018, 14, 14),
        new THREE.MeshBasicMaterial({
          color: new THREE.Color(pin.color),
          transparent: true,
          opacity: 0.98,
        }),
      )
      dot.position.copy(toSpherePosition(pin.lon, pin.lat, 1.5))
      dots.add(dot)
    })
    globeGroup.add(dots)

    const arcMaterial = new THREE.LineBasicMaterial({
      color: new THREE.Color(contained ? '#4de7c8' : active ? '#ff4d6d' : '#64748b'),
      transparent: true,
      opacity: active ? 0.92 : 0.22,
    })
    const arc = new THREE.Line(
      new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(-1.2, 0.35, 0.96),
        new THREE.Vector3(-0.5, 1.32, 0.7),
        new THREE.Vector3(0.72, 0.62, 1.03),
      ]),
      arcMaterial,
    )
    globeGroup.add(arc)

    const light = new THREE.DirectionalLight('#dff7ff', 2.2)
    light.position.set(2.6, 1.8, 3)
    scene.add(light)
    scene.add(new THREE.AmbientLight('#2c5c82', 1.2))

    const handleResize = () => {
      if (!mount) return
      camera.aspect = mount.clientWidth / mount.clientHeight
      camera.updateProjectionMatrix()
      renderer.setSize(mount.clientWidth, mount.clientHeight)
    }
    window.addEventListener('resize', handleResize)

    let raf = 0
    const animate = () => {
      globeGroup.rotation.y += expanded ? 0.002 : 0.001
      clouds.rotation.y += 0.0008
      arcMaterial.color.set(contained ? '#4de7c8' : active ? '#ff4d6d' : '#64748b')
      arcMaterial.opacity = active ? 0.92 : 0.22
      renderer.render(scene, camera)
      raf = window.requestAnimationFrame(animate)
    }
    animate()

    return () => {
      disposed = true
      window.cancelAnimationFrame(raf)
      window.removeEventListener('resize', handleResize)
      renderer.dispose()
      sphere.geometry.dispose()
      clouds.geometry.dispose()
      atmosphere.geometry.dispose()
      earthTexture.dispose()
      nightTexture.dispose()
      cloudTexture.dispose()
      arc.geometry.dispose()
      arcMaterial.dispose()
      mount.removeChild(renderer.domElement)
    }
  }, [active, contained, expanded])

  return <div className="globe-canvas" ref={mountRef} aria-label="Live identity telemetry globe" />
}

function App() {
  const [selectedAlert] = useState<Alert>(alerts[0])
  const [contained, setContained] = useState(false)
  const [selectedNode, setSelectedNode] = useState(selectedAlert.target)
  const [demoStep, setDemoStep] = useState(0)
  const [riskScore, setRiskScore] = useState(12)
  const [activeTimelineCount, setActiveTimelineCount] = useState(0)
  const [globeExpanded, setGlobeExpanded] = useState(false)
  const selectedPathNode = attackPath.nodes.find((node) => node.id === selectedNode) ?? attackPath.nodes[1]
  const hasIncident = demoStep > 0
  const isCritical = demoStep >= 3 && !contained

  const graph = useMemo(() => {
    const nodes: Node<AttackNodeData>[] = attackPath.nodes.map((node) => ({
      id: node.id,
      type: 'attackNode',
      position: positions[node.id] ?? { x: 0, y: 0 },
      data: {
        ...node,
        active: node.id === selectedNode || node.id === selectedAlert.target,
        contained,
        live: hasIncident,
      },
      draggable: false,
    }))

    const edges: Edge[] = attackPath.edges.map((edge, index) => ({
      id: `${edge.from}-${edge.to}`,
      source: edge.from,
      target: edge.to,
      label: edge.label,
      animated: hasIncident && !contained,
      type: 'smoothstep',
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: contained ? '#4de7c8' : index === 0 && hasIncident ? '#ff4d6d' : '#4de7c8',
      },
      style: {
        stroke: contained ? '#4de7c8' : index === 0 && hasIncident ? '#ff4d6d' : hasIncident ? '#4de7c8' : 'rgba(148, 163, 184, 0.34)',
        strokeWidth: hasIncident ? (index === 0 ? 3 : 2) : 1.6,
      },
    }))

    return { nodes, edges }
  }, [selectedNode, selectedAlert.target, contained, hasIncident])

  const riskAfter = contained ? 32 : riskScore
  const riskStyle = { '--risk': `${riskAfter}%` } as React.CSSProperties

  function runSimulation() {
    setContained(false)
    setDemoStep(1)
    setRiskScore(12)
    setActiveTimelineCount(1)

    riskSequence.forEach((score, index) => {
      window.setTimeout(() => {
        setRiskScore(score)
        setDemoStep(Math.min(index + 1, 3))
        setActiveTimelineCount(Math.min(index + 2, timeline.length))
      }, 620 * (index + 1))
    })
  }

  function containIdentity() {
    setContained(true)
    setDemoStep(4)
    setRiskScore(32)
    setActiveTimelineCount(timeline.length)
  }

  function resetDemo() {
    setContained(false)
    setDemoStep(0)
    setRiskScore(12)
    setActiveTimelineCount(0)
    setSelectedNode(selectedAlert.target)
  }

  return (
    <main className="soc-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="mark-core">
            <Fingerprint size={25} weight="duotone" />
          </div>
          <div>
            <strong>AUTHGRAPH</strong>
            <span>ITDR Console</span>
          </div>
        </div>
        <nav className="side-nav" aria-label="Product navigation">
          <a className="is-active"><House size={17} weight="duotone" /> Command</a>
          <a><ShieldWarning size={17} weight="duotone" /> Incidents</a>
          <a><Graph size={17} weight="duotone" /> Attack paths</a>
          <a><TerminalWindow size={17} weight="duotone" /> Sigma rules</a>
          <a><GearSix size={17} weight="duotone" /> Settings</a>
        </nav>
        <div className="operator-card">
          <span>Operator</span>
          <strong>Bahadur</strong>
          <small>Frontend lead / demo driver</small>
        </div>
      </aside>

      <section className="main-console">
        <header className="topbar">
          <div>
            <span className="section-kicker">Identity Threat Detection and Response</span>
            <h1>AUTHGRAPH</h1>
          </div>
          <div className="system-strip" aria-label="System status">
            <span><Broadcast size={16} weight="duotone" /> Wazuh signal live</span>
            <span><Circuitry size={16} weight="duotone" /> Sigma mapped</span>
            <span><ShieldWarning size={16} weight="duotone" /> MITRE {selectedAlert.mitre}</span>
          </div>
        </header>

        <section className="demo-console" aria-label="Demo controls">
          <div className="state-rail">
            {simulationSteps.map((step, index) => (
              <span className={index <= demoStep ? 'is-active' : ''} key={step}>{step}</span>
            ))}
          </div>
          <div className="demo-actions">
            <button type="button" onClick={runSimulation}><Play size={15} weight="fill" /> Run Kerberoasting Attack</button>
            <button
              type="button"
              onClick={() => {
                setDemoStep(Math.max(demoStep, 2))
                setActiveTimelineCount(Math.max(activeTimelineCount, 4))
              }}
            >
              <Broadcast size={15} weight="duotone" /> Replay Wazuh Alert
            </button>
            <button type="button" onClick={containIdentity}><ShieldCheck size={15} weight="duotone" /> Contain Identity</button>
            <button type="button" onClick={resetDemo}><ArrowClockwise size={15} weight="duotone" /> Reset Demo</button>
          </div>
        </section>

        <section className="soc-grid">
          <section className="panel stage">
            <div className="stage-header">
              <div>
                <span>Kerberoasting path reconstruction</span>
                <h2>{selectedNode} is inside the active Kerberoasting path</h2>
              </div>
              <div className={`status-capsule ${contained ? 'contained' : ''}`}>
                {contained ? <ShieldCheck size={17} weight="duotone" /> : <Warning size={17} weight="duotone" />}
                {contained ? 'Contained' : isCritical ? 'Critical' : hasIncident ? 'Correlating' : 'Waiting'}
              </div>
            </div>
            <div className="graph-toolbar" aria-label="Graph interaction modes">
              <button type="button" className="is-active">Trace path</button>
              <button type="button">Risk lens</button>
              <button type="button">Sigma view</button>
            </div>
            <div className="graph-shell">
              <ReactFlow
                nodes={graph.nodes}
                edges={graph.edges}
                nodeTypes={nodeTypes}
                onNodeMouseEnter={(_, node) => setSelectedNode(node.id)}
                onNodeMouseLeave={() => setSelectedNode(selectedAlert.target)}
                fitView
                fitViewOptions={{ padding: 0.16 }}
                minZoom={0.52}
                maxZoom={1.25}
                nodesDraggable={false}
                panOnDrag={false}
                zoomOnScroll={false}
                proOptions={{ hideAttribution: true }}
              >
                <Controls showInteractive={false} />
              </ReactFlow>
            </div>
          </section>

          <aside className="panel risk-panel">
            <div className="risk-ring" style={riskStyle}>
              <div>
                <span>Risk</span>
                <strong>{riskAfter}</strong>
              </div>
            </div>
            <h2>{selectedAlert.target}</h2>
            <p>Privileged service account with SPN exposure and an attack path into SQL administration.</p>
            <div className="focus-lens">
              <span>Graph focus</span>
              <strong>{selectedPathNode.id}</strong>
              <small>{selectedPathNode.type.replace('_', ' ')} / {selectedPathNode.risk} risk</small>
            </div>
            <div className="risk-delta">
              <span>Containment impact</span>
              <strong>{contained ? '-55 points' : 'pending action'}</strong>
            </div>
            <div className="identity-grid">
              <span>MITRE</span><strong>{selectedAlert.mitre}</strong>
              <span>Severity</span><strong>{contained ? 'contained' : selectedAlert.severity}</strong>
              <span>Source</span><strong>{selectedAlert.source}</strong>
            </div>
          </aside>

          <aside className="panel incidents-panel">
            <div className="panel-heading">
              <span>Active incidents</span>
              <strong>{hasIncident ? '1 critical' : 'quiet'}</strong>
            </div>
            <button className={`incident-card ${hasIncident ? 'is-live' : ''}`} type="button">
              <span className="incident-pulse"><Fire size={19} weight="fill" /></span>
              <span>
                <strong>{hasIncident ? selectedAlert.attack : 'No active identity incident'}</strong>
                <small>{hasIncident ? `${selectedAlert.user} to ${selectedAlert.target}` : 'Waiting for telemetry'}</small>
              </span>
              <b>{hasIncident ? riskScore : 12}</b>
            </button>
            <p className="incident-summary">
              {hasIncident
                ? 'Low-privileged user requested multiple RC4 Kerberos service tickets for svc-sql, indicating possible Kerberoasting.'
                : 'Run the simulation to replay telemetry, alerting, risk scoring, and response.'}
            </p>
            <div className="why-grid">
              <span><strong>{hasIncident ? 4 : 0}</strong> detection signals</span>
              <span><strong>{hasIncident ? 1 : 0}</strong> Sigma rule matched</span>
              <span><strong>{hasIncident ? 1 : 0}</strong> privileged path found</span>
            </div>
            <div className="telemetry-stack">
              <Telemetry icon={<Clock size={16} weight="duotone" />} label="Event time" value="14:03 UTC" />
              <Telemetry icon={<TerminalWindow size={16} weight="duotone" />} label="Windows event" value={`${selectedAlert.event_id}`} />
              <Telemetry icon={<Crosshair size={16} weight="duotone" />} label="Source IP" value={selectedAlert.source_ip} />
              <Telemetry icon={<Pulse size={16} weight="duotone" />} label="Host" value={selectedAlert.host} />
            </div>
          </aside>

          <section className="panel timeline-panel">
            <div className="panel-heading">
              <span>Attack timeline</span>
              <strong>5 steps</strong>
            </div>
            {timeline.map(([time, text], index) => (
              <div className={`timeline-row ${index < activeTimelineCount ? 'is-active' : ''}`} key={time}>
                <b>{time}</b>
                <span>{text}</span>
                <i>{index + 1}</i>
              </div>
            ))}
          </section>

          <section className="panel sigma-panel">
            <div className="panel-heading">
              <span>Sigma rule viewer</span>
              <strong>T1558.003</strong>
            </div>
            <pre>{sigmaRule}</pre>
          </section>

          <section className="panel response-panel">
            <div className="panel-heading">
              <span>Containment</span>
              <strong>{contained ? 'risk reduced' : 'ready'}</strong>
            </div>
            <button className="contain-button" type="button" onClick={containIdentity} disabled={contained}>
              <span>{contained ? 'Containment executed' : 'Contain svc-sql path'}</span>
              <span className="button-orb">{contained ? <ShieldCheck size={18} weight="duotone" /> : <Sparkle size={18} weight="duotone" />}</span>
            </button>
            <div className="response-actions">
              {(contained
                ? ['Source user disabled', 'Service account marked for password rotation', 'RC4 disabled recommendation generated', 'SOC ticket created']
                : selectedAlert.response
              ).map((action) => (
                <div key={action}><ShieldCheck size={15} weight="duotone" /> {action}</div>
              ))}
            </div>
          </section>
        </section>
      </section>
      <aside className={`globe-widget ${globeExpanded ? 'is-expanded' : ''}`} aria-label="Expandable telemetry globe">
        <button className="globe-toggle" type="button" onClick={() => setGlobeExpanded((value) => !value)}>
          <span>{globeExpanded ? 'Collapse telemetry globe' : 'Expand telemetry globe'}</span>
        </button>
        <ThreatGlobe active={hasIncident} contained={contained} expanded={globeExpanded} />
        <div className="globe-widget-copy">
          <strong>{hasIncident ? 'DC01 anomaly trace' : 'Global telemetry'}</strong>
          <span>{globeExpanded ? 'Repo-textured globe / calm point layer' : 'Click to inspect'}</span>
        </div>
      </aside>
    </main>
  )
}

function Telemetry({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="telemetry-item">
      {icon}
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}

export default App

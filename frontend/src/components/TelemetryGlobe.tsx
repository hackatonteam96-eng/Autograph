import { Suspense, useEffect, useMemo, useRef, useState } from 'react'
import { Canvas } from '@react-three/fiber'
import { motion, AnimatePresence } from 'motion/react'
import * as THREE from 'three'
import { GlobeScene, type GlobePin } from './GlobeScene'

const PIN_DETAIL: Record<string, (active: boolean, contained: boolean, ctx: PinContext) => string> = {
  dc01: (a, c, ctx) =>
    a && !c
      ? `ANOMALY: Kerberos Event 4769 from ${ctx.sourceIp || 'lab network'}.`
      : c ? 'CONTAINED: No further anomalous requests.' : 'NOMINAL: Log forwarding active.',
  attacker: (a, _c, ctx) =>
    a && ctx.user
      ? `SOURCE: ${ctx.user} — Kerberoast TGS for ${ctx.target || 'SPN target'}.`
      : 'NOMINAL: Awaiting live Wazuh telemetry.',
  sql: (_a, _c, ctx) =>
    ctx.target && ctx.host
      ? `EXPOSURE: ${ctx.target} on ${ctx.host}.`
      : 'NOMINAL: No mapped target host.',
  lab: () => 'Lab region online — waiting for Wazuh webhook to populate threat pins.',
}

type PinContext = { user?: string; target?: string; host?: string; sourceIp?: string }

const ROLE_DOT: Record<GlobePin['role'], string> = {
  dc: 'tglobe__dot--dc',
  attacker: 'tglobe__dot--attacker',
  asset: 'tglobe__dot--asset',
}

function useDpr(expanded: boolean) {
  const [dpr, setDpr] = useState(1.5)
  useEffect(() => {
    const max = expanded ? 2.5 : 1.75
    setDpr(Math.min(window.devicePixelRatio || 1, max))
  }, [expanded])
  return dpr
}

export default function TelemetryGlobe({
  active,
  contained,
  expanded = false,
  user,
  target,
  host,
  sourceIp,
}: {
  active: boolean
  contained: boolean
  expanded?: boolean
  user?: string
  target?: string
  host?: string
  sourceIp?: string
}) {
  const [selectedPin, setSelectedPin] = useState<GlobePin | null>(null)
  const [focusPinId, setFocusPinId] = useState<string | null>(null)
  const [autoRotate, setAutoRotate] = useState(true)
  const [resetToken, setResetToken] = useState(0)
  const [tick, setTick] = useState(0)
  const dpr = useDpr(expanded)
  const viewportRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const el = viewportRef.current
    if (!el) return
    const bump = () => window.dispatchEvent(new Event('resize'))
    const ro = new ResizeObserver(bump)
    ro.observe(el)
    bump()
    return () => ro.disconnect()
  }, [expanded])

  const ctx: PinContext = { user, target, host, sourceIp }

  const pins: GlobePin[] = useMemo(() => {
    if (!user && !host) {
      return [
        { id: 'lab', label: 'LAB', sub: 'Awaiting Wazuh webhook', lon: 49.8, lat: 40.4, role: 'dc' },
      ]
    }
    return [
      { id: 'dc01', label: host || 'DC', sub: 'Alert source host', lon: 49.8, lat: 40.4, role: 'dc' },
      { id: 'attacker', label: user?.split('@')[0] || 'Source', sub: 'Kerberoast source', lon: -77.0, lat: 38.9, role: 'attacker' },
      { id: 'sql', label: target || 'Target', sub: 'Service account / SPN', lon: 13.4, lat: 52.5, role: 'asset' },
    ]
  }, [user, target, host])

  useEffect(() => {
    const id = window.setInterval(() => setTick((t) => t + 1), 1200)
    return () => window.clearInterval(id)
  }, [])

  function handleSelectPin(pin: GlobePin) {
    setSelectedPin((prev) => {
      const next = prev?.id === pin.id ? null : pin
      setFocusPinId(next ? pin.id : null)
      if (next) setAutoRotate(false)
      return next
    })
  }

  function handleChipClick(pin: GlobePin) {
    setSelectedPin(pin)
    setFocusPinId(pin.id)
    setAutoRotate(false)
  }

  function handleReset() {
    setSelectedPin(null)
    setFocusPinId(null)
    setAutoRotate(true)
    setResetToken((t) => t + 1)
  }

  const eventsPerMin = active ? 24 + (tick % 6) : 0
  const latency = active ? 18 + (tick % 5) : 0
  const statusText = contained ? 'Contained' : active ? 'Live alert' : 'Awaiting lab'
  const statusClass = contained ? 'is-ok' : active ? 'is-alert' : ''

  return (
    <div className={`tglobe ${expanded ? 'tglobe--expanded' : 'tglobe--mini'}`}>
      <div className="tglobe__viewport" ref={viewportRef}>
        <Canvas
          camera={{ position: [0, 0, expanded ? 3.55 : 3.25], fov: 45 }}
          dpr={dpr}
          resize={{ debounce: 0, scroll: true }}
          gl={{
            antialias: true,
            alpha: false,
            powerPreference: 'high-performance',
          }}
          onCreated={({ gl }) => {
            gl.setClearColor('#000000')
            THREE.ColorManagement.enabled = true
            gl.toneMapping = THREE.ACESFilmicToneMapping
            gl.outputColorSpace = THREE.SRGBColorSpace
          }}
          style={{ width: '100%', height: '100%', display: 'block' }}
        >
          <Suspense fallback={null}>
            <GlobeScene
              active={active}
              contained={contained}
              pins={pins}
              selectedId={selectedPin?.id ?? null}
              focusPinId={focusPinId}
              onSelectPin={handleSelectPin}
              autoRotate={autoRotate}
              expanded={expanded}
              resetToken={resetToken}
            />
          </Suspense>
        </Canvas>
      </div>

      <div className="tglobe__hud">
        <div className="tglobe__top">
          {expanded && (
            <motion.div
              className="tglobe__stats"
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
            >
              <div className={`tglobe__stat ${active ? 'is-alert' : ''}`}>
                <span>Events/min</span>
                <motion.strong key={eventsPerMin} initial={{ opacity: 0.4, y: 4 }} animate={{ opacity: 1, y: 0 }}>
                  {eventsPerMin || '—'}
                </motion.strong>
              </div>
              <div className="tglobe__stat">
                <span>Regions</span>
                <strong>{pins.length}</strong>
              </div>
              <div className="tglobe__stat">
                <span>Latency</span>
                <motion.strong key={latency} initial={{ opacity: 0.4 }} animate={{ opacity: 1 }}>
                  {latency ? `${latency}ms` : '—'}
                </motion.strong>
              </div>
              <div className={`tglobe__stat ${active ? 'is-alert' : ''}`}>
                <span>Corridor</span>
                <strong>{active ? (contained ? 'Closed' : 'Open') : 'Idle'}</strong>
              </div>
            </motion.div>
          )}

          <div className="tglobe__legend">
            {pins.map((pin) => (
              <button
                key={pin.id}
                type="button"
                className={`tglobe__chip ${selectedPin?.id === pin.id ? 'is-active' : ''}`}
                onClick={() => handleChipClick(pin)}
              >
                <span className={`tglobe__dot ${ROLE_DOT[pin.role]}`} />
                {pin.label}
              </button>
            ))}
          </div>

          <div className="tglobe__toggles">
            <button type="button" className={autoRotate ? 'is-active' : ''} onClick={() => setAutoRotate((v) => !v)}>
              {autoRotate ? 'Pause' : 'Rotate'}
            </button>
            <button type="button" onClick={handleReset}>Reset</button>
          </div>
        </div>

        <AnimatePresence>
          {selectedPin && expanded && (
            <motion.aside
              className={`tglobe__detail tglobe__detail--${selectedPin.role}`}
              initial={{ opacity: 0, x: -16 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -8 }}
              transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
            >
              <div className="tglobe__detail-head">
                <span className={`tglobe__dot ${ROLE_DOT[selectedPin.role]}`} />
                <div>
                  <strong>{selectedPin.label}</strong>
                  <span>{selectedPin.sub}</span>
                </div>
              </div>
              <p className="tglobe__detail-coords">
                {selectedPin.lat.toFixed(2)}°N · {selectedPin.lon.toFixed(2)}°E
              </p>
              <p>{(PIN_DETAIL[selectedPin.id] ?? (() => 'Live lab telemetry.'))(active, contained, ctx)}</p>
            </motion.aside>
          )}
        </AnimatePresence>

        <div className="tglobe__footer">
          <div className={`tglobe__status ${statusClass}`}>
            <span className="tglobe__status-dot" />
            {statusText}
          </div>
          {expanded && (
            <span className="tglobe__tip">Drag to orbit · Scroll to zoom · Click pins or chips</span>
          )}
        </div>
      </div>
    </div>
  )
}

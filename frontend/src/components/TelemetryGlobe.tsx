import { Suspense, useEffect, useState } from 'react'
import { Canvas } from '@react-three/fiber'
import { motion, AnimatePresence } from 'motion/react'
import { GlobeScene, type GlobePin } from './GlobeScene'

const PINS: GlobePin[] = [
  { id: 'dc01',     label: 'DC01',        sub: 'Domain Controller',      lon: 49.8,  lat: 40.4, role: 'dc'       },
  { id: 'attacker', label: 'WS-ATTACKER', sub: 'Kerberoast source',      lon: -77.0, lat: 38.9, role: 'attacker' },
  { id: 'sql',      label: 'SQL-SERVER',  sub: 'Privileged target host', lon: 13.4,  lat: 52.5, role: 'asset'    },
]

const PIN_DETAIL: Record<string, (active: boolean, contained: boolean) => string> = {
  dc01: (a, c) =>
    a && !c
      ? 'ANOMALY: Burst of RC4 TGS requests (Event 4769) from 10.0.0.42.'
      : c ? 'CONTAINED: No further anomalous requests.' : 'NOMINAL: Log forwarding active.',
  attacker: (a) =>
    a ? 'SOURCE: lowpriv.user — GetUserSPNs, 4 TGS requests for svc-sql.' : 'NOMINAL: No suspicious activity.',
  sql: () => 'EXPOSURE: svc-sql → SQL Admins → Domain Sensitive Assets.',
}

export default function TelemetryGlobe({
  active,
  contained,
  expanded = false,
}: {
  active: boolean
  contained: boolean
  expanded?: boolean
}) {
  const [selectedPin, setSelectedPin] = useState<GlobePin | null>(null)
  const [autoRotate, setAutoRotate] = useState(true)
  const [resetToken, setResetToken] = useState(0)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    const id = window.setInterval(() => setTick((t) => t + 1), 1200)
    return () => window.clearInterval(id)
  }, [])

  function handleSelectPin(pin: GlobePin) {
    setSelectedPin((prev) => (prev?.id === pin.id ? null : pin))
  }

  function handleReset() {
    setSelectedPin(null)
    setAutoRotate(true)
    setResetToken((t) => t + 1)
  }

  const eventsPerMin = active ? 142 + (tick % 8) : 12
  const latency = active ? 18 + (tick % 5) : 42
  const statusText = contained ? 'Contained' : active ? 'Anomaly trace' : 'Nominal'

  return (
    <div className={`tglobe ${expanded ? 'tglobe--expanded' : 'tglobe--mini'}`}>
      <div className="tglobe__scan" aria-hidden />
      <div className="tglobe__grid" aria-hidden />

      <Canvas
        camera={{ position: [0, 0, expanded ? 2.9 : 3.1], fov: expanded ? 42 : 52 }}
        dpr={expanded ? [1, 2] : [1, 1.5]}
        gl={{ antialias: true, alpha: false, powerPreference: 'high-performance' }}
        onCreated={({ gl }) => gl.setClearColor('#040810')}
        style={{ width: '100%', height: '100%' }}
      >
        <Suspense fallback={null}>
          <GlobeScene
            active={active}
            contained={contained}
            pins={PINS}
            selectedId={selectedPin?.id ?? null}
            onSelectPin={handleSelectPin}
            autoRotate={autoRotate}
            expanded={expanded}
            resetToken={resetToken}
          />
        </Suspense>
      </Canvas>

      <div className="tglobe__hud">
        <div className="tglobe__top">
          {expanded && (
            <div className="tglobe__stats">
              <div className={`tglobe__stat ${active ? 'is-alert' : ''}`}>
                <span>Events/min</span>
                <motion.strong key={eventsPerMin} initial={{ opacity: 0.5 }} animate={{ opacity: 1 }}>{eventsPerMin}</motion.strong>
              </div>
              <div className="tglobe__stat"><span>Regions</span><strong>3</strong></div>
              <div className="tglobe__stat"><span>Latency</span><strong>{latency}ms</strong></div>
            </div>
          )}
          <div className="tglobe__toggles">
            <button type="button" className={autoRotate ? 'is-active' : ''} onClick={() => setAutoRotate((v) => !v)}>
              {autoRotate ? 'Pause' : 'Rotate'}
            </button>
            <button type="button" onClick={handleReset}>Reset</button>
          </div>
        </div>

        <div className="tglobe__legend">
          {PINS.map((pin) => (
            <button
              key={pin.id}
              type="button"
              className={`tglobe__chip ${selectedPin?.id === pin.id ? 'is-active' : ''}`}
              onClick={() => handleSelectPin(pin)}
            >
              <i className={`tglobe__dot tglobe__dot--${pin.role}`} />
              {pin.label}
            </button>
          ))}
        </div>

        <AnimatePresence>
          {selectedPin && expanded && (
            <motion.div
              className={`tglobe__detail tglobe__detail--${selectedPin.role}`}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 6 }}
              transition={{ duration: 0.18 }}
            >
              <div className="tglobe__detail-head">
                <i className={`tglobe__dot tglobe__dot--${selectedPin.role}`} />
                <strong>{selectedPin.label}</strong>
              </div>
              <p>{PIN_DETAIL[selectedPin.id]?.(active, contained)}</p>
            </motion.div>
          )}
        </AnimatePresence>

        <div className="tglobe__footer">
          <span className={`tglobe__status ${active ? (contained ? 'is-ok' : 'is-alert') : ''}`}>
            <span className="tglobe__status-dot" />
            {statusText}
          </span>
          {expanded && <span className="tglobe__tip">Drag · scroll to zoom</span>}
        </div>
      </div>
    </div>
  )
}

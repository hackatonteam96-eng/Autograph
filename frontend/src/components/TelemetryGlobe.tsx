import { Suspense, useEffect, useMemo, useRef, useState } from 'react'
import { Canvas } from '@react-three/fiber'
import * as THREE from 'three'
import { api } from '../api/client'
import { GlobeScene, type GlobePin } from './GlobeScene'

const PIN_DETAIL: Record<string, (active: boolean, contained: boolean, ctx: PinContext) => string> = {
  dc01: (a, c, ctx) =>
    a && !c
      ? `ANOMALY: Kerberos identity event from ${ctx.sourceIp || 'lab network'}.`
      : c ? 'CONTAINED: No further anomalous requests.' : 'NOMINAL: Log forwarding active.',
  attacker: (a, _c, ctx) =>
    a && ctx.user
      ? `SOURCE: ${ctx.user} — ${ctx.target ? `targeting ${ctx.target}` : 'identity attack path'}.`
      : 'NOMINAL: Awaiting live Wazuh telemetry.',
  sql: (_a, _c, ctx) =>
    ctx.target && ctx.host
      ? `EXPOSURE: ${ctx.target} on ${ctx.host}.`
      : 'NOMINAL: No mapped target host.',
  lab: () => 'Lab region online — waiting for Wazuh webhook to populate threat pins.',
}

type PinContext = { user?: string; target?: string; host?: string; sourceIp?: string }

const LAB_DC = { lon: 49.8, lat: 40.4 }
/** External threat origin — never overlap DC pin (avoids self-loop arcs) */
const EXTERNAL_ORIGIN = { lon: -74.006, lat: 40.7128, label: 'External source' }

function pinsTooClose(a: { lon: number; lat: number }, b: { lon: number; lat: number }) {
  return Math.abs(a.lon - b.lon) < 1.2 && Math.abs(a.lat - b.lat) < 1.2
}

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
  const [attackerGeo, setAttackerGeo] = useState<{ lat: number; lon: number; label: string } | null>(null)
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

  useEffect(() => {
    if (!sourceIp?.trim()) {
      setAttackerGeo(null)
      return
    }
    let cancelled = false
    api.geo(sourceIp).then((g) => {
      if (cancelled) return
      if (g.private || g.lat == null || g.lon == null) {
        setAttackerGeo({
          ...EXTERNAL_ORIGIN,
          label: g.label || `${sourceIp} · external / lab perimeter`,
        })
        return
      }
      setAttackerGeo({ lat: g.lat, lon: g.lon, label: g.label || g.city || sourceIp })
    }).catch(() => {
      if (!cancelled) setAttackerGeo({ ...EXTERNAL_ORIGIN, label: `Source ${sourceIp}` })
    })
    return () => { cancelled = true }
  }, [sourceIp])

  const pins: GlobePin[] = useMemo(() => {
    if (!user && !host) {
      return [
        { id: 'lab', label: 'LAB', sub: 'Awaiting Wazuh webhook', lon: 49.8, lat: 40.4, role: 'dc' },
      ]
    }
    let attackerLon = attackerGeo?.lon ?? EXTERNAL_ORIGIN.lon
    let attackerLat = attackerGeo?.lat ?? EXTERNAL_ORIGIN.lat
    if (pinsTooClose({ lon: attackerLon, lat: attackerLat }, LAB_DC)) {
      attackerLon = EXTERNAL_ORIGIN.lon
      attackerLat = EXTERNAL_ORIGIN.lat
    }
    const attackerSub = attackerGeo?.label
      ? attackerGeo.label
      : sourceIp
        ? `Source ${sourceIp}`
        : 'External threat origin'
    return [
      { id: 'dc01', label: host || 'DC', sub: 'Domain controller / alert host', lon: LAB_DC.lon, lat: LAB_DC.lat, role: 'dc' },
      { id: 'attacker', label: user?.split('@')[0] || 'Source', sub: attackerSub, lon: attackerLon, lat: attackerLat, role: 'attacker' },
      { id: 'sql', label: target || 'Target', sub: 'Target identity', lon: 13.4, lat: 52.5, role: 'asset' },
    ]
  }, [user, target, host, sourceIp, attackerGeo])

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
            <div className="tglobe__stats">
              <div className={`tglobe__stat ${active ? 'is-alert' : ''}`}>
                <span>Events/min</span>
                <strong>{eventsPerMin || '—'}</strong>
              </div>
              <div className="tglobe__stat">
                <span>Regions</span>
                <strong>{pins.length}</strong>
              </div>
              <div className="tglobe__stat">
                <span>Latency</span>
                <strong>{latency ? `${latency}ms` : '—'}</strong>
              </div>
              <div className={`tglobe__stat ${active ? 'is-alert' : ''}`}>
                <span>Corridor</span>
                <strong>{active ? (contained ? 'Closed' : 'Open') : 'Idle'}</strong>
              </div>
            </div>
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

        {selectedPin && expanded && (
            <aside className={`tglobe__detail tglobe__detail--${selectedPin.role}`}>
              <div className="tglobe__detail-head">
                <span className={`tglobe__dot ${ROLE_DOT[selectedPin.role]}`} />
                <div>
                  <strong>{selectedPin.label}</strong>
                  <span>{selectedPin.sub}</span>
                </div>
              </div>
              <p className="tglobe__detail-coords">
                {Math.abs(selectedPin.lat).toFixed(2)}°{selectedPin.lat >= 0 ? 'N' : 'S'} · {Math.abs(selectedPin.lon).toFixed(2)}°{selectedPin.lon >= 0 ? 'E' : 'W'}
                {selectedPin.id === 'attacker' && attackerGeo?.label ? ` · ${attackerGeo.label}` : ''}
              </p>
              <p>{(PIN_DETAIL[selectedPin.id] ?? (() => 'Live lab telemetry.'))(active, contained, ctx)}</p>
            </aside>
          )}

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

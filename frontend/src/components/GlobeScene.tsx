import { useEffect, useMemo, useRef } from 'react'
import { Html, OrbitControls, Stars } from '@react-three/drei'
import { useFrame, useLoader, useThree } from '@react-three/fiber'
import * as THREE from 'three'
import type { OrbitControls as OrbitControlsImpl } from 'three-stdlib'

export type GlobePin = {
  id: string
  label: string
  sub: string
  lon: number
  lat: number
  role: 'dc' | 'attacker' | 'asset'
}

export function latLonToVec3(lon: number, lat: number, r: number) {
  const phi = (90 - lat) * (Math.PI / 180)
  const theta = (lon + 180) * (Math.PI / 180)
  return new THREE.Vector3(
    -r * Math.sin(phi) * Math.cos(theta),
    r * Math.cos(phi),
    r * Math.sin(phi) * Math.sin(theta),
  )
}

function EarthMesh({
  active,
  contained,
  autoRotate,
}: {
  active: boolean
  contained: boolean
  autoRotate: boolean
}) {
  const group = useRef<THREE.Group>(null)
  const clouds = useRef<THREE.Mesh>(null)
  const aura = useRef<THREE.Mesh>(null)
  const [earthMap, nightMap, cloudsMap] = useLoader(THREE.TextureLoader, [
    '/models/earth/earth-albedo.jpg',
    '/models/earth/earth-night_lights_modified.jpg',
    '/models/earth/clouds-earth.jpg',
  ])

  useEffect(() => {
    for (const t of [earthMap, nightMap, cloudsMap]) t.colorSpace = THREE.SRGBColorSpace
  }, [earthMap, nightMap, cloudsMap])

  useFrame(({ clock }, dt) => {
    if (autoRotate && group.current) group.current.rotation.y += dt * 0.04
    if (autoRotate && clouds.current) clouds.current.rotation.y += dt * 0.025
    if (aura.current) {
      const pulse = active ? 0.05 + Math.sin(clock.elapsedTime * 0.8) * 0.015 : 0.03
      ;(aura.current.material as THREE.MeshBasicMaterial).opacity = pulse
    }
  })

  const emissive = contained ? '#1a9e7a' : active ? '#c04030' : '#1e3d60'

  return (
    <group ref={group}>
      <mesh>
        <sphereGeometry args={[1, 72, 72]} />
        <meshStandardMaterial
          map={earthMap}
          emissiveMap={nightMap}
          emissive={new THREE.Color(emissive)}
          emissiveIntensity={active ? 0.5 : 0.14}
          roughness={0.9}
          metalness={0}
        />
      </mesh>
      <mesh ref={clouds} scale={1.012}>
        <sphereGeometry args={[1, 48, 48]} />
        <meshPhongMaterial map={cloudsMap} transparent opacity={0.12} depthWrite={false} />
      </mesh>
      <mesh ref={aura} scale={1.06}>
        <sphereGeometry args={[1, 32, 32]} />
        <meshBasicMaterial
          color={contained ? '#2dd4a8' : active ? '#ff5c5c' : '#3a7bd5'}
          transparent
          opacity={0.04}
          side={THREE.BackSide}
        />
      </mesh>
    </group>
  )
}

function ThreatArc({
  active,
  contained,
  from,
  to,
}: {
  active: boolean
  contained: boolean
  from: THREE.Vector3
  to: THREE.Vector3
}) {
  const line = useMemo(() => {
    const mid = from.clone().add(to).multiplyScalar(0.5).normalize().multiplyScalar(1.5)
    const curve = new THREE.QuadraticBezierCurve3(from, mid, to)
    const geom = new THREE.BufferGeometry().setFromPoints(curve.getPoints(80))
    return new THREE.Line(geom, new THREE.LineBasicMaterial({ transparent: true, opacity: 0.2 }))
  }, [from, to])

  useFrame(({ clock }) => {
    const mat = line.material as THREE.LineBasicMaterial
    mat.color.set(contained ? '#2dd4a8' : '#ff5c5c')
    mat.opacity = active ? 0.18 + Math.sin(clock.elapsedTime * 0.6) * 0.08 : 0.05
  })

  return <primitive object={line} />
}

function Pin({
  pin,
  selected,
  active,
  contained,
  onSelect,
}: {
  pin: GlobePin
  selected: boolean
  active: boolean
  contained: boolean
  onSelect: (pin: GlobePin) => void
}) {
  const meshRef = useRef<THREE.Mesh>(null)
  const orbitRef = useRef<THREE.Mesh>(null)
  const pos = useMemo(() => latLonToVec3(pin.lon, pin.lat, 1.028), [pin.lon, pin.lat])

  const color =
    pin.role === 'attacker' && active && !contained ? '#ff5c5c'
    : pin.role === 'dc' && active ? (contained ? '#2dd4a8' : '#ffb347')
    : '#5ecfff'

  const showOrbit = selected || (active && pin.role === 'attacker' && !contained)

  useFrame(({ clock }) => {
    if (orbitRef.current && showOrbit) {
      orbitRef.current.rotation.z = clock.elapsedTime * 0.35
      ;(orbitRef.current.material as THREE.MeshBasicMaterial).opacity = 0.35 + Math.sin(clock.elapsedTime * 0.5) * 0.1
    }
    if (meshRef.current) {
      meshRef.current.scale.setScalar(selected ? 1.25 : 1)
    }
  })

  return (
    <group position={pos}>
      {showOrbit && (
        <mesh ref={orbitRef} rotation={[Math.PI / 2, 0, 0]}>
          <ringGeometry args={[0.038, 0.042, 48]} />
          <meshBasicMaterial color={color} transparent opacity={0.35} side={THREE.DoubleSide} />
        </mesh>
      )}
      <mesh
        ref={meshRef}
        onClick={(e) => { e.stopPropagation(); onSelect(pin) }}
        onPointerOver={() => { document.body.style.cursor = 'pointer' }}
        onPointerOut={() => { document.body.style.cursor = 'default' }}
      >
        <sphereGeometry args={[0.02, 12, 12]} />
        <meshBasicMaterial color={color} />
      </mesh>
      {selected && (
        <Html distanceFactor={3.2} style={{ pointerEvents: 'none', transform: 'translate(-50%, -150%)' }}>
          <div className={`globe-pin-label globe-pin-label--${pin.role}`}>{pin.label}</div>
        </Html>
      )}
    </group>
  )
}


export function GlobeScene({
  active,
  contained,
  pins,
  selectedId,
  onSelectPin,
  autoRotate,
  expanded = false,
  resetToken = 0,
}: {
  active: boolean
  contained: boolean
  pins: GlobePin[]
  selectedId: string | null
  onSelectPin: (pin: GlobePin) => void
  autoRotate: boolean
  expanded?: boolean
  resetToken?: number
}) {
  const controlsRef = useRef<OrbitControlsImpl>(null)
  const attacker = pins.find((p) => p.role === 'attacker')
  const dc = pins.find((p) => p.role === 'dc')
  const asset = pins.find((p) => p.role === 'asset')
  const from = attacker ? latLonToVec3(attacker.lon, attacker.lat, 1.02) : null
  const toDc = dc ? latLonToVec3(dc.lon, dc.lat, 1.02) : null
  const toAsset = asset ? latLonToVec3(asset.lon, asset.lat, 1.02) : null
  const { camera } = useThree()

  useEffect(() => {
    const z = expanded ? 2.9 : 3.1
    camera.position.set(0, 0, z)
    camera.lookAt(0, 0, 0)
    controlsRef.current?.reset()
  }, [resetToken, camera, expanded])

  return (
    <>
      <ambientLight intensity={0.9} />
      <directionalLight position={[5, 3, 5]} intensity={2.6} />
      <pointLight position={[-4, -1, 3]} intensity={0.6} color="#5080ff" />
      {active && <pointLight position={[0, 0, 2]} intensity={1.2} color={contained ? '#2dd4a8' : '#ff5c5c'} />}
      <EarthMesh active={active} contained={contained} autoRotate={autoRotate} />
      {active && from && toDc && <ThreatArc active={active} contained={contained} from={from} to={toDc} />}
      {active && from && toAsset && !contained && <ThreatArc active={active} contained={contained} from={from} to={toAsset} />}
      {pins.map((pin) => (
        <Pin
          key={pin.id}
          pin={pin}
          selected={pin.id === selectedId}
          active={active}
          contained={contained}
          onSelect={onSelectPin}
        />
      ))}
      <Stars radius={80} depth={30} count={expanded ? 900 : 400} factor={2} saturation={0} fade speed={0.15} />
      <OrbitControls
        ref={controlsRef}
        enablePan={false}
        enableZoom={expanded}
        enableRotate
        autoRotate={autoRotate}
        autoRotateSpeed={0.3}
        minDistance={1.9}
        maxDistance={expanded ? 5 : 3.5}
      />
    </>
  )
}

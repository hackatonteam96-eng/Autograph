import { useEffect, useMemo, useRef, useState } from 'react'

import { Html, OrbitControls, Stars } from '@react-three/drei'

import { useFrame, useLoader, useThree } from '@react-three/fiber'

import * as THREE from 'three'

import type { OrbitControls as OrbitControlsImpl } from 'three-stdlib'

import { getFresnelMat } from './earth/getFresnelMat'



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



/** 3D-Earth core — Icosahedron layers + fresnel glow (SaraRasoulian/3D-Earth, MIT) */

function Earth3D({

  contained,

  autoRotate,

}: {

  contained: boolean

  autoRotate: boolean

}) {

  const earthMesh = useRef<THREE.Mesh>(null)

  const lightsMesh = useRef<THREE.Mesh>(null)

  const cloudsMesh = useRef<THREE.Mesh>(null)

  const glowMesh = useRef<THREE.Mesh>(null)



  const geometry = useMemo(() => new THREE.IcosahedronGeometry(1, 14), [])



  const [earthMap, lightsMap, cloudsMap] = useLoader(THREE.TextureLoader, [

    '/models/earth/earthmap.jpg',

    '/models/earth/earth_lights.png',

    '/models/earth/cloud_combined.jpg',

  ])



  const fresnelMat = useMemo(() => getFresnelMat(), [])



  useEffect(() => {

    for (const t of [earthMap, lightsMap, cloudsMap]) {

      t.colorSpace = THREE.SRGBColorSpace

      t.anisotropy = 8

    }

  }, [earthMap, lightsMap, cloudsMap])



  useFrame((_, dt) => {

    const s = dt * 60

    if (autoRotate) {

      if (earthMesh.current) earthMesh.current.rotation.y += 0.0019 * s

      if (lightsMesh.current) lightsMesh.current.rotation.y += 0.0019 * s

      if (cloudsMesh.current) cloudsMesh.current.rotation.y += 0.0026 * s

      if (glowMesh.current) glowMesh.current.rotation.y += 0.002 * s

    }



    const rim = contained ? 0x2dd4a8 : 0x3abef9

    fresnelMat.uniforms.color1.value.lerp(new THREE.Color(rim), 0.04)

  })



  return (

    <group rotation={[0, 0, (-23.4 * Math.PI) / 180]}>

      <mesh ref={earthMesh} geometry={geometry}>

        <meshPhongMaterial map={earthMap} />

      </mesh>

      <mesh ref={lightsMesh} geometry={geometry}>

        <meshBasicMaterial map={lightsMap} blending={THREE.AdditiveBlending} />

      </mesh>

      <mesh ref={cloudsMesh} geometry={geometry} scale={1.003}>

        <meshStandardMaterial

          map={cloudsMap}

          transparent

          opacity={0.9}

          blending={THREE.AdditiveBlending}

          depthWrite={false}

        />

      </mesh>

      <mesh ref={glowMesh} geometry={geometry} scale={1.01} material={fresnelMat} />

    </group>

  )

}



function Starfield({ autoRotate }: { autoRotate: boolean }) {

  const ref = useRef<THREE.Group>(null)

  useFrame((_, dt) => {

    if (autoRotate && ref.current) ref.current.rotation.y -= 0.0002 * dt * 60

  })

  return (

    <group ref={ref}>

      <Stars radius={80} depth={50} count={5000} factor={4} saturation={0} fade speed={0.5} />

    </group>

  )

}

/** Curved arcs between correlated identity regions (attacker → DC → target) */
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
  const tubeRef = useRef<THREE.Mesh>(null)
  const pulseRef = useRef<THREE.Mesh>(null)

  const { curve, tubeGeo } = useMemo(() => {
    const lift = 1.28 + from.distanceTo(to) * 0.18
    const mid = from.clone().add(to).multiplyScalar(0.5).normalize().multiplyScalar(lift)
    const curve = new THREE.QuadraticBezierCurve3(from, mid, to)
    const tubeGeo = new THREE.TubeGeometry(curve, 80, 0.0035, 8, false)
    return { curve, tubeGeo }
  }, [from, to])

  useFrame(({ clock }) => {
    const col = contained ? '#2dd4a8' : '#ff5c5c'
    if (tubeRef.current) {
      const m = tubeRef.current.material as THREE.MeshBasicMaterial
      m.color.set(col)
      m.opacity = active ? 0.5 + Math.sin(clock.elapsedTime * 2) * 0.12 : 0.12
    }
    if (pulseRef.current && active) {
      const t = (clock.elapsedTime * 0.4) % 1
      pulseRef.current.position.copy(curve.getPoint(t))
      pulseRef.current.scale.setScalar(0.018 + Math.sin(t * Math.PI) * 0.014)
      ;(pulseRef.current.material as THREE.MeshBasicMaterial).color.set(col)
    }
  })

  return (
    <group>
      <mesh ref={tubeRef} geometry={tubeGeo}>
        <meshBasicMaterial color="#ff5c5c" transparent toneMapped={false} />
      </mesh>
      {active && (
        <mesh ref={pulseRef}>
          <sphereGeometry args={[1, 12, 12]} />
          <meshBasicMaterial color="#ff5c5c" transparent toneMapped={false} />
        </mesh>
      )}
    </group>
  )
}

function Pin({

  pin,

  selected,

  hovered,

  active,

  contained,

  onSelect,

  onHover,

}: {

  pin: GlobePin

  selected: boolean

  hovered: boolean

  active: boolean

  contained: boolean

  onSelect: (pin: GlobePin) => void

  onHover: (id: string | null) => void

}) {

  const meshRef = useRef<THREE.Mesh>(null)

  const pos = useMemo(() => latLonToVec3(pin.lon, pin.lat, 1.02), [pin.lon, pin.lat])

  const normal = useMemo(() => pos.clone().normalize(), [pos])

  const quat = useMemo(() => {

    const q = new THREE.Quaternion()

    q.setFromUnitVectors(new THREE.Vector3(0, 0, 1), normal)

    return q

  }, [normal])



  const color =

    pin.role === 'attacker' && active && !contained ? '#ff5c5c'

    : pin.role === 'dc' && active ? (contained ? '#2dd4a8' : '#ffb347')

    : '#5ecfff'



  useFrame(({ clock }) => {

    if (meshRef.current) {

      const base = selected ? 1.5 : hovered ? 1.2 : 1

      const pulse = active && pin.role === 'attacker' ? 1 + Math.sin(clock.elapsedTime * 3) * 0.1 : 1

      meshRef.current.scale.setScalar(base * pulse)

    }

  })



  return (

    <group position={pos} quaternion={quat}>

      <mesh

        ref={meshRef}

        onClick={(e) => { e.stopPropagation(); onSelect(pin) }}

        onPointerOver={(e) => { e.stopPropagation(); onHover(pin.id); document.body.style.cursor = 'pointer' }}

        onPointerOut={() => { onHover(null); document.body.style.cursor = 'default' }}

      >

        <sphereGeometry args={[0.022, 16, 16]} />

        <meshBasicMaterial color={color} toneMapped={false} />

      </mesh>

      {(selected || hovered) && (

        <Html distanceFactor={3.2} style={{ pointerEvents: 'none', transform: 'translate(-50%, -160%)' }}>

          <div className={`globe-pin-label globe-pin-label--${pin.role}`}>

            <strong>{pin.label}</strong>

            <span>{pin.sub}</span>

          </div>

        </Html>

      )}

    </group>

  )

}



function CameraFocus({

  focusPos,

  controlsRef,

  expanded,

}: {

  focusPos: THREE.Vector3 | null

  controlsRef: React.RefObject<OrbitControlsImpl | null>

  expanded: boolean

}) {

  const { camera } = useThree()

  const targetCam = useRef(new THREE.Vector3())

  const targetLook = useRef(new THREE.Vector3())

  const animating = useRef(false)



  useEffect(() => {

    if (!focusPos || !expanded) return

    const dir = focusPos.clone().normalize()

    targetLook.current.copy(focusPos)

    targetCam.current.copy(dir.multiplyScalar(2.0))

    animating.current = true

  }, [focusPos, expanded])



  useFrame((_, dt) => {

    if (!animating.current || !focusPos) return

    camera.position.lerp(targetCam.current, dt * 2.5)

    if (controlsRef.current) {

      controlsRef.current.target.lerp(targetLook.current, dt * 3)

      controlsRef.current.update()

    }

    if (camera.position.distanceTo(targetCam.current) < 0.03) animating.current = false

  })



  return null

}



export function GlobeScene({

  active,

  contained,

  pins,

  selectedId,

  focusPinId,

  onSelectPin,

  autoRotate,

  expanded = false,

  resetToken = 0,

}: {

  active: boolean

  contained: boolean

  pins: GlobePin[]

  selectedId: string | null

  focusPinId?: string | null

  onSelectPin: (pin: GlobePin) => void

  autoRotate: boolean

  expanded?: boolean

  resetToken?: number

}) {

  const controlsRef = useRef<OrbitControlsImpl>(null)

  const [hoverId, setHoverId] = useState<string | null>(null)

  const { camera } = useThree()



  const focusPin = pins.find((p) => p.id === focusPinId)

  const focusPos = focusPin ? latLonToVec3(focusPin.lon, focusPin.lat, 1.02) : null

  const attacker = pins.find((p) => p.role === 'attacker')
  const dc = pins.find((p) => p.role === 'dc')
  const asset = pins.find((p) => p.role === 'asset')
  const from = attacker ? latLonToVec3(attacker.lon, attacker.lat, 1.02) : null
  const toDc = dc ? latLonToVec3(dc.lon, dc.lat, 1.02) : null
  const toAsset = asset ? latLonToVec3(asset.lon, asset.lat, 1.02) : null

  useEffect(() => {

    const z = expanded ? 3.55 : 3.25

    camera.position.set(0, 0, z)

    camera.lookAt(0, 0, 0)

    controlsRef.current?.reset()

  }, [resetToken, camera, expanded])



  return (

    <>

      <color attach="background" args={['#000000']} />

      <ambientLight intensity={0.08} />

      <directionalLight intensity={2.0} color="#ffffff" position={[-2.2, 0.7, 1.6]} />



      <Earth3D contained={contained} autoRotate={autoRotate} />

      <Starfield autoRotate={autoRotate} />

      {active && from && toDc && from.distanceTo(toDc) > 0.05 && (
        <ThreatArc active={active} contained={contained} from={from} to={toDc} />
      )}
      {active && from && toAsset && !contained && from.distanceTo(toAsset) > 0.05 && (
        <ThreatArc active={active} contained={contained} from={from} to={toAsset} />
      )}

      {pins.map((pin) => (

        <Pin

          key={pin.id}

          pin={pin}

          selected={pin.id === selectedId}

          hovered={pin.id === hoverId}

          active={active}

          contained={contained}

          onSelect={onSelectPin}

          onHover={setHoverId}

        />

      ))}



      <OrbitControls

        ref={controlsRef}

        enablePan={false}

        enableZoom={expanded}

        enableRotate

        autoRotate={false}

        rotateSpeed={0.5}

        minDistance={1.6}

        maxDistance={expanded ? 6 : 4.5}

        dampingFactor={0.05}

        enableDamping

      />



      <CameraFocus focusPos={focusPos} controlsRef={controlsRef} expanded={expanded} />

    </>

  )

}



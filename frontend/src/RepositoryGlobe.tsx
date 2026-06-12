import { Suspense, useEffect, useMemo, useRef } from 'react'
import { Canvas, useFrame, useLoader } from '@react-three/fiber'
import { OrbitControls, Stars } from '@react-three/drei'
import * as THREE from 'three'

function EarthSphere({ active, contained }: { active: boolean; contained: boolean }) {
  const groupRef = useRef<THREE.Group>(null)
  const cloudsRef = useRef<THREE.Mesh>(null)
  const [earthMap, nightMap, cloudsMap] = useLoader(THREE.TextureLoader, [
    '/models/earth/earth-albedo.jpg',
    '/models/earth/earth-night_lights_modified.jpg',
    '/models/earth/clouds-earth.jpg',
  ])

  useEffect(() => {
    for (const tex of [earthMap, nightMap, cloudsMap]) {
      tex.colorSpace = THREE.SRGBColorSpace
      tex.anisotropy = 8
    }
  }, [cloudsMap, earthMap, nightMap])

  useFrame((_, delta) => {
    if (groupRef.current) groupRef.current.rotation.y += delta * 0.08
    if (cloudsRef.current) cloudsRef.current.rotation.y += delta * 0.05
  })

  const emissive = contained ? '#0bd3b1' : active ? '#ff7a59' : '#5a9fd4'
  const emissiveIntensity = active ? 0.55 : 0.28

  return (
    <group ref={groupRef} rotation={[0.18, 2.4, 0]}>
      <mesh>
        <sphereGeometry args={[1.6, 64, 64]} />
        <meshStandardMaterial
          map={earthMap}
          emissiveMap={nightMap}
          emissive={new THREE.Color(emissive)}
          emissiveIntensity={emissiveIntensity}
          roughness={0.92}
          metalness={0.02}
        />
      </mesh>
      <mesh ref={cloudsRef}>
        <sphereGeometry args={[1.625, 48, 48]} />
        <meshPhongMaterial
          map={cloudsMap}
          transparent
          opacity={0.14}
          depthWrite={false}
        />
      </mesh>
      <mesh>
        <sphereGeometry args={[1.68, 48, 48]} />
        <meshBasicMaterial color="#4dd4ff" transparent opacity={0.06} side={THREE.BackSide} />
      </mesh>
    </group>
  )
}

function ThreatArc({ active, contained }: { active: boolean; contained: boolean }) {
  const lineRef = useRef<THREE.Line>(null)

  const line = useMemo(() => {
    const curve = new THREE.CatmullRomCurve3([
      new THREE.Vector3(-1.2, 0.5, 1.1),
      new THREE.Vector3(-0.3, 1.4, 0.9),
      new THREE.Vector3(0.85, 0.7, 1.2),
    ])
    const geometry = new THREE.BufferGeometry().setFromPoints(curve.getPoints(48))
    return new THREE.Line(geometry, new THREE.LineBasicMaterial({ transparent: true }))
  }, [])

  useFrame(({ clock }) => {
    const mat = lineRef.current?.material as THREE.LineBasicMaterial | undefined
    if (!mat) return
    mat.color.set(contained ? '#52e0c4' : active ? '#ff5c70' : '#5a7088')
    mat.opacity = active ? 0.45 + Math.sin(clock.elapsedTime * 2) * 0.2 : 0.12
  })

  return <primitive ref={lineRef} object={line} />
}

function ThreatPin({ lon, lat, color, size = 0.04 }: { lon: number; lat: number; color: string; size?: number }) {
  const phi = (90 - lat) * (Math.PI / 180)
  const theta = (lon + 180) * (Math.PI / 180)
  const r = 1.65
  const x = -r * Math.sin(phi) * Math.cos(theta)
  const y = r * Math.cos(phi)
  const z = r * Math.sin(phi) * Math.sin(theta)

  return (
    <mesh position={[x, y, z]}>
      <sphereGeometry args={[size, 16, 16]} />
      <meshBasicMaterial color={color} />
    </mesh>
  )
}

function Scene({ active, contained, expanded }: { active: boolean; contained: boolean; expanded: boolean }) {
  return (
    <>
      <color attach="background" args={['#0a1219']} />
      <ambientLight intensity={1.4} color="#b8d4ff" />
      <directionalLight intensity={2.8} color="#ffffff" position={[4, 2, 5]} />
      <pointLight intensity={active ? 2.5 : 0.8} color={contained ? '#52e0c4' : '#ff8b6b'} position={[-3, 1, 2]} />
      <EarthSphere active={active} contained={contained} />
      <ThreatArc active={active} contained={contained} />
      <ThreatPin lon={49.8} lat={40.4} color={active && !contained ? '#ff5c70' : '#52e0c4'} size={expanded ? 0.05 : 0.035} />
      <ThreatPin lon={-77.0} lat={38.9} color="#52e0c4" size={expanded ? 0.04 : 0.028} />
      {expanded && <Stars radius={80} depth={40} count={1200} factor={3} saturation={0} fade speed={0.4} />}
      <OrbitControls
        enablePan={false}
        enableZoom={expanded}
        enableRotate={expanded}
        autoRotate={!expanded}
        autoRotateSpeed={0.5}
        minDistance={3.2}
        maxDistance={6}
      />
    </>
  )
}

export default function RepositoryGlobe({
  active,
  contained,
  expanded,
}: {
  active: boolean
  contained: boolean
  expanded: boolean
}) {
  return (
    <div className="globe-canvas">
      <Canvas
        camera={{ position: [0, 0, 4.2], fov: 42 }}
        dpr={[1, 2]}
        gl={{ alpha: true, antialias: true, powerPreference: 'high-performance' }}
        style={{ width: '100%', height: '100%', display: 'block' }}
      >
        <Suspense fallback={null}>
          <Scene active={active} contained={contained} expanded={expanded} />
        </Suspense>
      </Canvas>
    </div>
  )
}

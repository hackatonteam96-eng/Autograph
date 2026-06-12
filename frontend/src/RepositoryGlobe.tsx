import { Suspense, useEffect, useMemo, useRef, useState } from 'react'
import { Canvas, useFrame, useLoader } from '@react-three/fiber'
import { OrbitControls } from '@react-three/drei'
import * as THREE from 'three'

type RawGlobePoint = { lon: number; lat: number; type: string }
type GlobeData = { meta?: { landDotsColor?: string; oceanDotsColor?: string }; points: RawGlobePoint[] }

function toSpherePosition(lon: number, lat: number, radius = 2): [number, number, number] {
  const phi = (90 - lat) * (Math.PI / 180)
  const theta = (lon + 180) * (Math.PI / 180)

  return [
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta),
  ]
}

function GlobePointLayer({ active, contained, expanded }: { active: boolean; contained: boolean; expanded: boolean }) {
  const [pointData, setPointData] = useState<GlobeData | null>(null)

  useEffect(() => {
    let cancelled = false

    fetch('/data/globe-points.json')
      .then((response) => response.json())
      .then((data: GlobeData) => {
        if (!cancelled) setPointData(data)
      })
      .catch(() => undefined)

    return () => {
      cancelled = true
    }
  }, [])

  const geometry = useMemo(() => {
    if (!pointData) return null

    const sampleEvery = expanded ? 30 : 78
    const positions: number[] = []
    const colors: number[] = []
    const normal = new THREE.Color(contained ? '#52e0c4' : '#79c9ff')
    const quiet = new THREE.Color('#6f7d91')
    const danger = new THREE.Color(active && !contained ? '#ff5c70' : '#52e0c4')

    pointData.points.forEach((point, index) => {
      if (point.type !== 'land' || index % sampleEvery !== 0) return

      const position = toSpherePosition(point.lon, point.lat, 2.025)
      const isSignalPoint = index % 131 === 0
      positions.push(position[0], position[1], position[2])

      const color = isSignalPoint ? danger : index % 7 === 0 ? normal : quiet
      colors.push(color.r, color.g, color.b)
    })

    const buffer = new THREE.BufferGeometry()
    buffer.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3))
    buffer.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3))
    return buffer
  }, [active, contained, expanded, pointData])

  const material = useMemo(
    () =>
      new THREE.PointsMaterial({
        size: expanded ? 0.018 : 0.015,
        vertexColors: true,
        transparent: true,
        opacity: expanded ? 0.78 : 0.58,
        sizeAttenuation: true,
        depthWrite: false,
      }),
    [expanded],
  )

  if (!geometry) return null

  return <points geometry={geometry} material={material} />
}

function AttackTrace({ active, contained }: { active: boolean; contained: boolean }) {
  const geometry = useMemo(() => {
    const curve = new THREE.CatmullRomCurve3([
      new THREE.Vector3(-1.54, 0.74, 1.09),
      new THREE.Vector3(-0.58, 1.82, 0.84),
      new THREE.Vector3(0.9, 0.92, 1.42),
    ])
    return new THREE.BufferGeometry().setFromPoints(curve.getPoints(72))
  }, [])
  const trace = useMemo(
    () => new THREE.Line(geometry, new THREE.LineBasicMaterial({ transparent: true, opacity: active ? 0.7 : 0.16 })),
    [active, geometry],
  )

  useFrame(({ clock }) => {
    const material = trace.material as THREE.LineBasicMaterial
    material.opacity = active ? 0.54 + Math.sin(clock.elapsedTime * 2.2) * 0.16 : 0.16
    material.color.set(contained ? '#52e0c4' : active ? '#ff5c70' : '#7f8da3')
  })

  return <primitive object={trace} />
}

function Earth({ active, contained, expanded }: { active: boolean; contained: boolean; expanded: boolean }) {
  const groupRef = useRef<THREE.Group>(null)
  const cloudsRef = useRef<THREE.Mesh>(null)
  const [earthMap, nightMap, cloudsMap] = useLoader(THREE.TextureLoader, [
    '/models/earth/earth-albedo.jpg',
    '/models/earth/earth-night_lights_modified.jpg',
    '/models/earth/clouds-earth.jpg',
  ])

  useEffect(() => {
    earthMap.colorSpace = THREE.SRGBColorSpace
    nightMap.colorSpace = THREE.SRGBColorSpace
    cloudsMap.colorSpace = THREE.SRGBColorSpace
  }, [cloudsMap, earthMap, nightMap])

  useFrame(() => {
    if (groupRef.current) groupRef.current.rotation.y += expanded ? 0.0016 : 0.001
    if (cloudsRef.current) cloudsRef.current.rotation.y += 0.0007
  })

  return (
    <group ref={groupRef} rotation={[0.14, 2.15, -0.08]}>
      <mesh>
        <sphereGeometry args={[2, 112, 112]} />
        <meshStandardMaterial
          map={earthMap}
          emissiveMap={nightMap}
          emissive={contained ? '#0bd3b1' : active ? '#ff9a66' : '#8bbfff'}
          emissiveIntensity={active ? 0.8 : 0.34}
          roughness={0.86}
          metalness={0}
        />
      </mesh>
      <mesh ref={cloudsRef}>
        <sphereGeometry args={[2.028, 96, 96]} />
        <meshPhongMaterial
          map={cloudsMap}
          alphaMap={cloudsMap}
          transparent
          opacity={expanded ? 0.18 : 0.1}
          depthWrite={false}
        />
      </mesh>
      <mesh>
        <sphereGeometry args={[2.075, 96, 96]} />
        <meshBasicMaterial color="#63d7ff" transparent opacity={expanded ? 0.09 : 0.055} side={THREE.BackSide} />
      </mesh>
      <GlobePointLayer active={active} contained={contained} expanded={expanded} />
      <AttackTrace active={active} contained={contained} />
    </group>
  )
}

export default function RepositoryGlobe({ active, contained, expanded }: { active: boolean; contained: boolean; expanded: boolean }) {
  return (
    <div className="globe-canvas">
      <Canvas
        camera={{ position: [0, 0, expanded ? 5.65 : 5.35], fov: expanded ? 35 : 40 }}
        dpr={[1, 1.75]}
        gl={{ alpha: true, antialias: true, powerPreference: 'high-performance' }}
      >
        <ambientLight color="#c7ddff" intensity={2.2} />
        <directionalLight color="#ffffff" intensity={4.6} position={[3.8, 2.4, 5]} />
        <hemisphereLight color="#d9f2ff" groundColor="#1c3858" intensity={1.25} />
        <pointLight color={contained ? '#52e0c4' : '#ff8b6b'} intensity={active ? 3.2 : 1.2} position={[-3, 1, 3]} />
        <Suspense fallback={null}>
          <Earth active={active} contained={contained} expanded={expanded} />
        </Suspense>
        <OrbitControls
          enablePan={false}
          enableZoom={expanded}
          enableRotate={expanded}
          autoRotate={!expanded}
          autoRotateSpeed={0.34}
          minDistance={4.2}
          maxDistance={7}
        />
      </Canvas>
    </div>
  )
}

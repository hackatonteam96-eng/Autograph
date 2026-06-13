/**
 * Procedural starfield — ported from SaraRasoulian/3D-Earth (MIT)
 * https://github.com/SaraRasoulian/3D-Earth
 */
import * as THREE from 'three'

function randomSpherePoint() {
  const radius = Math.random() * 25 + 25
  const u = Math.random()
  const v = Math.random()
  const theta = 2 * Math.PI * u
  const phi = Math.acos(2 * v - 1)
  const x = radius * Math.sin(phi) * Math.cos(theta)
  const y = radius * Math.sin(phi) * Math.sin(theta)
  const z = radius * Math.cos(phi)
  return { pos: new THREE.Vector3(x, y, z), hue: 0.6 }
}

export function getStarfield({ numStars = 5000 }: { numStars?: number } = {}) {
  const verts: number[] = []
  const colors: number[] = []

  for (let i = 0; i < numStars; i += 1) {
    const { pos, hue } = randomSpherePoint()
    const col = new THREE.Color().setHSL(hue, 0.4, Math.random())
    verts.push(pos.x, pos.y, pos.z)
    colors.push(col.r, col.g, col.b)
  }

  const geo = new THREE.BufferGeometry()
  geo.setAttribute('position', new THREE.Float32BufferAttribute(verts, 3))
  geo.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3))

  const mat = new THREE.PointsMaterial({
    size: 0.2,
    vertexColors: true,
    map: new THREE.TextureLoader().load('/models/earth/stars/circle.png'),
    transparent: true,
    depthWrite: false,
  })

  return new THREE.Points(geo, mat)
}

'use client'

import { useRef, useMemo, useState, useEffect, useCallback } from 'react'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import { OrbitControls, Text, Html } from '@react-three/drei'
import * as THREE from 'three'
import type { DastFinding } from '@/lib/types'

interface AttackGraph3DProps {
  findings: DastFinding[]
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  attackChains?: any
  onFindingClick?: (finding: DastFinding) => void
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#6b7280',
}

interface GraphNode {
  id: string
  finding: DastFinding
  position: THREE.Vector3
  velocity: THREE.Vector3
  color: string
  radius: number
}

interface GraphEdge {
  source: string
  target: string
  color: string
}

// ── Force-directed layout simulation ──
function useForceLayout(nodes: GraphNode[], edges: GraphEdge[]) {
  const nodesRef = useRef(nodes)
  nodesRef.current = nodes

  useFrame(() => {
    const ns = nodesRef.current
    if (ns.length === 0) return

    const repulsion = 8
    const attraction = 0.005
    const damping = 0.92
    const centerPull = 0.002

    // Repulsion between all nodes
    for (let i = 0; i < ns.length; i++) {
      for (let j = i + 1; j < ns.length; j++) {
        const diff = new THREE.Vector3().subVectors(ns[i].position, ns[j].position)
        const dist = diff.length() || 0.1
        const force = repulsion / (dist * dist)
        diff.normalize().multiplyScalar(force)
        ns[i].velocity.add(diff)
        ns[j].velocity.sub(diff)
      }
    }

    // Attraction along edges
    for (const edge of edges) {
      const src = ns.find(n => n.id === edge.source)
      const tgt = ns.find(n => n.id === edge.target)
      if (!src || !tgt) continue
      const diff = new THREE.Vector3().subVectors(tgt.position, src.position)
      const force = diff.length() * attraction
      diff.normalize().multiplyScalar(force)
      src.velocity.add(diff)
      tgt.velocity.sub(diff)
    }

    // Center pull + damping + apply
    for (const node of ns) {
      node.velocity.add(node.position.clone().negate().multiplyScalar(centerPull))
      node.velocity.multiplyScalar(damping)
      node.position.add(node.velocity)
    }
  })
}

// ── Individual node sphere ──
function NodeSphere({
  node,
  isSelected,
  isOnCriticalPath,
  onClick,
}: {
  node: GraphNode
  isSelected: boolean
  isOnCriticalPath: boolean
  onClick: () => void
}) {
  const meshRef = useRef<THREE.Mesh>(null)
  const glowRef = useRef<THREE.Mesh>(null)
  const [hovered, setHovered] = useState(false)

  useFrame(({ clock }) => {
    if (meshRef.current) {
      meshRef.current.position.copy(node.position)
      // Pulse critical nodes
      if (node.finding.severity === 'CRITICAL') {
        const pulse = 1 + Math.sin(clock.elapsedTime * 3) * 0.15
        meshRef.current.scale.setScalar(pulse)
      }
    }
    if (glowRef.current) {
      glowRef.current.position.copy(node.position)
      const glowPulse = 1 + Math.sin(clock.elapsedTime * 2) * 0.3
      glowRef.current.scale.setScalar(glowPulse)
    }
  })

  return (
    <group>
      {/* Glow for critical path */}
      {isOnCriticalPath && (
        <mesh ref={glowRef}>
          <sphereGeometry args={[node.radius * 2, 16, 16]} />
          <meshBasicMaterial color={node.color} transparent opacity={0.1} />
        </mesh>
      )}
      {/* Main sphere */}
      <mesh
        ref={meshRef}
        onClick={(e) => { e.stopPropagation(); onClick() }}
        onPointerOver={() => setHovered(true)}
        onPointerOut={() => setHovered(false)}
      >
        <sphereGeometry args={[node.radius, 24, 24]} />
        <meshStandardMaterial
          color={node.color}
          emissive={node.color}
          emissiveIntensity={hovered || isSelected ? 0.8 : 0.3}
          roughness={0.3}
          metalness={0.6}
        />
      </mesh>
      {/* Selection ring */}
      {isSelected && (
        <mesh position={node.position}>
          <ringGeometry args={[node.radius * 1.4, node.radius * 1.6, 32]} />
          <meshBasicMaterial color="#ffffff" side={THREE.DoubleSide} />
        </mesh>
      )}
      {/* Label on hover */}
      {hovered && (
        <Html position={node.position} center style={{ pointerEvents: 'none' }}>
          <div
            className="mono"
            style={{
              background: 'rgba(0,0,0,0.85)',
              color: '#fff',
              padding: '6px 10px',
              borderRadius: 4,
              fontSize: 10,
              whiteSpace: 'nowrap',
              border: `1px solid ${node.color}`,
              maxWidth: 250,
            }}
          >
            <div style={{ fontWeight: 700, marginBottom: 2 }}>{node.finding.severity}</div>
            <div>{node.finding.title}</div>
            <div style={{ opacity: 0.7, fontSize: 9, marginTop: 2 }}>
              CVSS: {node.finding.cvssScore ?? 'N/A'}
            </div>
          </div>
        </Html>
      )}
    </group>
  )
}

// ── Edge lines with animated pulse ──
function EdgeLine({ edge, nodes, isCriticalPath }: { edge: GraphEdge; nodes: GraphNode[]; isCriticalPath: boolean }) {
  const groupRef = useRef<THREE.Group>(null)
  const lineObjRef = useRef<THREE.Line | null>(null)
  const pulseRef = useRef<THREE.Mesh>(null)

  // Create line object imperatively to avoid JSX <line> SVG conflict
  useEffect(() => {
    if (!groupRef.current) return
    const geo = new THREE.BufferGeometry()
    const positions = new Float32Array(6)
    geo.setAttribute('position', new THREE.BufferAttribute(positions, 3))
    const mat = new THREE.LineBasicMaterial({
      color: edge.color,
      transparent: true,
      opacity: isCriticalPath ? 0.6 : 0.2,
    })
    const lineObj = new THREE.Line(geo, mat)
    lineObjRef.current = lineObj
    groupRef.current.add(lineObj)
    return () => {
      if (groupRef.current) groupRef.current.remove(lineObj)
      geo.dispose()
      mat.dispose()
    }
  }, [edge.color, isCriticalPath])

  useFrame(({ clock }) => {
    const src = nodes.find(n => n.id === edge.source)
    const tgt = nodes.find(n => n.id === edge.target)
    if (!src || !tgt || !lineObjRef.current) return

    const geometry = lineObjRef.current.geometry as THREE.BufferGeometry
    const positions = geometry.attributes.position
    if (positions) {
      positions.setXYZ(0, src.position.x, src.position.y, src.position.z)
      positions.setXYZ(1, tgt.position.x, tgt.position.y, tgt.position.z)
      positions.needsUpdate = true
    }

    // Animate pulse along critical path
    if (isCriticalPath && pulseRef.current) {
      const t = (clock.elapsedTime * 0.5) % 1
      pulseRef.current.position.lerpVectors(src.position, tgt.position, t)
    }
  })

  return (
    <group ref={groupRef}>
      {isCriticalPath && (
        <mesh ref={pulseRef}>
          <sphereGeometry args={[0.15, 8, 8]} />
          <meshBasicMaterial color={edge.color} transparent opacity={0.8} />
        </mesh>
      )}
    </group>
  )
}

// ── Camera auto-orbit ──
function AutoOrbit({ enabled }: { enabled: boolean }) {
  const { camera } = useThree()
  const angleRef = useRef(0)

  useFrame((_, delta) => {
    if (!enabled) return
    angleRef.current += delta * 0.1
    const radius = camera.position.length()
    camera.position.x = Math.cos(angleRef.current) * radius * 0.7
    camera.position.z = Math.sin(angleRef.current) * radius * 0.7
    camera.lookAt(0, 0, 0)
  })

  return null
}

// ── Main 3D scene ──
function AttackGraphScene({
  findings,
  attackChains,
  onFindingClick,
}: AttackGraph3DProps) {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [autoOrbit, setAutoOrbit] = useState(true)

  // Build graph data
  const { nodes, edges, criticalPathIds } = useMemo(() => {
    const ns: GraphNode[] = findings.map((f, i) => {
      const angle = (i / findings.length) * Math.PI * 2
      const r = 3 + Math.random() * 5
      const y = (Math.random() - 0.5) * 6
      return {
        id: f.id,
        finding: f,
        position: new THREE.Vector3(Math.cos(angle) * r, y, Math.sin(angle) * r),
        velocity: new THREE.Vector3(),
        color: SEV_COLORS[f.severity] || '#6b7280',
        radius: Math.max(0.2, ((f.cvssScore || 3) / 10) * 0.8),
      }
    })

    const es: GraphEdge[] = []
    const critIds = new Set<string>()

    // Build edges from attack chain correlation data
    if (attackChains?.chains) {
      for (const chain of attackChains.chains) {
        if (chain.findingIds && chain.findingIds.length > 1) {
          const isCritical = chain.riskAmplifier > 1.5
          for (let i = 0; i < chain.findingIds.length - 1; i++) {
            const srcId = chain.findingIds[i]
            const tgtId = chain.findingIds[i + 1]
            if (ns.some(n => n.id === srcId) && ns.some(n => n.id === tgtId)) {
              es.push({
                source: srcId,
                target: tgtId,
                color: isCritical ? '#ef4444' : '#f97316',
              })
              if (isCritical) {
                critIds.add(srcId)
                critIds.add(tgtId)
              }
            }
          }
        }
      }
    }

    // Also create edges between findings affecting the same URL
    const urlGroups = new Map<string, string[]>()
    for (const f of findings) {
      const url = f.affectedUrl
      if (!urlGroups.has(url)) urlGroups.set(url, [])
      urlGroups.get(url)!.push(f.id)
    }
    for (const ids of urlGroups.values()) {
      if (ids.length > 1) {
        for (let i = 0; i < Math.min(ids.length - 1, 3); i++) {
          es.push({
            source: ids[i],
            target: ids[i + 1],
            color: '#4b5563',
          })
        }
      }
    }

    // Connect same OWASP category findings
    const owaspGroups = new Map<string, string[]>()
    for (const f of findings) {
      if (f.owaspCategory) {
        if (!owaspGroups.has(f.owaspCategory)) owaspGroups.set(f.owaspCategory, [])
        owaspGroups.get(f.owaspCategory)!.push(f.id)
      }
    }
    for (const ids of owaspGroups.values()) {
      if (ids.length > 1 && ids.length <= 6) {
        for (let i = 0; i < ids.length - 1; i++) {
          es.push({ source: ids[i], target: ids[i + 1], color: '#374151' })
        }
      }
    }

    return { nodes: ns, edges: es, criticalPathIds: critIds }
  }, [findings, attackChains])

  useForceLayout(nodes, edges)

  const handleNodeClick = useCallback((finding: DastFinding) => {
    setSelectedId(prev => prev === finding.id ? null : finding.id)
    setAutoOrbit(false)
    onFindingClick?.(finding)
  }, [onFindingClick])

  return (
    <>
      <ambientLight intensity={0.4} />
      <pointLight position={[10, 10, 10]} intensity={0.8} />
      <pointLight position={[-10, -10, -10]} intensity={0.3} color="#7c3aed" />

      {/* Edges */}
      {edges.map((edge, i) => (
        <EdgeLine
          key={`e-${i}`}
          edge={edge}
          nodes={nodes}
          isCriticalPath={criticalPathIds.has(edge.source) && criticalPathIds.has(edge.target)}
        />
      ))}

      {/* Nodes */}
      {nodes.map(node => (
        <NodeSphere
          key={node.id}
          node={node}
          isSelected={selectedId === node.id}
          isOnCriticalPath={criticalPathIds.has(node.id)}
          onClick={() => handleNodeClick(node.finding)}
        />
      ))}

      {/* Center label */}
      <Text
        position={[0, -5, 0]}
        fontSize={0.4}
        color="#6b7280"
        anchorX="center"
        anchorY="middle"
        font={undefined}
      >
        {findings.length} VULNERABILITIES
      </Text>

      <OrbitControls
        enableDamping
        dampingFactor={0.1}
        onStart={() => setAutoOrbit(false)}
      />
      <AutoOrbit enabled={autoOrbit} />
    </>
  )
}

// ── Selected finding detail panel ──
function FindingDetailPanel({ finding }: { finding: DastFinding | null }) {
  if (!finding) return null

  const breachCost = (finding.cvssScore || 0) * 52000

  return (
    <div style={{
      position: 'absolute', top: 12, right: 12, width: 280,
      background: 'rgba(0,0,0,0.85)', border: '1px solid var(--color-border)',
      borderRadius: 6, padding: 16, zIndex: 10,
      backdropFilter: 'blur(10px)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <span className="mono" style={{
          fontSize: 9, padding: '2px 6px', borderRadius: 3,
          color: SEV_COLORS[finding.severity],
          border: `1px solid ${SEV_COLORS[finding.severity]}`,
        }}>
          {finding.severity}
        </span>
        <span className="mono" style={{ fontSize: 10, color: '#9ca3af' }}>
          CVSS {finding.cvssScore ?? '—'}
        </span>
      </div>
      <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: '#fff', marginBottom: 6 }}>
        {finding.title}
      </div>
      <div style={{ fontSize: 11, color: '#9ca3af', lineHeight: 1.5, marginBottom: 10 }}>
        {finding.description?.substring(0, 150)}...
      </div>
      <div className="mono" style={{ fontSize: 9, color: '#6b7280', marginBottom: 4 }}>
        {finding.affectedUrl}
      </div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 8 }}>
        {finding.cweId && (
          <span className="mono" style={{ fontSize: 8, padding: '2px 5px', borderRadius: 3, background: '#1f2937', border: '1px solid #374151', color: '#9ca3af' }}>
            {finding.cweId}
          </span>
        )}
        {finding.owaspCategory && (
          <span className="mono" style={{ fontSize: 8, padding: '2px 5px', borderRadius: 3, background: '#1f2937', border: '1px solid #374151', color: '#9ca3af' }}>
            {finding.owaspCategory}
          </span>
        )}
      </div>
      <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid #374151' }}>
        <div className="mono" style={{ fontSize: 9, color: '#6b7280', letterSpacing: '0.08em' }}>EST. BREACH COST</div>
        <div className="mono" style={{
          fontSize: 16, fontWeight: 800, marginTop: 2,
          color: breachCost > 300000 ? '#ef4444' : '#f97316',
        }}>
          ${breachCost >= 1000000 ? `${(breachCost / 1000000).toFixed(1)}M` : `${(breachCost / 1000).toFixed(0)}K`}
        </div>
      </div>
    </div>
  )
}

// ── Legend overlay ──
function Legend() {
  return (
    <div style={{
      position: 'absolute', bottom: 12, left: 12,
      background: 'rgba(0,0,0,0.75)', borderRadius: 6, padding: 10,
      backdropFilter: 'blur(10px)', zIndex: 10,
    }}>
      <div className="mono" style={{ fontSize: 8, color: '#6b7280', letterSpacing: '0.1em', marginBottom: 6 }}>SEVERITY</div>
      {Object.entries(SEV_COLORS).map(([sev, color]) => (
        <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
          <div style={{ width: 8, height: 8, borderRadius: '50%', background: color }} />
          <span className="mono" style={{ fontSize: 9, color: '#9ca3af' }}>{sev}</span>
        </div>
      ))}
      <div style={{ marginTop: 8, borderTop: '1px solid #374151', paddingTop: 6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
          <div style={{ width: 16, height: 2, background: '#ef4444' }} />
          <span className="mono" style={{ fontSize: 9, color: '#9ca3af' }}>Attack Chain</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 16, height: 1, background: '#4b5563' }} />
          <span className="mono" style={{ fontSize: 9, color: '#9ca3af' }}>Same Endpoint</span>
        </div>
      </div>
    </div>
  )
}

// ── Stats overlay ──
function StatsOverlay({ findings }: { findings: DastFinding[] }) {
  const counts = useMemo(() => {
    const c: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
    for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1
    return c
  }, [findings])

  const totalBreachCost = useMemo(
    () => findings.reduce((s, f) => s + (f.cvssScore || 0) * 52000, 0),
    [findings]
  )

  return (
    <div style={{
      position: 'absolute', top: 12, left: 12,
      background: 'rgba(0,0,0,0.75)', borderRadius: 6, padding: 12,
      backdropFilter: 'blur(10px)', zIndex: 10,
    }}>
      <div className="mono" style={{ fontSize: 8, color: '#6b7280', letterSpacing: '0.1em', marginBottom: 6 }}>
        ATTACK SURFACE
      </div>
      <div style={{ display: 'flex', gap: 12 }}>
        {Object.entries(counts).filter(([, v]) => v > 0).map(([sev, count]) => (
          <div key={sev} style={{ textAlign: 'center' }}>
            <div className="mono" style={{ fontSize: 16, fontWeight: 800, color: SEV_COLORS[sev] }}>
              {count}
            </div>
            <div className="mono" style={{ fontSize: 7, color: '#6b7280', letterSpacing: '0.08em' }}>
              {sev}
            </div>
          </div>
        ))}
      </div>
      <div style={{ marginTop: 8, paddingTop: 8, borderTop: '1px solid #374151' }}>
        <div className="mono" style={{ fontSize: 8, color: '#6b7280', letterSpacing: '0.08em' }}>TOTAL RISK EXPOSURE</div>
        <div className="mono" style={{ fontSize: 14, fontWeight: 800, color: '#ef4444', marginTop: 2 }}>
          ${totalBreachCost >= 1000000 ? `${(totalBreachCost / 1000000).toFixed(1)}M` : `${(totalBreachCost / 1000).toFixed(0)}K`}
        </div>
      </div>
    </div>
  )
}

// ── Main export ──
export default function AttackGraph3D({ findings, attackChains, onFindingClick }: AttackGraph3DProps) {
  const [selectedFinding, setSelectedFinding] = useState<DastFinding | null>(null)

  const handleFindingClick = useCallback((finding: DastFinding) => {
    setSelectedFinding(prev => prev?.id === finding.id ? null : finding)
    onFindingClick?.(finding)
  }, [onFindingClick])

  if (findings.length === 0) {
    return (
      <div style={{ textAlign: 'center', padding: 60, color: 'var(--color-text-secondary)' }}>
        <div className="mono" style={{ fontSize: 14, fontWeight: 600 }}>No findings to visualize</div>
        <div className="mono" style={{ fontSize: 11, marginTop: 6 }}>
          Run a scan to see the 3D attack graph
        </div>
      </div>
    )
  }

  return (
    <div style={{ position: 'relative', width: '100%', height: 550, borderRadius: 8, overflow: 'hidden', background: '#0a0a0f' }}>
      <Canvas
        camera={{ position: [0, 5, 15], fov: 55 }}
        style={{ background: '#0a0a0f' }}
      >
        <fog attach="fog" args={['#0a0a0f', 15, 40]} />
        <AttackGraphScene
          findings={findings}
          attackChains={attackChains}
          onFindingClick={handleFindingClick}
        />
      </Canvas>

      <StatsOverlay findings={findings} />
      <Legend />
      <FindingDetailPanel finding={selectedFinding} />

      {/* Controls hint */}
      <div style={{
        position: 'absolute', bottom: 12, right: 12,
        background: 'rgba(0,0,0,0.6)', borderRadius: 4, padding: '4px 8px',
        zIndex: 10,
      }}>
        <span className="mono" style={{ fontSize: 8, color: '#6b7280' }}>
          DRAG TO ROTATE &bull; SCROLL TO ZOOM &bull; CLICK NODE FOR DETAILS
        </span>
      </div>
    </div>
  )
}

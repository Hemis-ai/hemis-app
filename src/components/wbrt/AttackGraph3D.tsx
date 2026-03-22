'use client'

import { useEffect, useRef, useCallback } from 'react'
import type * as THREE from 'three'
import type { AttackGraph, KillChain } from '@/lib/types/wbrt'

export interface AttackGraph3DProps {
  graph: AttackGraph
  killChains: KillChain[]
  selectedNodeId: string | null
  onSelectNode: (id: string | null) => void
  height?: number
}

const NODE_COLOR: Record<string, string> = {
  entry_point:   '#00d4aa',
  vulnerability: '#ef5a5a',
  asset:         '#5ab0ff',
  privilege:     '#f2d156',
  crown_jewel:   '#b06aff',
  data:          '#8ba8c8',
}

const SEV_SIZE: Record<string, number> = {
  CRITICAL: 10,
  HIGH:     8,
  MEDIUM:   6,
  LOW:      5,
}

const SHAPE_BY_TYPE: Record<string, string> = {
  entry_point:   'octahedron',
  vulnerability: 'sphere',
  asset:         'box',
  privilege:     'cone',
  crown_jewel:   'icosahedron',
  data:          'cylinder',
}

function buildKillChainEdgeSet(killChains: KillChain[], graph: AttackGraph): Set<string> {
  const set = new Set<string>()
  killChains.forEach(kc => {
    kc.steps.forEach(step => {
      graph.edges.forEach(e => {
        if (e.techniqueId === step.techniqueId) set.add(e.id)
      })
    })
  })
  if (set.size === 0) graph.edges.forEach(e => set.add(e.id))
  return set
}

export default function AttackGraph3D({
  graph,
  killChains,
  selectedNodeId,
  onSelectNode,
  height = 580,
}: AttackGraph3DProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const fgRef = useRef<any>(null)

  const killChainEdges = buildKillChainEdgeSet(killChains, graph)

  const graphData = {
    nodes: graph.nodes.map(n => ({
      ...n,
      id: n.id,
      color: NODE_COLOR[n.type] ?? '#888',
      val: SEV_SIZE[n.severity ?? ''] ?? 6,
    })),
    links: graph.edges.map(e => ({
      ...e,
      source: e.source,
      target: e.target,
      color: killChainEdges.has(e.id) ? '#ef5a5a' : 'rgba(255,255,255,0.12)',
      isKillChain: killChainEdges.has(e.id),
    })),
  }

  const handleNodeClick = useCallback(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (node: any) => {
      if (!fgRef.current) return
      onSelectNode(selectedNodeId === node.id ? null : node.id)
      const distance = 80
      const distRatio = 1 + distance / Math.hypot(node.x ?? 1, node.y ?? 1, node.z ?? 1)
      fgRef.current.cameraPosition(
        { x: (node.x ?? 0) * distRatio, y: (node.y ?? 0) * distRatio, z: (node.z ?? 0) * distRatio },
        node,
        1000,
      )
    },
    [selectedNodeId, onSelectNode],
  )

  const handleBackgroundClick = useCallback(() => {
    onSelectNode(null)
    if (fgRef.current) {
      fgRef.current.cameraPosition({ x: 0, y: 0, z: 300 }, { x: 0, y: 0, z: 0 }, 1000)
    }
  }, [onSelectNode])

  useEffect(() => {
    if (!containerRef.current) return
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let crownMeshes: any[] = []
    let animFrame: number

    async function init() {
      const ForceGraph3D = (await import('react-force-graph-3d')).default
      const THREEmod = await import('three')
      const ReactDOM = await import('react-dom/client')
      const React = await import('react')

      if (!containerRef.current) return

      const root = ReactDOM.createRoot(containerRef.current)

      function Graph() {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return React.createElement(ForceGraph3D as any, {
          ref: fgRef,
          graphData,
          backgroundColor: '#0a0d14',
          width: containerRef.current?.clientWidth ?? 900,
          height,
          nodeLabel: (node: any) => // eslint-disable-line @typescript-eslint/no-explicit-any
            `<div style="font-family:monospace;font-size:12px;padding:4px 8px;background:#1a1f2e;border:1px solid #333;border-radius:4px;color:#fff">${node.label}<br/><span style="color:${node.color};font-size:10px">${String(node.type ?? '').replace('_', ' ').toUpperCase()}</span></div>`,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          nodeThreeObject: (node: any) => {
            const color = NODE_COLOR[node.type as string] ?? '#888'
            const size = SEV_SIZE[node.severity as string] ?? 6
            const mat = new THREEmod.MeshLambertMaterial({ color, transparent: true, opacity: 0.9 })
            let geo: THREE.BufferGeometry
            switch (SHAPE_BY_TYPE[node.type as string]) {
              case 'octahedron':  geo = new THREEmod.OctahedronGeometry(size); break
              case 'box':         geo = new THREEmod.BoxGeometry(size, size, size); break
              case 'cone':        geo = new THREEmod.ConeGeometry(size * 0.7, size * 1.4, 8); break
              case 'icosahedron': geo = new THREEmod.IcosahedronGeometry(size * 1.1, 0); break
              case 'cylinder':    geo = new THREEmod.CylinderGeometry(size * 0.6, size * 0.6, size * 1.2, 8); break
              default:            geo = new THREEmod.SphereGeometry(size * 0.7, 16, 16)
            }
            const mesh = new THREEmod.Mesh(geo, mat)

            const canvas = document.createElement('canvas')
            canvas.width = 256; canvas.height = 48
            const ctx = canvas.getContext('2d')!
            ctx.clearRect(0, 0, 256, 48)
            ctx.font = '14px Inter, sans-serif'
            ctx.fillStyle = '#ffffff'
            ctx.textAlign = 'center'
            ctx.fillText(String(node.label ?? '').slice(0, 22), 128, 32)
            const tex = new THREEmod.CanvasTexture(canvas)
            const sprite = new THREEmod.Sprite(new THREEmod.SpriteMaterial({ map: tex, transparent: true }))
            sprite.scale.set(36, 8, 1)
            sprite.position.set(0, size + 12, 0)
            mesh.add(sprite)

            if (node.type === 'crown_jewel') crownMeshes.push(mesh)
            return mesh
          },
          linkColor: (link: any) => link.color as string, // eslint-disable-line @typescript-eslint/no-explicit-any
          linkWidth: (link: any) => (link.isKillChain ? 1.5 : 0.8), // eslint-disable-line @typescript-eslint/no-explicit-any
          linkDirectionalParticles: (link: any) => (link.isKillChain ? 6 : 0), // eslint-disable-line @typescript-eslint/no-explicit-any
          linkDirectionalParticleSpeed: 0.004,
          linkDirectionalParticleColor: () => '#ef5a5a',
          linkDirectionalParticleWidth: 1.5,
          onNodeClick: handleNodeClick,
          onBackgroundClick: handleBackgroundClick,
          enableNodeDrag: true,
        })
      }

      root.render(React.createElement(Graph))

      function animate() {
        animFrame = requestAnimationFrame(animate)
        crownMeshes.forEach(m => { m.rotation.y += 0.003 })
      }
      animate()
    }

    init()

    return () => {
      if (animFrame) cancelAnimationFrame(animFrame)
      crownMeshes = []
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div
      ref={containerRef}
      style={{ width: '100%', height, borderRadius: 2, overflow: 'hidden', background: '#0a0d14' }}
    />
  )
}

# WBRT 3D Attack Graph Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the flat SVG attack graph in the WBRT page with an interactive 3D force-directed graph using `react-force-graph-3d`.

**Architecture:** Install `react-force-graph-3d` (Three.js + D3-force wrapper). Create a standalone `AttackGraph3D.tsx` component loaded via `dynamic()` with `ssr: false`. Swap the existing `AttackGraphSvg` + `NodeDetailPanel` in `page.tsx` for the new component plus an inline info panel below.

**Tech Stack:** react-force-graph-3d, Three.js (bundled), Next.js dynamic imports, TypeScript, inline styles with CSS variables.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `src/components/wbrt/AttackGraph3D.tsx` | **Create** | 3D graph component — all Three.js logic isolated here |
| `src/app/(dashboard)/dashboard/hemis/wbrt/page.tsx` | **Modify** (lines 183–330, 1539–1573) | Swap SVG component, remove `AttackGraphSvg` + `NodeDetailPanel`, add dynamic import + inline info panel |
| `package.json` | **Modify** | Add `react-force-graph-3d` dependency |

---

## Task 1: Install dependency

**Files:**
- Modify: `package.json`

- [ ] **Step 1: Install react-force-graph-3d**

```bash
cd /Users/sai/Documents/GitHub/Hemis/hemis-app
npm install react-force-graph-3d
```

Expected: `added N packages` with no peer dependency errors.

- [ ] **Step 2: Verify import resolves**

```bash
node -e "require.resolve('react-force-graph-3d')" && echo "OK"
```

Expected: prints path + `OK`.

---

## Task 2: Create AttackGraph3D component

**Files:**
- Create: `src/components/wbrt/AttackGraph3D.tsx`

- [ ] **Step 1: Create directory**

```bash
mkdir -p /Users/sai/Documents/GitHub/Hemis/hemis-app/src/components/wbrt
```

- [ ] **Step 2: Write the component**

Create `/Users/sai/Documents/GitHub/Hemis/hemis-app/src/components/wbrt/AttackGraph3D.tsx`:

```tsx
'use client'

import { useEffect, useRef, useCallback } from 'react'
import type { AttackGraph, AttackGraphNode, AttackGraphEdge, KillChain } from '@/lib/types/wbrt'

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AttackGraph3DProps {
  graph: AttackGraph
  killChains: KillChain[]
  selectedNodeId: string | null
  onSelectNode: (id: string | null) => void
  height?: number
}

// ─── Constants ────────────────────────────────────────────────────────────────

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

// ─── Kill chain edge set ──────────────────────────────────────────────────────

function buildKillChainEdgeSet(killChains: KillChain[], graph: AttackGraph): Set<string> {
  const nodeIdsByLabel = new Map<string, string>()
  graph.nodes.forEach(n => nodeIdsByLabel.set(n.label.toLowerCase(), n.id))

  const set = new Set<string>()
  // Mark all edges that appear in any kill chain step sequence
  killChains.forEach(kc => {
    kc.steps.forEach((step, i) => {
      if (i === 0) return
      const prev = kc.steps[i - 1]
      // Find edges whose description contains technique from these steps
      graph.edges.forEach(e => {
        if (e.techniqueId === step.techniqueId || e.techniqueId === prev.techniqueId) {
          set.add(e.id)
        }
      })
    })
  })
  // If no matches, mark all edges as kill chain edges for visual richness
  if (set.size === 0) graph.edges.forEach(e => set.add(e.id))
  return set
}

// ─── Component ────────────────────────────────────────────────────────────────

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
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const THREE = useRef<any>(null)

  const killChainEdges = buildKillChainEdgeSet(killChains, graph)

  // Build graph data for react-force-graph-3d
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

      // Fly camera to node
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
    let fg: any // eslint-disable-line @typescript-eslint/no-explicit-any
    let animFrame: number
    let crownMeshes: any[] = [] // eslint-disable-line @typescript-eslint/no-explicit-any

    async function init() {
      const ForceGraph3D = (await import('react-force-graph-3d')).default
      const THREEmod = await import('three')
      THREE.current = THREEmod

      const { createRoot } = await import('react-dom/client')
      const React = await import('react')

      const root = createRoot(containerRef.current!)

      function Graph() {
        return React.createElement(ForceGraph3D, {
          ref: fgRef,
          graphData,
          backgroundColor: '#0a0d14',
          width: containerRef.current?.clientWidth ?? 900,
          height,
          nodeLabel: (node: any) => `<div style="font-family:monospace;font-size:12px;padding:4px 8px;background:#1a1f2e;border:1px solid #333;border-radius:4px;color:#fff">${node.label}<br/><span style="color:${node.color};font-size:10px">${node.type?.replace('_',' ').toUpperCase()}</span></div>`,
          nodeThreeObject: (node: any) => {
            const color = NODE_COLOR[node.type] ?? '#888'
            const size = SEV_SIZE[node.severity ?? ''] ?? 6
            const mat = new THREEmod.MeshLambertMaterial({ color, transparent: true, opacity: 0.9 })

            let geo: any
            switch (SHAPE_BY_TYPE[node.type]) {
              case 'octahedron':  geo = new THREEmod.OctahedronGeometry(size); break
              case 'box':         geo = new THREEmod.BoxGeometry(size, size, size); break
              case 'cone':        geo = new THREEmod.ConeGeometry(size * 0.7, size * 1.4, 8); break
              case 'icosahedron': geo = new THREEmod.IcosahedronGeometry(size * 1.1, 0); break
              case 'cylinder':    geo = new THREEmod.CylinderGeometry(size * 0.6, size * 0.6, size * 1.2, 8); break
              default:            geo = new THREEmod.SphereGeometry(size * 0.7, 16, 16)
            }

            const mesh = new THREEmod.Mesh(geo, mat)

            // Label sprite above node
            const canvas = document.createElement('canvas')
            canvas.width = 200; canvas.height = 40
            const ctx = canvas.getContext('2d')!
            ctx.fillStyle = 'rgba(0,0,0,0)'
            ctx.clearRect(0, 0, 200, 40)
            ctx.font = '14px Inter, sans-serif'
            ctx.fillStyle = '#ffffff'
            ctx.textAlign = 'center'
            ctx.fillText(node.label?.slice(0, 20) ?? '', 100, 28)
            const tex = new THREEmod.CanvasTexture(canvas)
            const sprite = new THREEmod.Sprite(new THREEmod.SpriteMaterial({ map: tex, transparent: true }))
            sprite.scale.set(30, 6, 1)
            sprite.position.set(0, size + 10, 0)
            mesh.add(sprite)

            // Track crown jewels for rotation
            if (node.type === 'crown_jewel') crownMeshes.push(mesh)

            return mesh
          },
          linkColor: (link: any) => link.color,
          linkWidth: (link: any) => link.isKillChain ? 1.5 : 0.8,
          linkDirectionalParticles: (link: any) => link.isKillChain ? 6 : 0,
          linkDirectionalParticleSpeed: 0.004,
          linkDirectionalParticleColor: () => '#ef5a5a',
          linkDirectionalParticleWidth: 1.5,
          onNodeClick: handleNodeClick,
          onBackgroundClick: handleBackgroundClick,
          enableNodeDrag: true,
        })
      }

      root.render(React.createElement(Graph))

      // Crown jewel rotation loop
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

  return <div ref={containerRef} style={{ width: '100%', height, borderRadius: 2, overflow: 'hidden' }} />
}
```

- [ ] **Step 3: Verify TypeScript compiles**

```bash
cd /Users/sai/Documents/GitHub/Hemis/hemis-app && npx tsc --noEmit 2>&1 | grep -i "components/wbrt" | head -20
```

Expected: no output (no errors for the new file).

---

## Task 3: Swap AttackGraphSvg → AttackGraph3D in page.tsx

**Files:**
- Modify: `src/app/(dashboard)/dashboard/hemis/wbrt/page.tsx`

The goal is to:
1. Remove the `AttackGraphSvg` function (lines ~183–330)
2. Remove the `NodeDetailPanel` function (lines ~332–420) — replace with inline panel in the tab
3. Add a `dynamic` import for `AttackGraph3D`
4. Replace `<AttackGraphSvg .../>` + `<NodeDetailPanel .../>` in the Attack Graph tab with `<AttackGraph3D .../>` + inline info panel

- [ ] **Step 1: Add dynamic import at top of file (after existing imports)**

Find the line:
```tsx
import {
  MOCK_WBRT_ENGAGEMENT,
```

Add ABOVE it:
```tsx
import dynamic from 'next/dynamic'

const AttackGraph3D = dynamic(() => import('@/components/wbrt/AttackGraph3D'), { ssr: false })

```

- [ ] **Step 2: Remove AttackGraphSvg function**

Delete the entire `AttackGraphSvg` function (from `function AttackGraphSvg({` through its closing `}`). This is approximately lines 183–330 in page.tsx. The function ends just before `function NodeDetailPanel`.

- [ ] **Step 3: Remove NodeDetailPanel function**

Delete the entire `NodeDetailPanel` function (from `function NodeDetailPanel({` through its closing `}`). This is approximately lines 332–420.

- [ ] **Step 4: Replace the graph rendering in the Attack Graph tab**

Find this block in the Attack Graph tab:
```tsx
            <AttackGraphSvg
              graph={attackGraph}
              selectedNodeId={selectedNodeId}
              onSelectNode={setSelectedNodeId}
            />

            {/* Color legend */}
            <div style={{ display: 'flex', gap: 16, marginTop: 14, flexWrap: 'wrap' }}>
              {Object.entries(NODE_COLOR).map(([type, color]) => (
                <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{ width: 10, height: 10, borderRadius: '50%', background: color, opacity: 0.85 }} />
                  <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: 9,
                    color: 'var(--color-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em',
                  }}>
                    {type.replace('_', ' ')}
                  </span>
                </div>
              ))}
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{ width: 22, height: 1, borderTop: '1px dashed var(--color-text-dim)' }} />
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)' }}>
                  low prob (&lt;60%)
                </span>
              </div>
            </div>

            {/* Node detail panel */}
            {selectedNodeId && (
              <NodeDetailPanel
                nodeId={selectedNodeId}
                graph={attackGraph}
                onClose={() => setSelectedNodeId(null)}
              />
            )}
```

Replace with:
```tsx
            <AttackGraph3D
              graph={attackGraph}
              killChains={killChains}
              selectedNodeId={selectedNodeId}
              onSelectNode={setSelectedNodeId}
              height={580}
            />

            {/* Node shape legend */}
            <div style={{ display: 'flex', gap: 16, marginTop: 14, flexWrap: 'wrap' }}>
              {Object.entries(NODE_COLOR).map(([type, color]) => (
                <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{ width: 10, height: 10, borderRadius: '50%', background: color, opacity: 0.85 }} />
                  <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: 9,
                    color: 'var(--color-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em',
                  }}>
                    {type.replace('_', ' ')}
                  </span>
                </div>
              ))}
            </div>

            {/* Inline node detail panel */}
            {selectedNodeId && (() => {
              const node = attackGraph.nodes.find(n => n.id === selectedNodeId)
              if (!node) return null
              const inbound  = attackGraph.edges.filter(e => e.target === selectedNodeId)
              const outbound = attackGraph.edges.filter(e => e.source === selectedNodeId)
              const color    = NODE_COLOR[node.type] ?? '#888'
              const inChains = killChains.filter(kc =>
                kc.steps.some(s => s.techniqueId && attackGraph.edges.some(
                  e => (e.source === selectedNodeId || e.target === selectedNodeId) && e.techniqueId === s.techniqueId
                ))
              )
              return (
                <div style={{
                  marginTop: 16,
                  background: 'var(--color-bg-surface)',
                  border: `1px solid ${color}44`,
                  borderRadius: 2, padding: 20,
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <div style={{
                        background: color + '22', border: `1px solid ${color}`,
                        borderRadius: 2, padding: '3px 10px',
                        fontFamily: 'var(--font-mono)', fontSize: 9, color,
                        textTransform: 'uppercase', letterSpacing: '0.1em',
                      }}>
                        {node.type.replace('_', ' ')}
                      </div>
                      <span style={{ fontFamily: 'var(--font-display)', fontSize: 16, fontWeight: 700, color: 'var(--color-text-primary)' }}>
                        {node.label}
                      </span>
                      {node.severity && (
                        <div style={{
                          background: 'var(--color-sev-' + node.severity.toLowerCase() + ')',
                          borderRadius: 2, padding: '2px 8px',
                          fontFamily: 'var(--font-mono)', fontSize: 9, color: '#000', fontWeight: 700,
                        }}>
                          {node.severity}
                        </div>
                      )}
                    </div>
                    <button
                      onClick={() => setSelectedNodeId(null)}
                      style={{
                        background: 'none', border: '1px solid var(--color-border)',
                        borderRadius: 2, padding: '4px 10px', cursor: 'pointer',
                        fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)',
                      }}
                    >
                      CLEAR ✕
                    </button>
                  </div>

                  {node.description && (
                    <p style={{ fontFamily: 'var(--font-sans)', fontSize: 12, color: 'var(--color-text-secondary)', marginBottom: 14 }}>
                      {node.description}
                    </p>
                  )}

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 14 }}>
                    {/* Inbound */}
                    <div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)', letterSpacing: '0.1em', marginBottom: 8, textTransform: 'uppercase' }}>
                        Inbound ({inbound.length})
                      </div>
                      {inbound.length === 0
                        ? <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)' }}>—</div>
                        : inbound.map(e => (
                          <div key={e.id} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#5ab0ff', background: 'rgba(90,176,255,0.1)', padding: '2px 6px', borderRadius: 2 }}>
                              {e.techniqueId}
                            </span>
                            <span style={{ fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-text-secondary)' }}>
                              {e.description?.slice(0, 40) ?? ''}
                            </span>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)' }}>
                              {Math.round((e.probability ?? 0) * 100)}%
                            </span>
                          </div>
                        ))
                      }
                    </div>
                    {/* Outbound */}
                    <div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)', letterSpacing: '0.1em', marginBottom: 8, textTransform: 'uppercase' }}>
                        Outbound ({outbound.length})
                      </div>
                      {outbound.length === 0
                        ? <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-dim)' }}>—</div>
                        : outbound.map(e => (
                          <div key={e.id} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#ef5a5a', background: 'rgba(239,90,90,0.1)', padding: '2px 6px', borderRadius: 2 }}>
                              {e.techniqueId}
                            </span>
                            <span style={{ fontFamily: 'var(--font-sans)', fontSize: 11, color: 'var(--color-text-secondary)' }}>
                              {e.description?.slice(0, 40) ?? ''}
                            </span>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)' }}>
                              {Math.round((e.probability ?? 0) * 100)}%
                            </span>
                          </div>
                        ))
                      }
                    </div>
                  </div>

                  {/* Kill chain membership */}
                  {inChains.length > 0 && (
                    <div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--color-text-dim)', letterSpacing: '0.1em', marginBottom: 8, textTransform: 'uppercase' }}>
                        Kill Chain Membership
                      </div>
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {inChains.map(kc => (
                          <div key={kc.id} style={{
                            background: 'rgba(239,90,90,0.1)', border: '1px solid rgba(239,90,90,0.3)',
                            borderRadius: 2, padding: '3px 10px',
                            fontFamily: 'var(--font-mono)', fontSize: 9, color: '#ef5a5a',
                          }}>
                            {kc.name}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )
            })()}
```

- [ ] **Step 5: Verify TypeScript compiles clean**

```bash
cd /Users/sai/Documents/GitHub/Hemis/hemis-app && npx tsc --noEmit 2>&1 | head -30
```

Expected: no output (zero errors).

- [ ] **Step 6: Verify dev server starts without error**

```bash
cd /Users/sai/Documents/GitHub/Hemis/hemis-app && npm run dev 2>&1 | grep -E "error|Error|ready|started" | head -10
```

Expected: `ready` or `started` message, no `error` lines.

---

## Task 4: Final verification

- [ ] **Step 1: Full TypeScript check**

```bash
cd /Users/sai/Documents/GitHub/Hemis/hemis-app && npx tsc --noEmit 2>&1
```

Expected: empty output (zero errors).

- [ ] **Step 2: Check component file exists and is non-empty**

```bash
wc -l /Users/sai/Documents/GitHub/Hemis/hemis-app/src/components/wbrt/AttackGraph3D.tsx
```

Expected: 150+ lines.

- [ ] **Step 3: Check dynamic import is present in page.tsx**

```bash
grep -n "AttackGraph3D\|dynamic\|react-force-graph" /Users/sai/Documents/GitHub/Hemis/hemis-app/src/app/(dashboard)/dashboard/hemis/wbrt/page.tsx | head -10
```

Expected: lines showing `dynamic` import and `<AttackGraph3D` usage.

- [ ] **Step 4: Check AttackGraphSvg is fully removed**

```bash
grep -n "AttackGraphSvg\|NodeDetailPanel" /Users/sai/Documents/GitHub/Hemis/hemis-app/src/app/(dashboard)/dashboard/hemis/wbrt/page.tsx
```

Expected: no output (both removed).

# WBRT 3D Attack Graph — Design Spec

**Date:** 2026-03-21
**Status:** Approved
**Feature:** Replace flat SVG attack graph with interactive 3D force-directed graph

---

## Overview

Replace the existing column-based SVG `AttackGraphSvg` component in the WBRT tab with a full 3D force-directed graph using `react-force-graph-3d` (Three.js + D3-force). The graph renders attack nodes as 3D geometric shapes floating in space, with animated particle streams along kill chain edges, camera fly-to on node click, and a detail panel below.

---

## Library

`react-force-graph-3d` — wraps Three.js + D3-force. Loaded via `dynamic()` with `ssr: false` to avoid SSR issues.

```bash
npm install react-force-graph-3d
```

---

## Visual Design — "Clean Intel"

### Background
- `#0a0d14` — near-black navy, clean void

### Node Shapes & Colors (by type)
| Type | Shape | Color | Size |
|---|---|---|---|
| `entry_point` | Octahedron | `#00d4aa` | 6 |
| `vulnerability` | Sphere | `#ef5a5a` | scaled by severity |
| `asset` | Box | `#5ab0ff` | 6 |
| `privilege` | Cone | `#f2d156` | 6 |
| `crown_jewel` | Icosahedron | `#b06aff` | 10, slow Y-rotation |
| `data` | Cylinder | `#8ba8c8` | 5 |

### Node Sizing by Severity
- CRITICAL → 10, HIGH → 8, MEDIUM → 6, LOW → 5, default → 6

### Labels
- White text, 11px, always face camera (billboarding), 18px above node

### Edges
- Default: `#ffffff22`, width 1.5, semi-transparent white lines
- Kill chain edges: animated red particles `#ef5a5a`, 6 particles per edge, speed 0.004

### Crown Jewel Animation
- Slow Y-axis rotation (0.003 rad/frame) on icosahedron mesh

---

## Interaction

### Click node
1. Camera smoothly animates to center on node (distance 80, 1000ms ease)
2. Info panel below graph populates with node detail

### Click background
- Camera returns to default orbit position
- Info panel clears

### Hover
- Node brightens (emissive intensity +0.3)
- Cursor: pointer
- Floating tooltip: label + severity badge

### Mouse orbit / scroll
- Drag to freely rotate in 3D
- Scroll to zoom

---

## Component API

```tsx
<AttackGraph3D
  graph={attackGraph}         // AttackGraph
  killChains={killChains}     // KillChain[] — determines which edges get particles
  selectedNodeId={string|null}
  onSelectNode={(id: string | null) => void}
  height={580}
/>
```

---

## Info Panel (below graph, shown when node selected)

- Node type badge (colored) + label (large bold)
- Description text
- Severity horizontal bar
- Two-column table: Inbound edges | Outbound edges
  - Each row: techniqueId (mono), description, probability %
- Kill chain membership: pill badges
- "Clear Selection" button

---

## Files

| File | Action |
|---|---|
| `src/components/wbrt/AttackGraph3D.tsx` | Create — 3D component |
| `src/app/(dashboard)/dashboard/hemis/wbrt/page.tsx` | Modify — swap SVG for 3D, wire panel |
| `package.json` | Modify — add react-force-graph-3d |

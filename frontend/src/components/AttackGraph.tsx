import { memo, useCallback, useEffect, useMemo } from 'react'
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react'
import { ArrowRight, Database, Graph, Key, LockKey, UserCircle } from '@phosphor-icons/react'
import type { AttackPath } from '../api/client'

export type AttackNodeData = AttackPath['nodes'][number] & {
  focused?: boolean
  onPath?: boolean
  contained?: boolean
}

const DISPLAY: Record<string, string> = {
  'Domain Sensitive Assets': 'Domain Assets',
}

const TYPE_META: Record<string, { icon: typeof UserCircle; color: string }> = {
  user:            { icon: UserCircle, color: '#5b9cf5' },
  service_account: { icon: Key,        color: '#f0b429' },
  group:           { icon: Graph,      color: '#a78bfa' },
  host:            { icon: Database,   color: '#f97316' },
  asset:           { icon: LockKey,    color: '#ff5c5c' },
}

function layoutNodes(nodes: AttackPath['nodes']) {
  const gap = 300
  return nodes.map((node, i) => ({
    id: node.id,
    x: i * gap,
    y: 24,
  }))
}

const AttackNode = memo(function AttackNode({ data }: NodeProps<Node<AttackNodeData>>) {
  const meta = TYPE_META[data.type] ?? TYPE_META.user
  const Icon = meta.icon
  const isCrit = data.risk === 'critical'
  const label = DISPLAY[data.id] ?? data.id

  return (
    <div className={[
      'anode anode--card',
      `anode--${data.risk}`,
      data.focused   ? 'is-focused'    : '',
      data.onPath    ? 'is-on-path'    : '',
      data.contained ? 'is-contained'  : '',
    ].join(' ')}>
      <Handle type="target" position={Position.Left}  className="anode__handle" />
      <div className="anode__icon" style={{ '--node-color': meta.color } as React.CSSProperties}>
        <Icon size={22} weight="duotone" />
        {isCrit && !data.contained && data.onPath && <span className="anode__pulse" />}
      </div>
      <div className="anode__text">
        <strong title={data.id}>{label}</strong>
        <span>{data.type.replace(/_/g, ' ')}</span>
        <em className={`anode__risk anode__risk--${data.risk}`}>{data.risk}</em>
      </div>
      <Handle type="source" position={Position.Right} className="anode__handle" />
    </div>
  )
})

const nodeTypes = { attackNode: AttackNode }

function FitViewOnLoad() {
  const { fitView } = useReactFlow()
  useEffect(() => {
    const t = window.setTimeout(() => fitView({ padding: 0.32, duration: 400 }), 50)
    return () => window.clearTimeout(t)
  }, [fitView])
  return null
}

type Props = {
  attackPath: AttackPath
  targetId: string
  focusedId: string | null
  onFocus: (id: string) => void
  hasIncident: boolean
  contained: boolean
  height?: number
}

export default function AttackGraph({
  attackPath,
  targetId,
  focusedId,
  onFocus,
  hasIncident,
  contained,
  height = 420,
}: Props) {
  const focus = focusedId ?? targetId
  const positions = useMemo(() => layoutNodes(attackPath.nodes), [attackPath.nodes])

  const { nodes, edges } = useMemo(() => {
    const pathIds = new Set<string>()
    attackPath.edges.forEach((e) => { pathIds.add(e.from); pathIds.add(e.to) })

    const posMap = Object.fromEntries(positions.map((p) => [p.id, p]))

    const nodes: Node<AttackNodeData>[] = attackPath.nodes.map((node) => ({
      id: node.id,
      type: 'attackNode',
      position: posMap[node.id] ?? { x: 0, y: 20 },
      data: {
        ...node,
        focused:   node.id === focus,
        onPath:    hasIncident && pathIds.has(node.id),
        contained,
      },
      draggable:  false,
      selectable: true,
      zIndex: node.id === focus ? 10 : 1,
    }))

    const edges: Edge[] = attackPath.edges.map((edge) => {
      const onActivePath = hasIncident && !contained
      const isFirst = edge.from === attackPath.nodes[0]?.id
      const isHot = onActivePath && (isFirst || edge.to === targetId || edge.from === targetId)
      return {
        id: `${edge.from}-${edge.to}`,
        source: edge.from,
        target: edge.to,
        animated: isHot,
        type: 'smoothstep',
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: isHot ? '#ff5c5c' : contained ? '#2dd4a8' : '#3d5570',
          width: 16,
          height: 16,
        },
        style: {
          stroke: isHot ? '#ff5c5c' : contained ? '#2dd4a8' : '#3d5570',
          strokeWidth: isHot ? 2.5 : 1.8,
          filter: isHot ? 'drop-shadow(0 0 8px rgba(255,92,92,0.55))' : 'none',
        },
        zIndex: 0,
      }
    })

    return { nodes, edges }
  }, [attackPath, focus, targetId, hasIncident, contained, positions])

  const onNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => onFocus(node.id),
    [onFocus],
  )

  return (
    <div className="apath-wrap">
      <div className="apath apath--full" style={{ height }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodeClick={onNodeClick}
          defaultViewport={{ x: 0, y: 0, zoom: 0.9 }}
          minZoom={0.45}
          maxZoom={1.4}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable
          panOnScroll
          zoomOnScroll
          proOptions={{ hideAttribution: true }}
        >
          <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#1a2838" />
          <Controls showInteractive={false} position="bottom-left" className="apath__controls" />
          <FitViewOnLoad />
        </ReactFlow>
      </div>
      <div className="apath-legend">
        {attackPath.edges.map((edge) => {
          const hot = hasIncident && !contained && (edge.to === targetId || edge.from === attackPath.nodes[0]?.id)
          return (
            <div key={`${edge.from}-${edge.to}`} className={`apath-legend__step ${hot ? 'is-hot' : ''}`}>
              <span className="apath-legend__from">{DISPLAY[edge.from] ?? edge.from}</span>
              <ArrowRight size={14} weight="bold" />
              <span className="apath-legend__label">{edge.label}</span>
              <ArrowRight size={14} weight="bold" />
              <span className="apath-legend__to">{DISPLAY[edge.to] ?? edge.to}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

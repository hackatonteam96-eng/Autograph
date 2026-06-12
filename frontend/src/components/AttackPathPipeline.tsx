import { motion } from 'motion/react'
import { Database, Graph, Key, LockKey, UserCircle, ArrowRight } from '@phosphor-icons/react'
import type { AttackPath } from '../api/client'

const TYPE_META: Record<string, { icon: typeof UserCircle; color: string }> = {
  user:            { icon: UserCircle, color: '#5b9cf5' },
  service_account: { icon: Key,        color: '#f0b429' },
  group:           { icon: Graph,      color: '#a78bfa' },
  host:            { icon: Database,   color: '#f97316' },
  asset:           { icon: LockKey,    color: '#ff5c5c' },
}

const SHORT: Record<string, string> = {
  'Domain Sensitive Assets': 'Domain Assets',
}

type Props = {
  attackPath: AttackPath
  targetId: string
  focusedId: string
  onFocus: (id: string) => void
  hasIncident: boolean
  contained: boolean
}

export default function AttackPathPipeline({
  attackPath,
  targetId,
  focusedId,
  onFocus,
  hasIncident,
  contained,
}: Props) {
  const ordered = [
    'lowpriv.user',
    'svc-sql',
    'SQL Admins',
    'SQL-SERVER',
    'Domain Sensitive Assets',
  ]

  const nodes = ordered
    .map((id) => attackPath.nodes.find((n) => n.id === id))
    .filter(Boolean) as AttackPath['nodes']

  const edges = attackPath.edges

  return (
    <div className="pipeline">
      <div className="pipeline__track">
        {nodes.map((node, i) => {
          const meta = TYPE_META[node.type] ?? TYPE_META.user
          const Icon = meta.icon
          const edge = edges.find((e) => e.from === node.id)
          const isHot = hasIncident && !contained && (node.id === targetId || node.id === 'lowpriv.user')
          const isFocus = node.id === focusedId

          return (
            <div key={node.id} className="pipeline__step">
              <motion.button
                type="button"
                className={[
                  'pipeline__node',
                  `pipeline__node--${node.risk}`,
                  isFocus ? 'is-focused' : '',
                  isHot ? 'is-hot' : '',
                  contained ? 'is-contained' : '',
                ].join(' ')}
                onClick={() => onFocus(node.id)}
                whileHover={{ y: -2 }}
                whileTap={{ scale: 0.98 }}
                transition={{ duration: 0.15 }}
              >
                <div className="pipeline__node-icon" style={{ color: meta.color }}>
                  <Icon size={18} weight="duotone" />
                  {isHot && !contained && <span className="pipeline__node-pulse" />}
                </div>
                <strong title={node.id}>{SHORT[node.id] ?? node.id}</strong>
                <span>{node.type.replace(/_/g, ' ')}</span>
                <em className={`pipeline__risk pipeline__risk--${node.risk}`}>{node.risk}</em>
              </motion.button>

              {edge && i < nodes.length - 1 && (
                <div className={`pipeline__edge ${isHot && !contained ? 'is-hot' : ''}`}>
                  <div className="pipeline__edge-line" />
                  <span>{edge.label}</span>
                  <ArrowRight size={12} weight="bold" />
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

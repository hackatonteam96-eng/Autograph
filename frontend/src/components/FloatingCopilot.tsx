import { useState } from 'react'
import { motion, AnimatePresence } from 'motion/react'
import { Cpu, X } from '@phosphor-icons/react'
import AnalystCopilot from './AnalystCopilot'

export default function FloatingCopilot({
  incidentId,
  disabled,
  hasIncident,
}: {
  incidentId?: string
  disabled?: boolean
  hasIncident?: boolean
}) {
  const [open, setOpen] = useState(false)

  return (
    <div className="float-copilot">
      <AnimatePresence>
        {open && (
          <motion.div
            className="float-copilot__panel"
            initial={{ opacity: 0, y: 16, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 12, scale: 0.97 }}
            transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
          >
            <button
              type="button"
              className="float-copilot__close"
              onClick={() => setOpen(false)}
              aria-label="Close ARIA"
            >
              <X size={14} weight="bold" />
            </button>
            <AnalystCopilot incidentId={incidentId} disabled={disabled} compact />
          </motion.div>
        )}
      </AnimatePresence>

      <motion.button
        type="button"
        className={`float-copilot__fab ${open ? 'is-open' : ''} ${hasIncident && !disabled ? 'is-live' : ''}`}
        onClick={() => setOpen((v) => !v)}
        whileHover={{ scale: 1.04 }}
        whileTap={{ scale: 0.96 }}
        aria-label={open ? 'Close ARIA' : 'Open ARIA analyst'}
        aria-expanded={open}
      >
        {open ? <X size={22} weight="bold" /> : <Cpu size={22} weight="duotone" />}
        {!open && (
          <span className="float-copilot__fab-label">
            ARIA
            {hasIncident && !disabled && <i className="float-copilot__fab-dot" />}
          </span>
        )}
        {!open && hasIncident && !disabled && (
          <motion.span
            className="float-copilot__fab-ring"
            animate={{ scale: [1, 1.35, 1], opacity: [0.5, 0, 0.5] }}
            transition={{ repeat: Infinity, duration: 2.2 }}
          />
        )}
      </motion.button>
    </div>
  )
}

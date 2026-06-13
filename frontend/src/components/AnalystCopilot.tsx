import { useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'motion/react'
import { PaperPlaneTilt, Cpu, CircleNotch } from '@phosphor-icons/react'
import { api } from '../api/client'

type Message = {
  role: 'user' | 'assistant'
  text: string
  ts: string
}

const QUICK = [
  { label: 'Why critical?', prompt: 'Why is this incident rated critical risk?' },
  { label: 'Contain first?', prompt: 'What is the highest-priority containment action right now?' },
  { label: 'Explain path', prompt: 'Walk me through the exact attack path from lowpriv.user to Domain Sensitive Assets.' },
  { label: 'Blast radius', prompt: 'What systems are at risk if svc-sql is fully compromised?' },
]

function useTypewriter(text: string, active: boolean) {
  const [displayed, setDisplayed] = useState('')

  useEffect(() => {
    if (!active) { setDisplayed(text); return }
    setDisplayed('')
    let i = 0
    let raf = 0
    const tick = () => {
      i++
      setDisplayed(text.slice(0, i))
      if (i < text.length) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [text, active])

  return displayed
}

function AssistantBubble({ msg, animate }: { msg: Message; animate: boolean }) {
  const displayed = useTypewriter(msg.text, animate)
  return (
    <motion.div
      className="aria-msg aria-msg--assistant"
      initial={{ opacity: 0, y: 8, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
    >
      <div className="aria-msg__avatar"><Cpu size={14} weight="duotone" /></div>
      <div className="aria-msg__body">
        <span className="aria-msg__name">ARIA<span className="aria-msg__ts">{msg.ts}</span></span>
        <p>{animate ? displayed : msg.text}</p>
      </div>
    </motion.div>
  )
}

export default function AnalystCopilot({
  incidentId,
  disabled,
  compact = false,
  viewContext,
}: {
  incidentId?: string
  disabled?: boolean
  compact?: boolean
  viewContext?: string
}) {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [lastAssistantIdx, setLastAssistantIdx] = useState(-1)
  const [modelLabel, setModelLabel] = useState('deepseek-v4-flash')
  const endRef = useRef<HTMLDivElement>(null)
  const seeded = useRef(false)

  useEffect(() => {
    if (disabled || seeded.current) return
    seeded.current = true
    setMessages([{
      role: 'assistant',
      ts: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      text: "ARIA here. Incident is live — ask me anything about the threat, path, or what to contain first.",
    }])
    setLastAssistantIdx(0)
  }, [disabled])

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  async function ask(text: string) {
    if (!text.trim() || loading || disabled) return
    const ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    const userMsg: Message = { role: 'user', text, ts }
    const nextMessages = [...messages, userMsg]
    setMessages(nextMessages)
    setInput('')
    setLoading(true)

    const history = nextMessages.slice(0, -1).map((m) => ({
      role: m.role,
      content: m.text,
    }))

    try {
      const data = await api.aiChat(incidentId, text, history, viewContext)
      const reply = data.reply || 'Signal lost — check backend.'
      if (data.model) {
        setModelLabel(data.model.includes('pro') ? 'deepseek-v4-pro' : 'deepseek-v4-flash')
      }
      setMessages((m) => {
        const updated = [...m, { role: 'assistant' as const, text: reply, ts: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }]
        setLastAssistantIdx(updated.length - 1)
        return updated
      })
    } catch (err) {
      const timedOut = err instanceof DOMException && err.name === 'TimeoutError'
      const text = timedOut
        ? 'That one needed deep reasoning and took too long. Try a more specific question.'
        : 'Lost connection to ARIA. Reconnect backend and try again.'
      setMessages((m) => [...m, { role: 'assistant', text, ts: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className={`aria ${compact ? 'aria--compact' : ''}`}>
      <header className="aria__head">
        <div className="aria__avatar-wrap">
          <Cpu size={20} weight="duotone" />
          <span className={`aria__dot ${disabled ? '' : 'is-online'}`} />
        </div>
        <div>
          <strong>ARIA</strong>
          <span>{disabled ? 'Awaiting incident' : `Online · ${modelLabel}`}</span>
        </div>
        {!disabled && <span className="aria__live-badge">LIVE</span>}
      </header>

      <div className="aria__feed" role="log" aria-live="polite">
        <AnimatePresence initial={false}>
          {messages.map((msg, i) =>
            msg.role === 'assistant' ? (
              <AssistantBubble key={`${msg.ts}-${i}`} msg={msg} animate={i === lastAssistantIdx} />
            ) : (
              <motion.div
                key={`${msg.ts}-${i}`}
                className="aria-msg aria-msg--user"
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.2 }}
              >
                <div className="aria-msg__body">
                  <span className="aria-msg__name">You<span className="aria-msg__ts">{msg.ts}</span></span>
                  <p>{msg.text}</p>
                </div>
              </motion.div>
            ),
          )}
        </AnimatePresence>
        {loading && (
          <div className="aria-msg aria-msg--assistant aria-msg--thinking">
            <div className="aria-msg__avatar"><Cpu size={14} weight="duotone" /></div>
            <div className="aria-msg__body">
              <span className="aria-msg__name">ARIA</span>
              <div className="aria-typing"><span /><span /><span /></div>
            </div>
          </div>
        )}
        <div ref={endRef} />
      </div>

      <div className="aria__quick">
        {QUICK.map((q) => (
          <button key={q.label} type="button" className="aria__chip" onClick={() => ask(q.prompt)} disabled={disabled || loading}>
            {q.label}
          </button>
        ))}
      </div>

      <form className="aria__compose" onSubmit={(e) => { e.preventDefault(); ask(input) }}>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={disabled ? 'Trigger an incident first…' : 'Ask ARIA anything…'}
          disabled={disabled || loading}
          autoComplete="off"
        />
        <button type="submit" disabled={disabled || loading || !input.trim()} aria-label="Send">
          {loading ? <CircleNotch size={16} weight="bold" className="spin" /> : <PaperPlaneTilt size={16} weight="fill" />}
        </button>
      </form>
    </div>
  )
}

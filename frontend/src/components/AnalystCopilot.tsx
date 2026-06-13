import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'motion/react'
import { PaperPlaneTilt, Cpu, CircleNotch } from '@phosphor-icons/react'
import { api } from '../api/client'
import AriaMessageContent from './AriaMessageContent'

type Message = {
  role: 'user' | 'assistant'
  text: string
  ts: string
  model?: string
}

function chatStorageKey(incidentId: string) {
  return `authgraph:aria-chat:${incidentId}`
}

function loadStoredMessages(incidentId: string): Message[] | null {
  try {
    const raw = sessionStorage.getItem(chatStorageKey(incidentId))
    if (!raw) return null
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed : null
  } catch {
    return null
  }
}

function saveStoredMessages(incidentId: string, messages: Message[]) {
  try {
    sessionStorage.setItem(chatStorageKey(incidentId), JSON.stringify(messages))
  } catch { /* quota / private mode */ }
}

function buildQuickPrompts(user?: string, target?: string) {
  const u = user ?? 'source user'
  const t = target ?? 'service account'
  return [
    { label: 'Why critical?', prompt: 'Why is this incident rated critical? Walk me through the risk factors.' },
    { label: 'Contain first?', prompt: 'What is the single highest-priority containment action right now, who owns it, and why?' },
    { label: 'Attack path', prompt: `Walk the attack path step-by-step from ${u} to domain sensitive assets.` },
    { label: 'Blast radius', prompt: `If ${t} is fully compromised, what systems and identities are exposed?` },
    { label: 'Executive brief', prompt: 'Give me a 2-sentence executive summary for leadership — no jargon.' },
    { label: 'False positive?', prompt: 'What evidence would downgrade this from critical? What should I verify first?' },
  ]
}

function AssistantBubble({ msg }: { msg: Message }) {
  return (
    <motion.div
      className="aria-msg aria-msg--assistant"
      initial={{ opacity: 0, y: 8, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
    >
      <div className="aria-msg__avatar"><Cpu size={14} weight="duotone" /></div>
      <div className="aria-msg__body">
        <span className="aria-msg__name">
          ARIA
          {msg.model && <em className="aria-msg__model">{msg.model.includes('v4-pro') ? 'v4-pro' : 'v4-flash'}</em>}
          <span className="aria-msg__ts">{msg.ts}</span>
        </span>
        <AriaMessageContent text={msg.text} />
      </div>
    </motion.div>
  )
}

export default function AnalystCopilot({
  incidentId,
  disabled,
  compact = false,
  viewContext,
  incidentUser,
  incidentTarget,
  autoAsk,
  onAutoAskHandled,
}: {
  incidentId?: string
  disabled?: boolean
  compact?: boolean
  viewContext?: string
  incidentHeadline?: string | null
  incidentVerdict?: string | null
  incidentUser?: string
  incidentTarget?: string
  incidentRisk?: number
  autoAsk?: string | null
  onAutoAskHandled?: () => void
}) {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [modelLabel, setModelLabel] = useState('deepseek-v4-flash')
  const endRef = useRef<HTMLDivElement>(null)
  const seededFor = useRef<string | null>(null)
  const initDone = useRef(false)
  const pendingAutoAsk = useRef<string | null>(null)
  const messagesRef = useRef<Message[]>([])

  const quickPrompts = useMemo(
    () => buildQuickPrompts(incidentUser, incidentTarget),
    [incidentUser, incidentTarget],
  )

  useEffect(() => {
    messagesRef.current = messages
  }, [messages])

  const ask = useCallback(async (text: string) => {
    if (!text.trim() || loading || disabled) return
    const ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    const userMsg: Message = { role: 'user', text, ts }
    const prior = messagesRef.current
    const nextMessages = [...prior, userMsg]
    setMessages(nextMessages)
    setInput('')
    setLoading(true)

    const history = prior.map((m) => ({
      role: m.role,
      content: m.text,
    }))

    try {
      const data = await api.aiChat(incidentId, text, history, viewContext)
      const reply = data.reply || 'Signal lost — check backend.'
      const usedModel = data.model || 'deepseek-v4-flash'
      if (data.model) {
        setModelLabel(data.model.includes('v4-pro') ? 'deepseek-v4-pro' : 'deepseek-v4-flash')
      }
      setMessages((m) => [...m, {
        role: 'assistant',
        text: reply,
        ts: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        model: usedModel,
      }])
    } catch (err) {
      const timedOut = err instanceof DOMException && err.name === 'TimeoutError'
      const msg = err instanceof Error ? err.message : 'Unknown error'
      const errText = timedOut
        ? 'Deep reasoning took too long. Try a narrower question — e.g. "what to contain first?"'
        : msg.includes('404') || msg.includes('Incident')
          ? 'Incident context changed — ask again (backend refreshed).'
          : msg.includes('Failed to fetch') || msg.includes('NetworkError')
            ? 'Cannot reach backend — confirm API is running on port 8787.'
            : `ARIA error: ${msg}`
      setMessages((m) => [...m, { role: 'assistant', text: errText, ts: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }])
    } finally {
      setLoading(false)
    }
  }, [disabled, incidentId, loading, viewContext])

  useEffect(() => {
    if (disabled || !incidentId) {
      initDone.current = false
      return
    }
    if (seededFor.current === incidentId) return
    seededFor.current = incidentId
    initDone.current = false

    const stored = loadStoredMessages(incidentId)
    if (stored?.length) {
      setMessages(stored)
    } else {
      const seedText = 'Hey — I\'m ARIA, on the board with you. Ask about the attack path, blast radius, containment, or say "summarize" for a quick brief.'
      setMessages([{
        role: 'assistant',
        ts: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        text: seedText,
        model: 'deepseek-v4-flash',
      }])
    }

    initDone.current = true

    if (pendingAutoAsk.current) {
      const q = pendingAutoAsk.current
      pendingAutoAsk.current = null
      window.setTimeout(() => { void ask(q) }, 50)
    }
  }, [disabled, incidentId, ask])

  useEffect(() => {
    if (!incidentId || messages.length === 0) return
    saveStoredMessages(incidentId, messages)
  }, [incidentId, messages])

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  useEffect(() => {
    if (!autoAsk?.trim() || disabled || loading) return
    onAutoAskHandled?.()
    if (!initDone.current) {
      pendingAutoAsk.current = autoAsk
      return
    }
    void ask(autoAsk)
  }, [autoAsk, disabled, loading, ask, onAutoAskHandled])

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
      </header>

      <div className="aria__feed" role="log" aria-live="polite">
        <AnimatePresence initial={false}>
          {messages.map((msg, i) =>
            msg.role === 'assistant' ? (
              <AssistantBubble key={`${msg.ts}-${i}`} msg={msg} />
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
              <span className="aria-msg__name">ARIA · reasoning</span>
              <div className="aria-typing"><span /><span /><span /></div>
            </div>
          </div>
        )}
        <div ref={endRef} />
      </div>

      <div className="aria__quick">
        {quickPrompts.map((q) => (
          <button key={q.label} type="button" className="aria__chip" onClick={() => ask(q.prompt)} disabled={disabled || loading}>
            {q.label}
          </button>
        ))}
      </div>

      <form className="aria__compose" onSubmit={(e) => { e.preventDefault(); ask(input) }}>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={disabled ? 'Trigger an incident first…' : 'Ask ARIA — path, blast radius, containment…'}
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

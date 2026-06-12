import type { Alert } from '../api/client'

type Tone = 'critical' | 'high' | 'medium' | 'low'
type Factor = { label: string; value: number; tone: Tone }

const TONE_COLOR: Record<Tone, string> = {
  critical: 'var(--red)',
  high:     'var(--amber)',
  medium:   'var(--blue)',
  low:      'var(--green)',
}

function barTone(v: number): Tone {
  if (v >= 85) return 'critical'
  if (v >= 65) return 'high'
  if (v >= 40) return 'medium'
  return 'low'
}

export default function RiskPanel({
  alert,
  score,
  focusedNode,
  contained,
  hasIncident,
}: {
  alert: Alert | null
  score: number
  focusedNode: string
  contained: boolean
  hasIncident: boolean
}) {
  const factors: Factor[] = hasIncident
    ? [
        { label: 'Kerberoast signal', value: 92, tone: 'critical' },
        { label: 'SPN exposure',       value: 88, tone: 'critical' },
        { label: 'Path privilege',     value: 76, tone: 'high'     },
        { label: 'RC4 ticket usage',   value: 84, tone: 'critical' },
        { label: 'Blast radius',       value: contained ? 28 : 71, tone: contained ? 'low' : 'high' },
      ]
    : [
        { label: 'Kerberoast signal', value: 8,  tone: 'low' },
        { label: 'SPN exposure',       value: 12, tone: 'low' },
        { label: 'Path privilege',     value: 15, tone: 'low' },
        { label: 'RC4 ticket usage',   value: 5,  tone: 'low' },
        { label: 'Blast radius',       value: 10, tone: 'low' },
      ]

  const tone = contained ? 'low' : barTone(score)
  const strokeColor = TONE_COLOR[tone]
  const circ = 2 * Math.PI * 54 // r=54 → 339.29

  return (
    <div className="risk-panel">
      {/* circular ring */}
      <div className="risk-panel__ring-wrap">
        <svg
          width="130" height="130" viewBox="0 0 130 130"
          className="risk-panel__ring"
          style={{ '--score': score, '--circ': circ } as React.CSSProperties}
        >
          <circle cx="65" cy="65" r="54" className="risk-panel__ring-track" />
          <circle
            cx="65" cy="65" r="54"
            className="risk-panel__ring-progress"
            style={{ stroke: strokeColor }}
          />
        </svg>
        <div className="risk-panel__ring-label">
          <strong style={{ color: strokeColor }}>{score}</strong>
          <span>risk score</span>
        </div>
      </div>

      {/* identity label */}
      <p style={{ textAlign: 'center', marginBottom: 16, fontSize: 12, color: 'var(--text-2)' }}>
        <strong style={{ color: 'var(--text)' }}>{alert?.target ?? focusedNode ?? 'svc-sql'}</strong>
        {' · '}Service account{' · '}
        <span style={{ color: strokeColor, fontWeight: 600 }}>{tone} risk</span>
      </p>

      {/* factor bars */}
      <div className="risk-bars">
        {factors.map((f) => (
          <div className="risk-factor" key={f.label}>
            <span className="risk-factor__label">{f.label}</span>
            <span className="risk-factor__value" style={{ color: TONE_COLOR[f.tone] }}>{f.value}</span>
            <div className="risk-factor__track">
              <div
                className="risk-factor__fill"
                style={{ width: `${f.value}%`, background: TONE_COLOR[f.tone] }}
              />
            </div>
          </div>
        ))}
      </div>

      {/* meta */}
      <dl style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginTop: 16, fontSize: 11 }}>
        {[
          ['MITRE', alert?.mitre ?? 'T1558.003'],
          ['Severity', contained ? 'Contained' : (alert?.severity ?? '—')],
          ['Source', alert?.source ?? 'Wazuh'],
          ['Event', alert?.event_id ?? '4769'],
        ].map(([dt, dd]) => (
          <div key={dt as string} style={{ background: 'var(--bg3)', borderRadius: 6, padding: '8px 10px' }}>
            <dt style={{ color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.4px', fontSize: 9, marginBottom: 3 }}>{dt}</dt>
            <dd style={{ color: 'var(--text)', fontWeight: 600, fontFamily: "'JetBrains Mono', monospace" }}>{dd}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

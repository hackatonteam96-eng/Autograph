import type { Alert } from '../api/client'

type Tone = 'critical' | 'high' | 'medium' | 'low'
type Factor = { label: string; value: number; tone: Tone }

const TONE_COLOR: Record<Tone, string> = {
  critical: 'var(--red)',
  high:     'var(--amber)',
  medium:   'var(--blue)',
  low:      'var(--green)',
}

const FACTOR_LABELS: Record<string, string> = {
  kerberoasting: 'Kerberoast signal',
  rc4_encryption: 'RC4 ticket usage',
  multiple_tgs: 'TGS burst pattern',
  service_account_spn: 'SPN exposure',
  privileged_path_full: 'Path privilege',
  privileged_asset_link: 'Privileged asset link',
}

function barTone(v: number): Tone {
  if (v >= 85) return 'critical'
  if (v >= 65) return 'high'
  if (v >= 40) return 'medium'
  return 'low'
}

function scalePoints(points: number) {
  return Math.min(100, Math.round((points / 35) * 92))
}

function buildFactors(alert: Alert | null, hasIncident: boolean, contained: boolean): Factor[] {
  const breakdown = alert?.detection?.risk_breakdown
  if (hasIncident && breakdown?.length) {
    const factors = breakdown.map((item) => ({
      label: FACTOR_LABELS[item.factor] || item.factor.replace(/_/g, ' '),
      value: scalePoints(item.points),
      tone: barTone(scalePoints(item.points)),
    }))
    factors.push({
      label: 'Blast radius',
      value: contained ? 28 : Math.min(100, Math.round((alert?.risk ?? 70) * 0.85)),
      tone: contained ? 'low' : barTone(Math.round((alert?.risk ?? 70) * 0.85)),
    })
    return factors
  }

  if (hasIncident) {
    return [
      { label: 'Kerberoast signal', value: 92, tone: 'critical' },
      { label: 'SPN exposure', value: 88, tone: 'critical' },
      { label: 'Path privilege', value: 76, tone: 'high' },
      { label: 'RC4 ticket usage', value: 84, tone: 'critical' },
      { label: 'Blast radius', value: contained ? 28 : 71, tone: contained ? 'low' : 'high' },
    ]
  }

  return [
    { label: 'Kerberoast signal', value: 8, tone: 'low' },
    { label: 'SPN exposure', value: 12, tone: 'low' },
    { label: 'Path privilege', value: 15, tone: 'low' },
    { label: 'RC4 ticket usage', value: 5, tone: 'low' },
    { label: 'Blast radius', value: 10, tone: 'low' },
  ]
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
  const factors = buildFactors(alert, hasIncident, contained)
  const tone = contained ? 'low' : barTone(score)
  const strokeColor = TONE_COLOR[tone]
  const circ = 2 * Math.PI * 54

  return (
    <div className="risk-panel">
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

      <p style={{ textAlign: 'center', marginBottom: 16, fontSize: 12, color: 'var(--text-2)' }}>
        <strong style={{ color: 'var(--text)' }}>{alert?.target ?? focusedNode ?? 'svc-sql'}</strong>
        {' · '}Service account{' · '}
        <span style={{ color: strokeColor, fontWeight: 600 }}>{tone} risk</span>
      </p>

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

      <dl style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginTop: 16, fontSize: 11 }}>
        {[
          ['MITRE', alert?.mitre ?? 'T1558.003'],
          ['Severity', contained ? 'Contained' : (alert?.severity ?? '—')],
          ['Source', alert?.source ?? 'Wazuh'],
          ['Event', alert?.event_id ?? '4769'],
        ].map(([dt, dd]) => (
          <div key={dt as string} style={{ background: 'var(--bg3)', borderRadius: 6, padding: '8px 10px' }}>
            <dt style={{ color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.4px', fontSize: 9, marginBottom: 3 }}>{dt}</dt>
            <dd style={{ color: 'var(--text)', fontWeight: 600, fontFamily: 'var(--mono)' }}>{dd}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

import { useState } from 'react'
import { Check, Copy } from '@phosphor-icons/react'

export default function CodeBlock({ code, lang = 'powershell' }: { code: string; lang?: string }) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    try {
      await navigator.clipboard.writeText(code)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 2000)
    } catch {
      /* clipboard blocked */
    }
  }

  return (
    <div className="code-snippet">
      <div className="code-snippet__bar">
        <span className="code-snippet__lang">{lang}</span>
        <button type="button" className="code-snippet__copy" onClick={copy} aria-label="Copy to clipboard">
          {copied ? <Check size={13} weight="bold" /> : <Copy size={13} weight="bold" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="code-snippet__body"><code>{code}</code></pre>
    </div>
  )
}

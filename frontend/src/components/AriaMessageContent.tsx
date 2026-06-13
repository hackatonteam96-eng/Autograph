import { useMemo } from 'react'
import CodeBlock from './CodeBlock'

type Block =
  | { type: 'p'; text: string }
  | { type: 'code'; text: string; lang?: string }
  | { type: 'h'; level: number; text: string }
  | { type: 'li'; text: string }

function parseInline(text: string): React.ReactNode[] {
  const parts: React.ReactNode[] = []
  const re = /(`[^`]+`|\*\*[^*]+\*\*)/g
  let last = 0
  let match: RegExpExecArray | null
  let key = 0

  while ((match = re.exec(text)) !== null) {
    if (match.index > last) parts.push(text.slice(last, match.index))
    const token = match[0]
    if (token.startsWith('`')) {
      parts.push(<code key={key++} className="aria-md__inline">{token.slice(1, -1)}</code>)
    } else {
      parts.push(<strong key={key++}>{token.slice(2, -2)}</strong>)
    }
    last = match.index + token.length
  }
  if (last < text.length) parts.push(text.slice(last))
  return parts.length ? parts : [text]
}

function parseMarkdown(source: string): Block[] {
  const blocks: Block[] = []
  const lines = source.split('\n')
  let i = 0
  let inCode = false
  let codeLang = ''
  let codeBuf: string[] = []

  while (i < lines.length) {
    const line = lines[i]

    if (line.startsWith('```')) {
      if (!inCode) {
        inCode = true
        codeLang = line.slice(3).trim()
        codeBuf = []
      } else {
        blocks.push({ type: 'code', text: codeBuf.join('\n'), lang: codeLang || undefined })
        inCode = false
        codeLang = ''
        codeBuf = []
      }
      i += 1
      continue
    }

    if (inCode) {
      codeBuf.push(line)
      i += 1
      continue
    }

    const trimmed = line.trim()
    if (!trimmed) { i += 1; continue }

    const heading = trimmed.match(/^(#{1,3})\s+(.+)$/)
    if (heading) {
      blocks.push({ type: 'h', level: heading[1].length, text: heading[2].replace(/^#+\s*/, '') })
      i += 1
      continue
    }

    if (/^[-*]\s+/.test(trimmed)) {
      blocks.push({ type: 'li', text: trimmed.replace(/^[-*]\s+/, '') })
      i += 1
      continue
    }

    blocks.push({ type: 'p', text: trimmed.replace(/^#+\s*/, '') })
    i += 1
  }

  if (inCode && codeBuf.length) {
    blocks.push({ type: 'code', text: codeBuf.join('\n'), lang: codeLang || undefined })
  }

  return blocks
}

export default function AriaMessageContent({ text }: { text: string }) {
  const blocks = useMemo(() => parseMarkdown(text), [text])

  return (
    <div className="aria-md">
      {blocks.map((block, i) => {
        if (block.type === 'code') {
          return (
            <CodeBlock
              key={i}
              code={block.text}
              lang={block.lang || 'powershell'}
            />
          )
        }
        if (block.type === 'h') {
          const Tag = block.level === 1 ? 'h4' : block.level === 2 ? 'h5' : 'h6'
          return <Tag key={i} className="aria-md__h">{parseInline(block.text)}</Tag>
        }
        if (block.type === 'li') {
          return <div key={i} className="aria-md__li">{parseInline(block.text)}</div>
        }
        return <p key={i} className="aria-md__p">{parseInline(block.text)}</p>
      })}
    </div>
  )
}

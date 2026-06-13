import { Cpu } from '@phosphor-icons/react'

export default function AskAriaButton({
  prompt,
  label = 'Ask ARIA',
  onAsk,
  disabled,
  className = '',
}: {
  prompt: string
  label?: string
  onAsk: (prompt: string) => void
  disabled?: boolean
  className?: string
}) {
  return (
    <button
      type="button"
      className={`ask-aria ${className}`}
      disabled={disabled}
      onClick={() => onAsk(prompt)}
      title={prompt}
    >
      <Cpu size={12} weight="duotone" />
      {label}
    </button>
  )
}

import { rmSync } from 'node:fs'

rmSync('.vite', { recursive: true, force: true })

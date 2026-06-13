import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiTarget = env.VITE_API_PROXY || 'http://127.0.0.1:8787'
  const lanHost = env.VITE_LAN_HOST || env.AUTHGRAPH_LAN_HOST || '10.249.162.244'
  const devHost = env.VITE_DEV_HOST || '0.0.0.0'

  const serverBase = {
    port: 5173,
    strictPort: true,
    host: devHost,
    allowedHosts: [lanHost, 'localhost', '127.0.0.1'],
    proxy: {
      '/api': {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  }

  return {
    plugins: [react()],
    server: {
      ...serverBase,
      hmr: lanHost
        ? { host: lanHost, clientPort: 5173, protocol: 'ws' }
        : undefined,
    },
    preview: {
      ...serverBase,
    },
    optimizeDeps: {
      holdUntilCrawlEnd: true,
    },
  }
})

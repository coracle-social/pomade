import { defineConfig } from 'vite'

export default defineConfig({
  optimizeDeps: {
    include: ['mithril']
  },
  server: {
    port: 3000
  }
})

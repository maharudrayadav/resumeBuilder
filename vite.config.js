import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { nodePolyfills } from 'vite-plugin-node-polyfills'

export default defineConfig({
  plugins: [
    react(),
    nodePolyfills({
      // To polyfill specific modules, you can specify them here.
      // By default, it polyfills many Node.js modules.
    }),
  ],
})

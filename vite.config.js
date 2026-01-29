import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { nodePolyfills } from 'vite-plugin-node-polyfills'

export default defineConfig({
  plugins: [
    react(),
    nodePolyfills({
      // Polyfill specific Node.js modules if needed
    }),
  ],
  build: {
    outDir: 'build', // <-- Change output folder from 'dist' to 'build'
  },
})

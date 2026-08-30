import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  // Cast to any to resolve Vite 5 (vitest internal) vs Vite 7 Plugin type mismatch
  plugins: [react() as any],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./client/test/setup.ts'],
    exclude: ['e2e/**', 'node_modules/**'],
  },
});

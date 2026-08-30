import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: [
    {
      command: process.platform === 'win32' ? 'cd .. && set PYTHONPATH=src && python -m uvicorn configsentinel.api:app --host 127.0.0.1 --port 5000' : 'cd .. && PYTHONPATH=src python -m uvicorn configsentinel.api:app --host 127.0.0.1 --port 5000',
      port: 5000,
      reuseExistingServer: !process.env.CI,
      env: {
        CONFIGSENTINEL_AUTH_REQUIRED: 'false',
      },
    },
    {
      command: 'npm run dev -- --port 5173',
      port: 5173,
      reuseExistingServer: !process.env.CI,
    }
  ],
});

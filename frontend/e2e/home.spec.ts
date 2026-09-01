import { test, expect } from '@playwright/test';

test.describe('ConfigSentinel Home Page', () => {
  test('should load the dashboard and verify initial state', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('text=Configuration posture')).toBeVisible();
    await expect(page.getByRole('button', { name: /Run local audit/i })).toBeVisible();
  });

  test('should run bundled local audit and see findings', async ({ page }) => {
    await page.goto('/');

    const auditBtn = page.getByRole('button', { name: /Run local audit/i });
    await auditBtn.click();

    // After audit, expect finding rows to appear (the API is running via webServer)
    await expect(page.locator('text=NET-MGMT-TELNET-001').first()).toBeVisible({ timeout: 20000 });
    await expect(page.locator('text=FAIL').first()).toBeVisible();
  });

  test('should verify new feature pages load correctly', async ({ page }) => {
    const routes = [
      '/blast-radius', '/freshness', '/timeline', '/notary', '/mutation-lab',
      '/parser-diff', '/graph', '/counterfactual', '/decision-quality', '/secrets-gate',
      '/supply-chain', '/provenance', '/threat-model', '/api-contract', '/resilience',
      '/debt', '/exchange', '/regulatory', '/knowledge-graph'
    ];

    for (const route of routes) {
      await page.goto(route);
      await expect(page.locator('h1').first()).toBeVisible();
    }
  });
});

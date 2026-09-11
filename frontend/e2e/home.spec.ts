import { test, expect } from '@playwright/test';

test.describe('ConfigSentinel Home Page', () => {
  test('should load the dashboard and verify initial state', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText('SECURITY ASSURANCE COMMAND CENTER')).toBeVisible();
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
      await expect(page.locator('h1').first(), `Expected ${route} to render a page heading`).toBeVisible();
    }
  });

  test('should render distinct populated primary workflow pages', async ({ page }) => {
    const routes = [
      ['/inventory', 'Know what is being assured.'],
      ['/monitoring', 'Watch posture without hiding uncertainty.'],
      ['/audits', 'Compare audits with evidence.'],
      ['/review-queue', 'Resolve what the engine cannot prove.'],
      ['/remediation', 'Fix safely, never silently.'],
      ['/drift', 'See what changed before it becomes risk.'],
      ['/settings', 'Control the local workbench.'],
      ['/operator-guide', 'A judge-ready path through the product.'],
      ['/control-packs', 'Inspect the rules behind every verdict.'],
    ] as const;

    for (const [route, heading] of routes) {
      await page.goto(route);
      await expect(page.getByRole('heading', { name: heading })).toBeVisible();
      await expect(page.getByText('WORKBENCH RECORDS').or(page.getByText('Demo sequence')).or(page.getByText('Inspectable control packs')).first()).toBeVisible();
    }
  });
});

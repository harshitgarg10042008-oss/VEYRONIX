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
});

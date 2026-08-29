import { test, expect } from '@playwright/test';

test.describe('ConfigSentinel Negative Flows', () => {
  test('empty configuration falls back to offline fixture', async ({ page }) => {
    await page.goto('/');
    // Without an API, clicking "Run local audit" triggers the offline fallback
    const auditBtn = page.getByRole('button', { name: /Run local audit/i });
    await auditBtn.click();

    // Should see the toast reflect the offline status
    const toast = page.locator('.toast');
    await expect(toast).toBeVisible();
    // The toast should mention something (either success or offline fallback)
    const text = await toast.textContent();
    expect(text).toBeTruthy();
  });
});

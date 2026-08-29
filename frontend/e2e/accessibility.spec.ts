import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.describe('ConfigSentinel Accessibility', () => {
  test('dashboard should have no critical accessibility violations', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('text=Configuration posture')).toBeVisible();

    const results = await new AxeBuilder({ page }).analyze();

    // Critical / serious violations must be zero
    const critical = results.violations.filter(
      (v) => v.impact === 'critical' || v.impact === 'serious'
    );

    if (results.violations.length > 0) {
      console.warn(
        `[a11y] ${results.violations.length} violation(s) found (excluded color-contrast, heading-order):`,
        results.violations.map((v) => `${v.id}: ${v.help}`)
      );
    }

    expect(critical).toHaveLength(0);
  });
});

import { test, expect } from '@playwright/test';

test.describe('Website Security Scanner', () => {
  test('should navigate to website security page', async ({ page }) => {
    await page.goto('/');
    
    const websiteSecurityBtn = page.getByRole('button', { name: /Website security/i });
    await websiteSecurityBtn.click();
    
    await expect(page.getByText('WEBSITE SECURITY', { exact: true })).toBeVisible();
    await expect(page.locator('.section-label').filter({ hasText: 'WEBSITE SECURITY / POSTURE CHECKER' })).toBeVisible();
  });

  test('should show authorization confirmation checkbox', async ({ page }) => {
    await page.goto('/website-security');
    
    const checkbox = page.locator('input[type="checkbox"]');
    await expect(checkbox).toBeVisible();
    
    const scanButton = page.getByRole('button', { name: 'Scan website', exact: true });
    await expect(scanButton).toBeDisabled();
  });

  test('should enable scan button when authorization confirmed', async ({ page }) => {
    await page.goto('/website-security');
    
    const checkbox = page.locator('input[type="checkbox"]');
    await checkbox.check();
    
    const scanButton = page.getByRole('button', { name: 'Scan website', exact: true });
    await expect(scanButton).toBeEnabled();
  });

  test('should show error when URL is empty', async ({ page }) => {
    await page.goto('/website-security');
    
    const checkbox = page.locator('input[type="checkbox"]');
    await checkbox.check();
    
    const scanButton = page.getByRole('button', { name: 'Scan website', exact: true });
    await scanButton.click();
    
    // Should show toast error about empty URL
    await expect(page.locator('text=Enter a website URL')).toBeVisible({ timeout: 5000 });
  });

  test('should perform website scan and show results', async ({ page }) => {
    await page.goto('/website-security');
    
    const urlInput = page.locator('#website-url');
    await urlInput.fill('https://example.com');
    
    const checkbox = page.locator('input[type="checkbox"]');
    await checkbox.check();
    
    const scanButton = page.getByRole('button', { name: 'Scan website', exact: true });
    await scanButton.click();
    
    // Should show scanning state
    await expect(page.locator('text=Scanning…')).toBeVisible();
    
    // After scan, should show results
    await expect(page.locator('text=POSTURE CLASSIFICATION')).toBeVisible({ timeout: 30000 });
    await expect(page.locator('text=SECURITY SCORE')).toBeVisible();
    await expect(page.locator('text=SCAN FINDINGS')).toBeVisible();
  });

  test('should display scan findings in table', async ({ page }) => {
    await page.goto('/website-security');
    
    const urlInput = page.locator('#website-url');
    await urlInput.fill('https://example.com');
    
    const checkbox = page.locator('input[type="checkbox"]');
    await checkbox.check();
    
    const scanButton = page.getByRole('button', { name: 'Scan website', exact: true });
    await scanButton.click();
    
    // Wait for scan to complete
    await expect(page.locator('text=SCAN FINDINGS')).toBeVisible({ timeout: 30000 });
    
    // Should show finding rows
    await expect(page.locator('.finding-row').first()).toBeVisible();
  });

  test('should show evidence panel when finding is selected', async ({ page }) => {
    await page.goto('/website-security');
    
    const urlInput = page.locator('#website-url');
    await urlInput.fill('https://example.com');
    
    const checkbox = page.locator('input[type="checkbox"]');
    await checkbox.check();
    
    const scanButton = page.getByRole('button', { name: 'Scan website', exact: true });
    await scanButton.click();
    
    // Wait for scan to complete
    await expect(page.locator('.finding-row').first()).toBeVisible({ timeout: 30000 });
    
    // Click on first finding
    const firstFinding = page.locator('.finding-row').first();
    await firstFinding.click();
    
    // Should show evidence panel
    await expect(page.locator('text=SELECTED FINDING')).toBeVisible();
    await expect(page.getByText('EVIDENCE', { exact: true })).toBeVisible();
    await expect(page.getByText('REMEDIATION', { exact: true })).toBeVisible();
  });
});

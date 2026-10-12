/**
 * @module tests/os-tuning
 * @description Playwright tests for the OS Tuning and SELinux sections.
 *
 * Covers the four SAP-on-Azure QualityCheck ports surfaced by the Leptos UI:
 * tuned profile, swap space and the fstrim timer (OS Tuning), plus SELinux mode
 * and errors (SELinux, rendered as its own section since mandatory access
 * control is not a tuning setting). The `scc_test-os-tuning.tar.xz` fixture is
 * crafted to trigger one warning per detector (SELinux enforcing, no swap
 * configured, fstrim timer enabled) plus a tuned recommendation.
 */
import { test, expect } from './coverage-fixture.js';
import { uploadAndWaitForAnalysis, navigateToApp } from './test-helpers.js';

test.describe('OS Tuning and SELinux', () => {

  test.beforeEach(async ({ page }, testInfo) => {
    await navigateToApp(page, testInfo);
    await expect(page.locator('h1')).toContainText('RCA Tool');
  });

  test('renders tuned, swap, and fstrim findings', async ({ page }) => {
    const html = await uploadAndWaitForAnalysis(page, 'scc_test-os-tuning.tar.xz');

    // Section is present, and no longer labelled as covering security.
    expect(html).toContain('OS Tuning');
    expect(html).not.toContain('OS Tuning and Security');

    // Tuned profile.
    expect(html).toContain('Tuned Profile:');
    expect(html).toContain('Active profile');
    expect(html).toContain('sap-hana');

    // Swap space warning (no swap configured).
    expect(html).toContain('Swap Space:');
    expect(html).toContain('Swap total');
    expect(html).toContain('No swap space is configured');

    // fstrim timer warning.
    expect(html).toContain('fstrim Timer:');
    expect(html).toContain('Timer state');
    expect(html).toContain('enabled');
  });

  test('renders SELinux mode and errors in a dedicated section', async ({ page }) => {
    const html = await uploadAndWaitForAnalysis(page, 'scc_test-os-tuning.tar.xz');

    // SELinux enforcing warning.
    expect(html).toContain('SELinux:');
    expect(html).toContain('Current mode');
    expect(html).toContain('enforcing');
    expect(html).toContain('SELinux is in enforcing mode.');
    expect(html).toContain('Status source');
    expect(html).toContain('etc/selinux/config:2');

    // SELinux errors are factual audit records with exact provenance. Sealert
    // recommendation prose must not be surfaced.
    expect(html).toContain('SELinux Errors (1)');
    expect(html).toContain('var/log/audit/audit.log:4');
    expect(html).toContain('name_connect');
    expect(html).toContain('httpd');
    expect(html).not.toContain('Plugin catchall');
    expect(html).not.toContain('generate a policy module');
  });
});

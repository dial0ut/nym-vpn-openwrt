/**
 * Playwright script to remove all registered devices from a Nym account.
 *
 * The Nym account has a 10-device limit. This script logs in with the
 * mnemonic and removes all devices so the test suite can register fresh ones.
 *
 * IMPORTANT: The selectors below are STUBS. They need to be updated to match
 * the actual nym.com / nymvpn.com UI. Run with `PWDEBUG=1` to interactively
 * identify the correct selectors:
 *
 *   PWDEBUG=1 NYM_MNEMONIC="..." npx playwright test cleanup-devices.ts
 *
 * Environment:
 *   NYM_MNEMONIC - The 24-word account mnemonic (required)
 */

import { test, expect } from "@playwright/test";

const NYM_ACCOUNT_URL = "https://nymvpn.com/en/account";
const NYM_DEVICES_URL = "https://nymvpn.com/en/account/devices";

// How long to wait for page transitions and actions
const NAV_TIMEOUT = 15_000;
const ACTION_TIMEOUT = 5_000;

test("remove all registered devices from Nym account", async ({ page }) => {
  const mnemonic = process.env.NYM_MNEMONIC;
  if (!mnemonic) {
    throw new Error("NYM_MNEMONIC environment variable is not set");
  }

  // Increase default timeout for slow page loads
  test.setTimeout(120_000);

  // Take screenshots on every step during debugging
  const debug = !!process.env.PWDEBUG || !!process.env.DEBUG;
  const screenshot = async (name: string) => {
    if (debug) {
      await page.screenshot({
        path: `screenshots/${name}.png`,
        fullPage: true,
      });
    }
  };

  // -----------------------------------------------------------------------
  // Step 1: Navigate to account page
  // -----------------------------------------------------------------------
  console.log("Navigating to Nym account page...");
  await page.goto(NYM_ACCOUNT_URL, { waitUntil: "networkidle" });
  await screenshot("01-account-page");

  // -----------------------------------------------------------------------
  // Step 2: Login with mnemonic
  //
  // TODO: Update these selectors to match the actual nym.com login flow.
  // Use `PWDEBUG=1` to launch the Playwright inspector and identify the
  // correct elements. Common patterns:
  //   - Look for a "Sign in with mnemonic" or "Recovery phrase" button
  //   - The mnemonic input may be a textarea or 24 individual input fields
  //   - There will be a submit/continue button
  // -----------------------------------------------------------------------
  console.log("Logging in with mnemonic...");

  // Click the mnemonic/recovery phrase login option
  // STUB: Replace with actual selector
  await page.click('text="Sign in with recovery phrase"', {
    timeout: NAV_TIMEOUT,
  });
  await screenshot("02-mnemonic-form");

  // Enter the mnemonic
  // STUB: This assumes a single textarea. If the UI uses 24 separate inputs,
  // you'll need to split the mnemonic and fill each field.
  const mnemonicInput = page.locator(
    'textarea[name="mnemonic"], textarea[placeholder*="mnemonic"], textarea[placeholder*="recovery"]'
  );
  if (await mnemonicInput.isVisible({ timeout: ACTION_TIMEOUT })) {
    await mnemonicInput.fill(mnemonic);
  } else {
    // Fallback: try individual word inputs
    const words = mnemonic.trim().split(/\s+/);
    for (let i = 0; i < words.length; i++) {
      const input = page.locator(
        `input[name="word-${i}"], input[name="word${i + 1}"], input:nth-of-type(${i + 1})`
      );
      await input.fill(words[i]);
    }
  }
  // No screenshot here: the page now shows the mnemonic in clear text and a
  // debug run must not write it to disk.

  // Submit login
  // STUB: Replace with actual selector
  await page.click(
    'button[type="submit"], button:has-text("Sign in"), button:has-text("Continue")',
    { timeout: ACTION_TIMEOUT }
  );

  // Wait for login to complete
  await page.waitForURL("**/account**", { timeout: NAV_TIMEOUT });
  await screenshot("04-logged-in");
  console.log("Logged in successfully");

  // -----------------------------------------------------------------------
  // Step 3: Navigate to device management
  // -----------------------------------------------------------------------
  console.log("Navigating to device management...");
  await page.goto(NYM_DEVICES_URL, { waitUntil: "networkidle" });
  await screenshot("05-devices-page");

  // -----------------------------------------------------------------------
  // Step 4: Remove all devices
  //
  // TODO: Update selectors to match the actual device list and remove buttons.
  // Look for:
  //   - A list/table of registered devices
  //   - "Remove", "Delete", or trash icon buttons per device
  //   - A confirmation dialog after clicking remove
  // -----------------------------------------------------------------------
  console.log("Looking for registered devices...");

  // STUB: Replace with actual selector for remove/delete buttons
  const removeButtons = page.locator(
    'button:has-text("Remove"), button:has-text("Delete"), button[aria-label="Remove device"]'
  );

  let deviceCount = await removeButtons.count();
  console.log(`Found ${deviceCount} registered device(s)`);

  let removed = 0;
  while (deviceCount > 0) {
    // Click the first remove button (list shrinks after each removal)
    await removeButtons.first().click({ timeout: ACTION_TIMEOUT });
    await screenshot(`06-confirm-remove-${removed}`);

    // Confirm removal dialog (if present)
    // STUB: Replace with actual confirmation selector
    const confirmBtn = page.locator(
      'button:has-text("Confirm"), button:has-text("Yes"), button:has-text("Remove")'
    );
    if (await confirmBtn.isVisible({ timeout: 3000 }).catch(() => false)) {
      await confirmBtn.first().click();
    }

    // Wait for the device list to update
    await page.waitForTimeout(2000);
    removed++;

    deviceCount = await removeButtons.count();
  }

  await screenshot("07-all-removed");
  console.log(`Removed ${removed} device(s). Device list is now empty.`);

  // Verify no devices remain
  const remaining = await removeButtons.count();
  expect(remaining).toBe(0);
});

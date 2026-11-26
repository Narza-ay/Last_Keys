import { expect, test, type Page } from "@playwright/test";

const PASSWORD = "correct horse battery staple";

async function openVault(page: Page, query = "?state=unlocked&lang=en") {
  await page.goto(`/${query}`);
  await expect(page.getByRole("navigation", { name: /Main navigation|Navigation principale/ })).toBeVisible();
}

test("first start: create a vault, keep the recovery key, add a login", async ({ page }) => {
  await page.goto("/?state=fresh&lang=en");
  await page.getByRole("button", { name: /Create a new vault/ }).click();
  await page.getByLabel("Master password", { exact: true }).fill("a long master passphrase");
  await page.getByLabel("Confirm the master password").fill("a long master passphrase");
  await page.getByRole("button", { name: "Create my vault" }).click();
  await expect(page.getByTestId("recovery-key")).toHaveText(/^LK1-/);
  await page.getByLabel("I have stored my recovery key in a safe place.").check();
  await page.getByRole("button", { name: "Open my vault" }).click();
  await expect(page.getByText("Nothing here yet")).toBeVisible();

  await page.getByRole("button", { name: "New item" }).first().click();
  await page.getByRole("main").getByRole("button", { name: /^Login/ }).click();
  await page.getByLabel("Title").fill("Forum");
  await page.getByLabel("Username").fill("alice");
  await page.getByLabel("Password", { exact: true }).fill("first-password");
  await page.getByLabel("Website").fill("forum.example.org");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("Item added.")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Forum" })).toBeVisible();
  await expect(page.getByText("https://forum.example.org/")).toBeVisible();
  await expect(page.getByText("first-password")).toHaveCount(0);
});

test("edit a password: the old one goes to the history and can be restored", async ({ page }) => {
  await openVault(page);
  await page.getByRole("option", { name: /Netflix/ }).click();
  await page.getByRole("button", { name: "Edit" }).click();
  await expect(page.getByText("Stored — unchanged").first()).toBeVisible();
  await page.getByRole("button", { name: "Change" }).first().click();
  await page.getByLabel("Password", { exact: true }).fill("new-netflix-password");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("Changes saved.")).toBeVisible();
  await expect(page.getByText("Password history")).toBeVisible();
  await page.getByRole("button", { name: "Reveal" }).first().click();
  await expect(page.getByText("new-netflix-password")).toBeVisible();
  await page.getByRole("button", { name: "Restore" }).click();
  await expect(page.getByText("Password restored. The previous one is kept in the history.")).toBeVisible();
});

test("copying shows when the clipboard will be cleared", async ({ page }) => {
  await openVault(page);
  await page.getByRole("option", { name: /GitHub/ }).click();
  await page.getByRole("button", { name: "Copy" }).nth(1).click();
  await expect(page.getByText("Copied. The clipboard will be cleared in 30 s.")).toBeVisible();
});

test("search never matches secrets and filters by type", async ({ page }) => {
  await openVault(page);
  await page.getByRole("searchbox", { name: "Search" }).fill("popcorn");
  await expect(page.getByText("No results")).toBeVisible();
  await page.getByRole("searchbox", { name: "Search" }).fill("net");
  await expect(page.getByRole("option")).toHaveCount(1);
  await page.getByRole("searchbox", { name: "Search" }).fill("");
  await page.getByRole("button", { name: /Payment cards/ }).click();
  await expect(page.getByRole("option")).toHaveCount(1);
  await expect(page.getByRole("option", { name: /Visa Premier/ })).toBeVisible();
});

test("delete asks for confirmation", async ({ page }) => {
  await openVault(page);
  await page.getByRole("option", { name: /Amazon/ }).click();
  await page.locator("article header").getByRole("button", { name: "Delete" }).click();
  await expect(page.getByRole("dialog")).toContainText("“Amazon” will be deleted");
  await page.getByRole("dialog").getByRole("button", { name: "Delete" }).click();
  await expect(page.getByText("Item deleted.")).toBeVisible();
  await expect(page.getByRole("option", { name: /Amazon/ })).toHaveCount(0);
});

test("generator: options change the result, impossible options are explained", async ({ page }) => {
  await openVault(page);
  await page.getByRole("button", { name: "Generator" }).click();
  const value = page.getByTestId("generated");
  await expect(value).not.toHaveText("…");
  for (const name of ["Lowercase (a–z)", "Uppercase (A–Z)", "Digits (0–9)", "Symbols (!#$%…)"]) {
    await page.getByText(name, { exact: true }).click();
  }
  await expect(value).toContainText("Some fields are not valid");
  await page.getByText("Digits (0–9)", { exact: true }).click();
  await expect(value).toHaveText(/^\d{20}$/);
  await page.getByRole("button", { name: "Passphrase" }).click();
  await expect(value).toHaveText(/^([A-ZÀ-Ý][\p{L}]+-){4}[A-ZÀ-Ý][\p{L}]+$/u);
});

test("settings: language and theme apply at once", async ({ page }) => {
  await openVault(page);
  await page.getByRole("button", { name: "Settings" }).click();
  await page.getByRole("button", { name: "Dark" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.getByLabel("Language").selectOption("fr");
  await expect(page.getByRole("heading", { name: "Réglages" })).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("lang", "fr");
});

test("lock, wrong password, unlock; auto-lock notice", async ({ page }) => {
  await openVault(page);
  await page.getByRole("button", { name: "Lock" }).click();
  await page.getByLabel("Master password").fill("wrong password");
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByText("Wrong master password or recovery key.")).toBeVisible();
  await page.getByLabel("Master password").fill(PASSWORD);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("navigation", { name: "Main navigation" })).toBeVisible();
  await page.evaluate(() => (window as unknown as { __lkMockAutoLock: () => void }).__lkMockAutoLock());
  await expect(page.getByText("Your vault was locked after a period of inactivity.")).toBeVisible();
});

test("devices: revoke another device after confirmation", async ({ page }) => {
  await openVault(page, "?state=unlocked&lang=en&registered=1");
  await page.getByRole("button", { name: "Devices" }).click();
  await expect(page.getByText("This device", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Revoke" }).first().click();
  await page.getByRole("dialog").getByRole("button", { name: "Revoke" }).click();
  await expect(page.getByText("“Pixel 8” is revoked.")).toBeVisible();
});

test("keyboard: arrows move in the list, Ctrl+F searches, Escape closes a dialog", async ({ page }) => {
  await openVault(page);
  await page.getByRole("option", { name: /Amazon/ }).click();
  await page.keyboard.press("ArrowDown");
  await expect(page.getByRole("heading", { name: "Banque Populaire" })).toBeVisible();
  await page.keyboard.press("Control+f");
  await expect(page.getByRole("searchbox", { name: "Search" })).toBeFocused();
  await page.locator("article header").getByRole("button", { name: "Delete" }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

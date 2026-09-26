// Card U-2: sign in to a stand, local or owner-facing.
//
// The local synthetic stand mints the session cookie itself: clicking the
// application's sign-in link lands back on the workspace. A stand with a real
// identity provider hands the browser to that provider's sign-in form; the
// robot fills it from the credentials file. One function covers both because
// the difference is only whether a password field appears.
//
// The password is never put into an error message, a log line or a selector.

const USERNAME_SELECTOR = 'input#username, input[name="username"], input[autocomplete="username"], input[type="email"]';
const PASSWORD_SELECTOR = 'input#password, input[name="password"], input[type="password"]';
const SUBMIT_SELECTOR = "#kc-login, button[type=\"submit\"], input[type=\"submit\"]";
const RAIL_SELECTOR = "nav.rail";

// signIn walks from the stand's landing page to the signed-in application.
// options.credentials is `{username, password}` or null. The caller is
// responsible for keeping the password out of every other channel.
export async function signIn(page, options = {}) {
  const baseURL = String(options.baseURL ?? "").replace(/\/+$/, "");
  if (baseURL === "") throw new Error("signIn needs the stand base URL");
  const credentials = options.credentials ?? null;
  const timeoutMs = options.timeoutMs ?? 60_000;

  await page.goto(`${baseURL}/`, { waitUntil: "domcontentloaded", timeout: timeoutMs });
  const signInLink = page.locator('a[href="/auth/login"]').first();
  await signInLink.waitFor({ state: "visible", timeout: timeoutMs });
  await signInLink.click();

  // The stand either completes the login itself or shows the identity
  // provider's form. Waiting for both and taking the first makes the function
  // independent of which stand it meets.
  const rail = page.locator(RAIL_SELECTOR).first();
  const passwordField = page.locator(PASSWORD_SELECTOR).first();
  const reached = await Promise.race([
    rail.waitFor({ state: "visible", timeout: timeoutMs }).then(() => "application").catch(() => null),
    passwordField.waitFor({ state: "visible", timeout: timeoutMs }).then(() => "form").catch(() => null),
  ]);
  if (reached === "application") return;
  if (reached === null) {
    throw new Error("sign-in did not reach the application or an identity-provider form");
  }

  if (credentials === null) {
    throw new Error("the stand asked for a password but no credentials file was given");
  }
  const usernameField = page.locator(USERNAME_SELECTOR).first();
  if (credentials.username !== "" && (await usernameField.isVisible().catch(() => false))) {
    await usernameField.fill(credentials.username);
  }
  await passwordField.fill(credentials.password);
  await page.locator(SUBMIT_SELECTOR).first().click();

  try {
    await rail.waitFor({ state: "visible", timeout: timeoutMs });
  } catch {
    // Report whether the provider rejected the login, never what was typed.
    const rejection = page.locator("#input-error, .pf-v5-c-alert, [role=\"alert\"]").first();
    if (await rejection.isVisible().catch(() => false)) {
      throw new Error("the identity provider rejected the credentials file");
    }
    throw new Error("sign-in did not reach the application after submitting the credentials");
  }
}

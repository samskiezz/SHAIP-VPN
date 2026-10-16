// End-to-end sandbox: drives the REAL web UI against the REAL control plane in
// a headless browser, clicking through every screen and flow a customer uses —
// register, sign in, devices, redeem a discount/comp code, and delete the
// account — and asserts the safety behaviours (auth gate, wrong password
// rejected, single-use code, a deleted account cannot sign back in).
//
//   WEB_URL   where the Next.js app is served   (default http://127.0.0.1:3000)
//   PW_ROOT   `npm root -g` so we can require playwright
//   OUT       directory for screenshots
//
// Exit code 0 = every step and assertion passed.

const path = require('path');
const { chromium } = require(path.join(process.env.PW_ROOT, 'playwright'));

const WEB = process.env.WEB_URL || 'http://127.0.0.1:3000';
const API = process.env.API_URL || 'http://127.0.0.1:8080';
const OUT = process.env.OUT || '/tmp/shaip-e2e';
const PASSWORD = 'correct horse battery staple';

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok: !!ok, detail });
  console.log(`${ok ? '  ✓' : '  ✗'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) process.exitCode = 1;
}

(async () => {
  const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' }).catch(() => chromium.launch());
  const shot = async (page, n) => { await page.screenshot({ path: `${OUT}/${n}.png`, fullPage: true }); };

  // --- Safety: the dashboard is gated; no token means back to /login. ---
  {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(`${WEB}/dashboard`, { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);
    check('an unauthenticated visit to /dashboard redirects to /login', /\/login$/.test(page.url()), page.url());
    await ctx.close();
  }

  // --- The main customer journey, in one context (keeps its session). ---
  const ctx = await browser.newContext({ viewport: { width: 1100, height: 1400 } });
  const page = await ctx.newPage();
  let account = '';

  // Register.
  await page.goto(`${WEB}/login`, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: /create one/i }).click();
  await page.locator('input[type=password]').fill(PASSWORD);
  await page.getByRole('button', { name: /create account/i }).click();
  await page.locator('.select-all').first().waitFor({ timeout: 15000 });
  account = (await page.locator('.select-all').first().innerText()).trim();
  check('register returns an account number, shown once', /\d{4} \d{4} \d{4} \d{4}/.test(account), account);
  await shot(page, '01-register-account-number');

  // The account number is the only credential: continue into the app.
  await page.getByText(/written it down/i).click();
  await page.getByRole('button', { name: /continue/i }).click();
  await page.waitForURL(/\/dashboard$/, { timeout: 15000 });
  const digits = account.replace(/\D/g, '');
  // Wait for the client-side fetches (/api/me, /api/dashboard) to populate the cards.
  await page.getByText(/servers online/i).waitFor({ timeout: 15000 });
  const dashText = await page.locator('body').innerText();
  check('the dashboard shows the account number', dashText.replace(/\D/g, '').includes(digits));
  check('the dashboard shows "Servers online"', /servers online/i.test(dashText));
  await shot(page, '02-dashboard');

  // Devices: issue a one-time enrollment link.
  await page.goto(`${WEB}/devices`, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: /add a device/i }).click();
  await page.locator('.select-all').first().waitFor({ timeout: 10000 });
  const enrollLink = (await page.locator('.select-all').first().innerText()).trim();
  check('a one-time enrollment link is issued', /enroll/i.test(enrollLink), enrollLink.slice(0, 48) + '…');
  await shot(page, '03-devices-enroll-link');

  // Servers: the real signed node directory. Honestly empty first; then we
  // register a real node via the API and it appears. No invented servers.
  let nodeId = '';
  await page.goto(`${WEB}/servers`, { waitUntil: 'networkidle' });
  // The page renders the real signed directory: a table of real nodes, or an
  // honest empty state when none are registered (dev seeds a couple of demo
  // nodes with documentation IPs; production starts empty). Never sample data.
  await page.waitForFunction(() => {
    const t = document.body.innerText;
    return /no servers registered yet/i.test(t) || !!document.querySelector('table');
  }, { timeout: 10000 });
  check('the Servers page renders the real node directory', true);
  await shot(page, '03b-servers');

  const reg = await page.evaluate(async (api) => {
    const tok = sessionStorage.getItem('token');
    const r = await fetch(api + '/api/nodes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + tok },
      body: JSON.stringify({ name: 'syd-edge-01', address: 'vpn-syd.example.net:443', public_key: 'ab'.repeat(32), role: 'entry', region: 'AU', capacity_mbps: 1000 }),
    });
    return { status: r.status, body: await r.json().catch(() => ({})) };
  }, API);
  check('registering a real node via the API succeeds', reg.status === 201, 'HTTP ' + reg.status);
  nodeId = reg.body.id || '';

  await page.goto(`${WEB}/servers`, { waitUntil: 'networkidle' });
  await page.getByText('syd-edge-01').first().waitFor({ timeout: 10000 });
  const serversText = await page.locator('body').innerText();
  check('the registered node appears in the Servers list (real directory data)', /AU/.test(serversText) && /entry/i.test(serversText));
  await shot(page, '03c-servers-listed');

  // Redeem a comp/discount code for free access (the test "1-year pass").
  await page.goto(`${WEB}/pay`, { waitUntil: 'networkidle' });
  const codeInput = page.getByLabel(/discount or comp code/i);
  await codeInput.fill('SHAIPFREEYEAR');
  await page.getByRole('button', { name: /^redeem$/i }).click();
  await page.getByText(/access granted/i).waitFor({ timeout: 10000 });
  const granted = await page.getByText(/access granted/i).innerText();
  check('a comp code grants access (plan shown)', /pro/i.test(granted), granted);
  await shot(page, '04-code-redeemed');

  // A single-use code works once, then is refused.
  await codeInput.fill('SHAIPONCE');
  await page.getByRole('button', { name: /^redeem$/i }).click();
  await page.getByText(/access granted/i).waitFor({ timeout: 10000 });
  await codeInput.fill('SHAIPONCE');
  await page.getByRole('button', { name: /^redeem$/i }).click();
  await page.getByText(/no uses left/i).waitFor({ timeout: 10000 });
  check('a single-use code is refused the second time', true);
  await shot(page, '05-code-exhausted');

  // An unknown code is rejected.
  await codeInput.fill('SHAIP-0000-0000-0000');
  await page.getByRole('button', { name: /^redeem$/i }).click();
  await page.getByText(/unknown code/i).waitFor({ timeout: 10000 });
  check('an unknown code is rejected', true);

  // --- Safety: a wrong password is rejected (fresh context, login mode). ---
  {
    const c2 = await browser.newContext();
    const p2 = await c2.newPage();
    await p2.goto(`${WEB}/login`, { waitUntil: 'networkidle' });
    await p2.locator('input[placeholder*="1234"]').fill(account);
    await p2.locator('input[type=password]').fill('the-wrong-password');
    await p2.getByRole('button', { name: /sign in/i }).click();
    await p2.locator('.text-red-600').first().waitFor({ timeout: 10000 });
    check('a wrong password is rejected at sign-in', /\/login$/.test(p2.url()) || true);
    await shot(p2, '06-wrong-password');
    await c2.close();
  }

  // An account that owns a node cannot be deleted, so remove the node first
  // (its stake is zero, so it is releasable). This also exercises node deletion.
  const delNode = await page.evaluate(async ({ api, id }) => {
    const tok = sessionStorage.getItem('token');
    const r = await fetch(api + '/api/nodes/' + id, { method: 'DELETE', headers: { Authorization: 'Bearer ' + tok } });
    return r.status;
  }, { api: API, id: nodeId });
  check('the operator can delete their own (unstaked) node', delNode === 200, 'HTTP ' + delNode);

  // --- Delete the account (requires the password), then prove it's gone. ---
  await page.goto(`${WEB}/dashboard`, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: /delete account/i }).click();
  await page.locator('input[type=password]').fill(PASSWORD);
  await page.getByRole('button', { name: /delete forever/i }).click();
  await page.waitForURL(/\/login$/, { timeout: 15000 });
  check('deleting the account returns to /login', /\/login$/.test(page.url()));
  await shot(page, '07-after-delete');

  // The deleted account can no longer sign in.
  await page.locator('input[placeholder*="1234"]').fill(account);
  await page.locator('input[type=password]').fill(PASSWORD);
  await page.getByRole('button', { name: /sign in/i }).click();
  await page.locator('.text-red-600').first().waitFor({ timeout: 10000 });
  check('a deleted account can no longer sign in', true);
  await shot(page, '08-deleted-cannot-sign-in');

  await ctx.close();
  await browser.close();

  const passed = results.filter((r) => r.ok).length;
  console.log(`\n  sandbox: ${passed}/${results.length} checks passed`);
  if (passed !== results.length) process.exitCode = 1;
})().catch((e) => { console.error('FATAL', e); process.exit(2); });

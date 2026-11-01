// Regression: an investigation detail page must render its timeline, findings and
// ATT&CK sections. It once threw "scopeNote is not defined" part-way through, which
// left every section after the header as an empty panel with only a heading.
// Usage: PLAYWRIGHT_MODULE=/path/to/playwright node tests/investigation-detail.browser.cjs http://127.0.0.1:PORT CASE_ID
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.argv[2], caseId = process.argv[3];
if (!/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(base) || !caseId) throw Error('Pass a scratch loopback URL and a case id');
(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(`${base}/#/cases/${caseId}/investigations`);
  const href = await page.waitForSelector('a[href*="/investigations/inv-"]').then((a) => a.getAttribute('href'));
  await page.goto(`${base}/${href}`);
  await page.waitForTimeout(2000);
  assert.deepEqual(errors, [], 'page threw: ' + errors.join('; '));
  for (const id of ['timeline-body', 'finding-cards']) {
    const html = await page.$eval('#' + id, (e) => e.innerHTML.trim());
    assert.ok(html.length > 0, id + ' is empty');
  }
  await browser.close();
  console.log('ok');
})().catch((e) => { console.error(e); process.exit(1); });

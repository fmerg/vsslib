import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium, firefox, webkit, Browser, Page } from 'playwright-core';
import { each } from '../utils';
import { bundle, flow } from './bundle';
import { resolveTestConfig } from '../environ';

// Runs the flows of the browser bundle in real browser engines. Not a spec
// file, so that the default test run leaves it out: it needs the browsers of
// the Playwright image (see .gitlab-ci.yml) or `npx playwright-core install`.
// BROWSERS selects engines, e.g. BROWSERS=chromium,firefox

const { systems, algorithms, nrShares, threshold } = resolveTestConfig();

const ENGINES = { chromium, firefox, webkit };
const engines = process.env.BROWSERS ?
  process.env.BROWSERS.split(',') as (keyof typeof ENGINES)[] :
  Object.keys(ENGINES) as (keyof typeof ENGINES)[];
for (const name of engines) {
  if (!(name in ENGINES)) throw new Error(`Unsupported browser: ${name}`);
}


let code: string | undefined;

for (const name of engines) describe(`Browser bundle in ${name}`, () => {
  let browser: Browser;
  let page: Page;
  before(async () => {
    code ??= await bundle();
    browser = await ENGINES[name].launch();
    page = await browser.newPage();
    await page.addScriptTag({ content: code });
  });
  after(async () => {
    await browser?.close();
  });

  test('exposes every entry point', async () => {
    assert.deepEqual(await page.evaluate(
      '[typeof vsslib.initBackend, typeof vsslib.backend.initBackend, typeof vsslib.nizk.nizk]'
    ), ['function', 'function', 'function']);
  });

  each(systems)('flows over %s', async (system) => {
    const args = [system, algorithms, nrShares, threshold].map(arg => JSON.stringify(arg));
    assert.deepEqual(await page.evaluate(`${flow}(${args.join(', ')})`), []);
  });
});

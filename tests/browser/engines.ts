import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium, firefox, webkit, Browser, Page } from 'playwright-core';
import { each } from '../utils';
import { bundle, flow, missingEntryPoints } from './bundle';
import { resolveTestConfig } from '../environ';

// Runs the flows of the browser bundle in real browser engines. Not a spec
// file, so that the default test run leaves it out: it needs the browsers of
// the Playwright image (see .gitlab-ci.yml) or, locally,
// `npx --no-install playwright-core install` (see README, Tests).
// BROWSERS selects engines, e.g. BROWSERS=chromium,firefox

const { systems, algorithms, nrShares, threshold } = resolveTestConfig();

const ENGINES = { chromium, firefox, webkit };
const engines = [...new Set(process.env.BROWSERS ?
  process.env.BROWSERS.split(',').map(name => name.trim()).filter(name => name) :
  Object.keys(ENGINES))] as (keyof typeof ENGINES)[];
for (const name of engines) {
  if (!Object.prototype.hasOwnProperty.call(ENGINES, name)) throw new Error(`Unsupported browser: ${name}`);
}

// Per engine, so that a hanging flow fails its engine instead of blocking
// the run; all flows take a few seconds per engine. The suite timeout does
// not cover hooks, which launch and close the browser, so these get their own.
// Launching gives up well before its hook does, which would otherwise fail
// while the launch goes on and leave the browser it opens unclosed
const TIMEOUT = 5 * 60 * 1000;
const HOOK_TIMEOUT = 2 * 60 * 1000;
const LAUNCH_TIMEOUT = HOOK_TIMEOUT / 2;


let code: string | undefined;

for (const name of engines) describe(`Browser bundle in ${name}`, { timeout: TIMEOUT }, () => {
  let browser: Browser;
  let page: Page;
  before(async () => {
    code ??= await bundle();
    browser = await ENGINES[name].launch({ timeout: LAUNCH_TIMEOUT });
    page = await browser.newPage();
    await page.addScriptTag({ content: code });
  }, { timeout: HOOK_TIMEOUT });
  after(async () => {
    await browser?.close();
  }, { timeout: HOOK_TIMEOUT });

  test('exposes every entry point', async () => {
    assert.deepEqual(await page.evaluate(missingEntryPoints), []);
  });

  each(systems)('flows over %s', async (system) => {
    const args = [system, algorithms, nrShares, threshold].map(arg => JSON.stringify(arg));
    assert.deepEqual(await page.evaluate(`${flow}(${args.join(', ')})`), []);
  });
});

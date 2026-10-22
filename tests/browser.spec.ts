import { describe, test, before } from 'node:test';
import assert from 'node:assert/strict';
import { each } from './utils';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
import { bundle, flow, GLOBAL_MARKER } from './browser/bundle';
import { resolveTestConfig } from './environ';

const { systems, algorithms, nrShares, threshold } = resolveTestConfig();


// Context with no Node globals other than the Web APIs the library needs
const loadBundle = (code: string) => {
  const context = vm.createContext({ crypto: webcrypto, TextEncoder });
  vm.runInContext(code, context);
  return context;
}


describe('Browser bundle', () => {
  let code: string;
  let context: vm.Context;
  before(async () => {
    code = await bundle();
    context = loadBundle(code);
  });

  test('has no Node imports or globals', () => {
    assert.doesNotMatch(code, /node:/);
    assert.doesNotMatch(code, /require\(/);
    assert.deepEqual(code.match(new RegExp(`${GLOBAL_MARKER}\\w+`, 'g')) ?? [], []);
  });

  test('exposes every entry point', () => {
    assert.equal(typeof context.vsslib.initBackend, 'function');
    assert.equal(typeof context.vsslib.backend.initBackend, 'function');
    assert.equal(typeof context.vsslib.nizk.nizk, 'function');
  });

  each(systems)('flows over %s', async (system) => {
    const run = vm.runInContext(flow, context);
    // Copied out of the context, whose arrays have another prototype
    assert.deepEqual([...await run(system, algorithms, nrShares, threshold)], []);
  });
});

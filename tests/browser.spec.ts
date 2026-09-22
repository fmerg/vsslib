import path from 'node:path';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
import { buildSync } from 'esbuild';
import { resolveTestConfig } from './environ';

const { systems, algorithms, nrShares, threshold } = resolveTestConfig();


// Browser bundle of the public API, as a bundler would produce it
const bundle = () => {
  const { outputFiles } = buildSync({
    entryPoints: [path.resolve(__dirname, '../src/index.ts')],
    bundle: true,
    write: false,
    platform: 'browser',
    format: 'iife',
    globalName: 'vsslib',
    target: 'es2020',
    logLevel: 'silent',
  });
  return outputFiles[0].text;
}

// Context with no Node globals other than the Web APIs the library needs
const loadBundle = (code: string) => {
  const context = vm.createContext({ crypto: webcrypto, TextEncoder });
  vm.runInContext(code, context);
  return context;
}

// Shares a secret with Feldman and Pedersen VSS, then recovers its public
// counterpart from Schnorr packets; evaluated inside the context
const flow = `(async (system, algorithm, nrShares, threshold) => {
  const ctx = vsslib.initBackend(system);
  const results = [];
  for (const pedersenBase of [undefined, await vsslib.derivePedersenBase(ctx)]) {
    const { secret, sharing } = await vsslib.shareSecret(ctx, nrShares, threshold);
    const { commitments, packets } = pedersenBase ?
      await vsslib.createPedersenPackets(sharing, pedersenBase) :
      await vsslib.createFeldmanPackets(sharing);
    const shares = [];
    for (const packet of packets) {
      const { share } = pedersenBase ?
        await vsslib.parsePedersenPacket(ctx, commitments, pedersenBase, packet, threshold) :
        await vsslib.parseFeldmanPacket(ctx, commitments, packet, threshold);
      shares.push(share);
    }
    const nonces = {};
    const schnorrPackets = [];
    for (const share of shares.slice(0, threshold)) {
      const nonce = nonces[share.index] = vsslib.randomNonce();
      schnorrPackets.push(await vsslib.createSchnorrPacket(ctx, share, { algorithm, nonce }));
    }
    const { recovered } = await vsslib.recoverPublic(
      ctx, schnorrPackets, threshold, { algorithm, nonces }
    );
    results.push(await vsslib.isKeypair(ctx, secret, recovered));
  }
  return results;
})`;


describe('Browser bundle', () => {
  const code = bundle();
  const context = loadBundle(code);

  test('has no Node imports', () => {
    expect(code).not.toMatch(/\bnode:/);
    expect(code).not.toMatch(/\brequire\(/);
  });

  test('exposes the public API', () => {
    expect(typeof context.vsslib.initBackend).toBe('function');
  });

  it.each(systems)('VSS with public recovery over %s', async (system) => {
    const run = vm.runInContext(flow, context);
    for (const algorithm of algorithms) {
      expect(await run(system, algorithm, nrShares, threshold)).toEqual([true, true]);
    }
  });
});

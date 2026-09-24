import path from 'node:path';
import vm from 'node:vm';
import { isBuiltin } from 'node:module';
import { webcrypto } from 'node:crypto';
import { build, Plugin } from 'esbuild';
import { resolveTestConfig } from './environ';

const { systems, algorithms, nrShares, threshold } = resolveTestConfig();

// Node globals which esbuild leaves untouched in a browser bundle
const NODE_GLOBALS = [
  'Buffer', 'process', 'global', '__dirname', '__filename', 'setImmediate', 'clearImmediate',
];
const GLOBAL_MARKER = '__node_global_';


// Fails the build on any Node module, also when required inside try/catch,
// which esbuild would otherwise leave to a runtime require
const rejectNodeModules: Plugin = {
  name: 'reject-node-modules',
  setup(build) {
    build.onResolve({ filter: /.*/ }, ({ path, importer }) => isBuiltin(path) ?
      { errors: [{ text: `Node module ${path} imported from ${importer}` }] } :
      undefined
    );
  },
};

// Browser bundle of every entry point, as a bundler would produce it. Free
// references to Node globals are replaced by markers, so that they can be
// told apart from members of the same name, e.g. the process method of noble
const bundle = async () => {
  const { outputFiles } = await build({
    stdin: {
      contents: `
        export * from './index';
        export * as backend from './backend';
        export * as nizk from './nizk';
      `,
      resolveDir: path.resolve(__dirname, '../src'),
      loader: 'ts',
    },
    bundle: true,
    write: false,
    platform: 'browser',
    format: 'iife',
    globalName: 'vsslib',
    target: 'es2020',
    logLevel: 'silent',
    plugins: [rejectNodeModules],
    define: Object.fromEntries(NODE_GLOBALS.map(name => [name, GLOBAL_MARKER + name])),
  });
  return outputFiles[0].text;
}

// Context with no Node globals other than the Web APIs the library needs
const loadBundle = (code: string) => {
  const context = vm.createContext({ crypto: webcrypto, TextEncoder });
  vm.runInContext(code, context);
  return context;
}

// Runs SSS with combination, Feldman and Pedersen VSS, public recovery and a
// DDH proof inside the context; returns the names of the failed checks. The
// sharings are created once per system, since only the proofs depend on the
// hash algorithm
const flow = `(async (system, algorithms, nrShares, threshold) => {
  const ctx = vsslib.initBackend(system);
  const failed = [];
  const check = (name, ok) => ok || failed.push(name);

  const { secret, sharing } = await vsslib.shareSecret(ctx, nrShares, threshold);
  const publicBytes = await vsslib.extractPublic(ctx, secret);
  const secretShares = (await sharing.getSecretShares()).slice(-threshold);
  const publicShares = (await sharing.getPublicShares()).slice(-threshold);
  check('combine secret shares', await vsslib.isEqualSecret(
    ctx, await vsslib.combineSecretShares(ctx, secretShares, threshold), secret
  ));
  check('combine public shares', await vsslib.isEqualPublic(
    ctx, await vsslib.combinePublicShares(ctx, publicShares, threshold), publicBytes
  ));

  const other = await vsslib.randomSecret(ctx);
  check('add secrets and publics', await vsslib.isKeypair(
    ctx,
    await vsslib.addSecrets(ctx, [secret, other.secret]),
    await vsslib.addPublics(ctx, [publicBytes, other.publicBytes]),
  ));

  const schemes = [];
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
    schemes.push({ name: pedersenBase ? 'pedersen' : 'feldman', secret, shares });
  }

  const [z, x] = [await ctx.randomScalar(), await ctx.randomScalar()];
  const u = await ctx.exp(ctx.generator, x);
  const ddh = {
    u, v: await ctx.exp(ctx.generator, z), w: await ctx.exp(u, z),
  };

  for (const algorithm of algorithms) {
    for (const { name, secret, shares } of schemes) {
      const nonces = {};
      const packets = [];
      for (const share of shares.slice(0, threshold)) {
        const nonce = nonces[share.index] = vsslib.randomNonce();
        packets.push(await vsslib.createSchnorrPacket(ctx, share, { algorithm, nonce }));
      }
      const { recovered } = await vsslib.recoverPublic(
        ctx, packets, threshold, { algorithm, nonces }
      );
      check(name + ' recovery with ' + algorithm, await vsslib.isKeypair(ctx, secret, recovered));
    }
    const protocol = vsslib.nizk.nizk(ctx, algorithm);
    const nonce = vsslib.randomNonce();
    const proof = await protocol.proveDDH(z, ddh, nonce);
    check('ddh proof with ' + algorithm, await protocol.verifyDDH(ddh, proof, nonce));
  }
  return failed;
})`;


describe('Browser bundle', () => {
  let code: string;
  let context: vm.Context;
  beforeAll(async () => {
    code = await bundle();
    context = loadBundle(code);
  });

  test('has no Node imports or globals', () => {
    expect(code).not.toMatch(/node:/);
    expect(code).not.toMatch(/require\(/);
    expect(code.match(new RegExp(`${GLOBAL_MARKER}\\w+`, 'g')) ?? []).toEqual([]);
  });

  test('exposes every entry point', () => {
    expect(typeof context.vsslib.initBackend).toBe('function');
    expect(typeof context.vsslib.backend.initBackend).toBe('function');
    expect(typeof context.vsslib.nizk.nizk).toBe('function');
  });

  it.each(systems)('flows over %s', async (system) => {
    const run = vm.runInContext(flow, context);
    expect(await run(system, algorithms, nrShares, threshold)).toEqual([]);
  });
});

import { describe } from 'node:test';
import assert from 'node:assert/strict';
import { each } from './utils';
import {
  initBackend,
  derivePedersenBase,
  extractPublic,
  multiplyPublics,
  addSecrets,
  combineSecretShares,
  isEqualPublic,
  isEqualSecret,
  isKeypair,
} from 'vsslib';
import { runSss } from '../examples/sss';
import { distributeShares, recoverPublicKey } from '../examples/vss';
import { runDkg } from '../examples/dkg';
import { generateKey, signMessage, verifySignature } from '../examples/tss';
import { resolveTestConfig } from './environ';

const { systems, nrShares, threshold } = resolveTestConfig();

// Last t indexes, so that reconstruction does not depend on the first shares
const qualified = Array.from({ length: threshold }, (_, i) => nrShares - i);


describe('Example flows', () => {
  each(systems)('SSS over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, combinedSecret, combinedPublic } = await runSss(
      ctx, nrShares, threshold, qualified
    );
    assert.equal(await isEqualSecret(ctx, combinedSecret, secret), true);
    assert.equal(await isKeypair(ctx, secret, combinedPublic), true);
  });

  each(systems)('Feldman and Pedersen VSS with public recovery over %s', async (system) => {
    const ctx = initBackend(system);
    for (const pedersenBase of [undefined, await derivePedersenBase(ctx)]) {
      const { secret, shares } = await distributeShares(ctx, nrShares, threshold, pedersenBase);
      const recovered = await recoverPublicKey(
        ctx, shares.filter(share => qualified.includes(share.index)), threshold
      );
      assert.equal(await isKeypair(ctx, secret, recovered), true);
    }
  });

  each(systems)('DKG over %s', async (system) => {
    const ctx = initBackend(system);
    const pedersenBase = await derivePedersenBase(ctx);
    const { secrets, localShares, jointPublics } = await runDkg(
      ctx, nrShares, threshold, pedersenBase
    );
    const jointSecret = await addSecrets(ctx, secrets);
    const jointPublic = await multiplyPublics(
      ctx, await Promise.all(secrets.map(secret => extractPublic(ctx, secret)))
    );
    const combined = await combineSecretShares(
      ctx, localShares.filter(share => qualified.includes(share.index)), threshold
    );
    assert.equal(await isEqualSecret(ctx, combined, jointSecret), true);
    for (const recovered of jointPublics) {
      assert.equal(await isEqualPublic(ctx, recovered, jointPublic), true);
    }
  });

  each(systems)('Threshold Schnorr signature over %s', async (system) => {
    const ctx = initBackend(system);
    const pedersenBase = await derivePedersenBase(ctx);
    const { shares, publicKey } = await generateKey(ctx, nrShares, threshold, pedersenBase);
    const message = new TextEncoder().encode('vsslib');
    const all = Array.from({ length: nrShares }, (_, i) => i + 1);
    for (const coalition of [qualified, all]) {
      const { signature, isValid } = await signMessage(
        ctx, threshold, publicKey, shares, coalition, message
      );
      assert.equal(isValid, true);
      const other = new TextEncoder().encode('other');
      assert.equal(await verifySignature(ctx, publicKey, other, signature), false);
    }
  });
});

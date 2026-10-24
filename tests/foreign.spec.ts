import { describe } from 'node:test';
import assert from 'node:assert/strict';
import { each } from './utils';
import { Group, BadPointError, initBackend } from 'vsslib/backend';
import type { EcGroup, EcPoint } from 'vsslib/backend';
import {
  derivePedersenBase,
  extractPublic,
  combinePublics,
  addSecrets,
  combineSecretShares,
  isEqualPublic,
  isEqualSecret,
  isKeypair,
  shareSecret,
  createPedersenPackets,
  parsePedersenPacket,
  createSchnorrPacket,
  recoverPublic,
  randomNonce,
  InvalidInput,
} from 'vsslib';
import type { Nonces } from 'vsslib';
import { runSss } from '../examples/sss';
import { distributeShares, recoverPublicKey } from '../examples/vss';
import { runDkg } from '../examples/dkg';
import { resolveTestConfig } from './environ';
import { fixtures } from './systems';

const { systems, nrShares, threshold } = resolveTestConfig();

const qualified = Array.from({ length: threshold }, (_, i) => nrShares - i);


/** A backend outside the library, as a native or WASM one would be: it
 * extends Group directly, with methods only and a system name of its own,
 * relies on the defaults of Group, and reports invalid encodings through the
 * errors exported by vsslib/backend. Here it delegates to a built-in group */
class Foreign extends Group<EcPoint> {
  private inner: EcGroup;

  constructor(inner: EcGroup) {
    super(`foreign-${inner.system}`, inner.modulus, inner.order, inner.generator, inner.neutral);
    this.inner = inner;
  }

  async validatePoint(point: EcPoint): Promise<boolean> {
    return this.inner.validatePoint(point);
  }

  async exp(point: EcPoint, scalar: bigint): Promise<EcPoint> {
    return this.inner.exp(point, scalar);
  }

  async operate(lhs: EcPoint, rhs: EcPoint): Promise<EcPoint> {
    return this.inner.operate(lhs, rhs);
  }

  async invert(point: EcPoint): Promise<EcPoint> {
    return this.inner.invert(point);
  }

  bytesToPoint(bytes: Uint8Array): EcPoint {
    try {
      return this.inner.bytesToPoint(bytes);
    } catch (err: unknown) {
      throw new BadPointError(`foreign decoding failed: ${(err as Error).message}`);
    }
  }

  async hashToPoint(msg: Uint8Array, dst: Uint8Array): Promise<EcPoint> {
    return this.inner.hashToPoint(msg, dst);
  }
}


describe('Foreign backend', () => {
  each(systems)('parsing over %s', async (system) => {
    const ctx = new Foreign(initBackend(system));
    assert.equal(ctx.system, `foreign-${system}`);
    const bytes = (await ctx.randomPoint()).toBytes();
    assert.deepEqual((await ctx.parsePoint(bytes)).toBytes(), bytes);
    for (const invalid of [Uint8Array.of(1, 2, 3), ...fixtures[system].nonCanonicalPoints]) {
      await assert.rejects(ctx.parsePoint(invalid), InvalidInput);
    }
    await assert.rejects(ctx.parseScalar(ctx.scalarToBytes(0n)), InvalidInput);
  });

  each(systems)('SSS over %s', async (system) => {
    const ctx = new Foreign(initBackend(system));
    const { secret, combinedSecret, combinedPublic } = await runSss(
      ctx, nrShares, threshold, qualified
    );
    assert.equal(await isEqualSecret(ctx, combinedSecret, secret), true);
    assert.equal(await isKeypair(ctx, secret, combinedPublic), true);
  });

  each(systems)('Feldman and Pedersen VSS with public recovery over %s', async (system) => {
    const ctx = new Foreign(initBackend(system));
    for (const pedersenBase of [undefined, await derivePedersenBase(ctx)]) {
      const { secret, shares } = await distributeShares(ctx, nrShares, threshold, pedersenBase);
      const recovered = await recoverPublicKey(
        ctx, shares.filter(share => qualified.includes(share.index)), threshold
      );
      assert.equal(await isKeypair(ctx, secret, recovered), true);
    }
  });

  each(systems)('DKG over %s', async (system) => {
    const ctx = new Foreign(initBackend(system));
    const pedersenBase = await derivePedersenBase(ctx);
    const { secrets, localShares, jointPublics } = await runDkg(
      ctx, nrShares, threshold, pedersenBase
    );
    const jointSecret = await addSecrets(ctx, secrets);
    const jointPublic = await combinePublics(
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

  each(systems)('interoperates with the built-in group over %s', async (system) => {
    // Same parameters, encodings and hashing, so that Pedersen bases, packets
    // and proofs made by one implementation verify under the other
    const builtin = initBackend(system);
    const ctx = new Foreign(initBackend(system));
    const pedersenBase = await derivePedersenBase(ctx);
    assert.deepEqual(pedersenBase, await derivePedersenBase(builtin));
    const { secret, sharing } = await shareSecret(ctx, nrShares, threshold);
    const { packets, commitments } = await createPedersenPackets(sharing, pedersenBase);
    const nonces: Nonces = {};
    const schnorr = [];
    for (const packet of packets) {
      const { share } = await parsePedersenPacket(builtin, commitments, pedersenBase, packet, threshold);
      nonces[share.index] = randomNonce();
      schnorr.push(await createSchnorrPacket(ctx, share, { nonce: nonces[share.index] }));
    }
    const { recovered } = await recoverPublic(builtin, schnorr, threshold, { nonces });
    assert.equal(await isKeypair(builtin, secret, recovered), true);
  });
});
